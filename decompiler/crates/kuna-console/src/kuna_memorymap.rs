//! (kuna) Checks a [`LoadMap`] against its file and target and turns it into
//! what the memory-map bootstrap installs: the loader's regions in byte
//! addresses, the executable ranges the ISA paints, the volatile ranges, and
//! the normalized entries, with the handlers of its vector tables, and their
//! names.

use std::collections::BTreeMap;

use kuna_analysis::analyzers::entry::kuna_mapvectors::stated_table_handlers;
use kuna_decomp::kuna_loadmap::{LoadMap, RegionBytes};
use kuna_sleigh::kuna_mappedimage::MappedRegion;

/// The most regions one map may hold.
pub(crate) const MAX_REGIONS: usize = 64;

/// The most slots a stated vector table may hold: the initial stack pointer,
/// 15 system exceptions and 496 interrupts.
const MAX_STATED_SLOTS: u32 = 512;

/// A checked [`LoadMap`], in byte addresses of the code space.
#[derive(Debug)]
pub(crate) struct MapPlan {
    pub(crate) regions: Vec<MappedRegion>,
    pub(crate) region_names: Vec<String>,
    pub(crate) executable: Vec<(u64, u64)>,
    pub(crate) volatile: Vec<(u64, u64)>,
    pub(crate) entries: Vec<u64>,
    pub(crate) names: BTreeMap<u64, String>,
}

/// Check `map` against `file` and a code space of `word_size`-byte units
/// whose highest byte address is `highest`. `arm32` drops bit 0 of each entry
/// and allows vector tables, whose words `big_endian` orders.
pub(crate) fn plan(
    map: &LoadMap,
    file: &[u8],
    word_size: u64,
    highest: u64,
    arm32: bool,
    big_endian: bool,
) -> Result<MapPlan, String> {
    let file_len = file.len() as u64;
    if map.regions.is_empty() {
        return Err("a memory map needs at least one region".into());
    }
    if map.regions.len() > MAX_REGIONS {
        return Err(format!("a memory map holds at most {MAX_REGIONS} regions"));
    }
    let to_byte = |value: u64, what: &str| {
        value.checked_mul(word_size).ok_or_else(|| {
            format!("{what} 0x{value:x} overflows the target's {word_size}-byte address units")
        })
    };

    let mut regions: Vec<(&str, MappedRegion)> = Vec::new();
    let mut volatile = Vec::new();
    for region in &map.regions {
        let name = region.name.as_str();
        if name.is_empty() {
            return Err(format!("the region at 0x{:x} has no name", region.address));
        }
        if regions.iter().any(|(other, _)| *other == name) {
            return Err(format!("two regions are named {name:?}"));
        }
        if region.size == 0 {
            return Err(format!("region {name:?} is empty"));
        }
        let address = to_byte(region.address, &format!("region {name:?} address"))?;
        let last = address
            .checked_add(region.size - 1)
            .filter(|&last| last <= highest)
            .ok_or_else(|| format!("region {name:?} lies outside the target address space"))?;
        let file_offset = match region.bytes {
            RegionBytes::File { offset } => {
                if region.volatile {
                    return Err(format!(
                        "region {name:?} is file-backed, so it cannot be volatile"
                    ));
                }
                if offset
                    .checked_add(region.size)
                    .is_none_or(|end| end > file_len)
                {
                    return Err(format!(
                        "region {name:?} reads file bytes 0x{offset:x}..0x{:x}, past the end of the 0x{file_len:x}-byte file",
                        offset.saturating_add(region.size)
                    ));
                }
                Some(offset)
            }
            RegionBytes::Zero => {
                if region.execute {
                    return Err(format!(
                        "region {name:?} is zero-filled, so it cannot be executable"
                    ));
                }
                None
            }
        };
        if region.volatile {
            volatile.push((address, last - address + 1));
        }
        regions.push((
            name,
            MappedRegion {
                address,
                size: region.size,
                file_offset,
                write: region.write,
                execute: region.execute,
            },
        ));
    }

    regions.sort_by_key(|(_, region)| region.address);
    for pair in regions.windows(2) {
        let ((first, a), (second, b)) = (&pair[0], &pair[1]);
        if b.address < a.address + a.size {
            return Err(format!("regions {first:?} and {second:?} overlap"));
        }
    }
    let mut backed: Vec<(&str, u64, u64)> = regions
        .iter()
        .filter_map(|(name, region)| {
            region
                .file_offset
                .map(|offset| (*name, offset, region.size))
        })
        .collect();
    backed.sort_by_key(|&(_, offset, _)| offset);
    for pair in backed.windows(2) {
        let ((first, offset, size), (second, next, _)) = (pair[0], pair[1]);
        if next < offset + size {
            return Err(format!(
                "regions {first:?} and {second:?} share file byte 0x{next:x}"
            ));
        }
    }

    let executable: Vec<(u64, u64)> = regions
        .iter()
        .filter(|(_, region)| region.execute)
        .map(|(_, region)| (region.address, region.size))
        .collect();
    if executable.is_empty() {
        return Err("a memory map needs a file-backed executable region".into());
    }

    if map.entries.is_empty() && map.vector_tables.is_empty() {
        return Err("a memory map needs at least one entry or one vector table".into());
    }
    let mut entries = Vec::new();
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for entry in &map.entries {
        let units = if arm32 {
            entry.address & !1
        } else {
            entry.address
        };
        let at = to_byte(units, "entry")?;
        if !executable
            .iter()
            .any(|&(start, size)| at >= start && at - start < size)
        {
            return Err(format!(
                "entry 0x{:x} is outside every executable region",
                entry.address
            ));
        }
        if !entries.contains(&at) {
            entries.push(at);
        }
        let Some(name) = &entry.name else { continue };
        if name.is_empty() {
            return Err(format!("entry 0x{:x} has an empty name", entry.address));
        }
        match names.get(&at) {
            Some(other) if other != name => {
                return Err(format!(
                    "entry 0x{:x} is named both {other:?} and {name:?}",
                    entry.address
                ));
            }
            _ => {
                names.insert(at, name.clone());
            }
        }
    }

    let in_exec = |at: u64| {
        executable
            .iter()
            .any(|&(start, size)| at >= start && at - start < size)
    };
    let mut handlers = Vec::new();
    for (i, table) in map.vector_tables.iter().enumerate() {
        let address = table.address;
        if !arm32 {
            return Err(format!(
                "vector table 0x{address:x}: only a 32-bit ARM target has Cortex-M vector tables"
            ));
        }
        if map.vector_tables[..i]
            .iter()
            .any(|other| other.address == address)
        {
            return Err(format!("two vector tables start at 0x{address:x}"));
        }
        if let Some(slots) = table.slots {
            if !(2..=MAX_STATED_SLOTS).contains(&slots) {
                return Err(format!(
                    "vector table 0x{address:x} states {slots} slots, not 2 to {MAX_STATED_SLOTS}"
                ));
            }
        }
        let at = to_byte(address, "vector table")?;
        if at % 4 != 0 {
            return Err(format!("vector table 0x{address:x} is not aligned to 4"));
        }
        let Some((name, region, offset)) = regions.iter().find_map(|(name, region)| {
            let offset = region.file_offset?;
            (at >= region.address && at - region.address < region.size)
                .then_some((name, region, offset))
        }) else {
            return Err(format!(
                "vector table 0x{address:x} is outside every file-backed region"
            ));
        };
        let start = (offset + (at - region.address)) as usize;
        let mut end = (offset + region.size) as usize;
        if let Some(slots) = table.slots {
            let stated = start + slots as usize * 4;
            if stated > end {
                return Err(format!(
                    "vector table 0x{address:x}'s {slots} slots run past the end of region {name:?}"
                ));
            }
            end = stated;
        }
        let found =
            stated_table_handlers(at, &file[start..end], !big_endian, &in_exec, table.slots);
        if found.first().map(|&(slot, _)| slot) != Some(1) {
            return Err(format!(
                "vector table 0x{address:x}: slot 1 holds no Thumb pointer into an executable region"
            ));
        }
        handlers.extend(found);
    }
    for (target, name) in cmsis_handler_names(&handlers) {
        if !names.contains_key(&target) && !names.values().any(|other| other == name) {
            names.insert(target, name.to_string());
        }
    }
    for &(_, target) in &handlers {
        if !entries.contains(&target) {
            entries.push(target);
        }
    }

    Ok(MapPlan {
        region_names: regions.iter().map(|(name, _)| name.to_string()).collect(),
        regions: regions.into_iter().map(|(_, region)| region).collect(),
        executable,
        volatile,
        entries,
        names,
    })
}

/// The CMSIS handler name of system exception `slot` (1 to 15); `None` for a
/// reserved slot or an interrupt.
fn cmsis_exception_name(slot: usize) -> Option<&'static str> {
    Some(match slot {
        1 => "Reset_Handler",
        2 => "NMI_Handler",
        3 => "HardFault_Handler",
        4 => "MemManage_Handler",
        5 => "BusFault_Handler",
        6 => "UsageFault_Handler",
        11 => "SVC_Handler",
        12 => "DebugMon_Handler",
        14 => "PendSV_Handler",
        15 => "SysTick_Handler",
        _ => return None,
    })
}

/// The CMSIS names `handlers` (every table's `(slot, target)` pairs, in map
/// order) suggest, in the same order. Slot 1's target is `Reset_Handler`
/// whatever else points at it, since reset always runs it. Another system
/// exception's target takes its name only when no other slot of any table
/// points at it: a shared default handler has no one right name.
fn cmsis_handler_names(handlers: &[(usize, u64)]) -> Vec<(u64, &'static str)> {
    let mut uses: BTreeMap<u64, usize> = BTreeMap::new();
    for &(_, target) in handlers {
        *uses.entry(target).or_default() += 1;
    }
    handlers
        .iter()
        .filter_map(|&(slot, target)| {
            let name = cmsis_exception_name(slot)?;
            (slot == 1 || uses[&target] == 1).then_some((target, name))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_decomp::kuna_loadmap::{LoadEntry, LoadRegion, VectorTable};

    fn region(name: &str, address: u64, size: u64, bytes: RegionBytes) -> LoadRegion {
        LoadRegion {
            name: name.into(),
            address,
            size,
            bytes,
            read: true,
            write: matches!(bytes, RegionBytes::Zero),
            execute: matches!(bytes, RegionBytes::File { .. }),
            volatile: false,
        }
    }

    fn map(regions: Vec<LoadRegion>, entries: &[(u64, Option<&str>)]) -> LoadMap {
        LoadMap {
            regions,
            entries: entries
                .iter()
                .map(|&(address, name)| LoadEntry {
                    address,
                    name: name.map(str::to_string),
                })
                .collect(),
            vector_tables: Vec::new(),
        }
    }

    fn refusal(map: &LoadMap) -> String {
        plan(map, &[0; 0x100], 1, u64::from(u32::MAX), true, false).unwrap_err()
    }

    #[test]
    fn a_thumb_entry_drops_its_low_bit_and_keeps_its_name() {
        let map = map(
            vec![region(
                "flash",
                0x1000,
                0x100,
                RegionBytes::File { offset: 0 },
            )],
            &[(0x1001, Some("reset")), (0x1000, None)],
        );
        let plan = plan(&map, &[0; 0x100], 1, u64::from(u32::MAX), true, false).unwrap();
        assert_eq!(plan.entries, vec![0x1000]);
        assert_eq!(plan.names.get(&0x1000).map(String::as_str), Some("reset"));
    }

    #[test]
    fn word_addresses_scale_to_bytes() {
        let map = map(
            vec![region(
                "flash",
                0x100,
                0x10,
                RegionBytes::File { offset: 0 },
            )],
            &[(0x101, None)],
        );
        let plan = plan(&map, &[0; 0x10], 2, 0xffff, false, false).unwrap();
        assert_eq!(plan.regions[0].address, 0x200);
        assert_eq!(plan.entries, vec![0x202]);
    }

    #[test]
    fn refuses_what_a_map_cannot_mean() {
        let flash = || region("flash", 0x1000, 0x80, RegionBytes::File { offset: 0 });
        let cases = [
            (
                map(
                    vec![flash(), region("ram", 0x107f, 4, RegionBytes::Zero)],
                    &[(0x1000, None)],
                ),
                "overlap",
            ),
            (
                map(
                    vec![
                        flash(),
                        region("copy", 0x2000, 4, RegionBytes::File { offset: 0x7f }),
                    ],
                    &[(0x1000, None)],
                ),
                "share file byte 0x7f",
            ),
            (
                map(
                    vec![region(
                        "flash",
                        0x1000,
                        0x81,
                        RegionBytes::File { offset: 0x80 },
                    )],
                    &[(0x1000, None)],
                ),
                "past the end",
            ),
            (
                map(vec![flash()], &[(0x1080, None)]),
                "outside every executable region",
            ),
            (
                map(vec![flash(), flash()], &[(0x1000, None)]),
                "two regions",
            ),
            (
                map(vec![region("ram", 0, 4, RegionBytes::Zero)], &[(0, None)]),
                "executable region",
            ),
            (map(vec![flash()], &[]), "at least one entry"),
            (
                map(
                    vec![region("top", 0xffff_fffe, 4, RegionBytes::Zero), flash()],
                    &[(0x1000, None)],
                ),
                "address space",
            ),
        ];
        for (map, expected) in cases {
            let err = refusal(&map);
            assert!(err.contains(expected), "{err:?} does not say {expected:?}");
        }
        let mut code_in_ram = map(
            vec![flash(), region("ram", 0x2000, 4, RegionBytes::Zero)],
            &[(0x1000, None)],
        );
        code_in_ram.regions[1].execute = true;
        assert!(refusal(&code_in_ram).contains("cannot be executable"));
        let mut volatile_flash = map(vec![flash()], &[(0x1000, None)]);
        volatile_flash.regions[0].volatile = true;
        assert!(refusal(&volatile_flash).contains("cannot be volatile"));
    }

    #[test]
    fn a_vector_table_alone_supplies_the_entries() {
        let mut file = vec![0u8; 0x100];
        for (slot, word) in [(0, 0x2000_1000u32), (1, 0x1041), (2, 0x1041)] {
            file[slot * 4..slot * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let mut map = map(
            vec![region(
                "flash",
                0x1000,
                0x100,
                RegionBytes::File { offset: 0 },
            )],
            &[],
        );
        map.vector_tables.push(VectorTable {
            address: 0x1000,
            slots: None,
        });
        let plan = plan(&map, &file, 1, u64::from(u32::MAX), true, false).unwrap();
        assert_eq!(plan.entries, vec![0x1040]);
        assert_eq!(
            plan.names.get(&0x1040).map(String::as_str),
            Some("Reset_Handler"),
            "reset names its handler even when NMI shares it"
        );
        assert_eq!(plan.names.len(), 1);
        let err = super::plan(&map, &file, 1, u64::from(u32::MAX), false, false).unwrap_err();
        assert!(err.contains("32-bit ARM"), "{err}");
    }

    fn two_tables(file: &mut [u8]) -> LoadMap {
        let words = [
            (0x00, 0x2000_1000u32),
            (0x04, 0x1041),
            (0x08, 0x1051),
            (0x0c, 0x1061),
            (0x80, 0x2000_1000),
            (0x84, 0x1071),
            (0x88, 0x1061),
        ];
        for (at, word) in words {
            file[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        let mut map = map(
            vec![region(
                "flash",
                0x1000,
                0x100,
                RegionBytes::File { offset: 0 },
            )],
            &[],
        );
        for address in [0x1000, 0x1080] {
            map.vector_tables.push(VectorTable {
                address,
                slots: None,
            });
        }
        map
    }

    #[test]
    fn slots_are_counted_across_every_table_and_the_first_table_names_reset() {
        let mut file = vec![0u8; 0x100];
        let map = two_tables(&mut file);
        let plan = plan(&map, &file, 1, u64::from(u32::MAX), true, false).unwrap();
        let name = |at: u64| plan.names.get(&at).map(String::as_str);
        assert_eq!(name(0x1040), Some("Reset_Handler"));
        assert_eq!(name(0x1050), Some("NMI_Handler"));
        assert_eq!(
            name(0x1060),
            None,
            "HardFault in one table, NMI in the other"
        );
        assert_eq!(name(0x1070), None, "the first table took Reset_Handler");
        let mut entries = plan.entries.clone();
        entries.sort_unstable();
        assert_eq!(entries, vec![0x1040, 0x1050, 0x1060, 0x1070]);
    }

    #[test]
    fn refuses_two_tables_at_one_address() {
        let mut file = vec![0u8; 0x100];
        let mut map = two_tables(&mut file);
        map.vector_tables[1].address = 0x1000;
        let err = plan(&map, &file, 1, u64::from(u32::MAX), true, false).unwrap_err();
        assert!(err.contains("two vector tables start at 0x1000"), "{err}");
    }
}
