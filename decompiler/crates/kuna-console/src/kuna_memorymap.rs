//! (kuna) Checks a [`LoadMap`] against its file and target and turns it into
//! what the memory-map bootstrap installs: the loader's regions in byte
//! addresses, the executable ranges the ISA paints, the volatile ranges, and
//! the normalized entries with their names.

use std::collections::BTreeMap;

use kuna_decomp::kuna_loadmap::{LoadMap, RegionBytes};
use kuna_sleigh::kuna_mappedimage::MappedRegion;

/// The most regions one map may hold.
pub(crate) const MAX_REGIONS: usize = 64;

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

/// Check `map` against a `file_len`-byte file and a code space of
/// `word_size`-byte units whose highest byte address is `highest`. `arm32`
/// drops bit 0 of each entry.
pub(crate) fn plan(
    map: &LoadMap,
    file_len: u64,
    word_size: u64,
    highest: u64,
    arm32: bool,
) -> Result<MapPlan, String> {
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

    if map.entries.is_empty() {
        return Err("a memory map needs at least one entry".into());
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

    Ok(MapPlan {
        region_names: regions.iter().map(|(name, _)| name.to_string()).collect(),
        regions: regions.into_iter().map(|(_, region)| region).collect(),
        executable,
        volatile,
        entries,
        names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_decomp::kuna_loadmap::{LoadEntry, LoadRegion};

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
        }
    }

    fn refusal(map: &LoadMap) -> String {
        plan(map, 0x100, 1, u64::from(u32::MAX), true).unwrap_err()
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
        let plan = plan(&map, 0x100, 1, u64::from(u32::MAX), true).unwrap();
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
        let plan = plan(&map, 0x10, 2, 0xffff, false).unwrap();
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
}
