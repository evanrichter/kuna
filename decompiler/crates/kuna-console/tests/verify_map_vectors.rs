//! A memory map's Cortex-M vector table seeds discovery: the reset handler and
//! the other system handlers that one slot points at take their CMSIS names,
//! and any other handler that several slots share keeps Kuna's generated name.

use crate::common;

use std::path::PathBuf;

use kuna_console::engine::{
    ArmIsa, Bootstrap, ConsoleProgram, LoadEntry, LoadMap, LoadRegion, RegionBytes, VectorTable,
};
use kuna_decomp::kuna_loadoptions::LoadOptions;
use kuna_decomp::kuna_memoryspecs::SpecRoot;

const TARGET: &str = "ARM:LE:32:Cortex";
const FLASH: u64 = 0x0800_0000;
const SRAM: u64 = 0x2000_0000;
const RESET: u64 = FLASH + 0x50;
const NMI: u64 = FLASH + 0x54;
const SHARED: u64 = FLASH + 0x58;
const IRQ1: u64 = FLASH + 0x5c;
const SLOTS: usize = 20;

fn specs() -> [SpecRoot; 1] {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    [root.join("specs").into()]
}

/// A 20-slot table at flash's start, then four Thumb handlers that each
/// return. Slot 1 is reset, slot 2 NMI, slot 3 (HardFault) and slot 16 (IRQ0)
/// share a handler, slot 17 (IRQ1) has its own, and the rest are zero.
/// `nmi` is what slot 2 points at.
fn firmware(nmi: u64) -> Vec<u8> {
    let mut table = [0u32; SLOTS];
    table[0] = (SRAM + 0x1000) as u32;
    table[1] = (RESET | 1) as u32;
    table[2] = (nmi | 1) as u32;
    table[3] = (SHARED | 1) as u32;
    table[16] = (SHARED | 1) as u32;
    table[17] = (IRQ1 | 1) as u32;
    let mut bytes: Vec<u8> = table.iter().flat_map(|w| w.to_le_bytes()).collect();
    for _ in 0..4 {
        // bx lr; nop
        bytes.extend([0x70, 0x47, 0x00, 0xbf]);
    }
    bytes
}

struct Image(PathBuf);

impl Image {
    fn holding(bytes: &[u8]) -> Image {
        let path = common::scratch_file("map-vectors", "bin");
        std::fs::write(&path, bytes).unwrap();
        Image(path)
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn map(len: usize, table: VectorTable) -> LoadMap {
    LoadMap {
        regions: vec![
            LoadRegion {
                name: "flash".into(),
                address: FLASH,
                size: len as u64,
                bytes: RegionBytes::File { offset: 0 },
                read: true,
                write: false,
                execute: true,
                volatile: false,
            },
            LoadRegion {
                name: "sram".into(),
                address: SRAM,
                size: 0x1000,
                bytes: RegionBytes::Zero,
                read: true,
                write: true,
                execute: false,
                volatile: false,
            },
        ],
        entries: Vec::new(),
        vector_tables: vec![table],
    }
}

fn table(address: u64, slots: Option<u32>) -> VectorTable {
    VectorTable { address, slots }
}

fn load(bytes: &[u8], map: &LoadMap) -> Result<ConsoleProgram, String> {
    let image = Image::holding(bytes);
    let options = LoadOptions::default();
    let mut prog = Bootstrap::new(&specs())
        .target(TARGET)
        .arm_isa(Some(ArmIsa::Thumb))
        .options(&options)
        .memory_map(image.0.to_str().unwrap(), map)
        .map_err(|e| e.to_string())?;
    prog.commit_pending_analysis().map_err(|e| e.to_string())?;
    Ok(prog)
}

fn name_at(prog: &ConsoleProgram, address: u64) -> Option<String> {
    prog.find_entry_at(address).map(|entry| entry.name)
}

#[test]
fn a_vector_table_names_the_handlers_one_system_slot_points_at() {
    let bytes = firmware(NMI);
    let prog = load(&bytes, &map(bytes.len(), table(FLASH, None))).expect("load");
    assert_eq!(name_at(&prog, RESET).as_deref(), Some("Reset_Handler"));
    assert_eq!(name_at(&prog, NMI).as_deref(), Some("NMI_Handler"));
    assert_eq!(name_at(&prog, SHARED).as_deref(), Some("sub_8000058"));
    assert_eq!(name_at(&prog, IRQ1).as_deref(), Some("sub_800005c"));
    assert!(prog.find_entry_by_name("HardFault_Handler").is_none());
}

#[test]
fn a_handler_nmi_shares_with_an_interrupt_keeps_its_generated_name() {
    let bytes = firmware(SHARED);
    let prog = load(&bytes, &map(bytes.len(), table(FLASH, None))).expect("load");
    assert_eq!(name_at(&prog, RESET).as_deref(), Some("Reset_Handler"));
    assert_eq!(name_at(&prog, SHARED).as_deref(), Some("sub_8000058"));
    assert!(prog.find_entry_by_name("NMI_Handler").is_none());
}

#[test]
fn the_reset_handler_keeps_its_name_when_nmi_shares_it() {
    let bytes = firmware(RESET);
    let prog = load(&bytes, &map(bytes.len(), table(FLASH, None))).expect("load");
    assert_eq!(name_at(&prog, RESET).as_deref(), Some("Reset_Handler"));
    assert!(prog.find_entry_by_name("NMI_Handler").is_none());
}

#[test]
fn a_stated_slot_count_ends_the_table() {
    let bytes = firmware(NMI);
    let prog = load(&bytes, &map(bytes.len(), table(FLASH, Some(17)))).expect("load");
    assert_eq!(name_at(&prog, SHARED).as_deref(), Some("sub_8000058"));
    assert!(
        prog.find_entry_at(IRQ1).is_none(),
        "slot 17 lies past a 17-slot table"
    );
}

#[test]
fn an_entry_name_beats_the_cmsis_name() {
    let bytes = firmware(NMI);
    let mut map = map(bytes.len(), table(FLASH, None));
    map.entries.push(LoadEntry {
        address: RESET | 1,
        name: Some("start".into()),
    });
    let prog = load(&bytes, &map).expect("load");
    assert_eq!(name_at(&prog, RESET).as_deref(), Some("start"));
    assert!(prog.find_entry_by_name("Reset_Handler").is_none());
    assert_eq!(name_at(&prog, NMI).as_deref(), Some("NMI_Handler"));
}

#[test]
fn refuses_a_table_outside_every_file_backed_region() {
    let bytes = firmware(NMI);
    for (table, expected) in [
        (table(SRAM, None), "outside every file-backed region"),
        (table(0x0900_0000, None), "outside every file-backed region"),
        (table(FLASH + 2, None), "not aligned to 4"),
        (table(FLASH, Some(1)), "not 2 to 512"),
        (table(FLASH + 0x50, Some(8)), "run past the end"),
        (table(FLASH + 0x10, None), "slot 1"),
    ] {
        let err = match load(&bytes, &map(bytes.len(), table)) {
            Ok(_) => panic!("loaded a table that should say {expected:?}"),
            Err(err) => err,
        };
        assert!(err.contains(expected), "{err:?} does not say {expected:?}");
    }
}
