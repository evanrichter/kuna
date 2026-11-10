//! A headerless firmware image loads from a memory map: flash from the file,
//! RAM and a peripheral block with no file bytes. Flash constants fold, RAM
//! stays memory whose contents are unknown, and every peripheral access is
//! kept.

use crate::common;

use std::path::PathBuf;

use kuna_analysis::analyzers::strings::kuna_stringinv::{self, Query, Termination};
use kuna_analysis::kuna_imageview::ImageView;
use kuna_analysis::listing::xrefs::{self, XrefKind};
use kuna_console::engine::{
    language_database, ArmIsa, Bootstrap, ConsoleProgram, LoadEntry, LoadMap, LoadRegion,
    RegionBytes,
};
use kuna_console::decompile_step::{decompile_one, DecompileSeed};
use kuna_console::inspect::string_uses_in;
use kuna_decomp::decompile_drive::print_c;
use kuna_decomp::kuna_loadoptions::{environment_fallbacks, LoadOptions};
use kuna_decomp::kuna_memoryspecs::SpecRoot;
use kuna_decomp::userop::{BUILTIN_VOLATILE_READ, BUILTIN_VOLATILE_WRITE};
use kuna_num::opcodes::OpCode;
use kuna_sleigh::loadimage::section_flags;

const TARGET: &str = "ARM:LE:32:Cortex";
const FLASH: u64 = 0x0800_0000;
const SRAM: u64 = 0x2000_0000;
const ROM: u64 = 0x3000_0000;
const PERIPH: u64 = 0x4000_0000;

fn specs() -> [SpecRoot; 1] {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    [root.join("specs").into()]
}

/// Thumb `bl` from `from` to `to`, as two halfwords.
fn bl(from: u64, to: u64) -> [u16; 2] {
    let offset = (to as i64 - (from as i64 + 4)) as u32;
    let s = (offset >> 24) & 1;
    let j1 = (!(offset >> 23) & 1) ^ s;
    let j2 = (!(offset >> 22) & 1) ^ s;
    let hi = 0xf000 | (s << 10) | ((offset >> 12) & 0x3ff);
    let lo = 0xd000 | (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x7ff);
    [hi as u16, lo as u16]
}

/// The flash image: Thumb functions, each followed by its literal pool.
fn flash() -> Vec<u8> {
    let mut words: Vec<u16> = Vec::new();
    let pool = |halves: &mut Vec<u16>, word: u32| {
        halves.push(word as u16);
        halves.push((word >> 16) as u16);
    };
    // 0x00 get_const: ldr r0,[pc,#0]; bx lr; .word 0xcafebabe
    words.extend([0x4800, 0x4770]);
    pool(&mut words, 0xcafe_babe);
    // 0x08 get_ram: ldr r1,[pc,#4]; ldr r0,[r1]; bx lr; nop; .word SRAM+0x10
    words.extend([0x4901, 0x6808, 0x4770, 0xbf00]);
    pool(&mut words, (SRAM + 0x10) as u32);
    // 0x14 get_rom: the same load from the zero-filled `r` region
    words.extend([0x4901, 0x6808, 0x4770, 0xbf00]);
    pool(&mut words, ROM as u32);
    // 0x20 uart_put: ldr r1,[pc,#8]; movs r0,#0x41; str r0,[r1,#4]; movs r0,#0x42; str r0,[r1,#4]; bx lr
    words.extend([0x4902, 0x2041, 0x6048, 0x2042, 0x6048, 0x4770]);
    pool(&mut words, PERIPH as u32);
    // 0x30 wait_ready: ldr r1,[pc,#8]; loop: ldr r0,[r1]; lsls r0,r0,#31; bpl loop; bx lr; nop
    words.extend([0x4902, 0x6808, 0x07c0, 0xd5fc, 0x4770, 0xbf00]);
    pool(&mut words, PERIPH as u32);
    // 0x40 wait_ram: the same loop over a RAM word
    words.extend([0x4902, 0x6808, 0x07c0, 0xd5fc, 0x4770, 0xbf00]);
    pool(&mut words, (SRAM + 0x20) as u32);
    // 0x50 main: push {r7,lr}; bl helper; pop {r7,pc}
    words.push(0xb580);
    words.extend(bl(FLASH + 0x52, FLASH + 0x60));
    words.push(0xbd80);
    words.resize(0x30, 0xbf00);
    // 0x60 helper: movs r0,#7; bx lr
    words.extend([0x2007, 0x4770]);
    words.iter().flat_map(|half| half.to_le_bytes()).collect()
}

/// `flash()` followed by `get_msg`, which returns the address of a string
/// stored after its literal pool.
const GET_MSG: u64 = 0x64;
const MESSAGE: u64 = 0x6c;
const TEXT: &str = "hello from flash";

fn flash_with_message() -> Vec<u8> {
    let mut bytes = flash();
    assert_eq!(bytes.len() as u64, GET_MSG);
    // ldr r0,[pc,#0]; bx lr; .word FLASH+MESSAGE
    for half in [0x4800u16, 0x4770] {
        bytes.extend(half.to_le_bytes());
    }
    bytes.extend(((FLASH + MESSAGE) as u32).to_le_bytes());
    bytes.extend(TEXT.as_bytes());
    bytes.push(0);
    bytes
}

struct Image(PathBuf);

impl Image {
    fn new() -> Image {
        Image::holding(&flash())
    }

    fn holding(bytes: &[u8]) -> Image {
        let path = common::scratch_file("memory-map", "bin");
        std::fs::write(&path, bytes).unwrap();
        Image(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn region(name: &str, address: u64, size: u64, bytes: RegionBytes, access: &str) -> LoadRegion {
    LoadRegion {
        name: name.into(),
        address,
        size,
        bytes,
        read: access.contains('r'),
        write: access.contains('w'),
        execute: access.contains('x'),
        volatile: false,
    }
}

fn entry(offset: u64, name: &str) -> LoadEntry {
    LoadEntry {
        address: FLASH + offset + 1,
        name: Some(name.into()),
    }
}

fn firmware_map() -> LoadMap {
    let mut periph = region("periph", PERIPH, 0x1000, RegionBytes::Zero, "rw");
    periph.volatile = true;
    LoadMap {
        regions: vec![
            region(
                "flash",
                FLASH,
                flash().len() as u64,
                RegionBytes::File { offset: 0 },
                "rx",
            ),
            region("sram", SRAM, 0x1000, RegionBytes::Zero, "rw"),
            region("rom", ROM, 0x100, RegionBytes::Zero, "r"),
            periph,
        ],
        entries: vec![
            entry(0x00, "get_const"),
            entry(0x08, "get_ram"),
            entry(0x14, "get_rom"),
            entry(0x20, "uart_put"),
            entry(0x30, "wait_ready"),
            entry(0x40, "wait_ram"),
            entry(0x50, "main"),
        ],
        vector_tables: Vec::new(),
    }
}

fn load(image: &Image, map: &LoadMap) -> Result<ConsoleProgram, String> {
    let options = LoadOptions::default();
    Bootstrap::new(&specs())
        .target(TARGET)
        .arm_isa(Some(ArmIsa::Thumb))
        .options(&options)
        .memory_map(image.path(), map)
        .map_err(|e| e.to_string())
}

fn decompile(prog: &mut ConsoleProgram, func: &str) -> String {
    let entry = prog
        .find_entry_by_name(func)
        .unwrap_or_else(|| panic!("{func} is a function"));
    let seed = DecompileSeed::plain(&[], &[]);
    let fd = decompile_one(prog.arch_mut(), &entry.name, entry.addr.clone(), 0, &seed, &[])
        .result
        .expect("decompile succeeds");
    print_c(prog.arch_mut(), &fd)
}

/// The firmware with `get_msg` and its string, `get_msg` an entry.
fn loaded_with_message() -> (Image, ConsoleProgram) {
    let bytes = flash_with_message();
    let image = Image::holding(&bytes);
    let mut map = firmware_map();
    map.regions[0].size = bytes.len() as u64;
    map.entries.push(entry(GET_MSG, "get_msg"));
    let mut prog = load(&image, &map).expect("bootstrap the memory map");
    prog.commit_pending_analysis()
        .expect("analysis commit succeeds");
    (image, prog)
}

fn loaded() -> (Image, ConsoleProgram) {
    let image = Image::new();
    let mut prog = load(&image, &firmware_map()).expect("bootstrap the memory map");
    prog.commit_pending_analysis()
        .expect("analysis commit succeeds");
    (image, prog)
}

/// Each volatile access the decompiled function keeps, as `(instruction
/// address, written, device address)`.
fn volatile_accesses(prog: &mut ConsoleProgram, func: &str) -> Vec<(u64, bool, u64)> {
    let entry = prog
        .find_entry_by_name(func)
        .unwrap_or_else(|| panic!("{func} is a function"));
    let seed = DecompileSeed::plain(&[], &[]);
    let fd = decompile_one(prog.arch_mut(), &entry.name, entry.addr.clone(), 0, &seed, &[])
        .result
        .expect("decompile succeeds");
    let mut out = Vec::new();
    for id in fd.obank().iter_alive() {
        let op = fd.obank().get(id).unwrap();
        if op.code() != OpCode::CPUI_CALLOTHER || op.num_input() < 2 {
            continue;
        }
        let index = fd.vbank().get(op.get_in(0).unwrap()).unwrap();
        let written = match index.get_offset() as u32 {
            BUILTIN_VOLATILE_READ => false,
            BUILTIN_VOLATILE_WRITE => true,
            _ => continue,
        };
        let device = fd.vbank().get(op.get_in(1).unwrap()).unwrap().get_offset();
        out.push((op.get_addr().get_offset(), written, device));
    }
    out.sort_unstable();
    out
}

#[test]
fn reads_file_bytes_and_zero_fill() {
    let (_image, prog) = loaded();
    assert_eq!(
        prog.read_bytes(FLASH + 4, 4),
        Some(vec![0xbe, 0xba, 0xfe, 0xca])
    );
    for zero in [SRAM, ROM + 0xfc, PERIPH + 4] {
        assert_eq!(prog.read_bytes(zero, 4), Some(vec![0; 4]), "0x{zero:x}");
    }
    assert_eq!(prog.read_bytes(0x1000_0000, 4), None);
    let sections = prog.sections();
    assert_eq!(sections.len(), 4);
    let code: Vec<u64> = sections
        .iter()
        .filter(|(_, _, flags)| flags & section_flags::CODE != 0)
        .map(|&(address, _, _)| address)
        .collect();
    assert_eq!(code, vec![FLASH]);
}

#[test]
fn a_literal_pool_load_from_flash_folds_to_its_constant() {
    let (_image, mut prog) = loaded();
    let c = decompile(&mut prog, "get_const");
    assert!(c.contains("return 0xcafebabe;"), "{c}");
}

#[test]
fn a_ram_global_stays_a_global() {
    let (_image, mut prog) = loaded();
    let c = decompile(&mut prog, "get_ram");
    assert!(c.contains("return dat_20000010;"), "{c}");
}

#[test]
fn a_load_from_a_zero_filled_read_only_region_is_not_folded() {
    let (_image, mut prog) = loaded();
    let c = decompile(&mut prog, "get_rom");
    assert!(c.contains("return dat_30000000;"), "{c}");
}

#[test]
fn both_stores_to_the_peripheral_region_survive() {
    let (_image, mut prog) = loaded();
    let c = decompile(&mut prog, "uart_put");
    assert!(c.contains("0x41") && c.contains("0x42"), "{c}");
    let writes: Vec<u64> = volatile_accesses(&mut prog, "uart_put")
        .into_iter()
        .filter(|&(_, written, _)| written)
        .map(|(_, _, device)| device)
        .collect();
    assert_eq!(writes, vec![PERIPH + 4, PERIPH + 4]);
}

#[test]
fn a_polling_loop_reads_the_peripheral_on_every_pass() {
    let (_image, mut prog) = loaded();
    let c = decompile(&mut prog, "wait_ready");
    assert!(
        c.lines()
            .any(|line| line.contains("while") && line.contains("dat_40000000")),
        "the loop condition does not read the status register:\n{c}"
    );
    let looped = FLASH + 0x32..FLASH + 0x38;
    let reads = volatile_accesses(&mut prog, "wait_ready");
    assert!(
        reads
            .iter()
            .any(|&(at, written, device)| !written && device == PERIPH && looped.contains(&at)),
        "no volatile read of the status register inside the loop: {reads:x?}"
    );
    assert_eq!(volatile_accesses(&mut prog, "wait_ram"), vec![]);
}

#[test]
fn entries_keep_their_names_and_seed_discovery() {
    let (_image, mut prog) = loaded();
    let main = prog.find_entry_by_name("main").expect("named entry");
    assert_eq!(main.addr.get_offset(), FLASH + 0x50);
    assert!(
        prog.find_entry_at(FLASH + 0x60).is_some(),
        "the callee of main is discovered"
    );
    let c = decompile(&mut prog, "main");
    assert!(c.contains("sub_8000060()"), "{c}");
}

#[test]
fn refuses_maps_that_cannot_load() {
    let image = Image::new();
    let len = flash().len() as u64;
    let mut overlap = firmware_map();
    overlap.regions[1].address = FLASH + len - 4;
    let mut shared = firmware_map();
    shared.regions.push(region(
        "copy",
        0x2100_0000,
        4,
        RegionBytes::File { offset: len - 4 },
        "r",
    ));
    let mut past = firmware_map();
    past.regions[0].size = len + 1;
    let mut outside = firmware_map();
    outside.entries.push(LoadEntry {
        address: SRAM + 1,
        name: None,
    });
    for (map, expected) in [
        (overlap, "overlap"),
        (shared, "share file byte"),
        (past, "past the end"),
        (outside, "outside every executable region"),
    ] {
        let err = match load(&image, &map) {
            Ok(_) => panic!("loaded a map that should say {expected:?}"),
            Err(err) => err,
        };
        assert!(err.contains(expected), "{err:?} does not say {expected:?}");
    }
}

#[test]
fn an_explicit_load_never_reads_the_environment() {
    std::thread::spawn(|| {
        let before = environment_fallbacks();
        let (_image, mut prog) = loaded();
        let c = decompile(&mut prog, "get_const");
        assert!(c.contains("0xcafebabe"), "{c}");
        assert_eq!(environment_fallbacks(), before);
    })
    .join()
    .unwrap();
}

#[test]
fn a_language_database_loads_the_same_program() {
    let image = Image::new();
    let db = language_database(&specs()).expect("scan specs");
    let options = LoadOptions::default();
    let mut prog = Bootstrap::new(&db)
        .target(TARGET)
        .arm_isa(Some(ArmIsa::Thumb))
        .options(&options)
        .memory_map(image.path(), &firmware_map())
        .expect("bootstrap over the database");
    prog.commit_pending_analysis().unwrap();
    let (_other, mut scanned) = loaded();
    for func in ["get_const", "uart_put", "wait_ready"] {
        assert_eq!(decompile(&mut prog, func), decompile(&mut scanned, func));
    }
}

#[test]
fn the_reference_walk_finds_a_direct_call_in_a_memory_map() {
    let (_image, prog) = loaded_with_message();
    let view = prog.image_view().expect("a memory-map program has an image view");
    let entries: Vec<u64> = prog
        .function_entries_canonical()
        .iter()
        .map(|e| e.addr.get_offset())
        .collect();
    let seeds = xrefs::discovery_seeds_in(&view, &entries, prog.arch().analysis_funcstart_patterns);
    let index = xrefs::build_in(&view, prog.arch(), prog.arch().translate(), &seeds);
    let calls: Vec<(u64, XrefKind)> = index
        .refs_to(FLASH + 0x60)
        .iter()
        .map(|r| (r.from, r.kind))
        .collect();
    assert_eq!(calls, vec![(FLASH + 0x52, XrefKind::Call)]);
    assert_eq!(index.function_containing(FLASH + 0x52), Some(FLASH + 0x50));
}

#[test]
fn the_inventory_finds_a_string_in_flash_and_the_load_that_uses_it() {
    let (_image, prog) = loaded_with_message();
    let view = prog.image_view().expect("a memory-map program has an image view");
    let query = Query {
        min_len: 5,
        ascii: true,
        utf8: false,
        utf16: false,
        section: None,
        termination: Termination::Nul,
    };
    let inventory = kuna_stringinv::inventory_in(&view, &query);
    assert_eq!(inventory.regions, vec!["flash"], "only flash holds bytes");
    let found = inventory
        .strings
        .iter()
        .find(|s| s.text == TEXT)
        .expect("the string in flash is found");
    assert_eq!(
        (found.addr, found.section.as_deref()),
        (FLASH + MESSAGE, Some("flash"))
    );
    let uses = string_uses_in(&prog, &view, &[(found.addr, u64::from(found.byte_len))]);
    let sites: Vec<(u64, Option<&str>)> = uses[0]
        .iter()
        .map(|u| (u.row.site, u.row.name.as_deref()))
        .collect();
    assert_eq!(sites, vec![(FLASH + GET_MSG, Some("get_msg"))]);
}

#[test]
fn a_memory_map_view_states_the_target_and_names_its_regions() {
    let (_image, prog) = loaded();
    let view = prog.image_view().expect("a memory-map program has an image view");
    assert_eq!(view.architecture(), object::Architecture::Arm);
    assert!(view.is_little_endian());
    assert_eq!(view.pointer_width(), 4);
    let names: Vec<Option<&str>> = view.regions().iter().map(|r| r.name).collect();
    assert_eq!(
        names,
        vec![Some("flash"), Some("sram"), Some("rom"), Some("periph")]
    );
}
