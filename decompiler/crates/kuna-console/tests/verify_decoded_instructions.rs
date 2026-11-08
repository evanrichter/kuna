//! What `XrefIndex::decoded_instructions` lists, pinned on a real image: every
//! instruction the walk decoded, once, in address order, with the length the
//! disassembler gives it.
//!
//! Fixture: `fauxware` (ELF x86-64). Bootstrapping needs the built `x86` `.sla`
//! under `specs/` (gitignored; `make specs`).

use std::path::PathBuf;

use kuna_analysis::listing::xrefs::{self, XrefIndex};
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use object::{Object, ObjectSection, SectionKind};

/// `main`'s instructions through its `ret` (`objdump -d`).
const MAIN: [u64; 47] = [
    0x40071d, 0x40071e, 0x400721, 0x400725, 0x400728, 0x40072c, 0x400730, 0x400734, 0x400739,
    0x40073e, 0x400742, 0x400747, 0x40074a, 0x40074f, 0x400754, 0x400758, 0x40075d, 0x400760,
    0x400765, 0x40076a, 0x40076f, 0x400774, 0x400778, 0x40077d, 0x400780, 0x400785, 0x40078a,
    0x40078e, 0x400793, 0x400796, 0x40079b, 0x4007a0, 0x4007a4, 0x4007a8, 0x4007ab, 0x4007ae,
    0x4007b3, 0x4007b6, 0x4007b9, 0x4007bb, 0x4007bd, 0x4007c2, 0x4007c7, 0x4007c9, 0x4007ce,
    0x4007d3, 0x4007d4,
];
/// The byte after `main`'s one-byte `ret`.
const MAIN_END: u64 = 0x4007d5;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn fixture() -> PathBuf {
    repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures/fauxware")
}

fn program() -> ConsoleProgram {
    let spec_roots = vec![repo_root().join("specs").to_str().unwrap().to_string()];
    let mut prog = bootstrap_from_object(fixture().to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    prog
}

fn index(prog: &ConsoleProgram) -> XrefIndex {
    let bytes = std::fs::read(fixture()).expect("fixture readable");
    let file = object::File::parse(&*bytes).expect("fixture parses");
    let seeds: Vec<u64> =
        prog.function_entries_canonical().iter().map(|e| e.addr.get_offset()).collect();
    xrefs::build(&file, prog.arch(), prog.arch().translate(), &seeds)
}

#[test]
fn instructions_are_listed_once_in_address_order_with_their_disassembled_lengths() {
    let prog = program();
    let idx = index(&prog);
    let listed: Vec<(u64, u32)> = idx.decoded_instructions().collect();
    assert!(!listed.is_empty());
    assert!(listed.windows(2).all(|w| w[0].0 < w[1].0), "not strictly ascending");
    for &(vma, len) in &listed {
        let (length, _, _) = prog.disassemble_at(vma).expect("a listed instruction disassembles");
        assert_eq!(i64::from(len), i64::from(length), "{vma:#x}");
    }
}

#[test]
fn the_listed_addresses_are_exactly_the_decoded_ones() {
    let prog = program();
    let idx = index(&prog);
    let listed: Vec<u64> = idx.decoded_instructions().map(|(vma, _)| vma).collect();
    assert_eq!(listed.len(), idx.instruction_count());
    let bytes = std::fs::read(fixture()).expect("fixture readable");
    let file = object::File::parse(&*bytes).expect("fixture parses");
    let mut decoded = Vec::new();
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let start = section.address();
        decoded.extend((start..start + section.size()).filter(|&vma| idx.is_decoded(vma)));
    }
    assert_eq!(listed, decoded);
}

#[test]
fn main_matches_objdump() {
    let prog = program();
    let idx = index(&prog);
    let ends = MAIN.iter().skip(1).chain([&MAIN_END]);
    let expected: Vec<(u64, u32)> =
        MAIN.iter().zip(ends).map(|(&at, &next)| (at, (next - at) as u32)).collect();
    let main: Vec<(u64, u32)> = idx
        .decoded_instructions()
        .filter(|&(vma, _)| (MAIN[0]..MAIN_END).contains(&vma))
        .collect();
    assert_eq!(main, expected);
}
