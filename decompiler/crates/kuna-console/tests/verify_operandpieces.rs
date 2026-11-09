//! `disassemble_structured_at` returns the text `disassemble_at` prints, tiled
//! by typed pieces: registers, constants, and addresses resolved to their
//! target (RIP- and PC-relative, flow targets, dereferenced fixed slots).
//!
//! Fixtures: `libwire_x86_64.so`, `libwire_i386.so`, `adrnext_aarch64` and
//! `adrnext_arm`. Bootstrapping needs the built `.sla` files under `specs/`.

use std::path::PathBuf;

use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_sleigh::kuna_operandpieces::{PieceKind, StructuredAssembly};
use object::{Object, ObjectSection, SectionKind};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(name)
}

fn program(name: &str) -> ConsoleProgram {
    let spec_roots = vec![repo_root().join("specs").to_str().unwrap().to_string()];
    bootstrap_from_object(fixture(name).to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap fixture with built processor specs")
}

fn insn(prog: &ConsoleProgram, vma: u64) -> StructuredAssembly {
    prog.disassemble_structured_at(vma)
        .expect("instruction decodes")
}

/// The non-text pieces with their text.
fn typed(s: &StructuredAssembly) -> Vec<(&str, PieceKind)> {
    s.pieces
        .iter()
        .filter(|p| p.kind != PieceKind::Text)
        .map(|p| (s.text(p), p.kind.clone()))
        .collect()
}

fn reg(name: &str, offset: u64, size: u32) -> PieceKind {
    PieceKind::Register {
        name: name.to_string(),
        offset,
        size,
    }
}

fn ram(offset: u64, code: bool) -> PieceKind {
    PieceKind::Address {
        space: "ram".to_string(),
        offset,
        code,
    }
}

#[test]
fn structured_text_matches_the_text_api_and_its_pieces_tile_the_body() {
    for name in [
        "libwire_x86_64.so",
        "libwire_i386.so",
        "adrnext_aarch64",
        "adrnext_arm",
    ] {
        let prog = program(name);
        let bytes = std::fs::read(fixture(name)).unwrap();
        let file = object::File::parse(&*bytes).unwrap();
        let (mut decoded, mut addresses) = (0, 0);
        for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
            let end = section.address() + section.size();
            let mut vma = section.address();
            while vma < end {
                let Ok((length, mnemonic, body)) = prog.disassemble_at(vma) else {
                    assert!(
                        prog.disassemble_structured_at(vma).is_err(),
                        "{name} {vma:#x}"
                    );
                    vma += 1;
                    continue;
                };
                let s = insn(&prog, vma);
                assert_eq!(
                    (s.length, &s.mnemonic, &s.body),
                    (length, &mnemonic, &body),
                    "{name} {vma:#x}"
                );
                let mut at = 0;
                for piece in &s.pieces {
                    assert_eq!(piece.span.start, at, "{name} {vma:#x} {body}");
                    assert!(piece.span.end > at, "{name} {vma:#x} {body}");
                    at = piece.span.end;
                }
                assert_eq!(at, body.len(), "{name} {vma:#x} {body}");
                addresses += s
                    .pieces
                    .iter()
                    .filter(|p| matches!(p.kind, PieceKind::Address { .. }))
                    .count();
                decoded += 1;
                vma += length as u64;
            }
        }
        assert!(
            decoded > 10 && addresses > 0,
            "{name}: {decoded} decoded, {addresses} addresses"
        );
    }
}

#[test]
fn a_rip_relative_load_names_its_register_and_the_slot_it_reads() {
    let s = insn(&program("libwire_x86_64.so"), 0x116f);
    assert_eq!(s.body, "RDX,qword ptr [0x3fc8]");
    assert_eq!(
        typed(&s),
        [("RDX", reg("RDX", 16, 8)), ("0x3fc8", ram(0x3fc8, false))]
    );
    let operands: Vec<_> = s.pieces.iter().map(|p| (s.text(p), p.operand)).collect();
    assert_eq!(
        operands,
        [
            ("RDX", Some(1)),
            (",", None),
            ("qword ptr [", Some(0)),
            ("0x3fc8", Some(0)),
            ("]", Some(0))
        ]
    );
}

#[test]
fn a_direct_call_resolves_to_its_target_as_code() {
    let prog = program("libwire_x86_64.so");
    let call = insn(&prog, 0x10d2);
    assert_eq!(
        (call.mnemonic.as_str(), typed(&call)),
        ("CALL", vec![("0x1030", ram(0x1030, true))])
    );
    let jz = insn(&prog, 0x1012);
    assert_eq!(
        (jz.mnemonic.as_str(), typed(&jz)),
        ("JZ", vec![("0x1016", ram(0x1016, true))])
    );
}

#[test]
fn an_indirect_jump_names_its_slot_as_data() {
    let s = insn(&program("libwire_x86_64.so"), 0x1026);
    assert_eq!(s.body, "qword ptr [0x3ff8]");
    assert_eq!(typed(&s), [("0x3ff8", ram(0x3ff8, false))]);
}

#[test]
fn immediates_and_register_displacements_stay_constants() {
    let prog = program("libwire_x86_64.so");
    let sub = insn(&prog, 0x1004);
    assert_eq!(sub.body, "RSP,0x8");
    assert_eq!(
        typed(&sub),
        [
            ("RSP", reg("RSP", 32, 8)),
            ("0x8", PieceKind::Constant { value: 8 })
        ]
    );
    let lea = insn(&prog, 0x11e5);
    assert_eq!(lea.body, "EDX,[RCX + 0x1]");
    assert_eq!(
        typed(&lea),
        [
            ("EDX", reg("EDX", 16, 4)),
            ("RCX", reg("RCX", 8, 8)),
            ("0x1", PieceKind::Constant { value: 1 })
        ]
    );
}

#[test]
fn aarch64_pc_relative_values_and_branch_targets_are_addresses() {
    let prog = program("adrnext_aarch64");
    let adr = insn(&prog, 0x210128);
    assert_eq!(adr.body, "x0, 0x21012c");
    assert_eq!(
        typed(&adr),
        [
            ("x0", reg("x0", 0x4000, 8)),
            ("0x21012c", ram(0x21012c, false))
        ]
    );
    let bl = insn(&prog, 0x210140);
    assert_eq!(
        (bl.mnemonic.as_str(), typed(&bl)),
        ("bl", vec![("0x210120", ram(0x210120, true))])
    );
    let stp = insn(&prog, 0x21013c);
    assert_eq!(stp.body, "x29, x30, [sp, #-0x10]!");
    assert_eq!(
        typed(&stp),
        [
            ("x29", reg("x29", 0x40e8, 8)),
            ("x30", reg("x30", 0x40f0, 8)),
            ("sp", reg("sp", 8, 8)),
            ("-0x10", PieceKind::Constant { value: -16 }),
        ]
    );
}

#[test]
fn arm_branch_and_adr_resolve_to_their_targets() {
    let prog = program("adrnext_arm");
    let bl = insn(&prog, 0x200c8);
    assert_eq!(
        (bl.mnemonic.as_str(), typed(&bl)),
        ("bl", vec![("0x200b4", ram(0x200b4, true))])
    );
    let adr = insn(&prog, 0x200b4);
    assert_eq!(adr.body, "r0,0x200b8");
    assert_eq!(
        typed(&adr),
        [("r0", reg("r0", 0x20, 4)), ("0x200b8", ram(0x200b8, false))]
    );
}

#[test]
fn word_addressed_branch_targets_are_byte_offsets() {
    // AVR code space is word-addressed: `rjmp` at word 0 reaches word 2 and
    // `jmp` names word 4. The spec prints byte offsets and exports the word
    // location; the pieces carry the byte offset, as every kuna address does.
    let path = crate::common::scratch_file("operandpieces-avr", "bin");
    std::fs::write(&path, [0x01, 0xc0, 0, 0, 0x0c, 0x94, 0x04, 0x00, 0, 0]).unwrap();
    let spec_roots = vec![repo_root().join("specs").to_str().unwrap().to_string()];
    let prog = kuna_console::engine::bootstrap_from_raw(
        path.to_str().unwrap(),
        "avr8:LE:16:default",
        0,
        &[0],
        None,
        &spec_roots,
    )
    .expect("bootstrap raw AVR image with built processor specs");
    let code = |offset| PieceKind::Address {
        space: "code".to_string(),
        offset,
        code: true,
    };
    let rjmp = insn(&prog, 0);
    assert_eq!(
        (rjmp.mnemonic.as_str(), typed(&rjmp)),
        ("rjmp", vec![("0x4", code(4))])
    );
    let jmp = insn(&prog, 4);
    assert_eq!(
        (jmp.mnemonic.as_str(), typed(&jmp)),
        ("jmp", vec![("0x8", code(8))])
    );
    let _ = std::fs::remove_file(&path);
}
