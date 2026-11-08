//! `ConsoleProgram::set_local_synthesized_structs` makes the structures
//! `structsynth` guesses local to one decompile: a function prints the same C
//! whatever the program decompiled before it, guessed structures do not pile up
//! in the factory, and every other named type stays.
//!
//! `libwire_x86_64.so` (see its `.c`) has three functions that read a
//! `struct Request *` in `RDI`. `transmit` and `init_request` read different
//! fields, so each guesses a layout of its own; `send_request` guesses none.

use std::path::PathBuf;

use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::grammar::{parse_c, parse_type, DataOrg};
use kuna_decomp::decompile_drive::print_c;
use kuna_decomp::kuna_structsynth::shard::held_names;

const FUNCS: [&str; 3] = ["transmit", "init_request", "send_request"];

fn libwire(local: bool) -> ConsoleProgram {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let specs = root.join("specs").to_str().unwrap().to_string();
    let path = root.join("decompiler/crates/kuna-analysis/tests/fixtures/libwire_x86_64.so");
    let mut prog = bootstrap_from_object(path.to_str().unwrap(), "", &[specs])
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    prog.set_local_synthesized_structs(local);
    prog
}

fn decompile(prog: &mut ConsoleProgram, func: &str) -> String {
    let entry = prog.find_entry_by_name(func).expect("function in fixture");
    let (fd, _) = prog.decompile_with_input_types(&entry, &[]).expect("decompile succeeds");
    print_c(prog.arch_mut(), &fd)
}

fn alone(func: &str) -> String {
    decompile(&mut libwire(true), func)
}

#[test]
fn the_program_wide_ledger_stays_the_default() {
    let mut prog = libwire(false);
    let first = decompile(&mut prog, "transmit");
    assert!(first.contains("struct_0 *a0"), "in:\n{first}");
    decompile(&mut prog, "init_request");
    let again = decompile(&mut prog, "transmit");
    assert!(again.contains("struct_0 *a0"), "transmit lost its structure in:\n{again}");
    let mut prog = libwire(false);
    decompile(&mut prog, "init_request");
    let after = decompile(&mut prog, "transmit");
    assert!(after.contains("struct_1 *a0"), "the ledger no longer carries over:\n{after}");
}

#[test]
fn a_function_prints_the_same_c_alone_and_after_others() {
    for func in FUNCS {
        let expected = alone(func);
        if func != "send_request" {
            assert!(expected.contains("struct_0 *a0"), "{func} guessed no structure:\n{expected}");
        }
        let mut prog = libwire(true);
        for other in FUNCS.iter().chain(FUNCS.iter().rev()) {
            decompile(&mut prog, other);
            assert_eq!(decompile(&mut prog, func), expected, "{func} after {other}");
        }
    }
}

#[test]
fn guessed_structures_do_not_pile_up() {
    let mut fresh = libwire(true);
    decompile(&mut fresh, "transmit");
    let one = held_names(fresh.arch().types_impl());
    assert_eq!(one, ["struct_0"]);
    let mut prog = libwire(true);
    for _ in 0..3 {
        for func in FUNCS {
            decompile(&mut prog, func);
        }
    }
    decompile(&mut prog, "transmit");
    assert_eq!(held_names(prog.arch().types_impl()), one);
    prog.forget_synthesized_structs().unwrap();
    assert!(held_names(prog.arch().types_impl()).is_empty());
}

#[test]
fn types_held_before_the_setting_stay() {
    let mut prog = libwire(false);
    let (addr_size, word_size) = prog.arch().data_org();
    let org = DataOrg { addr_size, word_size };
    parse_c("struct Request { uint4 kind; void *payload; uint4 length; };", prog.arch().types(), org, &[], |_, _| Ok(()))
        .expect("struct Request parses");
    decompile(&mut prog, "transmit");
    prog.set_local_synthesized_structs(true);
    for func in FUNCS {
        decompile(&mut prog, func);
    }
    decompile(&mut prog, "transmit");
    let types = prog.arch().types();
    assert!(parse_type("Request *", types, org).is_ok(), "the parsed struct is gone");
    assert_eq!(held_names(prog.arch().types_impl()), ["struct_0"]);
    let code = decompile(&mut prog, "transmit");
    assert!(code.contains("struct_0 *a0"), "transmit no longer reuses the held structure:\n{code}");
}

#[test]
fn turning_the_setting_off_restores_the_program_wide_ledger() {
    let mut prog = libwire(true);
    decompile(&mut prog, "init_request");
    prog.set_local_synthesized_structs(false);
    decompile(&mut prog, "init_request");
    let after = decompile(&mut prog, "transmit");
    assert!(after.contains("struct_1 *a0"), "in:\n{after}");
}
