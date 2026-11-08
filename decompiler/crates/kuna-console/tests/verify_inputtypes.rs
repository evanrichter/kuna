//! `ConsoleProgram::decompile_with_input_types` retypes a parameter found by its
//! storage at entry, keeps the other parameters, reports one outcome per input,
//! and leaves nothing behind for the next decompile.
//!
//! The fixture `libwire_x86_64.so` is a `-O1` shared library whose functions
//! take a `struct Request *` in `RDI` (see its `.c`); `libwire_i386.so` is its
//! 32-bit build, which passes every parameter on the stack.

use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::grammar::{parse_c, parse_type, DataOrg};
use kuna_console::kuna_inputtypes::InputTypeOutcome;
use kuna_decomp::decompile_drive::print_c;
use kuna_decomp::dtype::Datatype;

fn libwire() -> ConsoleProgram {
    fixture("libwire_x86_64.so")
}

fn fixture(name: &str) -> ConsoleProgram {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let specs = root.join("specs").to_str().unwrap().to_string();
    let path = root.join("decompiler/crates/kuna-analysis/tests/fixtures").join(name);
    let mut prog = bootstrap_from_object(path.to_str().unwrap(), "", &[specs])
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    prog
}

fn ctype(prog: &ConsoleProgram, decl: &str) -> Rc<Datatype> {
    let (addr_size, word_size) = prog.arch().data_org();
    let org = DataOrg { addr_size, word_size };
    let types = prog.arch().types();
    if decl.starts_with("Request") && parse_type("Request", types, org).is_err() {
        parse_c(
            "struct Request { uint4 kind; void *payload; uint4 length; uint2 flags; uint2 attempts; int4 status; };",
            types,
            org,
            &[],
            |_, _| Ok(()),
        )
        .expect("struct Request parses");
    }
    parse_type(decl, types, org).expect("type parses").0
}

fn register(prog: &ConsoleProgram, name: &str) -> Address {
    let storage = prog.arch().translate().get_register(name).expect("x86-64 register");
    Address::new(storage.space.expect("register space"), storage.offset)
}

/// Decompile `func` with `inputs` (register name, C type) and return its C and
/// the outcomes.
fn decompile(prog: &mut ConsoleProgram, func: &str, inputs: &[(&str, &str)]) -> (String, Vec<InputTypeOutcome>) {
    let entry = prog.find_entry_by_name(func).expect("function in fixture");
    let inputs: Vec<(Address, Rc<Datatype>)> =
        inputs.iter().map(|(reg, decl)| (register(prog, reg), ctype(prog, decl))).collect();
    let (fd, outcomes) = prog.decompile_with_input_types(&entry, &inputs).expect("decompile succeeds");
    (print_c(prog.arch_mut(), &fd), outcomes)
}

fn signature<'a>(code: &'a str, func: &str) -> &'a str {
    code.lines().find(|line| line.contains(&format!("{func}("))).unwrap_or_else(|| panic!("no {func} signature in:\n{code}"))
}

#[test]
fn send_request_reads_payload_through_a_retyped_parameter() {
    let mut prog = libwire();
    let (code, outcomes) = decompile(&mut prog, "send_request", &[("RDI", "Request *")]);
    assert_eq!(outcomes, [InputTypeOutcome::Applied], "in:\n{code}");
    assert!(code.contains("a0->payload"), "no a0->payload in:\n{code}");
    assert!(signature(&code, "send_request").contains("(Request *a0)"), "in:\n{code}");
}

#[test]
fn init_request_keeps_every_other_parameter() {
    let mut prog = libwire();
    let (untyped, _) = decompile(&mut prog, "init_request", &[]);
    let (code, outcomes) = decompile(&mut prog, "init_request", &[("RDI", "Request *")]);
    assert_eq!(outcomes, [InputTypeOutcome::Applied], "in:\n{code}");
    let before = signature(&untyped, "init_request");
    let after = signature(&code, "init_request");
    assert_eq!(after.matches(',').count(), 3, "four parameters in:\n{code}");
    assert!(after.contains("(Request *a0,"), "in:\n{code}");
    assert_eq!(after.split_once(',').unwrap().1, before.split_once(',').unwrap().1, "the other parameters changed");
    for field in ["kind", "payload", "length", "flags", "attempts", "status"] {
        assert!(code.contains(&format!("a0->{field} = ")), "no a0->{field} store in:\n{code}");
    }
}

#[test]
fn a_type_where_no_parameter_lives_is_rejected_with_a_reason() {
    let mut prog = libwire();
    let (untyped, _) = decompile(&mut prog, "kind_weight", &[]);
    let (code, outcomes) = decompile(&mut prog, "kind_weight", &[("R9", "uint8")]);
    match outcomes.as_slice() {
        [InputTypeOutcome::Rejected(reason)] => assert!(reason.contains("R9"), "reason names no storage: {reason}"),
        other => panic!("expected one rejection, got {other:?}"),
    }
    assert_eq!(code, untyped, "a rejected input changed the C");
}

#[test]
fn a_type_of_another_width_is_rejected_with_a_reason() {
    let mut prog = libwire();
    let (code, outcomes) = decompile(&mut prog, "kind_weight", &[("RDI", "Request *")]);
    match outcomes.as_slice() {
        [InputTypeOutcome::Rejected(reason)] => assert!(reason.contains("4 bytes"), "reason: {reason}"),
        other => panic!("expected one rejection, got {other:?} in:\n{code}"),
    }
}

#[test]
fn a_second_input_at_the_same_storage_is_rejected() {
    let mut prog = libwire();
    let (code, outcomes) = decompile(&mut prog, "send_request", &[("RDI", "Request *"), ("RDI", "char *")]);
    assert_eq!(outcomes[0], InputTypeOutcome::Applied, "in:\n{code}");
    assert!(matches!(&outcomes[1], InputTypeOutcome::Rejected(reason) if reason.contains("RDI")), "{outcomes:?}");
    assert!(code.contains("a0->payload"), "the first input lost in:\n{code}");
}

#[test]
fn a_retype_leaves_nothing_behind() {
    let mut prog = libwire();
    let (before, _) = decompile(&mut prog, "send_request", &[]);
    assert!(signature(&before, "send_request").contains("void *a0"), "in:\n{before}");
    decompile(&mut prog, "send_request", &[("RDI", "Request *")]);
    let (after, outcomes) = decompile(&mut prog, "send_request", &[]);
    assert!(outcomes.is_empty());
    assert_eq!(after, before, "the retype changed the next untyped decompile");
}

#[test]
fn a_retype_leaves_nothing_behind_for_other_functions() {
    let mut prog = libwire();
    let funcs = ["transmit", "send_request", "init_request"];
    let before: Vec<String> = funcs.iter().map(|func| decompile(&mut prog, func, &[]).0).collect();
    for func in funcs {
        let (code, outcomes) = decompile(&mut prog, func, &[("RDI", "Request *")]);
        assert_eq!(outcomes, [InputTypeOutcome::Applied], "in:\n{code}");
    }
    let after: Vec<String> = funcs.iter().map(|func| decompile(&mut prog, func, &[]).0).collect();
    for ((func, before), after) in funcs.iter().zip(&before).zip(&after) {
        assert_eq!(after, before, "retyping changed the next untyped decompile of {func}");
    }
}

/// A stack slot as its offset from the stack pointer at entry.
fn stack(prog: &ConsoleProgram, offset: i64) -> Address {
    let space = prog.arch().manage().get_stack_space().expect("stack space");
    Address::new(Rc::clone(space), space.wrap_offset(offset as u64))
}

#[test]
fn a_stack_parameter_is_found_by_its_offset_at_entry() {
    let mut prog = fixture("libwire_i386.so");
    let entry = prog.find_entry_by_name("init_request").expect("function in fixture");
    let inputs = [
        (stack(&prog, 4), ctype(&prog, "Request *")),
        (stack(&prog, 12), ctype(&prog, "char *")),
        (stack(&prog, -8), ctype(&prog, "uint4")),
    ];
    let (fd, outcomes) = prog.decompile_with_input_types(&entry, &inputs).expect("decompile succeeds");
    let code = print_c(prog.arch_mut(), &fd);
    assert_eq!(outcomes[..2], [InputTypeOutcome::Applied, InputTypeOutcome::Applied], "in:\n{code}");
    assert!(matches!(&outcomes[2], InputTypeOutcome::Rejected(reason) if reason.contains("stack-0x8")), "{outcomes:?}");
    assert!(signature(&code, "init_request").contains("(Request *a0,unsigned int a1,char *a2,"), "in:\n{code}");
    assert!(code.contains("a0->payload = a2"), "in:\n{code}");
}
