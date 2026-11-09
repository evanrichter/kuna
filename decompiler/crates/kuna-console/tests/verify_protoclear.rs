//! `Architecture::clear_function_prototype_pieces_at` takes back a callee
//! prototype that `set_function_prototype_pieces_at` parked: callers decompile
//! as they did before the park, and a prototype parked again applies again.
//!
//! The fixture `libwire_x86_64.so` is a `-O1` shared library (see its `.c`);
//! `send_request` calls the static `transmit(const struct Request *)`.

use std::path::PathBuf;

use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_decomp::decompile_drive::print_c;
use kuna_decomp::dtype::type_metatype;
use kuna_decomp::fspec::PrototypePieces;

fn libwire() -> ConsoleProgram {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let specs = root.join("specs").to_str().unwrap().to_string();
    let path = root.join("decompiler/crates/kuna-analysis/tests/fixtures/libwire_x86_64.so");
    let mut prog = bootstrap_from_object(path.to_str().unwrap(), "", &[specs])
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    prog
}

fn decompile(prog: &mut ConsoleProgram, func: &str) -> String {
    let entry = prog.find_entry_by_name(func).expect("function in fixture");
    let (fd, _) = prog.decompile_with_input_types(&entry, &[]).expect("decompile succeeds");
    print_c(prog.arch_mut(), &fd)
}

/// `transmit` declared as taking two `uint8` and returning `uint1`: a prototype
/// the caller's C cannot miss.
fn odd_transmit(prog: &ConsoleProgram) -> PrototypePieces {
    let types = prog.arch().types();
    let wide = types.get_base(8, type_metatype::TYPE_UINT).unwrap();
    PrototypePieces {
        name: "transmit".into(),
        outtype: Some(types.get_base(1, type_metatype::TYPE_UINT).unwrap()),
        intypes: vec![wide.clone(), wide],
        first_var_arg_slot: -1,
        ..Default::default()
    }
}

#[test]
fn a_cleared_callee_prototype_leaves_its_callers_as_they_were() {
    let mut prog = libwire();
    let transmit = prog.lookup_symbol("transmit").expect("transmit in fixture");
    assert!(prog.arch().symboltab.function_proto_pieces_across_scopes(&transmit).is_none());
    let before = decompile(&mut prog, "send_request");

    let pieces = odd_transmit(&prog);
    prog.arch_mut().set_function_prototype_pieces_at(&transmit, pieces.clone());
    let parked = decompile(&mut prog, "send_request");
    assert_ne!(parked, before, "the parked prototype changed nothing:\n{parked}");

    prog.arch_mut().clear_function_prototype_pieces_at(&transmit);
    assert!(prog.arch().symboltab.function_proto_pieces_across_scopes(&transmit).is_none());
    assert_eq!(decompile(&mut prog, "send_request"), before);

    prog.arch_mut().set_function_prototype_pieces_at(&transmit, pieces);
    assert_eq!(decompile(&mut prog, "send_request"), parked);
}

#[test]
fn clearing_where_no_function_starts_changes_nothing() {
    let mut prog = libwire();
    let before = decompile(&mut prog, "send_request");
    let inside = &prog.lookup_symbol("send_request").expect("send_request in fixture") + 1;
    prog.arch_mut().clear_function_prototype_pieces_at(&inside);
    assert_eq!(decompile(&mut prog, "send_request"), before);
}
