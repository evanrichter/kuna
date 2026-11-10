//! A local declaration's name token names the HighVariable it declares
//! ([`EmitToken::high`]), every other token names none, and capturing it
//! leaves the C text unchanged.
//!
//! The fixture `libwire_x86_64.so` is a `-O1` shared library; `transmit`
//! declares several locals (a `struct Header` on the stack among them) and
//! `send_request` keeps a register local live across a retry loop.

use std::collections::BTreeSet;
use std::path::PathBuf;

use kuna_console::engine::{bootstrap_from_object, EntrySelector};
use kuna_decomp::decompile_drive::{decompile_func_full, print_c, print_c_with_srcmap};
use kuna_decomp::prettyprint::{EmitToken, TokenKind};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// Decompiles `function` and checks the declared highs against its Funcdata.
/// Returns the C and its tokens.
fn decompile(function: &str) -> (String, Vec<EmitToken>) {
    let root = repo_root();
    let specs = root.join("specs").to_str().unwrap().to_string();
    let path = root.join("decompiler/crates/kuna-analysis/tests/fixtures/libwire_x86_64.so");
    let mut prog = bootstrap_from_object(path.to_str().unwrap(), "", &[specs])
        .expect("bootstrap fixture with built processor specs");
    let entry = prog.resolve_body_entry(&EntrySelector::parse(function)).expect("entry");
    let fd = decompile_func_full(prog.arch_mut(), &entry.name, entry.addr, 0, &[], None)
        .expect("decompile");
    let plain = print_c(prog.arch_mut(), &fd);
    let (code, _, tokens) = print_c_with_srcmap(prog.arch_mut(), &fd);
    assert_eq!(code, plain, "capturing tokens changed the C text");
    for token in &tokens {
        if let Some(high) = token.high {
            assert!(fd.high_bank().get(high).is_some(), "{function}: {:?} names no high", token.text);
        }
    }
    (code, tokens)
}

fn check(function: &str) {
    let (code, tokens) = decompile(function);
    let declared: Vec<&EmitToken> = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Variable && t.in_var_decl && !t.in_proto)
        .collect();
    assert!(!declared.is_empty(), "{function} declares no local in:\n{code}");
    for token in &declared {
        assert!(token.high.is_some(), "{function}: declaration of {:?} names no high in:\n{code}", token.text);
    }
    let highs: BTreeSet<_> = declared.iter().filter_map(|t| t.high).collect();
    assert_eq!(highs.len(), declared.len(), "{function}: two declarations share a high in:\n{code}");
    assert!(
        tokens
            .iter()
            .filter(|t| !(t.kind == TokenKind::Variable && t.in_var_decl && !t.in_proto))
            .all(|t| t.high.is_none()),
        "{function}: only a declaration's name names a high in:\n{code}"
    );
}

#[test]
fn local_declarations_name_their_high() {
    check("transmit");
    check("send_request");
}
