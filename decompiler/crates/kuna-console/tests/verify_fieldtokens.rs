//! A captured field token names its containing structure and the field's byte
//! offset ([`EmitToken::field`]), and capturing it leaves the C text unchanged.
//!
//! The fixture `libwire_x86_64.so` is a `-O1` shared library; `init_request`
//! stores each of its parameters into a `struct Request *`. Its prototype is
//! declared here, so every store prints as a `req->field` access.

use std::path::PathBuf;

use kuna_console::engine::bootstrap_from_object;
use kuna_console::ifacedecomp::{execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
use kuna_console::ifaceterm::ConsoleCommands;
use kuna_console::interface::IfaceStatus;
use kuna_decomp::decompile_drive::{print_c, print_c_with_srcmap};
use kuna_decomp::prettyprint::{EmitToken, TokenKind};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// Decompile `init_request` with a `struct Request *` first parameter and
/// return its plain C, and the C and tokens of the token-capturing render.
fn init_request() -> (String, String, Vec<EmitToken>) {
    let root = repo_root();
    let specs = root.join("specs").to_str().unwrap().to_string();
    let path = root.join("decompiler/crates/kuna-analysis/tests/fixtures/libwire_x86_64.so");
    let mut prog = bootstrap_from_object(path.to_str().unwrap(), "", &[specs])
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");

    let cmds: Vec<String> = [
        "parse line struct Request { uint4 kind; void *payload; uint4 length; uint2 flags; uint2 attempts; int4 status; };",
        "parse line extern void init_request(Request *req,uint4 kind,void *payload,uint4 length);",
        "load function init_request",
        "decompile",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let count = cmds.len();
    let mut status = ConsoleCommands::into_status(cmds);
    register_decomp_commands(&mut status);
    dcp(&mut status).conf = Some(prog);
    for _ in 0..count {
        execute(&mut status);
    }
    assert!(!status.optr.contains("rror"), "console reported an error:\n{}", status.optr);
    let dcp = dcp(&mut status);
    let fd = dcp.fd.take().expect("init_request decompiled");
    let prog = dcp.conf.as_mut().unwrap();
    let plain = print_c(prog.arch_mut(), &fd);
    let (code, _, tokens) = print_c_with_srcmap(prog.arch_mut(), &fd);
    (plain, code, tokens)
}

fn dcp(status: &mut IfaceStatus) -> &mut IfaceDecompData {
    let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
    data.as_any_mut().downcast_mut::<IfaceDecompData>().unwrap()
}

#[test]
fn field_tokens_name_their_struct_and_offset() {
    let (plain, code, tokens) = init_request();
    assert_eq!(code, plain, "capturing tokens changed the C text");
    for line in [
        "req->kind = kind;",
        "req->payload = payload;",
        "req->length = length;",
        "req->flags = 0;",
        "req->attempts = 0;",
        "req->status = 0;",
    ] {
        assert!(code.contains(line), "missing `{line}` in:\n{code}");
    }

    let fields: Vec<(&str, Option<(&str, i32)>)> = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Field)
        .map(|t| (t.text.as_str(), t.field.as_ref().map(|(s, o)| (s.as_str(), *o))))
        .collect();
    assert_eq!(
        fields,
        [
            ("kind", Some(("Request", 0))),
            ("payload", Some(("Request", 8))),
            ("length", Some(("Request", 0x10))),
            ("flags", Some(("Request", 0x14))),
            ("attempts", Some(("Request", 0x16))),
            ("status", Some(("Request", 0x18))),
        ],
        "in:\n{code}"
    );
    assert!(
        tokens.iter().filter(|t| t.kind != TokenKind::Field).all(|t| t.field.is_none()),
        "only field tokens carry a field"
    );
}
