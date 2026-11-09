//! End-to-end two-pass gate for `wrapmain` — a stripped glibc 2.34+ ARM or
//! AArch64 executable recovers `main` through the `__wrap_main` trampoline its
//! crt1 `_start` hands to `__libc_start_main` (P1 program prep).
//!
//! Fixtures: `wrapmain_interwork_le32`, a stripped ARM image whose Thumb `main`
//! (0x10428) calls the A32 `init_request`@0x10560, `send_request`@0x10590 and
//! `kind_weight`@0x105e0 with `blx`, and the static Thumb `fill_header`@0x103f0
//! and `pick_kind`@0x10414 with `bl`; `send_request` calls the A32 `transmit`@0x104d8,
//! which calls `checksum`@0x10490. `_start` passes `__wrap_main`@0x10328, whose
//! `b` lands on the veneer@0x105f8 (`ldr pc,[pc,#-4]` and `main|1`).
//! `wrapmain_aarch64` is the AArch64 build: `__wrap_main`@0x400674 is
//! `bti c ; b main`@0x4007bc. Both run with `fast_funcdisc`, the call-following
//! discovery a stripped image depends on.
//!
//! ## The two passes
//!
//! * **option OFF (the bug):** on ARM nothing names `main` and none of the
//!   program's functions past crt1 is discovered; on AArch64 `main` is an
//!   anonymous tail-call target of `_start`, whose extent swallows the trampoline.
//! * **option ON (the fix):** `main` is named, decodes as Thumb on ARM, and the
//!   walk follows its `blx` calls into the A32 functions and on to their callees.
//!   On AArch64 the trampoline stays in `_start`, whose `.eh_frame` FDE covers it.

use std::path::PathBuf;

use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::ifacedecomp::{
    execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE,
};
use kuna_console::ifaceterm::ConsoleCommands;

/// The program's own functions in the interwork image, `main` first.
const INTERWORK: [u64; 8] = [0x10428, 0x103f0, 0x10414, 0x10560, 0x10590, 0x105e0, 0x104d8, 0x10490];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn bootstrap(fixture: &str, wrapmain: bool) -> ConsoleProgram {
    let bin = repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures").join(fixture);
    let specs = repo_root().join("specs");
    let spec_roots = vec![specs.to_str().unwrap().to_string()];
    let mut prog = bootstrap_from_object(bin.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap fixture with built processor specs");
    prog.arch_mut().set_kuna_option("fast_funcdisc", "on").expect("fast_funcdisc flips");
    prog.arch_mut()
        .set_kuna_option("wrapmain", if wrapmain { "on" } else { "off" })
        .expect("wrapmain flips");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    prog
}

fn entries(prog: &ConsoleProgram) -> Vec<(u64, String)> {
    prog.function_entries_canonical()
        .into_iter()
        .map(|entry| (entry.addr.get_offset(), entry.name))
        .collect()
}

fn decompile(prog: ConsoleProgram, name: &str) -> String {
    let cmds: Vec<String> = [format!("load function {name}"), "decompile".into(), "print C".into()]
        .into_iter()
        .collect();
    let count = cmds.len();
    let mut status = ConsoleCommands::into_status(cmds);
    register_decomp_commands(&mut status);
    {
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
        let dcp = data.as_any_mut().downcast_mut::<IfaceDecompData>().unwrap();
        dcp.conf = Some(prog);
    }
    for _ in 0..count {
        execute(&mut status);
    }
    status.optr.clone()
}

/// BEFORE: the interwork image lists none of the program's functions and no
/// `main`.
#[test]
fn the_interwork_program_is_undiscovered_with_the_option_off() {
    let prog = bootstrap("wrapmain_interwork_le32", false);
    assert!(prog.lookup_symbol("main").is_none());
    let listed = entries(&prog);
    for at in INTERWORK {
        assert!(listed.iter().all(|(entry, _)| *entry != at), "{at:#x} listed: {listed:?}");
    }
}

/// AFTER: `main` is named, the trampoline and veneer are entries, and the walk
/// reaches every function `main` calls, across both mode switches.
#[test]
fn the_interwork_program_is_discovered_through_its_thumb_main() {
    let prog = bootstrap("wrapmain_interwork_le32", true);
    let listed = entries(&prog);
    assert!(listed.contains(&(0x10428, "main".to_string())), "{listed:?}");
    for at in [0x10328, 0x105f8].into_iter().chain(INTERWORK) {
        assert!(listed.iter().any(|(entry, _)| *entry == at), "{at:#x} missing: {listed:?}");
    }
    // Thumb decoding: the body reaches the program's own calls and its printf.
    let body = decompile(prog, "main");
    for want in ["main(int4 argc", "sub_10560(", "sub_10590(", "sub_105e0(", "printf("] {
        assert!(body.contains(want), "main's body must contain {want}; got:\n{body}");
    }
}

/// The Thumb paint at `main` does not reach the A32 functions placed after it:
/// `checksum` and `kind_weight` decompile from their A32 encodings.
#[test]
fn the_a32_callees_after_the_thumb_main_decode_as_a32() {
    for (name, want) in [("sub_10490", "* 0x1f"), ("sub_105e0", "return a0 * a0;")] {
        let body = decompile(bootstrap("wrapmain_interwork_le32", true), name);
        assert!(body.contains(want), "{name} must contain {want}; got:\n{body}");
    }
}

/// AArch64: off, `main` is anonymous; on, it is named and nothing else changes.
/// The trampoline stays inside `_start`, because glibc's `.eh_frame` FDE for
/// `_start` (0x400640..0x40067c) covers it and `fdeinterior` keeps it there.
#[test]
fn the_aarch64_main_is_named() {
    let off = entries(&bootstrap("wrapmain_aarch64", false));
    assert!(off.contains(&(0x4007bc, "sub_4007bc".to_string())), "{off:?}");
    let on = entries(&bootstrap("wrapmain_aarch64", true));
    let renamed: Vec<_> =
        off.iter().map(|(at, name)| (*at, if *at == 0x4007bc { "main".into() } else { name.clone() })).collect();
    assert_eq!(on, renamed);
}
