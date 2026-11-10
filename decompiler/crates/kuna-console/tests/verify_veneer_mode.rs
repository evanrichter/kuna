//! A Thumb function reached only through an A32 interworking stub decompiles
//! as Thumb on a fresh program.
//!
//! Fixture: `arm_interwork_stubs_o0_le32`, a stripped shared object whose
//! linker moved each exported Thumb function's symbol onto its A32 stub
//! (`ldr ip,[pc,#4] ; add ip,ip,pc ; bx ip`) and kept the function's size:
//! `thumb_export` at 0x5fc reaches 0x460, `dispatch` at 0x60c reaches 0x48a and
//! `thumb_export2` at 0x61c reaches 0x598. Every function symbol is even, so
//! nothing else marks those functions Thumb, and with the default options no
//! walk runs to carry the mode through the stubs.
use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::project::{decompile_entry, DecompileOptions};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// The fixture with the default options.
fn program() -> ConsoleProgram {
    let fixture = repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures/arm_interwork_stubs_o0_le32");
    let specs = vec![repo_root().join("specs").to_str().unwrap().to_string()];
    let mut prog = bootstrap_from_object(fixture.to_str().unwrap(), "", &specs)
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().unwrap();
    prog
}

fn decompile(prog: &mut ConsoleProgram, at: u64) -> String {
    let space = prog.arch().manage().get_default_code_space().unwrap().clone();
    let entry = prog.resolve_address(&Address::new(space, at)).unwrap();
    let result = decompile_entry(prog, entry, &DecompileOptions::default());
    assert!(result.error.is_none(), "{:?}", result.error);
    result.code.unwrap()
}

/// `dispatch(i, x)` returns `tab[i & 3](x)`.
#[test]
fn dispatch_behind_its_stub_decompiles_as_thumb() {
    let code = decompile(&mut program(), 0x48a);
    assert!(
        code.contains("tab[(a0 & 3) * 4]") && code.contains("(a1)") && !code.contains("halt_"),
        "{code}"
    );
}

/// The other two stubbed Thumb functions make their calls: `thumb_export` to
/// `a_called` (0x2e8) and `t_called` (0x360), `thumb_export2` to `a_after`
/// (0x564) and `t_helper` (0x294).
#[test]
fn every_stubbed_thumb_function_decompiles_as_thumb() {
    for (at, calls) in [(0x460, ["sub_2e8(", "sub_360("]), (0x598, ["sub_564(", "sub_294("])] {
        let code = decompile(&mut program(), at);
        assert!(
            calls.iter().all(|call| code.contains(call)) && !code.contains("halt_"),
            "{at:#x}: {code}"
        );
    }
}
