//! A reference walk leaves the program's decode context as it found it.
//!
//! Fixture: `arm_interwork_stubs_o0_le32`, whose A32 `arm_export` at 0x414
//! calls the Thumb `t_called` at 0x360 with `blx`. Decoding that `blx` commits
//! Thumb mode at 0x360, and the commit runs on past 0x414. A commit that
//! outlived the walk (or the `picbase` probe that decodes the prologues first)
//! would make the next decode of `arm_export` read it as Thumb.
use kuna_analysis::listing::xrefs::{self, XrefIndex, XrefKind};
use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::project::{decompile_entry, DecompileOptions};
use std::path::PathBuf;

const ARM_EXPORT: u64 = 0x414;
const BLX_SITE: u64 = 0x428;
const T_CALLED: u64 = 0x360;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

type Summary = (Vec<(u64, u32)>, Vec<(u64, u64, &'static str)>);

fn summary(idx: &XrefIndex) -> Summary {
    let decoded = idx.decoded_instructions().collect();
    let mut edges: Vec<_> = idx
        .decoded_instructions()
        .flat_map(|(vma, _)| {
            idx.refs_from_instruction(vma).iter().map(|r| (r.from, r.to, r.kind.as_str()))
        })
        .collect();
    edges.sort_unstable();
    (decoded, edges)
}

fn fixture() -> PathBuf {
    repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures/arm_interwork_stubs_o0_le32")
}

fn program(options: &[(&str, &str)]) -> ConsoleProgram {
    let specs = vec![repo_root().join("specs").to_str().unwrap().to_string()];
    let mut prog = bootstrap_from_object(fixture().to_str().unwrap(), "", &specs)
        .expect("bootstrap fixture with built processor specs");
    for (name, value) in options {
        prog.arch_mut().set_kuna_option(name, value).unwrap();
    }
    prog.commit_pending_analysis().unwrap();
    prog
}

fn build(prog: &ConsoleProgram) -> XrefIndex {
    let bytes = std::fs::read(fixture()).unwrap();
    let file = object::File::parse(&*bytes).unwrap();
    let seeds: Vec<u64> =
        prog.function_entries_canonical().iter().map(|e| e.addr.get_offset()).collect();
    xrefs::build(&file, prog.arch(), prog.arch().translate(), &seeds)
}

fn decompile(prog: &mut ConsoleProgram, at: u64) -> String {
    let space = prog.arch().manage().get_default_code_space().unwrap().clone();
    let entry = prog.resolve_address(&Address::new(space, at)).unwrap();
    let result = decompile_entry(prog, entry, &DecompileOptions::default());
    assert!(result.error.is_none(), "{:?}", result.error);
    result.code.unwrap()
}

/// Builds the index twice on one program; returns the first and the second's summary.
fn build_twice(options: &[(&str, &str)]) -> (XrefIndex, Summary) {
    let prog = program(options);
    let first = build(&prog);
    let second = summary(&build(&prog));
    assert_eq!(summary(&first), second, "{options:?}: a second build differs");
    (first, second)
}

#[test]
fn a_second_build_matches_the_first() {
    let (on, _) = build_twice(&[]);
    assert!(
        on.decoded_instructions().any(|insn| insn == (ARM_EXPORT, 4)),
        "arm_export decodes as A32"
    );
    assert!(
        on.refs_from_instruction(BLX_SITE)
            .iter()
            .any(|r| r.to == T_CALLED && r.kind == XrefKind::Call),
        "arm_export's blx calls t_called"
    );
}

/// ARM frame recovery publishes the modes it proves, and a second walk reads
/// them back to the same index.
#[test]
fn a_second_build_with_frame_recovery_matches_the_first() {
    build_twice(&[("armframes", "on"), ("funcstart_patterns", "on")]);
}

/// A decompile after an index build reads the decode modes a fresh program
/// does, so `arm_export` stays A32 and keeps its three calls.
#[test]
fn a_build_leaves_later_decompiles_unchanged() {
    let fresh = decompile(&mut program(&[]), ARM_EXPORT);
    let mut prog = program(&[]);
    build(&prog);
    let after = decompile(&mut prog, ARM_EXPORT);
    assert_eq!(fresh, after, "the build changed arm_export's C");
    assert!(
        ["sub_360(", "sub_2e8(", "sub_294("].iter().all(|call| after.contains(call))
            && !after.contains("halt_"),
        "{after}"
    );
}
