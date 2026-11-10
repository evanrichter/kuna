//! A reference walk decodes each instruction in the mode its edge carries.
//!
//! A `blx imm` commits its target's mode from the target up to the next point
//! where the mode was set. With the default options a stripped image has no
//! such point, so when the caller lies above its callee the commit reaches the
//! caller's own next instruction, and the walk read the rest of the caller in
//! the callee's mode.
//!
//! A call to a function the program marks no-return ends the walk: the bytes
//! after it are a literal pool or another function, not the caller.
use kuna_analysis::listing::xrefs::{self, XrefIndex, XrefKind};
use kuna_console::engine::bootstrap_from_object;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../kuna-analysis/tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap()
}

/// The index over `name` with the default options, seeded as `kuna xrefs` seeds it.
fn index(name: &str) -> XrefIndex {
    let path = fixture(name);
    let specs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../specs");
    let specs = vec![specs.canonicalize().unwrap().to_str().unwrap().to_string()];
    let mut prog = bootstrap_from_object(path.to_str().unwrap(), "", &specs)
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let file = object::File::parse(&*bytes).unwrap();
    let entries: Vec<u64> =
        prog.function_entries_canonical().iter().map(|e| e.addr.get_offset()).collect();
    let seeds = xrefs::discovery_seeds(&file, &entries, prog.arch().analysis_funcstart_patterns);
    xrefs::build(&file, prog.arch(), prog.arch().translate(), &seeds)
}

fn calls(idx: &XrefIndex, site: u64, target: u64) -> bool {
    idx.refs_from_instruction(site).iter().any(|r| r.to == target && r.kind == XrefKind::Call)
}

/// `arm_export` (A32, 0x414) calls the Thumb `t_called` at 0x360 with `blx`,
/// then the A32 0x2e8 with `bl` and the Thumb 0x294 with `blx`. The
/// instruction after the first `blx` stays A32, so both later calls are found.
#[test]
fn a_caller_keeps_its_mode_after_a_blx_to_a_lower_callee() {
    let idx = index("arm_interwork_stubs_o0_le32");
    assert!(calls(&idx, 0x428, 0x360), "the blx to t_called");
    assert!(idx.decoded_instructions().any(|insn| insn == (0x42c, 4)), "0x42c decodes as A32");
    assert!(calls(&idx, 0x438, 0x2e8), "arm_export's bl to 0x2e8");
    assert!(calls(&idx, 0x448, 0x294), "arm_export's blx to 0x294");
}

/// The A32 entry calls a Thumb helper with `blx` and then an A32 helper above
/// it with `bl`; the A32 helper is read in the mode the `bl` keeps.
#[test]
fn a_bl_target_above_a_blx_target_decodes_in_its_callers_mode() {
    let idx = index("arm_interwork_le32");
    assert!(calls(&idx, 0x0200_0008, 0x0200_0080), "the bl to the A32 helper");
    let helper: Vec<_> = idx
        .decoded_instructions()
        .filter(|&(vma, _)| (0x0200_0080..0x0200_0088).contains(&vma))
        .collect();
    assert_eq!(helper, [(0x0200_0080, 4), (0x0200_0084, 4)]);
}

/// Each function in this stack-protected image ends in a call to
/// `__stack_chk_fail`'s PLT stub at 0x10470, followed by its literal pool. The
/// walk stops at those calls, so it decodes no pool word as code.
#[test]
fn a_walk_stops_at_a_call_to_a_noreturn_function() {
    let idx = index("arm_funcmode_stackprot_le32.so");
    for (call, pool) in [(0x10304, 0x10308), (0x10368, 0x1036c), (0x103d4, 0x103d8), (0x1040c, 0x10410)] {
        assert!(calls(&idx, call, 0x10470), "the call to __stack_chk_fail at {call:#x}");
        assert!(!idx.is_decoded(pool), "the pool word at {pool:#x}");
    }
}
