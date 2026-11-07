//! What `XrefIndex::has_indirect_calls` means, pinned on a real image.
//!
//! The field answers one question a reference index otherwise cannot: a
//! computed call files no Call edge, so "this function calls nothing" and "this
//! function's callee is decided at run time" look identical from
//! `refs_from_function`. `kuna decompile-graph` reports it per function for
//! exactly that reason.
//!
//! The claim is narrow — `CALLIND`, not any indirection — and the third test is
//! the one that keeps it narrow: a PLT stub's `JMP qword ptr [0x601000]` is an
//! indirect *branch*, and reading it as a computed call would mark most of a
//! dynamically linked program's import stubs as having unknowable callees when
//! their target is in fact the one thing about them that is known.
//!
//! Fixture: `fauxware` (ELF x86-64), the repo's smallest linked image with all
//! three shapes in it. Bootstrapping needs the built `x86` `.sla` under
//! `specs/` (gitignored; `make specs`); when it is absent the test prints that
//! and returns early.

use std::path::PathBuf;

use kuna_analysis::listing::xrefs::{self, XrefIndex, XrefKind};
use kuna_console::engine::bootstrap_from_object;

/// `__do_global_ctors_aux` — its loop body is one `CALL RAX` (`ff d0`).
const COMPUTED_CALL: u64 = 0x400880;
/// `main` — nine call sites onto five callees, every one a direct `CALL <vma>`.
const DIRECT_CALLS_ONLY: u64 = 0x40071d;
/// The `puts` PLT stub — `JMP qword ptr [0x601000]`, a `BRANCHIND`.
const FORWARDING_VENEER: u64 = 0x400510;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// The index `kuna xrefs` answers out of.
fn index() -> XrefIndex {
    let bin = repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures/fauxware");
    let specs = repo_root().join("specs");
    let spec_roots = vec![specs.to_str().unwrap().to_string()];
    let mut prog = bootstrap_from_object(bin.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    let bytes = std::fs::read(&bin).expect("fixture readable");
    let file = object::File::parse(&*bytes).expect("fixture parses");
    let seeds: Vec<u64> =
        prog.function_entries_canonical().iter().map(|e| e.addr.get_offset()).collect();
    xrefs::build(&file, prog.arch(), prog.arch().translate(), &seeds)
}

#[test]
fn a_computed_call_is_reported() {
    let idx = index();
    assert!(
        idx.has_indirect_calls(COMPUTED_CALL),
        "__do_global_ctors_aux's `CALL RAX` was not reported"
    );
    // And it really has no static callee to have been reported as one instead:
    // its only references are the two touches of the `__CTOR_END__` pointer it
    // reads the destination out of.
    assert!(
        idx.refs_from_function(COMPUTED_CALL)
            .iter()
            .all(|r| !matches!(r.kind, XrefKind::Call | XrefKind::Jump)),
        "the computed call filed a target edge after all"
    );
}

#[test]
fn direct_calls_alone_are_not_reported() {
    let idx = index();
    assert!(
        !idx.has_indirect_calls(DIRECT_CALLS_ONLY),
        "main's nine call sites are all direct"
    );
    assert!(
        idx.refs_from_function(DIRECT_CALLS_ONLY)
            .iter()
            .any(|r| r.kind == XrefKind::Call),
        "main's callees vanished"
    );
}

#[test]
fn an_indirect_branch_is_not_a_computed_call() {
    let idx = index();
    assert!(
        !idx.has_indirect_calls(FORWARDING_VENEER),
        "the puts PLT stub's `JMP qword ptr [...]` was read as a computed call"
    );
    // The veneer's destination is not unknown, it is the slot it reads.
    assert_eq!(idx.veneer_slot(FORWARDING_VENEER), Some(0x601000));
}

/// Every `CALLIND` in `fauxware`'s code (`objdump -d`): `deregister_tm_clones`'s
/// `CALL RAX`, `__do_global_dtors_aux`'s `CALL [0x600e38 + RAX*8]`,
/// `__libc_csu_init`'s `CALL [R12 + RBX*8]` and `__do_global_ctors_aux`'s
/// `CALL RAX`.
const INDIRECT_CALL_SITES: [u64; 4] = [0x4005bc, 0x400613, 0x400839, 0x4008a4];

#[test]
fn each_computed_call_site_is_listed_once_in_address_order() {
    let idx = index();
    assert_eq!(idx.indirect_call_sites().collect::<Vec<_>>(), INDIRECT_CALL_SITES);
}

#[test]
fn a_listed_site_belongs_to_a_function_reported_as_making_computed_calls() {
    let idx = index();
    for site in idx.indirect_call_sites() {
        let owner = idx.function_containing(site).expect("a listed site is decoded code");
        assert!(idx.has_indirect_calls(owner), "{site:#x}'s owner {owner:#x} is not reported");
    }
    assert_eq!(idx.function_containing(0x4008a4), Some(COMPUTED_CALL));
    assert!(
        idx.indirect_call_sites().all(|site| idx.function_containing(site) != Some(DIRECT_CALLS_ONLY)),
        "a site was listed in main, whose calls are all direct"
    );
}
