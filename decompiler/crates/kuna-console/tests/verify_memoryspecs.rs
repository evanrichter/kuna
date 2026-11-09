//! A caller can hand Kuna its SLEIGH specs from memory: a `MemorySpecs` root
//! bootstraps and decompiles exactly as the `specs/` directory it was read
//! from, never falls back to the filesystem, mixes with directory roots, and
//! needs no Ghidra layout: one language's four files, flat, are a root.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use kuna_console::engine::{bootstrap_from_object_with_specs, ConsoleProgram};
use kuna_decomp::decompile_drive::print_c;
use kuna_decomp::kuna_memoryspecs::{MemorySpecs, SpecRoot};

const FUNCS: [&str; 3] = ["transmit", "init_request", "send_request"];
const X86_64_SLA: &str = "Ghidra/Processors/x86/data/languages/x86-64.sla";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn specs_dir() -> PathBuf {
    repo_root().join("specs")
}

fn fixture() -> String {
    let path = repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures/libwire_x86_64.so");
    path.to_str().unwrap().to_string()
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, out);
        } else if !name.ends_with(".slaspec") && !name.ends_with(".sinc") {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            out.push((rel, std::fs::read(&path).unwrap()));
        }
    }
}

/// Every file `make specs` leaves under `specs/` except the SLEIGH sources,
/// copied into memory once.
fn embedded() -> &'static [(String, Vec<u8>)] {
    static FILES: OnceLock<Vec<(String, Vec<u8>)>> = OnceLock::new();
    FILES.get_or_init(|| {
        let root = specs_dir();
        let mut files = Vec::new();
        collect(&root, &root, &mut files);
        assert!(
            files.iter().any(|(rel, _)| *rel == X86_64_SLA),
            "{X86_64_SLA} is not built; run `make specs`"
        );
        files
    })
}

fn bootstrap(roots: &[SpecRoot]) -> ConsoleProgram {
    let mut prog = bootstrap_from_object_with_specs(&fixture(), "", roots).expect("bootstrap libwire");
    prog.commit_pending_analysis()
        .expect("analysis commit succeeds");
    prog
}

fn decompile_all(prog: &mut ConsoleProgram) -> Vec<String> {
    FUNCS
        .iter()
        .map(|func| {
            let entry = prog.find_entry_by_name(func).expect("function in fixture");
            let (fd, _) = prog
                .decompile_with_input_types(&entry, &[])
                .expect("decompile succeeds");
            print_c(prog.arch_mut(), &fd)
        })
        .collect()
}

#[test]
fn memory_specs_decompile_as_the_specs_directory_does() {
    let memory = MemorySpecs::from_files(embedded().iter().cloned());
    let from_memory = decompile_all(&mut bootstrap(&[memory.into()]));
    let from_disk = decompile_all(&mut bootstrap(&[specs_dir().into()]));
    assert!(
        from_memory[2].contains("send_request"),
        "in:\n{}",
        from_memory[2]
    );
    assert_eq!(from_memory, from_disk);
}

#[test]
fn memory_specs_never_fall_back_to_the_filesystem() {
    let memory = MemorySpecs::from_files(embedded().iter().filter(|(rel, _)| rel != X86_64_SLA).cloned());
    let err = match bootstrap_from_object_with_specs(&fixture(), "", &[memory]) {
        Ok(_) => panic!("bootstrapped without {X86_64_SLA}"),
        Err(err) => err.to_string(),
    };
    assert!(err.contains(".sla"), "{err}");
}

#[test]
fn a_memory_root_mixes_with_path_roots() {
    let missing = SpecRoot::Dir(repo_root().join("no-such-specs"));
    let memory = MemorySpecs::from_files(embedded().iter().cloned());
    let mut prog = bootstrap(&[missing, memory.into()]);
    let entry = prog
        .find_entry_by_name("send_request")
        .expect("function in fixture");
    assert!(prog.decompile_with_input_types(&entry, &[]).is_ok());
}

#[test]
fn one_languages_files_alone_are_a_root() {
    let languages = "Ghidra/Processors/x86/data/languages";
    let file = |name: &str| -> (String, Vec<u8>) {
        let rel = format!("{languages}/{name}");
        let bytes = embedded().iter().find(|(p, _)| *p == rel).expect(&rel).1.clone();
        (name.to_string(), bytes)
    };
    let flat = MemorySpecs::from_files(
        ["x86.ldefs", "x86-64.sla", "x86-64.pspec", "x86-64-gcc.cspec"].map(file),
    );
    let from_flat = decompile_all(&mut bootstrap(&[flat.into()]));
    let from_disk = decompile_all(&mut bootstrap(&[specs_dir().into()]));
    assert_eq!(from_flat, from_disk);
}
