//! A program loads with the load-time options its caller passes, not the
//! process environment's, so threads can load images at once with different
//! settings. The CLI's environment channel still feeds the entry points that
//! read it. These tests set environment variables, so they run in their own
//! binary.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};

use kuna_console::engine::{
    bootstrap_from_image, bootstrap_from_object, bootstrap_from_object_with_options, ArmIsa,
    Bootstrap, ConsoleProgram, ARM_ISA_ENV,
};
use kuna_decomp::kuna_loadoptions::LoadOptions;
use kuna_decomp::kuna_sourcelang::SourceLang;
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn specs() -> String {
    root().join("specs").to_str().unwrap().to_string()
}

fn libwire() -> PathBuf {
    root().join("decompiler/crates/kuna-analysis/tests/fixtures/libwire_x86_64.so")
}

/// An x86-64 relocatable object whose `.go.buildinfo` names `version`, which
/// is all Kuna needs to take it for a Go image of that release.
fn go_object(version: &str) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = obj.section_id(StandardSection::Text);
    let code = [0x48, 0x8d, 0x04, 0x1f, 0xc3]; // lea rax, [rdi+rbx]; ret
    let value = obj.append_section_data(text, &code, 16);
    obj.add_symbol(Symbol {
        name: b"main.add".to_vec(),
        value,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let mut blob = b"\xff Go buildinf:".to_vec();
    blob.extend([8, 2]); // pointer size, inline strings
    blob.resize(32, 0);
    blob.push(u8::try_from(version.len()).unwrap());
    blob.extend(version.as_bytes());
    let info = obj.add_section(
        Vec::new(),
        b".go.buildinfo".to_vec(),
        SectionKind::ReadOnlyData,
    );
    obj.append_section_data(info, &blob, 16);
    obj.write().unwrap()
}

fn load(path: &Path, options: &LoadOptions) -> ConsoleProgram {
    let mut prog =
        bootstrap_from_object_with_options(path.to_str().unwrap(), "", &[specs()], None, options)
            .expect("bootstrap with built processor specs");
    prog.commit_pending_analysis()
        .expect("analysis commit succeeds");
    prog
}

/// The compiler field of the program's language id (`gcc`, `golang`, …).
fn compiler(prog: &ConsoleProgram) -> String {
    prog.arch().archid.rsplit(':').next().unwrap().to_string()
}

fn go_image() -> PathBuf {
    let path = common::scratch_file("loadoptions-go", "o");
    std::fs::write(&path, go_object("go1.25.3")).unwrap();
    path
}

/// What a load decided: its compiler spec, source language and Go release.
type Outcome = (String, SourceLang, Option<(u16, u16)>);

fn outcome(prog: &ConsoleProgram) -> Outcome {
    (
        compiler(prog),
        prog.arch().source_lang_detected,
        prog.arch().load_options().go_version,
    )
}

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const ENV_VARS: [&str; 4] = [
    "KUNA_GOABI",
    "KUNA_SOURCELANG",
    "KUNA_RELOC_OBJECTS",
    "KUNA_GOVERSION",
];

fn snapshot() -> Vec<Option<std::ffi::OsString>> {
    ENV_VARS.iter().map(std::env::var_os).collect()
}

#[test]
fn concurrent_loads_keep_their_own_options() {
    let go = go_image();
    let wire = libwire();
    let go_off = LoadOptions {
        goabi: false,
        ..LoadOptions::default()
    };
    let forced_c = LoadOptions {
        sourcelang: Some(SourceLang::C),
        ..LoadOptions::default()
    };
    let forced_go = LoadOptions {
        sourcelang: Some(SourceLang::Go),
        ..LoadOptions::default()
    };
    let stated_go = LoadOptions {
        go_version: Some((1, 22)),
        ..forced_go.clone()
    };
    let cases = [
        (
            go.clone(),
            LoadOptions::default(),
            ("golang".into(), SourceLang::Go, Some((1, 25))),
        ),
        (
            go.clone(),
            go_off,
            ("gcc".into(), SourceLang::Go, Some((1, 25))),
        ),
        (
            go.clone(),
            forced_c,
            ("gcc".into(), SourceLang::C, Some((1, 25))),
        ),
        (
            wire.clone(),
            LoadOptions::default(),
            ("gcc".into(), SourceLang::C, None),
        ),
        (
            wire.clone(),
            forced_go,
            ("golang".into(), SourceLang::Go, None),
        ),
        (
            wire,
            stated_go.clone(),
            ("golang".into(), SourceLang::Go, Some((1, 22))),
        ),
        (
            go.clone(),
            stated_go,
            ("golang".into(), SourceLang::Go, Some((1, 25))),
        ),
    ];
    for _ in 0..3 {
        let start = Arc::new(Barrier::new(cases.len()));
        let loads: Vec<_> = cases
            .iter()
            .cloned()
            .map(|(path, options, want)| {
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    let prog = load(&path, &options);
                    assert_eq!(prog.arch().load_options().goabi, options.goabi);
                    assert_eq!(prog.arch().load_options().sourcelang, options.sourcelang);
                    (outcome(&prog), want)
                })
            })
            .collect();
        for load in loads {
            let (got, want) = load.join().unwrap();
            assert_eq!(got, want);
        }
    }
    std::fs::remove_file(go).unwrap();
}

#[test]
fn explicit_options_neither_read_nor_write_the_environment() {
    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    let go = go_image();
    std::env::set_var("KUNA_GOABI", "off");
    std::env::set_var("KUNA_SOURCELANG", "rust");
    std::env::set_var("KUNA_RELOC_OBJECTS", "0");
    std::env::set_var("KUNA_GOVERSION", "1.20");
    let before = snapshot();
    let prog = load(&go, &LoadOptions::default());
    assert_eq!(
        outcome(&prog),
        ("golang".into(), SourceLang::Go, Some((1, 25)))
    );
    assert_eq!(
        snapshot(),
        before,
        "an explicit load leaves the environment alone"
    );
    for name in ENV_VARS {
        std::env::remove_var(name);
    }
    std::fs::remove_file(go).unwrap();
}

#[test]
fn the_environment_feeds_the_entry_points_that_read_it() {
    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    let go = go_image();
    std::env::set_var("KUNA_GOABI", "off");
    std::env::set_var("KUNA_SOURCELANG", "rust");
    std::env::set_var("KUNA_GOVERSION", "1.20");
    let from_env = LoadOptions::from_env();
    assert!(!from_env.goabi);
    assert_eq!(from_env.sourcelang, Some(SourceLang::Rust));
    let mut prog = bootstrap_from_object(go.to_str().unwrap(), "", &[specs()]).unwrap();
    prog.commit_pending_analysis().unwrap();
    assert_eq!(
        outcome(&prog),
        ("gcc".into(), SourceLang::Rust, Some((1, 25)))
    );
    assert_eq!(
        std::env::var("KUNA_GOVERSION").as_deref(),
        Ok("1.25"),
        "an environment-reading load publishes the image's Go release"
    );
    assert_eq!(
        kuna_decomp::kuna_goreg::GoLayout::from_env(),
        kuna_decomp::kuna_goreg::GoLayout::from_version(1, 25)
    );
    for name in ENV_VARS {
        std::env::remove_var(name);
    }
    std::fs::remove_file(go).unwrap();
}

/// The language a load of the fat Mach-O fixture chose: its slice's processor.
fn fat_slice(options: &LoadOptions) -> String {
    let fat = root().join("decompiler/crates/kuna-analysis/tests/fixtures/macho_fat");
    let prog = load(&fat, options);
    let archid = prog.arch().archid.clone();
    archid.split(':').next().unwrap().to_string()
}

#[test]
fn an_explicit_load_picks_its_own_fat_slice() {
    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("KUNA_MACHO_SLICE", "arm64");
    let default = fat_slice(&LoadOptions::default());
    let x86 = fat_slice(&LoadOptions {
        macho_slice: Some("x86_64".into()),
        ..LoadOptions::default()
    });
    std::env::set_var("KUNA_MACHO_SLICE", "x86_64");
    let arm = fat_slice(&LoadOptions {
        macho_slice: Some("arm64".into()),
        ..LoadOptions::default()
    });
    std::env::remove_var("KUNA_MACHO_SLICE");
    assert_eq!(
        default, "x86",
        "no slice named: the default, not the environment's"
    );
    assert_eq!(x86, "x86");
    assert_eq!(arm, "AARCH64");
}

/// Decompile and print `name` through the console, as a session would.
fn console_decompile(prog: ConsoleProgram, name: &str) -> String {
    use kuna_console::ifacedecomp::{
        execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE,
    };
    use kuna_console::ifaceterm::ConsoleCommands;
    let cmds: Vec<String> = [
        format!("load function {name}"),
        "decompile".into(),
        "print C".into(),
    ]
    .into();
    let count = cmds.len();
    let mut status = ConsoleCommands::into_status(cmds);
    register_decomp_commands(&mut status);
    let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
    let dcp = data.as_any_mut().downcast_mut::<IfaceDecompData>().unwrap();
    dcp.conf = Some(prog);
    for _ in 0..count {
        execute(&mut status);
    }
    status.optr.clone()
}

/// A gate read outside every load scope falls back to the environment, which
/// is the race explicit options exist to remove. Everything a library does with
/// an explicitly loaded program -- the load, the commit, listing, lookups,
/// declarations, decompiles on both drivers, printing -- reads the program's
/// own options.
#[test]
fn an_explicit_program_never_reads_the_environment() {
    use kuna_decomp::decompile_drive::print_c_with_srcmap;
    use kuna_decomp::kuna_loadoptions::environment_fallbacks;
    let go = go_image();
    let fat = root().join("decompiler/crates/kuna-analysis/tests/fixtures/macho_fat");
    let before = environment_fallbacks();
    for path in [libwire(), fat, go.clone()] {
        let mut prog = load(&path, &LoadOptions::default());
        let entries = prog.function_entries_executable();
        assert!(!entries.is_empty(), "{} lists functions", path.display());
        for entry in entries.iter().take(6) {
            assert!(prog.find_entry_at(entry.addr.get_offset()).is_some());
            prog.has_symbol_named(&entry.name);
            let (fd, _) = prog
                .decompile_with_input_types(entry, &[])
                .expect("decompiles");
            assert!(!print_c_with_srcmap(prog.arch_mut(), &fd).0.is_empty());
        }
        let first = entries[0].clone();
        prog.ensure_function_symbol(first.addr.clone()).unwrap();
        prog.declare_function(first.addr.clone(), Some("outer::inner::renamed"), 0)
            .unwrap();
        assert!(prog.has_symbol_named("outer::inner::renamed"));
        assert!(prog.find_entry_by_name("outer::inner::renamed").is_some());
        let c = console_decompile(prog, "outer::inner::renamed");
        assert!(c.contains("renamed("), "the console decompiles it:\n{c}");
    }
    assert_eq!(
        environment_fallbacks(),
        before,
        "a gate read the environment on an explicit program's thread"
    );
    std::fs::remove_file(go).unwrap();
}

/// The public items `LoadOptions` replaced inside Kuna keep their names,
/// signatures and environment readings, so a caller written against the
/// environment API still builds and behaves as before.
#[test]
fn the_environment_api_keeps_its_names_and_readings() {
    use kuna_decomp::kuna_goreg::{GoLayout, GOVERSION_ENV};
    use kuna_decomp::kuna_ppc32picimports::Mode;
    use kuna_decomp::{kuna_goabi, kuna_sourcelang};
    use std::path::PathBuf;

    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    let _: fn() -> Option<PathBuf> = kuna_analysis::pdb::locate::pdb_path_from_env;
    let _: fn() -> Option<SourceLang> = kuna_sourcelang::forced_from_env;
    let _: fn() -> bool = kuna_goabi::goabi_env_enabled;
    let _: fn() -> GoLayout = GoLayout::from_env;
    let _: fn() -> Mode = Mode::from_env;
    let _: fn() -> Mode = Mode::loaded;
    let _: &str = GOVERSION_ENV;

    std::env::set_var("kuna_pdb_path", "/some/where.pdb");
    std::env::set_var("KUNA_SOURCELANG", "rust");
    std::env::set_var("KUNA_GOABI", "off");
    std::env::set_var(GOVERSION_ENV, "1.23");
    std::env::set_var("KUNA_PPC32PICIMPORTS", "abi");
    // The `*_from_env` readers read the environment even while a load with
    // other options is in force.
    {
        let _load = LoadOptions::default().enter();
        assert_eq!(
            kuna_analysis::pdb::locate::pdb_path_from_env(),
            Some(PathBuf::from("/some/where.pdb"))
        );
        assert_eq!(kuna_sourcelang::forced_from_env(), Some(SourceLang::Rust));
        assert_eq!(GoLayout::from_env(), GoLayout::from_version(1, 23));
        assert_eq!(Mode::from_env(), Mode::Abi);
    }
    // Outside a load, the gates read the environment as they always did.
    assert!(!kuna_goabi::goabi_env_enabled());
    assert_eq!(Mode::loaded(), Mode::Abi);
    for name in ["kuna_pdb_path", "KUNA_SOURCELANG", "KUNA_GOABI", GOVERSION_ENV, "KUNA_PPC32PICIMPORTS"] {
        std::env::remove_var(name);
    }
    assert_eq!(kuna_analysis::pdb::locate::pdb_path_from_env(), None);
    assert_eq!(GoLayout::from_env(), GoLayout::baseline());
    assert!(kuna_goabi::goabi_env_enabled());
}

/// `set_kuna_option` still carries a load-time option to the environment for
/// a later environment-reading load, and that write cannot reach a load with
/// explicit options.
#[test]
fn set_kuna_option_exports_without_reaching_explicit_loads() {
    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    let go = go_image();
    std::env::remove_var("KUNA_GOABI");
    let mut prog = load(&go, &LoadOptions::default());
    prog.arch_mut().set_kuna_option("goabi", "off").unwrap();
    assert_eq!(std::env::var("KUNA_GOABI").as_deref(), Ok("off"));
    assert!(!prog.arch().load_options().goabi);
    assert_eq!(compiler(&load(&go, &LoadOptions::default())), "golang");
    let mut legacy = bootstrap_from_object(go.to_str().unwrap(), "", &[specs()]).unwrap();
    legacy.commit_pending_analysis().unwrap();
    assert_eq!(compiler(&legacy), "gcc");
    for name in ENV_VARS {
        std::env::remove_var(name);
    }
    std::fs::remove_file(go).unwrap();
}

/// A program loaded through an entry point that takes no options reads the
/// environment when each gate runs, as it did before `LoadOptions`: a scope
/// bound set after the load reaches a later declaration. An explicit program
/// loaded alongside keeps its own options.
#[test]
fn an_environment_program_reads_the_environment_live() {
    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("KUNA_SYMBOLNAMEBOUND");
    let wire = libwire();
    let mut legacy = bootstrap_from_object(wire.to_str().unwrap(), "", &[specs()]).unwrap();
    legacy.commit_pending_analysis().unwrap();
    let mut explicit = load(&wire, &LoadOptions::default());
    std::env::set_var("KUNA_SYMBOLNAMEBOUND", "1");
    for prog in [&mut legacy, &mut explicit] {
        let first = prog.function_entries_executable()[0].addr.clone();
        prog.ensure_function_symbol(first.clone()).unwrap();
        prog.declare_function(first, Some("outer::inner::renamed"), 0)
            .unwrap();
    }
    std::env::remove_var("KUNA_SYMBOLNAMEBOUND");
    assert!(
        !legacy.has_symbol_named("outer::inner::renamed"),
        "the declaration read the environment's bound"
    );
    assert!(explicit.has_symbol_named("outer::inner::renamed"));
}

/// A `Bootstrap` without options reads the environment as the entry points
/// that take none do: its load options, and an unset ISA from
/// `KUNA_ARM_ISA`. With options, it reads neither, so a bad `KUNA_ARM_ISA`
/// cannot fail it.
#[test]
fn a_bootstrap_without_options_reads_the_environment() {
    use kuna_analysis::loadimage_te::synthetic::TeImage;
    use kuna_decomp::decompile_drive::print_c;

    fn first_function(load: kuna_base::error::KunaResult<ConsoleProgram>) -> String {
        let mut prog = load.expect("bootstrap");
        prog.commit_pending_analysis().unwrap();
        let entry = prog.function_entries_executable()[0].clone();
        let (fd, _) = prog.decompile_with_input_types(&entry, &[]).unwrap();
        print_c(prog.arch_mut(), &fd)
    }

    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            std::env::remove_var(ARM_ISA_ENV);
            for name in ENV_VARS {
                std::env::remove_var(name);
            }
        }
    }

    let _env = ENVIRONMENT.lock().unwrap_or_else(|e| e.into_inner());
    let _clear = ClearOnDrop;
    let specs = [specs()];
    let roots = Bootstrap::new(&specs);
    let te = common::scratch_file("loadoptions-te", "te");
    std::fs::write(&te, TeImage::arm(&[0x07, 0x20, 0x70, 0x47, 0x1e, 0xff, 0x2f, 0xe1]).build()).unwrap();
    let te = te.to_str().unwrap();
    let options = LoadOptions::default();

    std::env::set_var(ARM_ISA_ENV, "thumb");
    let legacy = first_function(bootstrap_from_image(te, "", &specs));
    assert!(legacy.contains("return 7"), "{legacy}");
    assert_eq!(first_function(roots.image(te)), legacy);
    assert_eq!(first_function(roots.isa(Some(ArmIsa::Thumb)).image(te)), legacy);
    let explicit = first_function(roots.options(&options).image(te));
    assert_eq!(explicit, first_function(roots.isa(None).options(&options).image(te)));
    assert_ne!(explicit, legacy, "an explicit load ignored KUNA_ARM_ISA");

    std::env::set_var(ARM_ISA_ENV, "bogus");
    let refused = |load: kuna_base::error::KunaResult<ConsoleProgram>| match load {
        Ok(_) => panic!("loaded with KUNA_ARM_ISA=bogus"),
        Err(err) => err.to_string(),
    };
    let err = refused(bootstrap_from_image(te, "", &specs));
    assert!(err.contains("invalid --isa"), "{err}");
    assert_eq!(refused(roots.image(te)), err);
    assert_eq!(first_function(roots.options(&options).image(te)), explicit);
    std::env::remove_var(ARM_ISA_ENV);
    std::fs::remove_file(te).unwrap();

    let go = go_image();
    std::env::set_var("KUNA_GOABI", "off");
    let mut prog = roots.object(go.to_str().unwrap()).unwrap();
    prog.commit_pending_analysis().unwrap();
    assert_eq!(compiler(&prog), "gcc");
    assert_eq!(std::env::var("KUNA_GOVERSION").as_deref(), Ok("1.25"));
    let mut prog = roots.options(&options).object(go.to_str().unwrap()).unwrap();
    prog.commit_pending_analysis().unwrap();
    assert_eq!(compiler(&prog), "golang");
    std::fs::remove_file(go).unwrap();
}
