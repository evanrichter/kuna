//! Every `bootstrap_*` entry point is one setting of the `Bootstrap` builder:
//! for each input and each setting — languages, target, ISA, options — the
//! builder loads exactly what the entry point loads.

use crate::common;

use std::path::{Path, PathBuf};
use std::rc::Rc;

use kuna_analysis::loadimage_te::synthetic::TeImage;
use kuna_base::error::KunaResult;
use kuna_base::xml::{DocumentStorage, Element};
use kuna_console::engine::{
    bootstrap_from_file, bootstrap_from_image, bootstrap_from_image_with_db,
    bootstrap_from_image_with_isa, bootstrap_from_image_with_options,
    bootstrap_from_memory_map_with_db, bootstrap_from_memory_map_with_options,
    bootstrap_from_mz_bytes, bootstrap_from_object, bootstrap_from_object_with_db,
    bootstrap_from_object_with_isa, bootstrap_from_object_with_options, bootstrap_from_raw,
    bootstrap_from_root, bootstrap_from_te, bootstrap_from_te_bytes, bootstrap_program,
    language_database, ArmIsa, Bootstrap, ConsoleProgram, LoadEntry, LoadMap, LoadRegion,
    RegionBytes,
};
use kuna_decomp::decompile_drive::print_c;
use kuna_decomp::kuna_loadoptions::{environment_fallbacks, LoadOptions};

const X86_64: &str = "x86:LE:64:default";
const CORTEX: &str = "ARM:LE:32:Cortex";
/// `lea rax, [rdi+rbx]; ret`
const X86_ADD: [u8; 5] = [0x48, 0x8d, 0x04, 0x1f, 0xc3];
/// Thumb `movs r0, #7; bx lr`, which decodes as something else in A32.
const THUMB_RETURN_7: [u8; 4] = [0x07, 0x20, 0x70, 0x47];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn specs() -> Vec<String> {
    vec![repo_root().join("specs").to_string_lossy().into_owned()]
}

fn fixture(name: &str) -> String {
    let path = repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(name);
    path.to_str().unwrap().to_string()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(stem: &str, extension: &str, bytes: &[u8]) -> Self {
        let path = common::scratch_file(stem, extension);
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// What a load built, as far as a caller can see it: the language, the
/// description, the sections, every function and the C of the first few, or
/// the error.
fn fingerprint(load: KunaResult<ConsoleProgram>) -> String {
    let mut prog = match load {
        Ok(prog) => prog,
        Err(err) => return format!("error: {err}"),
    };
    prog.commit_pending_analysis()
        .expect("analysis commit succeeds");
    let mut out = format!(
        "{}\n{}\n{:?}\nsymbols {}\n",
        prog.arch().archid,
        prog.description(),
        prog.sections(),
        prog.num_symbols()
    );
    let entries = prog.function_entries_canonical();
    for entry in &entries {
        out += &format!("{} @ {:#x}\n", entry.name, entry.addr.get_offset());
    }
    for entry in entries.iter().take(3) {
        match prog.decompile_with_input_types(entry, &[]) {
            Ok((fd, _)) => out += &print_c(prog.arch_mut(), &fd),
            Err(err) => out += &format!("decompile error: {err}\n"),
        }
    }
    out
}

/// Both loads build the same program, and it is a real one.
fn same(old: KunaResult<ConsoleProgram>, new: KunaResult<ConsoleProgram>) -> String {
    let old = fingerprint(old);
    assert!(!old.starts_with("error"), "{old}");
    assert_eq!(old, fingerprint(new));
    old
}

/// Entry `0000:0000` far-calls `0002:0000`, which returns 9 with `RETF`.
fn dos_image() -> Vec<u8> {
    let mut module = vec![0x90u8; 0x24];
    module[..10].copy_from_slice(&[0x9a, 0x00, 0x00, 0x02, 0x00, 0xb8, 0x00, 0x4c, 0xcd, 0x21]);
    module[0x20..0x24].copy_from_slice(&[0xb8, 0x09, 0x00, 0xcb]);
    let mut header = vec![0u8; 0x20];
    header[..2].copy_from_slice(b"MZ");
    header[0x1c..0x20].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    let total = header.len() + module.len();
    let words: [(usize, u16); 6] = [
        (0x02, (total % 512) as u16),
        (0x04, total.div_ceil(512) as u16),
        (0x06, 1),
        (0x08, (header.len() / 16) as u16),
        (0x10, 0x100),
        (0x18, 0x1c),
    ];
    for (at, value) in words {
        header[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    header.extend_from_slice(&module);
    header
}

const XML_IMAGE: &str = r#"<binaryimage arch="x86:LE:64:default"><bytechunk space="ram" offset="0x1000">488d041fc3</bytechunk><symbol space="ram" offset="0x1000" name="add"/></binaryimage>"#;

fn xml_root() -> Rc<Element> {
    DocumentStorage::new()
        .parse_document(XML_IMAGE.as_bytes())
        .unwrap()
        .get_root()
        .clone()
}

fn flash_map(size: u64) -> LoadMap {
    LoadMap {
        regions: vec![
            LoadRegion {
                name: "flash".into(),
                address: 0x0800_0000,
                size,
                bytes: RegionBytes::File { offset: 0 },
                read: true,
                write: false,
                execute: true,
                volatile: false,
            },
            LoadRegion {
                name: "sram".into(),
                address: 0x2000_0000,
                size: 0x1000,
                bytes: RegionBytes::Zero,
                read: true,
                write: true,
                execute: false,
                volatile: false,
            },
        ],
        entries: vec![LoadEntry {
            address: 0x0800_0000,
            name: Some("seven".into()),
        }],
        vector_tables: Vec::new(),
    }
}

#[test]
fn object_loads_match_on_every_axis() {
    let specs = specs();
    let db = language_database(&specs).unwrap();
    let wire = fixture("libwire_x86_64.so");
    let arm = fixture("adrnext_arm");
    let options = LoadOptions::default();
    let go_off = LoadOptions {
        goabi: false,
        ..LoadOptions::default()
    };
    let roots = Bootstrap::new(&specs);

    let c = same(
        bootstrap_from_object(&wire, "", &specs),
        roots.object(&wire),
    );
    assert!(c.contains("transmit"), "{c}");
    same(
        bootstrap_from_object(&wire, X86_64, &specs),
        roots.target(X86_64).object(&wire),
    );
    for isa in [None, Some(ArmIsa::Arm), Some(ArmIsa::Thumb)] {
        same(
            bootstrap_from_object_with_isa(&arm, "", &specs, isa),
            roots.isa(isa).object(&arm),
        );
        same(
            bootstrap_from_object_with_options(&arm, "", &specs, isa, &options),
            roots.isa(isa).options(&options).object(&arm),
        );
        same(
            bootstrap_from_object_with_db(&arm, "", &db, isa, &options),
            Bootstrap::new(&db).isa(isa).options(&options).object(&arm),
        );
    }
    same(
        bootstrap_from_object_with_options(&wire, "", &specs, None, &go_off),
        roots.options(&go_off).object(&wire),
    );
    same(
        bootstrap_from_object_with_db(&wire, "", &db, None, &options),
        roots.options(&options).object(&wire),
    );
}

#[test]
fn image_loads_match_on_every_axis() {
    let specs = specs();
    let db = language_database(&specs).unwrap();
    let wire = fixture("libwire_x86_64.so");
    let te = Scratch::new(
        "bootstrap-te",
        "te",
        &TeImage::thumb(&THUMB_RETURN_7).build(),
    );
    let mz = Scratch::new("bootstrap-mz", "exe", &dos_image());
    let options = LoadOptions::default();
    let roots = Bootstrap::new(&specs);

    let arm_isas = [None, Some(ArmIsa::Arm), Some(ArmIsa::Thumb)];
    for (path, isas) in [
        (wire.as_str(), &arm_isas[..1]),
        (te.path(), &arm_isas),
        (mz.path(), &arm_isas[..1]),
    ] {
        same(bootstrap_from_image(path, "", &specs), roots.image(path));
        for &isa in isas {
            same(
                bootstrap_from_image_with_isa(path, "", &specs, isa),
                roots.isa(isa).image(path),
            );
            same(
                bootstrap_from_image_with_options(path, "", &specs, isa, &options),
                roots.isa(isa).options(&options).image(path),
            );
            same(
                bootstrap_from_image_with_db(path, "", &db, isa, &options),
                Bootstrap::new(&db).isa(isa).options(&options).image(path),
            );
        }
    }
}

#[test]
fn file_loads_match_for_every_format() {
    let specs = specs();
    let wire = fixture("libwire_x86_64.so");
    let te = Scratch::new(
        "bootstrap-file-te",
        "te",
        &TeImage::thumb(&THUMB_RETURN_7).build(),
    );
    let mz = Scratch::new("bootstrap-file-mz", "exe", &dos_image());
    let xml = Scratch::new("bootstrap-file-xml", "xml", XML_IMAGE.as_bytes());
    let junk = Scratch::new("bootstrap-file-junk", "bin", &[0x01, 0x02, 0x03, 0x04]);
    let roots = Bootstrap::new(&specs);
    for path in [wire.as_str(), te.path(), mz.path(), xml.path()] {
        same(bootstrap_from_file(path, "", &specs), roots.file(path));
    }
    let refused = fingerprint(roots.file(junk.path()));
    assert!(refused.contains("--raw-image"), "{refused}");
    assert_eq!(
        fingerprint(bootstrap_from_file(junk.path(), "", &specs)),
        refused
    );
}

#[test]
fn te_loads_match_and_the_isa_is_live() {
    let specs = specs();
    let bytes = TeImage::arm(&THUMB_RETURN_7).build();
    let te = Scratch::new("bootstrap-te-isa", "te", &bytes);
    let roots = Bootstrap::new(&specs);
    let mut decoded = Vec::new();
    for isa in [Some(ArmIsa::Arm), Some(ArmIsa::Thumb)] {
        let c = same(
            bootstrap_from_te(te.path(), "", &specs, isa),
            roots.isa(isa).te(te.path()),
        );
        same(
            bootstrap_from_te_bytes(te.path(), &bytes, "", &specs, isa),
            roots.isa(isa).te_bytes(te.path(), &bytes),
        );
        decoded.push(c);
    }
    assert_ne!(decoded[0], decoded[1], "the ISA changes the decode");
    assert!(decoded[1].contains("return 7"), "{}", decoded[1]);
}

#[test]
fn mz_loads_match() {
    let specs = specs();
    let bytes = dos_image();
    let mz = Scratch::new("bootstrap-mz-bytes", "exe", &bytes);
    let roots = Bootstrap::new(&specs);
    same(
        bootstrap_from_mz_bytes(mz.path(), &bytes, "", &specs, None),
        roots.mz_bytes(mz.path(), &bytes),
    );
}

#[test]
fn raw_loads_match_and_need_a_target() {
    let specs = specs();
    let raw = Scratch::new("bootstrap-raw", "bin", &X86_ADD);
    let roots = Bootstrap::new(&specs);
    let c = same(
        bootstrap_from_raw(raw.path(), X86_64, 0x1000, &[0x1000], None, &specs),
        roots.target(X86_64).raw(raw.path(), 0x1000, &[0x1000]),
    );
    assert!(c.contains("return"), "{c}");
    let refused = fingerprint(roots.raw(raw.path(), 0x1000, &[0x1000]));
    assert!(refused.contains("requires --target"), "{refused}");
    assert_eq!(
        fingerprint(bootstrap_from_raw(
            raw.path(),
            "",
            0x1000,
            &[0x1000],
            None,
            &specs
        )),
        refused
    );
}

#[test]
fn memory_map_loads_match_on_every_axis() {
    let specs = specs();
    let db = language_database(&specs).unwrap();
    let flash = Scratch::new("bootstrap-map", "bin", &THUMB_RETURN_7);
    let map = flash_map(THUMB_RETURN_7.len() as u64);
    let options = LoadOptions::default();
    for isa in [Some(ArmIsa::Arm), Some(ArmIsa::Thumb)] {
        same(
            bootstrap_from_memory_map_with_options(
                flash.path(),
                CORTEX,
                &map,
                &specs,
                isa,
                &options,
            ),
            Bootstrap::new(&specs)
                .target(CORTEX)
                .isa(isa)
                .options(&options)
                .memory_map(flash.path(), &map),
        );
        same(
            bootstrap_from_memory_map_with_db(flash.path(), CORTEX, &map, &db, isa, &options),
            Bootstrap::new(&db)
                .target(CORTEX)
                .isa(isa)
                .options(&options)
                .memory_map(flash.path(), &map),
        );
    }
}

#[test]
fn xml_loads_match() {
    let specs = specs();
    let roots = Bootstrap::new(&specs);
    let root = xml_root();
    let c = same(bootstrap_from_root(&root, &specs), roots.xml_root(&root));
    assert!(c.contains("add @ 0x1000"), "{c}");
    same(
        bootstrap_program(Rc::clone(&root), X86_64, &specs),
        roots.xml_image(root, X86_64),
    );
}

type Load<'a> = dyn Fn() -> KunaResult<ConsoleProgram> + 'a;

#[test]
fn explicit_options_reach_every_input_without_the_environment() {
    let specs = specs();
    let db = language_database(&specs).unwrap();
    let raw = Scratch::new("bootstrap-scoped-raw", "bin", &X86_ADD);
    let te_bytes = TeImage::thumb(&THUMB_RETURN_7).build();
    let te = Scratch::new("bootstrap-scoped-te", "te", &te_bytes);
    let mz_bytes = dos_image();
    let mz = Scratch::new("bootstrap-scoped-mz", "exe", &mz_bytes);
    let xml = Scratch::new("bootstrap-scoped-xml", "xml", XML_IMAGE.as_bytes());
    let flash = Scratch::new("bootstrap-scoped-map", "bin", &THUMB_RETURN_7);
    let map = flash_map(THUMB_RETURN_7.len() as u64);
    let wire = fixture("libwire_x86_64.so");
    let options = LoadOptions {
        goabi: false,
        ..LoadOptions::default()
    };
    let load = Bootstrap::new(&db).options(&options);

    let loads: Vec<(&str, Box<Load>)> = vec![
        ("object", Box::new(|| load.object(&wire))),
        ("image", Box::new(|| load.image(te.path()))),
        ("file", Box::new(|| load.file(xml.path()))),
        (
            "raw",
            Box::new(|| load.target(X86_64).raw(raw.path(), 0x1000, &[0x1000])),
        ),
        (
            "memory map",
            Box::new(|| {
                load.target(CORTEX)
                    .isa(Some(ArmIsa::Thumb))
                    .memory_map(flash.path(), &map)
            }),
        ),
        ("te", Box::new(|| load.te(te.path()))),
        ("te bytes", Box::new(|| load.te_bytes(te.path(), &te_bytes))),
        ("mz bytes", Box::new(|| load.mz_bytes(mz.path(), &mz_bytes))),
        ("xml root", Box::new(|| load.xml_root(&xml_root()))),
    ];
    for (input, bootstrap) in loads {
        let before = environment_fallbacks();
        let prog = bootstrap().unwrap_or_else(|err| panic!("{input}: {err}"));
        assert_eq!(
            environment_fallbacks(),
            before,
            "{input} read the environment"
        );
        assert!(
            !prog.arch().load_options().goabi,
            "{input} dropped its options"
        );
    }
}

#[test]
fn a_spec_root_array_or_vec_is_a_language_source() {
    let path: &Path = &repo_root().join("specs");
    let wire = fixture("libwire_x86_64.so");
    let from_array = fingerprint(Bootstrap::new(&[path]).object(&wire));
    let from_vec = fingerprint(Bootstrap::new(&vec![path]).object(&wire));
    let from_slice = fingerprint(Bootstrap::new(&specs()[..]).object(&wire));
    assert_eq!(from_array, from_vec);
    assert_eq!(from_array, from_slice);
}

#[test]
fn one_builder_loads_on_several_threads() {
    let specs = specs();
    let db = language_database(&specs).unwrap();
    let wire = fixture("libwire_x86_64.so");
    let options = LoadOptions::default();
    let load = Bootstrap::new(&db).options(&options);
    let expected = fingerprint(load.object(&wire));
    std::thread::scope(|scope| {
        let threads: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| fingerprint(load.object(&wire))))
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), expected);
        }
    });
}
