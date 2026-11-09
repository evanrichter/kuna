use super::*;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read fixture {path}"))
}

fn recovered(name: &str) -> Option<WrapMain> {
    let bytes = fixture(name);
    let file = object::File::parse(bytes.as_slice()).unwrap_or_else(|e| panic!("{name}: {e}"));
    recover(&file)
}

/// Oracle 4 and `armlibcmain` recover nothing from either
/// glibc 2.34+ `_start`, so a stripped image names no `main`.
#[test]
fn oracle_4_and_armlibcmain_miss_both_wrap_main_starts() {
    for name in ["wrapmain_interwork_le32", "wrapmain_aarch64"] {
        let bytes = fixture(name);
        let file = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(super::super::libc_start_main_target(&file, file.entry()), None, "{name}");
        assert_eq!(super::super::kuna_armlibcmain::main_vma(&file, &bytes), None, "{name}");
    }
}

/// A32 `_start` passes `__wrap_main`@0x10328 (`b __main_from_arm`), whose
/// veneer@0x105f8 (`ldr pc,[pc,#-4]`) loads `main|1`: `main` is Thumb at 0x10428.
#[test]
fn follows_an_a32_trampoline_and_veneer_to_a_thumb_main() {
    assert_eq!(
        recovered("wrapmain_interwork_le32"),
        Some(WrapMain { steps: vec![0x10328, 0x105f8], main: 0x10428, thumb: true })
    );
}

/// AArch64 `_start` passes `__wrap_main`@0x400674 (`bti c ; b main`).
#[test]
fn follows_an_aarch64_trampoline_to_main() {
    assert_eq!(
        recovered("wrapmain_aarch64"),
        Some(WrapMain { steps: vec![0x400674], main: 0x4007bc, thumb: false })
    );
}

/// The PIE and literal-pool shapes stay with oracle 4 and `armlibcmain`; other
/// architectures and formats contribute nothing. `plt_aarch64` keeps its
/// `main` symbol, so its `nop ; b main` trampoline names nothing new.
#[test]
fn leaves_other_starts_alone() {
    for name in [
        "entrymain_aarch64",
        "plt_aarch64",
        "entrymain_arm",
        "armlibcmain_le32",
        "armlibcmain_got_le32",
        "cet_pie_x86_64",
        "macho_imports_arm64",
    ] {
        assert_eq!(recovered(name), None, "{name}");
    }
}

#[test]
fn decodes_the_words_the_idiom_is_built_from() {
    // ldr r0,[pc,#20] at 0x10308.
    assert_eq!(a32_ldr_literal(0xe59f_0014, 0x10310), Some((0, 0x10324)));
    // add r3,pc,#16 at 0x1030c.
    assert_eq!(a32_add_pc(0xe28f_3010, 0x10314), Some((3, 0x10324)));
    // add r0,r3,r0.
    assert_eq!(a32_add_reg(0xe083_0000), Some((0, 3, 0)));
    // bl 0x102bc at 0x1031c.
    assert_eq!(a32_bl_target(0xebff_ffe6, 0x10324), Some(0x102bc));
    // mov r3,#0 writes r3; push {r0} writes back sp; ldr r0,[r1] and mov r0,#1 write r0;
    // cmp r0,#0 writes nothing; pop {r0,r4} writes both and sp; mul r2,r0,r1 writes r2.
    assert_eq!(a32_written(0xe3a0_3000), 1 << 3);
    assert_eq!(a32_written(0xe52d_0004), 1 << 13);
    assert_eq!(a32_written(0xe591_0000), 1);
    assert_eq!(a32_written(0xe3a0_0001), 1);
    assert_eq!(a32_written(0xe350_0000), 0);
    assert_eq!(a32_written(0xe8bd_0011), 1 | 1 << 4 | 1 << 13);
    assert_ne!(a32_written(0xe002_0190) & 1 << 2, 0);
    // adrp x0,0x400000 at 0x40065c; add x0,x0,#0x674.
    assert_eq!(a64_adrp(0x9000_0000, 0x40065c), Some((0, 0x400000)));
    assert_eq!(a64_add_imm(0x9119_d000), Some((0, 0, 0x674)));
    // bl 0x4005a0 at 0x40066c.
    assert_eq!(a64_bl_target(0x97ff_ffcd, 0x40066c), Some(0x4005a0));
}
