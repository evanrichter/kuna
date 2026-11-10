//! (kuna `armfuncmode`) An even ARM function symbol starts A32 code.
//!
//! Bit 0 of an ARM ELF `STT_FUNC` value is set for a Thumb function and clear
//! for an A32 one (AAELF32 "Symbol Values"). `arm_markers` paints the Thumb
//! half as a point paint, which fills up to the next point where the mode was
//! set; with no such point at the A32 function after it, the Thumb mode of the
//! function before it (or of a `blx` target before it) reaches it. Mapping
//! symbols (`$a`/`$t`) supply that point when the image has them; this pass
//! supplies it from the function symbol when the image has none: `TMode=0` over
//! each defined even function symbol's `[value, value + size)` in an executable
//! section that a Thumb function symbol's paint would otherwise reach, i.e. one
//! after the first odd function symbol. The extent is cut at the next function
//! symbol and at the section's end (a linker moves an exported Thumb function's
//! symbol onto its A32 interworking stub and keeps the function's size). Past
//! the extent the Thumb mode resumes, as the Thumb symbol's paint gave it
//! before, so unsymbolized Thumb code after an A32 function keeps its mode. A
//! symbol with size 0 says nothing about its extent and is skipped, and an
//! image whose function symbols are all even keeps the language default it
//! already has.
//!
//! Nothing is painted for an image with `$a`/`$t` mapping symbols, a
//! relocatable object (its section addresses are not where the loader places
//! the code), an image whose build attributes rule out A32, a Cortex-M image
//! with a vector table, or any non-ARM or non-ELF object. An address that also
//! carries an odd (Thumb) function symbol is left to `arm_markers`.
//!
//! A linker that moves an exported Thumb function's symbol onto its A32
//! interworking stub leaves the function itself with no symbol, so in an image
//! whose only function symbols are such stubs nothing marks it Thumb, and it
//! decodes as A32. [`arm_veneer_mode_paints`] reads each even function symbol's
//! bytes; where they are a stub that loads a Thumb address and jumps to it
//! (`ldr ip,[pc,#4] ; add ip,ip,pc ; bx ip`, `ldr ip,[pc] ; bx ip`, or
//! `ldr pc,[pc,#-4]`, each followed by its literal), it paints `TMode=1` over
//! the stub's target for the symbol's size, cut at the next function symbol,
//! the next such target and the end of the target's executable section. The
//! same scope rules apply, except that the image need not have an odd function
//! symbol; a target that carries a function symbol of its own is left to it.
//! These paints reach the program's context only, not the Listing walk's
//! painter (`listing::context`): `armwalkmode` and `flowmode` stand down on an
//! image the painter paints, and they carry modes through the stubs themselves.

use std::collections::{BTreeMap, BTreeSet};

use object::read::{Object, ObjectSection, ObjectSymbol};
use object::{ObjectKind, SectionIndex, SymbolKind};

use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, ContextPaint, Phase};

const TMODE: &str = "TMode";
const SHF_EXECINSTR: u64 = 0x4;
const EF_ARM_BE8: u32 = 0x0080_0000;

pub struct ArmFuncModePass;

fn is_mapping_mode_symbol(name: &str) -> bool {
    matches!(name, "$a" | "$t") || name.starts_with("$a.") || name.starts_with("$t.")
}

fn executable_end(file: &object::File, index: SectionIndex) -> Option<u64> {
    let section = file.section_by_index(index).ok()?;
    let object::SectionFlags::Elf { sh_flags } = section.flags() else {
        return None;
    };
    (sh_flags & SHF_EXECINSTR != 0).then(|| section.address().saturating_add(section.size()))
}

/// The `TMode` paints for the image's even function symbols (see the module
/// docs); empty whenever the image is out of scope.
pub fn arm_func_mode_paints(file: &object::File) -> Vec<ContextPaint> {
    if file.architecture() != object::Architecture::Arm
        || file.format() != object::BinaryFormat::Elf
        || file.kind() == ObjectKind::Relocatable
    {
        return Vec::new();
    }
    let symbols = || file.symbols().chain(file.dynamic_symbols());
    if symbols().any(|sym| sym.name().is_ok_and(is_mapping_mode_symbol)) {
        return Vec::new();
    }
    let functions: Vec<(u64, u64, SectionIndex, u64)> = symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text && sym.is_definition() && sym.address() != 0)
        .filter_map(|sym| {
            let index = sym.section_index()?;
            Some((sym.address(), sym.size(), index, executable_end(file, index)?))
        })
        .collect();
    let thumb: BTreeSet<u64> =
        functions.iter().filter(|(addr, ..)| addr & 1 != 0).map(|(addr, ..)| addr & !1).collect();
    let Some(&first_thumb) = thumb.first() else {
        return Vec::new();
    };
    let starts: BTreeSet<u64> = functions.iter().map(|(addr, ..)| addr & !1).collect();
    let next_start = |addr: u64| starts.range(addr + 1..).next().copied().unwrap_or(u64::MAX);
    let mut arm: BTreeMap<u64, (u64, u64, SectionIndex)> = BTreeMap::new();
    for &(addr, size, index, section_end) in functions.iter() {
        if addr & 1 != 0 || addr < first_thumb || size == 0 || thumb.contains(&addr) {
            continue;
        }
        let limit = next_start(addr).min(section_end);
        let end = addr.saturating_add(size).min(limit);
        let extent = arm.entry(addr).or_insert((end, limit, index));
        extent.0 = extent.0.max(end);
    }
    if arm.is_empty()
        || super::kuna_armfloatabi::thumb_only(file)
        || !crate::analyzers::entry::cortexm_thumb_paints(file, true).is_empty()
    {
        return Vec::new();
    }
    let little = file.is_little_endian()
        || matches!(file.flags(), object::FileFlags::Elf { e_flags, .. } if e_flags & EF_ARM_BE8 != 0);
    let noreturn = super::noreturn::known_noreturn_addrs(file);
    let mut paints = Vec::new();
    for (addr, (end, limit, index)) in arm.into_iter().filter(|(addr, (end, ..))| end > addr) {
        let end = file
            .section_by_index(index)
            .ok()
            .and_then(|section| Some((section.address(), section.data().ok()?)))
            .map_or(end, |(base, data)| a32_reach(data, base, little, addr, end, limit, &noreturn));
        paints.push(ContextPaint { addr, end: Some(end), var: TMODE, value: 0 });
        if end < next_start(addr) {
            paints.push(ContextPaint { addr: end, end: None, var: TMODE, value: 1 });
        }
    }
    paints
}

/// The `TMode=1` paints over the Thumb functions the image's A32 interworking
/// stubs reach (see the module docs); empty whenever the image is out of scope.
pub fn arm_veneer_mode_paints(file: &object::File) -> Vec<ContextPaint> {
    if file.architecture() != object::Architecture::Arm
        || file.format() != object::BinaryFormat::Elf
        || file.kind() == ObjectKind::Relocatable
    {
        return Vec::new();
    }
    let symbols = || file.symbols().chain(file.dynamic_symbols());
    if symbols().any(|sym| sym.name().is_ok_and(is_mapping_mode_symbol)) {
        return Vec::new();
    }
    let functions: Vec<(u64, u64, SectionIndex)> = symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text && sym.is_definition() && sym.address() != 0)
        .filter_map(|sym| {
            let index = sym.section_index()?;
            executable_end(file, index)?;
            Some((sym.address(), sym.size(), index))
        })
        .collect();
    let starts: BTreeSet<u64> = functions.iter().map(|(addr, ..)| addr & !1).collect();
    let insn_little = file.is_little_endian()
        || matches!(file.flags(), object::FileFlags::Elf { e_flags, .. } if e_flags & EF_ARM_BE8 != 0);
    let data_little = file.is_little_endian();
    // Each Thumb target, with the size of the stub symbol that reaches it.
    let mut targets: BTreeMap<u64, u64> = BTreeMap::new();
    for &(addr, size, index) in &functions {
        if addr & 1 != 0 || size == 0 {
            continue;
        }
        let Some(target) = file
            .section_by_index(index)
            .ok()
            .and_then(|section| stub_target(section.data().ok()?, section.address(), addr, insn_little, data_little))
        else {
            continue;
        };
        if target & 1 == 0 || starts.contains(&(target & !1)) {
            continue;
        }
        let largest = targets.entry(target & !1).or_insert(size);
        *largest = (*largest).max(size);
    }
    if targets.is_empty()
        || super::kuna_armfloatabi::thumb_only(file)
        || !crate::analyzers::entry::cortexm_thumb_paints(file, true).is_empty()
    {
        return Vec::new();
    }
    let mut paints = Vec::new();
    for (&at, &size) in &targets {
        let Some(section_end) = file.sections().find_map(|section| {
            let object::SectionFlags::Elf { sh_flags } = section.flags() else { return None };
            let end = section.address().saturating_add(section.size());
            (sh_flags & SHF_EXECINSTR != 0 && section.address() <= at && at < end).then_some(end)
        }) else {
            continue;
        };
        let next_symbol = starts.range(at + 1..).next().copied().unwrap_or(u64::MAX);
        let next_target = targets.range(at + 1..).next().map_or(u64::MAX, |(&next, _)| next);
        let end = at.saturating_add(size).min(next_symbol).min(next_target).min(section_end);
        paints.push(ContextPaint { addr: at, end: Some(end), var: TMODE, value: 1 });
    }
    paints
}

/// Where the A32 interworking stub at `at` jumps: the address its literal holds
/// (with the Thumb bit), or `None` when the bytes there are no such stub.
fn stub_target(data: &[u8], base: u64, at: u64, insn_little: bool, data_little: bool) -> Option<u64> {
    let word = |i: u64, little: bool| -> Option<u32> {
        let offset = usize::try_from(at.checked_add(i * 4)?.checked_sub(base)?).ok()?;
        let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) })
    };
    let insn = |i: u64| word(i, insn_little);
    let literal = |i: u64| word(i, data_little);
    const BX_IP: u32 = 0xE12F_FF1C;
    match insn(0)? {
        // ldr pc,[pc,#-4] ; .word target
        0xE51F_F004 => literal(1).map(u64::from),
        // ldr ip,[pc] ; bx ip ; .word target
        0xE59F_C000 if insn(1)? == BX_IP => literal(2).map(u64::from),
        // ldr ip,[pc,#4] ; add ip,ip,pc ; bx ip ; .word target - (stub + 12)
        0xE59F_C004 if matches!(insn(1)?, 0xE08C_C00F | 0xE08F_C00C) && insn(2)? == BX_IP => {
            Some(u64::from(literal(3)?.wrapping_add((at as u32).wrapping_add(12))))
        }
        _ => None,
    }
}

/// The end of the A32 code `[addr, end)` reaches by a direct A32 `b`/`bl` into
/// `[end, limit)`, the bytes before the next function symbol: such a target is
/// A32 by its encoding, so the extent grows over it, up to the first return,
/// unconditional branch, call to a function that never returns (`noreturn`),
/// or literal-pool word on the target's linear run, and over what that run
/// branches to in turn. A run that reaches `limit` without such a stop says
/// nothing about where its code ends and adds nothing. Words a PC-relative
/// `ldr` loads are data and are never read as branches.
fn a32_reach(
    data: &[u8],
    base: u64,
    little: bool,
    addr: u64,
    end: u64,
    limit: u64,
    noreturn: &BTreeSet<u64>,
) -> u64 {
    let word = |at: u64| -> Option<u32> {
        let offset = usize::try_from(at.checked_sub(base)?).ok()?;
        let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) })
    };
    let target = |at: u64, insn: u32| -> Option<u64> {
        if insn >> 28 == 0xF || (insn >> 25) & 7 != 0b101 {
            return None;
        }
        let offset = (((insn & 0x00FF_FFFF) << 8) as i32 >> 6) as i64;
        at.checked_add(8)?.checked_add_signed(offset)
    };
    let literal = |at: u64, insn: u32| -> Option<u64> {
        if insn >> 28 == 0xF || insn & 0x0F7F_0000 != 0x051F_0000 {
            return None;
        }
        let pc = at.checked_add(8)?;
        let imm = u64::from(insn & 0xFFF);
        if insn & (1 << 23) != 0 { pc.checked_add(imm) } else { pc.checked_sub(imm) }.map(|lit| lit & !3)
    };
    let stops = |at: u64, insn: u32| {
        insn >> 28 == 0xE
            && ((insn & 0x0FFF_FFF0) == 0x012F_FF10
                || (insn >> 24) & 0xF == 0b1010
                || (insn & 0x0FFF_8000) == 0x08BD_8000
                || insn == 0xE49D_F004
                || insn == 0xE1A0_F00E
                || ((insn >> 24) & 0xF == 0b1011 && target(at, insn).is_some_and(|to| noreturn.contains(&to))))
    };
    let mut pool: BTreeSet<u64> = BTreeSet::new();
    let mut at = addr & !3;
    while at < end {
        if let Some(lit) = word(at).and_then(|insn| literal(at, insn)) {
            pool.insert(lit);
        }
        at += 4;
    }
    let mut reach = end;
    let mut walked: BTreeSet<u64> = BTreeSet::new();
    let mut queue: Vec<u64> = Vec::new();
    let mut at = addr & !3;
    while at < end {
        if !pool.contains(&at) {
            if let Some(to) = word(at).and_then(|insn| target(at, insn)) {
                queue.push(to);
            }
        }
        walked.insert(at);
        at += 4;
    }
    while let Some(start) = queue.pop() {
        if start < end || start >= limit || start & 3 != 0 || walked.contains(&start) || pool.contains(&start) {
            continue;
        }
        let mut run: BTreeSet<u64> = BTreeSet::new();
        let mut run_pool: BTreeSet<u64> = BTreeSet::new();
        let mut branches: Vec<u64> = Vec::new();
        let mut at = start;
        let mut stopped = false;
        while at < limit {
            if pool.contains(&at) || run_pool.contains(&at) || walked.contains(&at) || !run.insert(at) {
                stopped = true;
                break;
            }
            let Some(insn) = word(at) else { break };
            if let Some(lit) = literal(at, insn) {
                run_pool.insert(lit);
            }
            if let Some(to) = target(at, insn) {
                branches.push(to);
            }
            let stop = stops(at, insn);
            at += 4;
            if stop {
                stopped = true;
                break;
            }
        }
        if stopped {
            reach = reach.max(at);
            walked.extend(run);
            pool.extend(run_pool);
            queue.extend(branches);
        }
    }
    reach
}

impl AnalysisPass for ArmFuncModePass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "armfuncmode"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut context_paints = arm_func_mode_paints(ctx.file);
        context_paints.extend(arm_veneer_mode_paints(ctx.file));
        AnalysisOutput { context_paints, ..AnalysisOutput::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paints(fixture: &str) -> Vec<(u64, Option<u64>, u32)> {
        let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("read fixture");
        let file = object::File::parse(bytes.as_slice()).expect("parse fixture");
        let out = arm_func_mode_paints(&file);
        assert!(out.iter().all(|p| p.var == TMODE));
        out.iter().map(|p| (p.addr, p.end, p.value)).collect()
    }

    #[test]
    fn even_function_symbols_after_a_thumb_symbol_are_a32_over_their_size() {
        let expected = vec![(0x0200_0080, Some(0x0200_0088), 0), (0x0200_0088, None, 1)];
        assert_eq!(paints("arm_funcmode_le32"), expected);
        assert_eq!(paints("arm_funcmode_nocall_le32"), expected);
    }

    #[test]
    fn a_direct_a32_branch_past_the_extent_keeps_its_target_a32() {
        let paints = paints("arm_funcmode_helper_o2_le32.so");
        let a32 = paints.iter().find(|(addr, ..)| *addr == 0x101f8).copied();
        assert!(a32.is_some_and(|(_, end, value)| value == 0 && end.is_some_and(|end| end > 0x1020c)), "{paints:x?}");
    }

    #[test]
    fn a32_growth_stops_at_noreturn_calls_runs_without_a_stop_and_literal_pools() {
        for (fixture, thumb) in [
            ("arm_funcmode_noreturn_le32.so", 0x10290),
            ("arm_funcmode_stackprot_le32.so", 0x103e0),
            ("arm_funcmode_pool_le32", 0x0200_0094),
        ] {
            let paints = paints(fixture);
            let covered = paints.iter().any(|&(addr, end, value)| {
                value == 0 && addr <= thumb && end.is_some_and(|end| thumb < end)
            });
            assert!(!covered, "{fixture}: {paints:x?}");
        }
    }

    #[test]
    fn size_zero_symbols_are_skipped() {
        assert!(paints("arm_funcmode_sizes_le32").is_empty());
    }

    #[test]
    fn all_even_function_symbols_paint_nothing() {
        assert!(paints("arm_interwork_stubs_o0_le32").is_empty());
    }

    fn veneer_paints(fixture: &str) -> Vec<(u64, Option<u64>, u32)> {
        let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
        let bytes = std::fs::read(&path).expect("read fixture");
        let file = object::File::parse(bytes.as_slice()).expect("parse fixture");
        arm_veneer_mode_paints(&file).iter().map(|p| (p.addr, p.end, p.value)).collect()
    }

    /// The exported Thumb functions' symbols sit on their A32 stubs (0x5fc,
    /// 0x60c, 0x61c), each sized as the function it reaches.
    #[test]
    fn thumb_functions_behind_interworking_stubs_are_thumb_over_their_stub_symbol_size() {
        assert_eq!(
            veneer_paints("arm_interwork_stubs_o0_le32"),
            [(0x460, Some(0x48a), 1), (0x48a, Some(0x4c0), 1), (0x598, Some(0x5c0), 1)],
        );
    }

    fn words(words: &[u32], little: bool) -> Vec<u8> {
        words.iter().flat_map(|w| if little { w.to_le_bytes() } else { w.to_be_bytes() }).collect()
    }

    /// Each stub shape yields the Thumb address it jumps to, in either byte
    /// order and in BE8 (A32 instructions little-endian, data big-endian).
    #[test]
    fn stub_shapes_yield_their_jump_target() {
        const LDR_PC: u32 = 0xE51F_F004;
        const LDR_IP_0: u32 = 0xE59F_C000;
        const LDR_IP_4: u32 = 0xE59F_C004;
        const ADD_IP_IP_PC: u32 = 0xE08C_C00F;
        const ADD_IP_PC_IP: u32 = 0xE08F_C00C;
        const BX_IP: u32 = 0xE12F_FF1C;
        for little in [true, false] {
            let data = words(&[LDR_PC, 0x1235], little);
            assert_eq!(stub_target(&data, 0x100, 0x100, little, little), Some(0x1235));
            let data = words(&[LDR_IP_0, BX_IP, 0x1235], little);
            assert_eq!(stub_target(&data, 0x100, 0x100, little, little), Some(0x1235));
            for add in [ADD_IP_IP_PC, ADD_IP_PC_IP] {
                // The literal is relative to the add's PC, the stub plus 12.
                let data = words(&[0, LDR_IP_4, add, BX_IP, 0x1235u32.wrapping_sub(0x104 + 12)], little);
                assert_eq!(stub_target(&data, 0x100, 0x104, little, little), Some(0x1235));
            }
        }
        let mut be8 = words(&[LDR_IP_0, BX_IP], true);
        be8.extend(0x1235u32.to_be_bytes());
        assert_eq!(stub_target(&be8, 0, 0, true, false), Some(0x1235));
    }

    /// Code that only starts like a stub, and a stub cut off by the end of its
    /// section, is no stub.
    #[test]
    fn near_stubs_and_truncated_stubs_yield_nothing() {
        let le = |w: &[u32]| words(w, true);
        // ldr ip,[pc] followed by something other than bx ip.
        assert_eq!(stub_target(&le(&[0xE59F_C000, 0xE12F_FF13, 0x1235]), 0, 0, true, true), None);
        // ldr ip,[pc,#4] ; add ip,ip,r1 ; bx ip.
        assert_eq!(stub_target(&le(&[0xE59F_C004, 0xE08C_C001, 0xE12F_FF1C, 0x1235]), 0, 0, true, true), None);
        // ldr ip,[pc,#4] ; add ip,ip,pc ; blx ip.
        assert_eq!(stub_target(&le(&[0xE59F_C004, 0xE08C_C00F, 0xE12F_FF3C, 0x1235]), 0, 0, true, true), None);
        // A stub whose literal lies past the section's bytes.
        assert_eq!(stub_target(&le(&[0xE59F_C000, 0xE12F_FF1C]), 0, 0, true, true), None);
        assert_eq!(stub_target(&le(&[0xE51F_F004]), 0, 0, true, true), None);
        // An address below the section's base.
        assert_eq!(stub_target(&le(&[0xE51F_F004, 0x1235]), 0x100, 0xfc, true, true), None);
    }

    #[test]
    fn veneer_paints_skip_mapping_symbols_relocatable_objects_and_other_architectures() {
        assert!(veneer_paints("arm_funcmode_mapsyms_le32").is_empty());
        assert!(veneer_paints("arm_thumb_le32.o").is_empty());
        assert!(veneer_paints("fauxware").is_empty());
    }

    #[test]
    fn mapping_symbols_relocatable_objects_and_other_architectures_paint_nothing() {
        assert!(paints("arm_funcmode_mapsyms_le32").is_empty());
        assert!(paints("arm_thumb_le32.o").is_empty());
        assert!(paints("fauxware").is_empty());
    }
}
