//! (kuna) `wrapmain` — recover `main` from a glibc 2.34+ crt1 `_start` on
//! 32-bit ARM and AArch64, where `_start` hands `__libc_start_main` the
//! `__wrap_main` trampoline rather than `main` itself (P1 program prep).
//!
//! Since glibc 2.34 a non-PIE crt1 passes `__wrap_main`, a one-instruction
//! function that branches to `main`, and computes its address from the PC:
//!
//! - **A32**: `ldr r0,[pc,#imm] ; add rX,pc,#imm ; add r0,rX,r0`, the pool word
//!   holding `__wrap_main` minus the `add`'s PC. `armlibcmain` reads that word
//!   as an absolute address and refuses it, and oracle 4 finds no
//!   `R_ARM_RELATIVE` for it.
//! - **AArch64**: `adrp x0,page ; add x0,x0,#lo12`. Oracle 4 reads only the PIE
//!   `adrp ; ldr` GOT load.
//!
//! On a stripped image nothing then names `main`. On AArch64 the trampoline
//! has no entry, so `_start`'s body runs on into it and `main` is found only as
//! that body's tail-call target. On ARM the trampoline is never reached at all,
//! and when `main` is Thumb the trampoline's `b` lands on a linker veneer
//! (`ldr pc,[pc,#-4]` and a word holding `main|1`), which the Listing walk does
//! not follow; `main` and everything only it calls stay undiscovered.
//!
//! This pass decodes both shapes, anchored on the `bl` to the PLT stub the
//! import table names `__libc_start_main`. When the recovered address lies in
//! crt1's `_start` window, where glibc places `__wrap_main`, it follows that
//! trampoline's direct branch, then at most [`MAX_HOPS`] steps in all through
//! ARM long-branch veneers to the routine they reach; a `main` crt1 passes
//! directly is taken as it is, even when it opens with a branch. Each step is
//! an entry and the last is named `main`; a Thumb `main` is reported so the
//! walk can decode it as Thumb. Where an `.eh_frame` FDE describes `_start` as
//! covering the trampoline (glibc's AArch64 crt1 does), `fdeinterior` keeps it
//! inside `_start`.
//!
//! It refuses an image that is not an executable ARM or AArch64 ELF, a Thumb
//! `_start`, an image with no `__libc_start_main` stub, a step outside every
//! executable section or back at `_start`, and a `main` that already carries a
//! function symbol (an unstripped image names it already).
//!
//! The facts are computed at LOAD and COMMITTED only when the gate is on, so
//! `--option wrapmain off` (the default) commits nothing.

use object::read::Object;

use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, ContextPaint, Phase};

use super::{executable_sections, existing_function_addrs, in_executable_section};

const MAIN: &str = "main";

const LIBC_START_MAIN: &[u8] = b"__libc_start_main";

/// How far past `e_entry` the crt1 window runs; glibc's `_start` is under 0x40
/// bytes on both architectures.
const WINDOW: usize = 0x80;

/// The most branches and veneers followed from the address `_start` passes.
pub const MAX_HOPS: usize = 4;

/// What the pass recovered: the routines from the address crt1 passes to
/// `main`, in the order control reaches them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapMain {
    /// The trampoline and veneers before `main`; empty when crt1 passes `main`.
    pub steps: Vec<u64>,
    /// `main`'s entry, with the Thumb bit cleared.
    pub main: u64,
    /// Whether `main` is Thumb code.
    pub thumb: bool,
}

impl WrapMain {
    /// Every recovered entry with its ARM decode mode (0 = A32 or AArch64,
    /// 1 = Thumb).
    pub fn entries(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.steps.iter().map(|&at| (at, 0)).chain(std::iter::once((self.main, u32::from(self.thumb))))
    }
}

/// (kuna) The `_start` → `__wrap_main` → `main` pass (`wrapmain`).
pub struct WrapMainPass;

impl AnalysisPass for WrapMainPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "wrapmain"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        let Some(found) = recover(ctx.file) else {
            return out;
        };
        out.entries.extend(found.entries().map(|(at, _)| at));
        out.entry_names.push((found.main, MAIN.to_string()));
        if found.thumb {
            out.context_paints.push(ContextPaint { addr: found.main, end: None, var: "TMode", value: 1 });
        }
        out
    }
}

/// `main` as this pass recovers it, for [`super::kuna_elfmain`]'s prototype.
pub(super) fn main_vma(file: &object::File) -> Option<u64> {
    recover(file).map(|found| found.main)
}

/// The routines crt1 hands `__libc_start_main` reaches, once every refusal in
/// the module header has been applied.
pub fn recover(file: &object::File) -> Option<WrapMain> {
    let bytes = match file {
        object::File::Elf32(elf) => elf.data(),
        object::File::Elf64(elf) => elf.data(),
        _ => return None,
    };
    if !file.is_little_endian() {
        return None;
    }
    let arm = match file.architecture() {
        object::Architecture::Arm => true,
        object::Architecture::Aarch64 => false,
        _ => return None,
    };
    let entry = file.entry();
    if entry == 0 || entry & 1 != 0 {
        return None;
    }
    let stub = crate::loader::elf_plt::resolve_plt_imports(file, bytes)
        .into_iter()
        .find(|s| s.name == LIBC_START_MAIN)?
        .addr;
    let (sec_addr, data) = super::section_bytes_containing(file, entry)?;
    let start = usize::try_from(entry - sec_addr).ok()?;
    let window = data.get(start..(start + WINDOW).min(data.len()))?;
    let passed = if arm { a32_first_argument(entry, window, stub)? } else { a64_first_argument(entry, window, stub)? };
    let execs = executable_sections(file);
    let mut steps = Vec::new();
    let mut at = passed & !1;
    let mut thumb = arm && passed & 1 != 0;
    loop {
        if at == entry || !in_executable_section(&execs, at) {
            return None;
        }
        // glibc's `__wrap_main` sits in crt1 right after `_start`; past it only a
        // linker veneer is followed, so a `main` that opens with a `b` is kept.
        let trampoline = steps.is_empty() && at > entry && at < entry + WINDOW as u64;
        let next = if thumb { None } else { branch_from(file, at, arm, trampoline) };
        let Some(next) = next else { break };
        if steps.len() == MAX_HOPS {
            return None;
        }
        steps.push(at);
        at = next & !1;
        thumb = arm && next & 1 != 0;
    }
    if existing_function_addrs(file, bytes).binary_search(&at).is_ok() {
        return None;
    }
    Some(WrapMain { steps, main: at, thumb })
}

/// The value in `r0` at the A32 `bl` to `stub`, when an `add` with the PC built
/// it: `ldr rA,[pc,#imm]`, `add rB,pc,#imm`, then `add r0,rA,rB`. A value the
/// pool word alone supplies is `armlibcmain`'s shape and is not claimed here.
fn a32_first_argument(entry: u64, window: &[u8], stub: u64) -> Option<u64> {
    let mut regs: [Option<(u32, bool)>; 16] = [None; 16];
    let mut off = 0;
    while off + 4 <= window.len() {
        let addr = entry + off as u64;
        let insn = super::read_u32(&window[off..], true);
        let pc = addr.wrapping_add(8);
        if let Some((rt, pool)) = a32_ldr_literal(insn, pc) {
            let word = pool
                .checked_sub(entry)
                .and_then(|at| usize::try_from(at).ok())
                .and_then(|at| window.get(at..at + 4))
                .map(|word| super::read_u32(word, true));
            regs[rt as usize] = word.map(|word| (word, false));
        } else if let Some((rd, value)) = a32_add_pc(insn, pc) {
            regs[rd as usize] = Some((value, true));
        } else if let Some((rd, rn, rm)) = a32_add_reg(insn) {
            regs[rd as usize] = match (regs[rn as usize], regs[rm as usize]) {
                (Some((a, x)), Some((b, y))) => Some((a.wrapping_add(b), x || y)),
                _ => None,
            };
        } else if a32_bl_target(insn, pc) == Some(stub) {
            return regs[0].filter(|&(_, from_pc)| from_pc).map(|(value, _)| u64::from(value));
        } else {
            let written = a32_written(insn);
            for (reg, value) in regs.iter_mut().enumerate() {
                if written & (1 << reg) != 0 {
                    *value = None;
                }
            }
        }
        off += 4;
    }
    None
}

/// The value in `x0` at the A64 `bl` to `stub`, built by `adrp x0` and
/// `add x0,x0,#lo12`.
fn a64_first_argument(entry: u64, window: &[u8], stub: u64) -> Option<u64> {
    let mut x0: Option<u64> = None;
    let mut off = 0;
    while off + 4 <= window.len() {
        let addr = entry + off as u64;
        let insn = super::read_u32(&window[off..], true);
        if let Some((rd, page)) = a64_adrp(insn, addr) {
            if rd == 0 {
                x0 = Some(page);
            }
        } else if let Some((rd, rn, imm)) = a64_add_imm(insn) {
            if rd == 0 {
                x0 = x0.filter(|_| rn == 0).map(|base| base.wrapping_add(imm));
            }
        } else if a64_bl_target(insn, addr) == Some(stub) {
            return x0;
        } else if insn & 0x1F == 0 {
            x0 = None;
        }
        off += 4;
    }
    None
}

/// Where the routine at `at` branches unconditionally as its first act, if
/// that is all it does: when it is the `trampoline`, an A64 `b` (after an
/// optional `bti` or, in a build without BTI, `nop`) or an A32 `b`; always an A32 long-branch veneer (`ldr pc,[pc,#-4]`, or `ldr ip,[pc] ; bx ip`) whose
/// word carries the target's Thumb bit.
fn branch_from(file: &object::File, at: u64, arm: bool, trampoline: bool) -> Option<u64> {
    let (sec_addr, data) = super::section_bytes_containing(file, at)?;
    let code = data.get(usize::try_from(at - sec_addr).ok()?..)?;
    let word = |i: usize| code.get(i * 4..i * 4 + 4).map(|b| super::read_u32(b, true));
    let first = word(0)?;
    if !arm {
        if !trampoline {
            return None;
        }
        let landing = first & 0xFFFF_FF3F == 0xD503_241F || first == 0xD503_201F;
        let (insn, addr) = if landing { (word(1)?, at + 4) } else { (first, at) };
        return (insn & 0xFC00_0000 == 0x1400_0000).then(|| {
            let imm = (((insn & 0x03FF_FFFF) << 6) as i32 >> 4) as i64;
            addr.wrapping_add(imm as u64)
        });
    }
    match first {
        0xE51F_F004 => word(1).map(u64::from),
        0xE59F_C000 if word(1)? == 0xE12F_FF1C => word(2).map(u64::from),
        insn if trampoline && insn & 0xFF00_0000 == 0xEA00_0000 => {
            let imm = (((insn & 0x00FF_FFFF) << 8) as i32 >> 6) as i64;
            Some(at.wrapping_add(8).wrapping_add(imm as u64))
        }
        _ => None,
    }
}

/// `ldr rt,[pc,#±imm12]` (A32, any condition but `0xF`): the register and the
/// literal's address.
fn a32_ldr_literal(insn: u32, pc: u64) -> Option<(u32, u64)> {
    if insn >> 28 == 0xF || insn & 0x0F7F_0000 != 0x051F_0000 {
        return None;
    }
    let imm = u64::from(insn & 0xFFF);
    let at = if insn & (1 << 23) != 0 { pc.wrapping_add(imm) } else { pc.wrapping_sub(imm) };
    Some(((insn >> 12) & 0xF, at))
}

/// `add rd,pc,#imm` (A32, unconditional, no flags): the register and its value.
fn a32_add_pc(insn: u32, pc: u64) -> Option<(u32, u32)> {
    if insn & 0xFFFF_0000 != 0xE28F_0000 {
        return None;
    }
    let imm = (insn & 0xFF).rotate_right(2 * ((insn >> 8) & 0xF));
    Some(((insn >> 12) & 0xF, (pc as u32).wrapping_add(imm)))
}

/// The registers an A32 instruction may write, as a mask over `r0`..`r15`;
/// where the encoding is unclear, more rather than fewer.
fn a32_written(insn: u32) -> u16 {
    let field = |shift: u32| 1u16 << ((insn >> shift) & 0xF);
    let load = insn & (1 << 20) != 0;
    let pre_indexed = insn & (1 << 24) != 0;
    let writeback = insn & (1 << 21) != 0;
    let if_ = |cond: bool, mask: u16| if cond { mask } else { 0 };
    match (insn >> 25) & 0x7 {
        // Multiplies and the extra loads and stores.
        0b000 if insn & 0x90 == 0x90 => field(12) | field(16),
        0b000 | 0b001 => if_(!((insn >> 23) & 0x3 == 0b10 && load), field(12)),
        // Media instructions.
        0b011 if insn & (1 << 4) != 0 => field(12) | field(16),
        0b010 | 0b011 => if_(load, field(12)) | if_(!pre_indexed || writeback, field(16)),
        0b100 => if_(load, insn as u16) | if_(writeback, field(16)),
        0b101 => if_(pre_indexed, 1 << 14),
        _ => field(12) | field(16),
    }
}

/// `add rd,rn,rm` (A32, unconditional, no flags, no shift).
fn a32_add_reg(insn: u32) -> Option<(u32, u32, u32)> {
    (insn & 0xFFF0_0FF0 == 0xE080_0000).then_some(((insn >> 12) & 0xF, (insn >> 16) & 0xF, insn & 0xF))
}

/// `bl <target>` (A32, unconditional).
fn a32_bl_target(insn: u32, pc: u64) -> Option<u64> {
    (insn & 0xFF00_0000 == 0xEB00_0000).then(|| {
        let imm = (((insn & 0x00FF_FFFF) << 8) as i32 >> 6) as i64;
        pc.wrapping_add(imm as u64)
    })
}

/// `adrp xd,<page>`: the register and the page.
fn a64_adrp(insn: u32, addr: u64) -> Option<(u32, u64)> {
    if insn & 0x9F00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo = u64::from((insn >> 29) & 0x3);
    let immhi = u64::from((insn >> 5) & 0x7_FFFF);
    let imm = (((immhi << 2) | immlo) << 43) as i64 >> 31;
    Some((insn & 0x1F, (addr & !0xFFF).wrapping_add(imm as u64)))
}

/// `add xd,xn,#imm12{,lsl #12}` (64-bit, no flags).
fn a64_add_imm(insn: u32) -> Option<(u32, u32, u64)> {
    if insn & 0xFF80_0000 != 0x9100_0000 {
        return None;
    }
    let imm = u64::from((insn >> 10) & 0xFFF) << if insn & (1 << 22) != 0 { 12 } else { 0 };
    Some((insn & 0x1F, (insn >> 5) & 0x1F, imm))
}

/// `bl <target>` (A64).
fn a64_bl_target(insn: u32, addr: u64) -> Option<u64> {
    (insn & 0xFC00_0000 == 0x9400_0000).then(|| {
        let imm = (((insn & 0x03FF_FFFF) << 6) as i32 >> 4) as i64;
        addr.wrapping_add(imm as u64)
    })
}

#[cfg(test)]
mod tests;
