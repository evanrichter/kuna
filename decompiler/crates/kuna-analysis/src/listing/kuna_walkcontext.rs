//! ARM modes belong to queued control-flow edges and successful instruction spans.
//! Decoder mode commits are evidence for successors, never global range writes.
//!
//! A [`carrying`](WalkContext::carrying) context serves a walk that decodes in a
//! private copy of the context database. A `blx` writes its target's mode from
//! the target up to the next change point; when the caller lies above its
//! callee, the write covers the rest of the caller. The context carries each
//! edge's mode past such writes, and starts a function in the mode a call
//! committed there. It leaves the writes in place, so a function no call has
//! reached yet starts in the mode they left, as it did before. The walk stops
//! at a call to a no-return function ([`halts`](WalkContext::halts)) rather than
//! carry the caller's mode into the bytes after it.

use std::collections::BTreeMap;
use std::rc::Rc;

use kuna_base::{address::Address, space::AddrSpace};
use kuna_decomp::architecture::Architecture;
use kuna_sleigh::translate::{ContextCommitRecord, Translate};

pub(super) struct WalkContext<'a> {
    translate: &'a dyn Translate,
    word: usize,
    shift: u32,
    bits: u32,
    saved_writes: u32,
    original: Vec<(u64, u64, u32)>,
    calls: BTreeMap<u64, u32>,
    inventory: BTreeMap<u64, u32>,
    carrying: bool,
}

impl<'a> WalkContext<'a> {
    pub fn new(
        enabled: bool,
        translate: &'a dyn Translate,
        arch: &Architecture,
        space: &Rc<AddrSpace>,
        exec: &[(u64, u64)],
    ) -> Option<Self> {
        if !enabled {
            return None;
        }
        let var = arch
            .with_context_db_mut(|db| db.get_variable(b"TMode"))
            .ok()?;
        let word = var.get_word() as usize;
        let shift = var.get_shift() as u32;
        let bits = var.get_mask() << shift;
        let read_override = translate.set_context_read_override(word, 0, 0);
        translate.set_context_read_override(word, read_override.0, read_override.1);
        let original = arch.with_context_db_mut(|db| {
            let mut runs: Vec<(u64, u64, u32)> = Vec::new();
            for &(start, end) in exec {
                let mut at = start;
                while at < end {
                    let (words, _, last) =
                        db.get_context_bounds(&Address::new(Rc::clone(space), at));
                    let next = last.saturating_add(1).min(end);
                    let effective =
                        (words[word] & !read_override.0) | (read_override.1 & read_override.0);
                    let value = (effective & bits) >> shift;
                    if let Some(last) = runs.last_mut().filter(|run| run.1 == at && run.2 == value)
                    {
                        last.1 = next;
                    } else {
                        runs.push((at, next, value));
                    }
                    at = next;
                }
            }
            runs
        });
        let saved_writes = translate.set_context_write_mask(word, u32::MAX);
        translate.set_context_write_mask(word, saved_writes & !bits);
        Some(Self {
            translate,
            word,
            shift,
            bits,
            saved_writes,
            original,
            calls: BTreeMap::new(),
            inventory: BTreeMap::new(),
            carrying: false,
        })
    }

    /// A context for a walk in a private copy of the database: it carries modes
    /// along edges through [`read`](Self::read) and leaves decoder writes alone.
    pub fn carrying(translate: &'a dyn Translate, arch: &Architecture) -> Option<Self> {
        let var = arch
            .with_context_db_mut(|db| db.get_variable(b"TMode"))
            .ok()?;
        let word = var.get_word() as usize;
        let shift = var.get_shift() as u32;
        let bits = var.get_mask() << shift;
        Some(Self {
            translate,
            word,
            shift,
            bits,
            saved_writes: u32::MAX,
            original: Vec::new(),
            calls: BTreeMap::new(),
            inventory: BTreeMap::new(),
            carrying: true,
        })
    }

    pub fn seed_inventory_modes(&mut self, seeds: impl Iterator<Item = u64>, modes: &[(u64, u64, u32)]) {
        if modes.is_empty() { return; }
        for at in seeds {
            let Some(index) = modes.partition_point(|&(start, _, _)| start <= at).checked_sub(1) else { continue };
            let (_, end, mode) = modes[index];
            if at < end { self.inventory.insert(at, mode); }
        }
    }

    pub fn entry(&self, at: u64) -> Option<u32> {
        self.calls.get(&at).or_else(|| self.inventory.get(&at)).copied().or_else(|| {
            let index = self
                .original
                .partition_point(|&(start, _, _)| start <= at)
                .checked_sub(1)?;
            let (_, end, mode) = self.original[index];
            (at < end).then_some(mode)
        })
    }

    /// The mode a carrying walk starts a function at `at` in: the mode a call
    /// committed there, else the database's.
    pub fn start(&self, arch: &Architecture, space: &Rc<AddrSpace>, at: u64) -> u32 {
        if let Some(&mode) = self.calls.get(&at) {
            return mode;
        }
        let (mask, value) = self.translate.set_context_read_override(self.word, 0, 0);
        self.translate.set_context_read_override(self.word, mask, value);
        let word = arch.with_context_db_mut(|db| {
            db.get_context(&Address::new(Rc::clone(space), at))
                .get(self.word)
                .copied()
                .unwrap_or(0)
        });
        (((word & !mask) | (value & mask)) & self.bits) >> self.shift
    }

    /// The mode a carrying walk takes from an edge carrying `mode` to `at`: a
    /// call's mode there wins, so code a call reached in the other mode is not
    /// read in the mode of code that runs into it.
    pub fn carried(&self, at: u64, mode: Option<u32>) -> Option<u32> {
        if self.carrying {
            self.calls.get(&at).copied().or(mode)
        } else {
            mode
        }
    }

    /// Whether a carrying walk stops at a call to `targets`: every target is a
    /// function the program marks no-return. The bytes after such a call are
    /// not the caller's (a literal pool, or the next function), so the caller's
    /// mode says nothing about them.
    pub fn halts(&self, arch: &Architecture, space: &Rc<AddrSpace>, targets: &[u64]) -> bool {
        self.carrying
            && !targets.is_empty()
            && targets.iter().all(|&at| {
                arch.symboltab
                    .function_is_no_return_across_scopes(&Address::new(Rc::clone(space), at))
            })
    }

    /// Make decodes read `mode` until the returned guard drops, without the
    /// span paint [`InstructionMode`] publishes.
    pub fn read(&self, mode: Option<u32>) -> Option<ModeRead<'a>> {
        let mode = mode?;
        let saved = self.translate.set_context_read_override(self.word, 0, 0);
        self.translate.set_context_read_override(
            self.word,
            saved.0 | self.bits,
            (saved.1 & !self.bits) | (mode << self.shift),
        );
        Some(ModeRead { translate: self.translate, word: self.word, saved })
    }

    pub fn successor(
        &self,
        at: u64,
        mode: Option<u32>,
        commits: &[ContextCommitRecord],
    ) -> Option<u32> {
        commits
            .iter()
            .rev()
            .find(|c| {
                c.addr.get_offset() == at
                    && c.word as usize == self.word
                    && c.mask & self.bits == self.bits
            })
            .map(|c| (c.value & self.bits) >> self.shift)
            .or(mode)
    }

    pub fn called(&mut self, at: u64, mode: Option<u32>) {
        if let Some(mode) = mode {
            self.calls.insert(at, mode);
        }
    }

    pub fn reset(&mut self) {
        self.calls.clear();
    }
}

impl Drop for WalkContext<'_> {
    fn drop(&mut self) {
        if !self.carrying {
            self.translate
                .set_context_write_mask(self.word, self.saved_writes);
        }
    }
}

/// Holds a carried mode for decodes to read until it drops; see [`WalkContext::read`].
pub(super) struct ModeRead<'a> {
    translate: &'a dyn Translate,
    word: usize,
    saved: (u32, u32),
}

impl Drop for ModeRead<'_> {
    fn drop(&mut self) {
        self.translate
            .set_context_read_override(self.word, self.saved.0, self.saved.1);
    }
}

/// Select the effective read mode without changing database values or boundaries.
/// A failed decode publishes nothing; success publishes only its full byte span.
pub(super) struct InstructionMode<'a> {
    arch: &'a Architecture,
    translate: &'a dyn Translate,
    space: &'a Rc<AddrSpace>,
    at: u64,
    mode: u32,
    word: usize,
    bits: u32,
    value: u32,
    saved_read: (u32, u32),
}

impl<'a> InstructionMode<'a> {
    pub fn select(
        arch: &'a Architecture,
        translate: &'a dyn Translate,
        space: &'a Rc<AddrSpace>,
        at: u64,
        mode: Option<u32>,
    ) -> Option<Self> {
        let mode = mode?;
        let var = arch
            .with_context_db_mut(|db| db.get_variable(b"TMode"))
            .ok()?;
        let word = var.get_word() as usize;
        let bits = var.get_mask() << var.get_shift();
        let value = mode << var.get_shift();
        let saved_read = translate.set_context_read_override(word, 0, 0);
        translate.set_context_read_override(
            word,
            saved_read.0 | bits,
            (saved_read.1 & !bits) | value,
        );
        Some(Self {
            arch,
            translate,
            space,
            at,
            mode,
            word,
            bits,
            value,
            saved_read,
        })
    }

    pub fn context_word(&self, index: usize, value: u32) -> u32 {
        if index == self.word {
            (value & !self.bits) | self.value
        } else {
            value
        }
    }

    pub fn accept(&self, len: u32) {
        paint(
            self.arch,
            self.space,
            self.at,
            self.at.saturating_add(u64::from(len)),
            self.mode,
        );
    }
}

impl Drop for InstructionMode<'_> {
    fn drop(&mut self) {
        self.translate
            .set_context_read_override(self.word, self.saved_read.0, self.saved_read.1);
    }
}

fn paint(arch: &Architecture, space: &Rc<AddrSpace>, start: u64, end: u64, mode: u32) {
    arch.with_context_db_mut(|db| {
        let addr = Address::new(Rc::clone(space), start);
        let Ok(var) = db.get_variable(b"TMode") else {
            return;
        };
        let (words, _, last) = db.get_context_bounds(&addr);
        if var.get_value(words) != mode || last.saturating_add(1) < end {
            let _ =
                db.set_variable_region(b"TMode", &addr, &Address::new(Rc::clone(space), end), mode);
        }
    });
}
