//! (kuna) A memory map for a headerless image: which ranges of the file load
//! where, which memory the file does not back, and where code starts.
//!
//! A library caller fills a [`LoadMap`] and passes it, with the file, to
//! `kuna_console::engine::bootstrap_from_memory_map_with_options` (or
//! `_with_db`). Addresses are in the target's address units, as
//! `bootstrap_from_raw`'s base and entries are; sizes and file offsets are in
//! bytes.

/// The regions of memory an image occupies and the entries that seed function
/// discovery.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadMap {
    /// The regions, which must not overlap in memory or share a file byte.
    pub regions: Vec<LoadRegion>,
    /// Addresses where code starts, each inside an executable region.
    pub entries: Vec<LoadEntry>,
    /// Cortex-M vector tables, whose handlers seed discovery as entries do.
    pub vector_tables: Vec<VectorTable>,
}

/// One named address range of a [`LoadMap`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadRegion {
    /// A name unique in the map.
    pub name: String,
    /// Where the region's first byte loads, in the target's address units.
    pub address: u64,
    /// The region's length in bytes; for a file-backed region, the length of
    /// its file range.
    pub size: u64,
    /// Where the region's bytes come from.
    pub bytes: RegionBytes,
    /// The region may be read.
    pub read: bool,
    /// The region may be written. A file-backed region without it is
    /// read-only, so loads from it fold into constants.
    pub write: bool,
    /// The region holds code. Only a file-backed region may.
    pub execute: bool,
    /// Every access to the region is a device access the decompiler keeps.
    /// Only a zero-filled region may be volatile.
    pub volatile: bool,
}

/// Where a [`LoadRegion`]'s bytes come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionBytes {
    /// `size` bytes of the file from `offset`.
    File { offset: u64 },
    /// No file bytes: memory whose contents are unknown, such as RAM or a
    /// peripheral block. It reads as zeros but is never read-only.
    Zero,
}

/// An address where code starts, with the name the function takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadEntry {
    /// The entry's address. On 32-bit ARM, bit 0 is ignored: the bootstrap's
    /// ISA decides the decode mode.
    pub address: u64,
    /// The function's name; `None` takes Kuna's generated name.
    pub name: Option<String>,
}

/// A Cortex-M vector table: the initial stack pointer, then one handler
/// pointer per slot. Slot 1's handler takes the CMSIS name `Reset_Handler`;
/// another system exception's handler takes its CMSIS name, such as
/// `NMI_Handler`, only when no other slot of any table points at it. An
/// entry's name beats either, and the first table in the map keeps a name two
/// tables would both give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorTable {
    /// The table's address, in a file-backed region and aligned to 4.
    pub address: u64,
    /// The number of slots, counting the stack pointer's, from 2 to 512.
    /// `None` ends the table at the first word that is neither zero nor a
    /// Thumb pointer into an executable region, or where the lowest handler
    /// starts.
    pub slots: Option<u32>,
}
