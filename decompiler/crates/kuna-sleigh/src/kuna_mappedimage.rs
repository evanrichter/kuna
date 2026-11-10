//! (kuna) A [`LoadImage`] over a memory map: a headerless file whose ranges
//! load at caller-stated addresses, beside regions of memory the file does not
//! back at all.
//!
//! [`RawLoadImage`](crate::loadimage::RawLoadImage) maps one contiguous file at
//! one base and calls all of it code. Firmware is not shaped like that: flash
//! holds code and constants, RAM and peripheral blocks hold no file bytes, and
//! only the flash is read-only. [`MappedLoadImage`] serves each
//! [`MappedRegion`] as stated: file-backed regions from the file, zero-filled
//! regions as zeros, and every other address as unmapped.
//!
//! Each region is one section (`CODE` when executable, `NOLOAD` when
//! zero-filled, `READONLY` when file-backed without write access) and one
//! segment with its access. Only a file-backed region without write access is
//! read-only, so a load from a zero-filled region is never folded to the zeros
//! it serves.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use kuna_base::address::{Address, RangeList};
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::AddrSpace;

use crate::loadimage::{section_flags, ImageBytes, LoadImage, LoadImageSection};

/// One region of a memory map, in byte addresses of the code space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedRegion {
    /// Byte address of the region's first byte.
    pub address: u64,
    /// Number of bytes in the region.
    pub size: u64,
    /// File offset of the region's first byte; `None` for a zero-filled region.
    pub file_offset: Option<u64>,
    /// The region may be written at run time.
    pub write: bool,
    /// The region holds code.
    pub execute: bool,
}

impl MappedRegion {
    fn end(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end()
    }

    /// Whether Kuna may fold loads from this region into constants.
    pub fn is_readonly(&self) -> bool {
        self.file_offset.is_some() && !self.write
    }

    fn section_flags(&self) -> u32 {
        let mut flags = if self.execute {
            section_flags::CODE
        } else {
            section_flags::DATA
        };
        if self.file_offset.is_none() {
            flags |= section_flags::NOLOAD;
        }
        if self.is_readonly() {
            flags |= section_flags::READONLY;
        }
        flags
    }

    fn segment_flags(&self) -> u32 {
        let mut flags = if self.execute {
            section_flags::CODE
        } else {
            section_flags::DATA
        };
        if !self.write {
            flags |= section_flags::READONLY;
        }
        flags
    }
}

/// The bytes a memory map serves, readable from any thread.
#[derive(Debug)]
pub struct MappedBytes {
    regions: Vec<MappedRegion>,
    file: Vec<u8>,
}

impl MappedBytes {
    /// The regions over `file`, sorted by address. Fails when two regions
    /// overlap, a region is empty, or a file-backed region runs past the file.
    pub fn new(mut regions: Vec<MappedRegion>, file: Vec<u8>) -> Result<MappedBytes, String> {
        regions.sort_by_key(|region| region.address);
        for region in &regions {
            if region.size == 0 {
                return Err(format!("the region at 0x{:x} is empty", region.address));
            }
            if region.address.checked_add(region.size).is_none() {
                return Err(format!(
                    "the region at 0x{:x} overflows the address space",
                    region.address
                ));
            }
            if let Some(offset) = region.file_offset {
                let end = offset.checked_add(region.size);
                if end.is_none_or(|end| end > file.len() as u64) {
                    return Err(format!(
                        "the region at 0x{:x} reads file bytes 0x{offset:x}..0x{:x} past the end of the 0x{:x}-byte file",
                        region.address,
                        offset.saturating_add(region.size),
                        file.len()
                    ));
                }
            }
        }
        for pair in regions.windows(2) {
            if pair[1].address < pair[0].end() {
                return Err(format!(
                    "the regions at 0x{:x} and 0x{:x} overlap",
                    pair[0].address, pair[1].address
                ));
            }
        }
        Ok(MappedBytes { regions, file })
    }

    /// The regions, sorted by address.
    pub fn regions(&self) -> &[MappedRegion] {
        &self.regions
    }

    /// The file bytes `region` serves, or `None` for a zero-filled region or
    /// one this map does not hold.
    pub fn region_bytes(&self, region: &MappedRegion) -> Option<&[u8]> {
        let offset = usize::try_from(region.file_offset?).ok()?;
        let size = usize::try_from(region.size).ok()?;
        self.file.get(offset..offset.checked_add(size)?)
    }

    fn region_at(&self, addr: u64) -> Option<&MappedRegion> {
        let index = self.regions.partition_point(|region| region.end() <= addr);
        self.regions
            .get(index)
            .filter(|region| region.contains(addr))
    }
}

impl ImageBytes for MappedBytes {
    fn fill_span(&self, dst: &mut [u8], start: u64) -> usize {
        if self.region_at(start).is_none() {
            return dst.len();
        }
        let mut done = 0usize;
        while done < dst.len() {
            let addr = start.wrapping_add(done as u64);
            let Some(region) = self.region_at(addr) else {
                dst[done] = 0;
                done += 1;
                continue;
            };
            let run = usize::try_from(region.end() - addr)
                .unwrap_or(usize::MAX)
                .min(dst.len() - done);
            let out = &mut dst[done..done + run];
            match region.file_offset {
                Some(offset) => {
                    let from = (offset + (addr - region.address)) as usize;
                    out.copy_from_slice(&self.file[from..from + run]);
                }
                None => out.fill(0),
            }
            done += run;
        }
        0
    }

    fn mapped_covers(&self, lo: u64, hi: u64) -> bool {
        let mut at = lo;
        while at < hi {
            match self.region_at(at) {
                Some(region) => at = region.end(),
                None => return false,
            }
        }
        true
    }
}

/// \brief (kuna) A load image over a memory map ([`MappedRegion`]s over one
/// file).
#[derive(Debug)]
pub struct MappedLoadImage {
    filename: String,
    bytes: Arc<MappedBytes>,
    spaceid: Option<Rc<AddrSpace>>,
    cursection: Cell<usize>,
}

impl MappedLoadImage {
    /// An image named `filename` that serves `bytes`, not yet attached to a space.
    pub fn new(filename: &str, bytes: MappedBytes) -> MappedLoadImage {
        MappedLoadImage {
            filename: filename.to_string(),
            bytes: Arc::new(bytes),
            spaceid: None,
            cursection: Cell::new(0),
        }
    }

    /// Attach the image to the space its region addresses name.
    pub fn attach_to_space(&mut self, id: Rc<AddrSpace>) {
        self.spaceid = Some(id);
    }

    /// The regions, sorted by address.
    pub fn regions(&self) -> &[MappedRegion] {
        self.bytes.regions()
    }

    /// The bytes the image serves, shared with every reader of the image.
    pub fn bytes(&self) -> &Arc<MappedBytes> {
        &self.bytes
    }

    fn space(&self) -> &Rc<AddrSpace> {
        self.spaceid
            .as_ref()
            .expect("MappedLoadImage used before attach_to_space")
    }
}

impl LoadImage for MappedLoadImage {
    fn get_file_name(&self) -> &str {
        &self.filename
    }

    fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
        let in_space = match (addr.get_space(), &self.spaceid) {
            (Some(space), Some(own)) => Rc::ptr_eq(space, own),
            _ => false,
        };
        if !in_space || self.bytes.fill_span(ptr, addr.get_offset()) != 0 {
            let mut errmsg = format!(
                "Unable to load {} bytes at {}",
                ptr.len(),
                addr.get_shortcut()
            );
            addr.print_raw(&mut errmsg)?;
            return Err(KunaError::data_unavail(errmsg));
        }
        Ok(())
    }

    fn open_section_info(&self) {
        self.cursection.set(0);
    }

    fn get_next_section(&self, record: &mut LoadImageSection) -> bool {
        let index = self.cursection.get();
        let regions = self.bytes.regions();
        let Some(region) = regions.get(index) else {
            record.size = 0;
            return false;
        };
        record.address = Address::new(Rc::clone(self.space()), region.address);
        record.size = region.size;
        record.flags = region.section_flags();
        self.cursection.set(index + 1);
        index + 1 < regions.len()
    }

    fn get_segments(&self) -> Vec<(u64, u64, u32)> {
        self.bytes
            .regions()
            .iter()
            .map(|region| (region.address, region.size, region.segment_flags()))
            .collect()
    }

    fn shared_bytes(&self) -> Option<Arc<dyn ImageBytes>> {
        Some(Arc::clone(&self.bytes) as Arc<dyn ImageBytes>)
    }

    fn get_readonly(&self, list: &mut RangeList) {
        let space = self.space();
        for region in self
            .bytes
            .regions()
            .iter()
            .filter(|region| region.is_readonly())
        {
            list.insert_range(Rc::clone(space), region.address, region.end() - 1);
        }
    }

    fn get_arch_type(&self) -> Vec<u8> {
        b"unknown".to_vec()
    }

    /// The map states every address, so there is nothing to adjust.
    fn adjust_vma(&mut self, _adjust: i64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(address: u64, size: u64, file_offset: Option<u64>, write: bool) -> MappedRegion {
        MappedRegion {
            address,
            size,
            file_offset,
            write,
            execute: false,
        }
    }

    fn flash_and_ram() -> MappedBytes {
        MappedBytes::new(
            vec![
                region(0x2000, 4, None, true),
                region(0x1000, 4, Some(2), false),
            ],
            vec![0, 1, 2, 3, 4, 5],
        )
        .unwrap()
    }

    #[test]
    fn serves_file_bytes_and_zero_fill() {
        let bytes = flash_and_ram();
        let mut flash = [0xffu8; 4];
        assert_eq!(bytes.fill_span(&mut flash, 0x1000), 0);
        assert_eq!(flash, [2, 3, 4, 5]);
        let mut ram = [0xffu8; 4];
        assert_eq!(bytes.fill_span(&mut ram, 0x2000), 0);
        assert_eq!(ram, [0; 4]);
        let mut tail = [0xffu8; 4];
        assert_eq!(bytes.fill_span(&mut tail, 0x1002), 0);
        assert_eq!(tail, [4, 5, 0, 0]);
    }

    #[test]
    fn region_bytes_are_the_file_slice_or_none_for_zero_fill() {
        let bytes = flash_and_ram();
        let [flash, ram] = bytes.regions() else { panic!("two regions") };
        assert_eq!(bytes.region_bytes(flash), Some(&[2u8, 3, 4, 5][..]));
        assert_eq!(bytes.region_bytes(ram), None);
    }

    #[test]
    fn an_address_in_no_region_is_unmapped() {
        let bytes = flash_and_ram();
        assert_eq!(bytes.fill_span(&mut [0u8; 2], 0x1004), 2);
        assert!(bytes.mapped_covers(0x1000, 0x1004));
        assert!(!bytes.mapped_covers(0x1000, 0x1005));
    }

    #[test]
    fn refuses_overlap_and_ranges_past_the_file() {
        let file = vec![0u8; 8];
        let overlap = vec![
            region(0x1000, 8, Some(0), false),
            region(0x1004, 4, None, true),
        ];
        assert!(MappedBytes::new(overlap, file.clone())
            .unwrap_err()
            .contains("overlap"));
        let past = vec![region(0x1000, 8, Some(1), false)];
        assert!(MappedBytes::new(past, file)
            .unwrap_err()
            .contains("past the end"));
    }
}
