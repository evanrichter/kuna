//! (kuna) `ImageView`: the image a whole-image walk reads, without an
//! `object::File`.
//!
//! The reference walk ([`crate::listing::xrefs::build_in`]), its seeds
//! ([`crate::listing::xrefs::discovery_seeds_in`]) and the string inventory
//! ([`crate::strings::kuna_stringinv::inventory_in`]) read an image's section
//! partition: which addresses are code, which are mapped, and their bytes.
//! An [`ImageView`] answers exactly that, plus the byte order and pointer
//! width the walks read words at. [`ObjectView`] answers it for an object
//! file and [`MappedView`] for a memory map
//! ([`MappedLoadImage`](kuna_sleigh::kuna_mappedimage::MappedLoadImage)).
//!
//! Some walks also read what only an object file holds: symbols, the GOT,
//! relocations. A view answers those through [`ImageView::object`], which
//! [`ObjectView`] fills and every other view leaves empty; the walks then run
//! without them, as they do for an object file that lacks them.

use object::read::{Object, ObjectSection, ObjectSegment};
use object::{Architecture, SegmentFlags};

use kuna_sleigh::kuna_mappedimage::MappedBytes;

/// One mapped region of an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageRegion<'a> {
    /// The region's name (a section name, or a memory map's region name).
    pub name: Option<&'a str>,
    /// Address of the region's first byte.
    pub address: u64,
    /// Number of bytes the region maps.
    pub size: u64,
    /// The region's bytes, or `None` when it maps `size` bytes the image does
    /// not hold (`.bss`, RAM). May be shorter than `size`.
    pub bytes: Option<&'a [u8]>,
    /// The region holds code.
    pub code: bool,
    /// The region may be written at run time.
    pub write: bool,
}

impl ImageRegion<'_> {
    /// One past the region's last address.
    pub fn end(&self) -> u64 {
        self.address.saturating_add(self.size)
    }
}

/// What a whole-image walk reads from an image.
pub trait ImageView {
    /// The image's instruction set architecture.
    fn architecture(&self) -> Architecture;
    /// Whether the image stores words least significant byte first.
    fn is_little_endian(&self) -> bool;
    /// The width of a pointer in bytes (4 or 8).
    fn pointer_width(&self) -> u32;
    /// The mapped regions, in image order.
    fn regions(&self) -> Vec<ImageRegion<'_>>;
    /// The object file behind the view, for what only an object file holds.
    fn object(&self) -> Option<&object::File<'_>> {
        None
    }
}

/// An [`ImageView`] over an object file.
#[derive(Clone, Copy)]
pub struct ObjectView<'a, 'd> {
    file: &'a object::File<'d>,
}

impl<'a, 'd> ObjectView<'a, 'd> {
    /// The view of `file`.
    pub fn new(file: &'a object::File<'d>) -> Self {
        ObjectView { file }
    }
}

impl ImageView for ObjectView<'_, '_> {
    fn architecture(&self) -> Architecture {
        self.file.architecture()
    }

    fn is_little_endian(&self) -> bool {
        self.file.is_little_endian()
    }

    fn pointer_width(&self) -> u32 {
        if self.file.is_64() { 8 } else { 4 }
    }

    /// The allocated sections, or the loadable segments of an image with no
    /// section table.
    fn regions(&self) -> Vec<ImageRegion<'_>> {
        if self.file.sections().next().is_none() {
            return self
                .file
                .segments()
                .filter(|seg| seg.size() != 0)
                .map(|seg| {
                    let (code, write) = match seg.flags() {
                        SegmentFlags::Elf { p_flags } => (p_flags & 1 != 0, p_flags & 2 != 0),
                        _ => (false, true),
                    };
                    ImageRegion {
                        name: None,
                        address: seg.address(),
                        size: seg.size(),
                        bytes: seg.data().ok().filter(|d| !d.is_empty()),
                        code,
                        write,
                    }
                })
                .collect();
        }
        self.file
            .sections()
            .filter(|sec| sec.address() != 0 && sec.size() != 0 && crate::listing::xrefs::is_mapped_section(sec))
            .map(|sec| ImageRegion {
                name: sec.name().ok().filter(|n| !n.is_empty()),
                address: sec.address(),
                size: sec.size(),
                bytes: sec.data().ok().filter(|d| !d.is_empty()),
                code: crate::entry::is_executable(&sec),
                write: !crate::listing::kuna_poolref::is_read_only(&sec),
            })
            .collect()
    }

    fn object(&self) -> Option<&object::File<'_>> {
        Some(self.file)
    }
}

/// An [`ImageView`] over a memory map's bytes
/// ([`MappedLoadImage::bytes`](kuna_sleigh::kuna_mappedimage::MappedLoadImage::bytes)).
/// The map states no architecture, byte order or pointer width, so the caller
/// gives them from the language it loaded the map with.
#[derive(Clone, Copy)]
pub struct MappedView<'a> {
    bytes: &'a MappedBytes,
    names: &'a [String],
    architecture: Architecture,
    little_endian: bool,
    pointer_width: u32,
}

impl<'a> MappedView<'a> {
    /// The view of `bytes` for a target of `architecture`, byte order and
    /// `pointer_width` bytes.
    pub fn new(bytes: &'a MappedBytes, architecture: Architecture, little_endian: bool, pointer_width: u32) -> Self {
        MappedView { bytes, names: &[], architecture, little_endian, pointer_width }
    }

    /// The view with `names` naming its regions, in address order.
    pub fn with_names(self, names: &'a [String]) -> Self {
        MappedView { names, ..self }
    }
}

impl ImageView for MappedView<'_> {
    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn is_little_endian(&self) -> bool {
        self.little_endian
    }

    fn pointer_width(&self) -> u32 {
        self.pointer_width
    }

    fn regions(&self) -> Vec<ImageRegion<'_>> {
        self.bytes
            .regions()
            .iter()
            .enumerate()
            .map(|(i, region)| ImageRegion {
                name: self.names.get(i).map(String::as_str),
                address: region.address,
                size: region.size,
                bytes: self.bytes.region_bytes(region),
                code: region.execute,
                write: region.write,
            })
            .collect()
    }
}

/// The `(start, end, bytes)` of each code region, as
/// [`crate::entry::executable_sections`] gives them for an object file.
pub(crate) fn executable_sections(view: &dyn ImageView) -> Vec<(u64, u64, Vec<u8>)> {
    match view.object() {
        Some(file) => crate::entry::executable_sections(file),
        None => view
            .regions()
            .into_iter()
            .filter(|r| r.code && r.size != 0)
            .map(|r| (r.address, r.end(), r.bytes.map(<[u8]>::to_vec).unwrap_or_default()))
            .collect(),
    }
}

/// The `(start, end)` of every mapped region, sorted.
pub(crate) fn mapped_ranges(view: &dyn ImageView) -> Vec<(u64, u64)> {
    match view.object() {
        Some(file) => crate::listing::xrefs::mapped_ranges(file),
        None => {
            let mut out: Vec<(u64, u64)> =
                view.regions().into_iter().filter(|r| r.size != 0).map(|r| (r.address, r.end())).collect();
            out.sort_unstable();
            out
        }
    }
}

/// The `(start, end, bytes)` of every region that is read-only and holds
/// bytes, as [`crate::listing::kuna_poolref`] reads pool words from.
pub(crate) fn read_only(view: &dyn ImageView) -> Vec<(u64, u64, &[u8])> {
    view.regions()
        .into_iter()
        .filter(|r| !r.write && r.size != 0)
        .filter_map(|r| {
            let data = r.bytes?;
            Some((r.address, r.address.saturating_add(r.size.min(data.len() as u64)), data))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_sleigh::kuna_mappedimage::MappedRegion;

    fn map() -> MappedBytes {
        let region = |address, size, file_offset, write, execute| MappedRegion {
            address,
            size,
            file_offset,
            write,
            execute,
        };
        MappedBytes::new(
            vec![region(0x2000_0000, 0x100, None, true, false), region(0x0800_0000, 4, Some(0), false, true)],
            vec![1, 2, 3, 4],
        )
        .unwrap()
    }

    #[test]
    fn a_mapped_view_serves_file_regions_and_zero_fill_in_address_order() {
        let bytes = map();
        let names = ["flash".to_string(), "sram".to_string()];
        let view = MappedView::new(&bytes, Architecture::Arm, true, 4).with_names(&names);
        assert_eq!(
            view.regions(),
            vec![
                ImageRegion { name: Some("flash"), address: 0x0800_0000, size: 4, bytes: Some(&[1, 2, 3, 4]), code: true, write: false },
                ImageRegion { name: Some("sram"), address: 0x2000_0000, size: 0x100, bytes: None, code: false, write: true },
            ]
        );
        assert!(view.object().is_none());
        assert_eq!(executable_sections(&view), vec![(0x0800_0000, 0x0800_0004, vec![1, 2, 3, 4])]);
        assert_eq!(mapped_ranges(&view), vec![(0x0800_0000, 0x0800_0004), (0x2000_0000, 0x2000_0100)]);
        assert_eq!(read_only(&view), vec![(0x0800_0000, 0x0800_0004, &[1u8, 2, 3, 4][..])]);
    }

    #[test]
    fn an_object_view_maps_the_allocated_sections() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/poolref_arm_le32");
        let data = std::fs::read(path).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let view = ObjectView::new(&file);
        assert_eq!((view.architecture(), view.is_little_endian(), view.pointer_width()), (Architecture::Arm, true, 4));
        let regions = view.regions();
        let text = regions.iter().find(|r| r.name == Some(".text")).expect(".text is mapped");
        assert!(text.code && !text.write && text.bytes.is_some());
        let mut spans: Vec<(u64, u64)> = regions.iter().map(|r| (r.address, r.end())).collect();
        spans.sort_unstable();
        assert_eq!(spans, mapped_ranges(&view));
        for (lo, hi, _) in executable_sections(&view) {
            assert!(regions.iter().any(|r| r.code && r.address == lo && r.end() == hi));
        }
    }
}
