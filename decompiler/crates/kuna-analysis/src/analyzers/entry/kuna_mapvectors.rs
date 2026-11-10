//! (kuna) Cortex-M vector tables whose address the caller states, as a memory
//! map does for a headerless image: the handlers such a table holds, by slot.
//!
//! A stated table needs no signature search. The harvest is the ELF oracle's
//! loop ([`super::harvest_vector_slots`]) with the `cortexmvectors` relocation
//! relaxation, so a table that lies above its handlers is not cut short.

/// The handlers of the vector table whose first word (the initial stack
/// pointer) is `data[0..4]` at `address`, as `(slot, target)` pairs in table
/// order. A handler is an odd word whose even target `in_exec` accepts.
///
/// Without `slots`, the table ends at the first word that is neither zero nor
/// a handler, or where the lowest handler starts. With `slots`, the loop reads
/// exactly that many slots, as far as `data` reaches, and skips any word that
/// is not a handler.
pub fn stated_table_handlers(
    address: u64,
    data: &[u8],
    little_endian: bool,
    in_exec: &dyn Fn(u64) -> bool,
    slots: Option<u32>,
) -> Vec<(usize, u64)> {
    super::harvest_vector_slot_targets(
        address,
        data,
        little_endian,
        in_exec,
        true,
        slots.map(|n| n as usize),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn in_flash(target: u64) -> bool {
        (0x0800_0000..0x0800_1000).contains(&target)
    }

    #[test]
    fn a_stated_count_reads_exactly_that_many_slots() {
        let data = table(&[
            0x2000_4000,
            0x0800_0101,
            0x1234_5678,
            0x0800_0111,
            0x0800_0121,
        ]);
        let all = stated_table_handlers(0x0800_0000, &data, true, &in_flash, None);
        assert_eq!(
            all,
            vec![(1, 0x0800_0100)],
            "a non-handler word ends the table"
        );
        let four = stated_table_handlers(0x0800_0000, &data, true, &in_flash, Some(4));
        assert_eq!(four, vec![(1, 0x0800_0100), (3, 0x0800_0110)]);
    }

    #[test]
    fn a_table_above_its_handlers_is_not_cut_short() {
        let data = table(&[0x2000_4000, 0x0800_0101, 0, 0x0800_0111]);
        let handlers = stated_table_handlers(0x0800_0800, &data, true, &in_flash, None);
        assert_eq!(handlers, vec![(1, 0x0800_0100), (3, 0x0800_0110)]);
    }
}
