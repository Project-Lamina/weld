//! Segment layout helpers: alignment and flat segment buffer construction.

use crate::link::MergedLayout;

/// Round `value` up to the next multiple of `align`. Returns `value` unchanged
/// when `align` is 0.
pub fn align_up_u64(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Round `value` up to the next multiple of `align`. Returns `value` unchanged
/// when `align` is 0.
pub fn align_up_usize(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Flatten all sections in `layout` into a contiguous byte buffer.
///
/// Returns `(base_vaddr, buffer)` where `base_vaddr` is the virtual address of
/// the first section (or `default_base` when the layout is empty). Each section
/// is placed at `section.vaddr - base_vaddr` within the buffer; gaps are
/// zero-filled.
pub fn build_segment_buffer(layout: &MergedLayout, default_base: u64) -> (u64, Vec<u8>) {
    let base = layout
        .sections
        .first()
        .map(|s| s.vaddr)
        .unwrap_or(default_base);

    let end = layout
        .sections
        .iter()
        .map(|s| s.vaddr + s.data.len() as u64)
        .max()
        .unwrap_or(base);

    let seg_size = (end - base) as usize;
    let mut buf = vec![0u8; seg_size];

    for sec in &layout.sections {
        let off = (sec.vaddr - base) as usize;
        let len = sec.data.len().min(seg_size.saturating_sub(off));
        buf[off..off + len].copy_from_slice(&sec.data[..len]);
    }

    (base, buf)
}
