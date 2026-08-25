//! Bounded file-backed radix-2 DFT over canonical Goldilocks rows.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use thiserror::Error;

use crate::merkle_store::GOLDILOCKS_MODULUS;

const NATURAL_DFT_CANCEL_POLL_ROWS: usize = 256;

#[derive(Debug, Error)]
pub(crate) enum ExternalRadix2Error {
    #[error("invalid external radix-2 DFT: {0}")]
    Invalid(&'static str),
    #[error("external radix-2 DFT buffer allocation failed")]
    BufferAllocation,
    #[error("external radix-2 DFT I/O failed while {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Transform one bit-reversed, row-major Goldilocks matrix in place.
///
/// Each field element is stored as one canonical little-endian `u64` at
/// `data_offset`. The output is natural row order. `buffer_values` bounds each
/// of the two reusable butterfly buffers and must describe a whole number of
/// rows. The largest power-of-two block that fits one buffer is transformed
/// through all of its local stages after one read and before one write. Later
/// stages retain the bounded external-butterfly path. Twiddles are derived on
/// demand instead of being retained per stage.
pub(crate) fn dft_goldilocks_rows_in_place(
    file: &mut File,
    path: &Path,
    data_offset: u64,
    height: usize,
    width: usize,
    buffer_values: usize,
) -> Result<(), ExternalRadix2Error> {
    if width == 0 {
        return Err(ExternalRadix2Error::Invalid(
            "DFT row width must be nonzero",
        ));
    }
    if height < 2 || !height.is_power_of_two() {
        return Err(ExternalRadix2Error::Invalid(
            "DFT height must be a power of two of at least two",
        ));
    }
    if height.ilog2() as usize > Goldilocks::TWO_ADICITY {
        return Err(ExternalRadix2Error::Invalid(
            "DFT height exceeds Goldilocks two-adicity",
        ));
    }
    if buffer_values < width || !buffer_values.is_multiple_of(width) {
        return Err(ExternalRadix2Error::Invalid(
            "DFT buffer must contain a nonzero whole number of rows",
        ));
    }
    let transform_end = checked_transform_end(data_offset, height, width)?;
    let file_len = file
        .metadata()
        .map_err(|source| io_error("reading metadata for", path, source))?
        .len();
    if file_len < transform_end {
        return Err(ExternalRadix2Error::Invalid(
            "DFT transform region exceeds file length",
        ));
    }
    let buffer_rows = buffer_values / width;
    let max_values = buffer_rows
        .checked_mul(width)
        .ok_or(ExternalRadix2Error::Invalid("DFT buffer size overflow"))?;
    let mut left = allocate_buffer(max_values)?;
    let mut right = allocate_buffer(max_values)?;
    let max_bytes = max_values
        .checked_mul(8)
        .ok_or(ExternalRadix2Error::Invalid("DFT byte count overflow"))?;
    let mut encoded = allocate_byte_buffer(max_bytes)?;

    let fused_rows = fused_block_rows(height, buffer_rows);
    let fused_values = fused_rows
        .checked_mul(width)
        .ok_or(ExternalRadix2Error::Invalid("DFT buffer size overflow"))?;
    let fused_bytes = fused_values
        .checked_mul(8)
        .ok_or(ExternalRadix2Error::Invalid("DFT byte count overflow"))?;
    for block in (0..height).step_by(fused_rows) {
        read_values(
            file,
            path,
            data_offset,
            width,
            block,
            &mut left[..fused_values],
            &mut encoded[..fused_bytes],
        )?;
        dft_local_block_in_place(&mut left[..fused_values], fused_rows, width);
        write_values(
            file,
            path,
            data_offset,
            width,
            block,
            &left[..fused_values],
            &mut encoded[..fused_bytes],
        )?;
    }
    if fused_rows == height {
        return Ok(());
    }

    let mut len = fused_rows
        .checked_mul(2)
        .ok_or(ExternalRadix2Error::Invalid("DFT stage size overflow"))?;
    loop {
        let half = len / 2;
        let root = Goldilocks::two_adic_generator(len.ilog2() as usize);
        for block in (0..height).step_by(len) {
            let mut offset = 0_usize;
            while offset < half {
                let rows = (half - offset).min(buffer_rows);
                let values = rows
                    .checked_mul(width)
                    .ok_or(ExternalRadix2Error::Invalid("DFT buffer size overflow"))?;
                let bytes = values
                    .checked_mul(8)
                    .ok_or(ExternalRadix2Error::Invalid("DFT byte count overflow"))?;
                read_values(
                    file,
                    path,
                    data_offset,
                    width,
                    block + offset,
                    &mut left[..values],
                    &mut encoded[..bytes],
                )?;
                read_values(
                    file,
                    path,
                    data_offset,
                    width,
                    block + half + offset,
                    &mut right[..values],
                    &mut encoded[..bytes],
                )?;
                let mut twiddle = root.exp_u64(offset as u64);
                for row in 0..rows {
                    for column in 0..width {
                        let index = row * width + column;
                        let a = Goldilocks::new(left[index]);
                        let b = Goldilocks::new(right[index]) * twiddle;
                        left[index] = (a + b).as_canonical_u64();
                        right[index] = (a - b).as_canonical_u64();
                    }
                    twiddle *= root;
                }
                write_values(
                    file,
                    path,
                    data_offset,
                    width,
                    block + offset,
                    &left[..values],
                    &mut encoded[..bytes],
                )?;
                write_values(
                    file,
                    path,
                    data_offset,
                    width,
                    block + half + offset,
                    &right[..values],
                    &mut encoded[..bytes],
                )?;
                offset += rows;
            }
        }
        if len == height {
            break;
        }
        len *= 2;
    }
    Ok(())
}

/// Transform one natural-order, row-major Goldilocks matrix in place.
///
/// The complete rows are first permuted into bit-reversed order, then the same
/// radix-2 butterfly core used by the file-backed transform produces natural
/// row-order evaluations. Validation completes before any input value changes.
#[cfg(test)]
pub(crate) fn dft_goldilocks_natural_rows_in_place(
    values: &mut [u64],
    height: usize,
    width: usize,
) -> Result<(), ExternalRadix2Error> {
    let cancelled =
        dft_goldilocks_natural_rows_in_place_cancellable(values, height, width, || false)?;
    debug_assert!(!cancelled);
    Ok(())
}

/// Cancellable sibling of [`dft_goldilocks_natural_rows_in_place`].
///
/// The callback is polled before mutation and after each fixed-size group of
/// bit-reversal or butterfly rows. After `Ok(true)`, the caller must discard
/// the current buffer state. All input validation still completes before the
/// first callback or mutation.
pub(crate) fn dft_goldilocks_natural_rows_in_place_cancellable<F>(
    values: &mut [u64],
    height: usize,
    width: usize,
    mut should_cancel: F,
) -> Result<bool, ExternalRadix2Error>
where
    F: FnMut() -> bool,
{
    if width == 0 {
        return Err(ExternalRadix2Error::Invalid(
            "DFT row width must be nonzero",
        ));
    }
    if height < 2 || !height.is_power_of_two() {
        return Err(ExternalRadix2Error::Invalid(
            "DFT height must be a power of two of at least two",
        ));
    }
    if height.ilog2() as usize > Goldilocks::TWO_ADICITY {
        return Err(ExternalRadix2Error::Invalid(
            "DFT height exceeds Goldilocks two-adicity",
        ));
    }
    let expected_values = height
        .checked_mul(width)
        .ok_or(ExternalRadix2Error::Invalid("DFT matrix size overflow"))?;
    if values.len() != expected_values {
        return Err(ExternalRadix2Error::Invalid(
            "DFT input length does not match height and width",
        ));
    }
    if values.iter().any(|value| *value >= GOLDILOCKS_MODULUS) {
        return Err(ExternalRadix2Error::Invalid(
            "DFT input contains a noncanonical Goldilocks value",
        ));
    }

    let bits = height.ilog2();
    for natural_row in 0..height {
        if natural_row.is_multiple_of(NATURAL_DFT_CANCEL_POLL_ROWS) && should_cancel() {
            return Ok(true);
        }
        let reversed_row = natural_row.reverse_bits() >> (usize::BITS - bits);
        if natural_row < reversed_row {
            for column in 0..width {
                values.swap(natural_row * width + column, reversed_row * width + column);
            }
        }
    }
    if dft_local_block_in_place_cancellable(values, height, width, &mut should_cancel) {
        return Ok(true);
    }
    Ok(should_cancel())
}

fn fused_block_rows(height: usize, buffer_rows: usize) -> usize {
    let available_rows = height.min(buffer_rows);
    1_usize << available_rows.ilog2()
}

fn dft_local_block_in_place(values: &mut [u64], rows: usize, width: usize) {
    let cancelled = dft_local_block_in_place_cancellable(values, rows, width, &mut || false);
    debug_assert!(!cancelled);
}

fn dft_local_block_in_place_cancellable<F>(
    values: &mut [u64],
    rows: usize,
    width: usize,
    should_cancel: &mut F,
) -> bool
where
    F: FnMut() -> bool,
{
    debug_assert!(rows.is_power_of_two());
    debug_assert_eq!(values.len(), rows * width);
    let mut rows_until_poll = 0_usize;
    let mut len = 2_usize;
    while len <= rows {
        let half = len / 2;
        let root = Goldilocks::two_adic_generator(len.ilog2() as usize);
        for block in (0..rows).step_by(len) {
            let mut twiddle = root.exp_u64(0);
            for row in 0..half {
                if rows_until_poll == 0 {
                    if should_cancel() {
                        return true;
                    }
                    rows_until_poll = NATURAL_DFT_CANCEL_POLL_ROWS;
                }
                let left_row = (block + row) * width;
                let right_row = (block + half + row) * width;
                for column in 0..width {
                    let left_index = left_row + column;
                    let right_index = right_row + column;
                    let a = Goldilocks::new(values[left_index]);
                    let b = Goldilocks::new(values[right_index]) * twiddle;
                    values[left_index] = (a + b).as_canonical_u64();
                    values[right_index] = (a - b).as_canonical_u64();
                }
                twiddle *= root;
                rows_until_poll -= 1;
            }
        }
        len *= 2;
    }
    false
}

fn allocate_buffer(values: usize) -> Result<Vec<u64>, ExternalRadix2Error> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(values)
        .map_err(|_| ExternalRadix2Error::BufferAllocation)?;
    buffer.resize(values, 0);
    Ok(buffer)
}

fn allocate_byte_buffer(bytes: usize) -> Result<Vec<u8>, ExternalRadix2Error> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(bytes)
        .map_err(|_| ExternalRadix2Error::BufferAllocation)?;
    buffer.resize(bytes, 0);
    Ok(buffer)
}

fn read_values(
    file: &mut File,
    path: &Path,
    data_offset: u64,
    width: usize,
    row_start: usize,
    output: &mut [u64],
    encoded: &mut [u8],
) -> Result<(), ExternalRadix2Error> {
    let offset = row_offset(data_offset, row_start, width)?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seeking in", path, source))?;
    debug_assert_eq!(encoded.len(), output.len() * 8);
    file.read_exact(encoded)
        .map_err(|source| io_error("reading staged rows from", path, source))?;
    for (value, bytes) in output.iter_mut().zip(encoded.chunks_exact(8)) {
        *value = u64::from_le_bytes(bytes.try_into().expect("eight-byte chunk"));
        if *value >= GOLDILOCKS_MODULUS {
            return Err(ExternalRadix2Error::Invalid(
                "staged DFT row contains a noncanonical Goldilocks value",
            ));
        }
    }
    Ok(())
}

fn write_values(
    file: &mut File,
    path: &Path,
    data_offset: u64,
    width: usize,
    row_start: usize,
    values: &[u64],
    encoded: &mut [u8],
) -> Result<(), ExternalRadix2Error> {
    let offset = row_offset(data_offset, row_start, width)?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seeking in", path, source))?;
    debug_assert_eq!(encoded.len(), values.len() * 8);
    for (value, bytes) in values.iter().zip(encoded.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    file.write_all(encoded)
        .map_err(|source| io_error("writing staged rows to", path, source))
}

fn row_offset(data_offset: u64, row: usize, width: usize) -> Result<u64, ExternalRadix2Error> {
    u64::try_from(row)
        .ok()
        .and_then(|row| row.checked_mul(u64::try_from(width).ok()?))
        .and_then(|values| values.checked_mul(8))
        .and_then(|offset| data_offset.checked_add(offset))
        .ok_or(ExternalRadix2Error::Invalid("DFT row offset overflow"))
}

#[cfg(target_pointer_width = "64")]
fn checked_transform_end(
    data_offset: u64,
    height: usize,
    width: usize,
) -> Result<u64, ExternalRadix2Error> {
    u64::try_from(height)
        .ok()
        .and_then(|height| height.checked_mul(u64::try_from(width).ok()?))
        .and_then(|values| values.checked_mul(8))
        .and_then(|bytes| data_offset.checked_add(bytes))
        .ok_or(ExternalRadix2Error::Invalid(
            "DFT transform region overflows u64",
        ))
}

#[cfg(not(target_pointer_width = "64"))]
fn checked_transform_end(
    _data_offset: u64,
    _height: usize,
    _width: usize,
) -> Result<u64, ExternalRadix2Error> {
    Err(ExternalRadix2Error::Invalid(
        "external radix-2 DFT requires a 64-bit target",
    ))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ExternalRadix2Error {
    ExternalRadix2Error::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-external-radix2-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn reverse_bits_len(value: usize, bits: u32) -> usize {
        value.reverse_bits() >> (usize::BITS - bits)
    }

    fn input(height: usize, width: usize) -> Vec<u64> {
        (0..height * width)
            .map(|index| {
                ((index as u64)
                    .wrapping_mul(0x9e37_79b9)
                    .wrapping_add(width as u64 + 17))
                    % GOLDILOCKS_MODULUS
            })
            .collect()
    }

    fn stage_bit_reversed(
        file: &mut File,
        data_offset: u64,
        height: usize,
        width: usize,
        values: &[u64],
    ) {
        file.set_len(data_offset + (height * width * 8) as u64)
            .unwrap();
        let bits = height.ilog2();
        for natural_row in 0..height {
            let physical_row = reverse_bits_len(natural_row, bits);
            file.seek(SeekFrom::Start(
                data_offset + (physical_row * width * 8) as u64,
            ))
            .unwrap();
            for value in &values[natural_row * width..(natural_row + 1) * width] {
                file.write_all(&value.to_le_bytes()).unwrap();
            }
        }
    }

    fn read_all(file: &mut File, data_offset: u64, value_count: usize) -> Vec<u64> {
        file.seek(SeekFrom::Start(data_offset)).unwrap();
        let mut encoded = vec![0_u8; value_count * 8];
        file.read_exact(&mut encoded).unwrap();
        encoded
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect()
    }

    fn file_bytes(file: &mut File) -> Vec<u8> {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn matches_small_batch_across_widths_offsets_and_non_power_of_two_buffers() {
        for (height, width, data_offset) in [(2, 4, 0), (64, 4, 173), (4, 12, 1), (128, 12, 4_097)]
        {
            let values = input(height, width);
            let expected = Radix2DFTSmallBatch::new(height)
                .dft_batch(RowMajorMatrix::new(
                    values.iter().copied().map(Goldilocks::new).collect(),
                    width,
                ))
                .values
                .into_iter()
                .map(|value| value.as_canonical_u64())
                .collect::<Vec<_>>();
            for buffer_rows in [1, 3, 5, 6, 31, 64, 257] {
                let path = test_path("parity");
                let mut file = File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                let prefix = (0_u64..data_offset)
                    .map(|index| index.wrapping_mul(29_u64).wrapping_add(7_u64) as u8)
                    .collect::<Vec<_>>();
                file.write_all(&prefix).unwrap();
                stage_bit_reversed(&mut file, data_offset, height, width, &values);
                let transform_end = data_offset + (height * width * 8) as u64;
                let auth_tail = b"preserved-auth-tail";
                file.seek(SeekFrom::Start(transform_end)).unwrap();
                file.write_all(auth_tail).unwrap();
                dft_goldilocks_rows_in_place(
                    &mut file,
                    &path,
                    data_offset,
                    height,
                    width,
                    buffer_rows * width,
                )
                .unwrap();
                assert_eq!(read_all(&mut file, data_offset, values.len()), expected);
                file.seek(SeekFrom::Start(0)).unwrap();
                let mut actual_prefix = vec![0_u8; prefix.len()];
                file.read_exact(&mut actual_prefix).unwrap();
                assert_eq!(actual_prefix, prefix);
                file.seek(SeekFrom::Start(transform_end)).unwrap();
                let mut actual_tail = vec![0_u8; auth_tail.len()];
                file.read_exact(&mut actual_tail).unwrap();
                assert_eq!(actual_tail, auth_tail);
                drop(file);
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    #[test]
    fn natural_rows_match_small_batch_across_heights_and_widths() {
        for (height, width) in [(2, 1), (4, 4), (8, 3), (16, 12), (64, 5), (128, 4)] {
            let mut actual = input(height, width);
            let expected = Radix2DFTSmallBatch::new(height)
                .dft_batch(RowMajorMatrix::new(
                    actual.iter().copied().map(Goldilocks::new).collect(),
                    width,
                ))
                .values
                .into_iter()
                .map(|value| value.as_canonical_u64())
                .collect::<Vec<_>>();

            dft_goldilocks_natural_rows_in_place(&mut actual, height, width).unwrap();
            assert_eq!(actual, expected, "height={height}, width={width}");
        }
    }

    #[test]
    fn cancellable_natural_rows_match_the_existing_wrapper() {
        for (height, width) in [(2, 1), (64, 5), (512, 4), (1_024, 3)] {
            let mut expected = input(height, width);
            let mut actual = expected.clone();
            dft_goldilocks_natural_rows_in_place(&mut expected, height, width).unwrap();

            let mut polls = 0_usize;
            let cancelled = dft_goldilocks_natural_rows_in_place_cancellable(
                &mut actual,
                height,
                width,
                || {
                    polls += 1;
                    false
                },
            )
            .unwrap();

            let bit_reversal_polls = height.div_ceil(NATURAL_DFT_CANCEL_POLL_ROWS);
            let butterfly_rows = (height / 2) * height.ilog2() as usize;
            let butterfly_polls = butterfly_rows.div_ceil(NATURAL_DFT_CANCEL_POLL_ROWS);
            assert!(!cancelled);
            assert_eq!(actual, expected, "height={height}, width={width}");
            assert_eq!(
                polls,
                bit_reversal_polls + butterfly_polls + 1,
                "height={height}, width={width}"
            );
        }
    }

    #[test]
    fn cancellable_natural_rows_stop_during_butterflies() {
        const HEIGHT: usize = 1_024;
        const WIDTH: usize = 4;

        let original = input(HEIGHT, WIDTH);
        let mut completed = original.clone();
        dft_goldilocks_natural_rows_in_place(&mut completed, HEIGHT, WIDTH).unwrap();

        let bit_reversal_polls = HEIGHT.div_ceil(NATURAL_DFT_CANCEL_POLL_ROWS);
        let cancel_at = bit_reversal_polls + 3;
        let mut polls = 0_usize;
        let mut partial = original.clone();
        let cancelled =
            dft_goldilocks_natural_rows_in_place_cancellable(&mut partial, HEIGHT, WIDTH, || {
                polls += 1;
                polls == cancel_at
            })
            .unwrap();

        assert!(cancelled);
        assert_eq!(polls, cancel_at);
        assert_ne!(partial, original);
        assert_ne!(partial, completed);
    }

    #[test]
    fn cancellable_natural_rows_validate_before_polling_and_cancel_before_mutation() {
        let mut values = vec![1, GOLDILOCKS_MODULUS];
        let original = values.clone();
        let mut polls = 0_usize;
        assert!(matches!(
            dft_goldilocks_natural_rows_in_place_cancellable(&mut values, 2, 1, || {
                polls += 1;
                true
            }),
            Err(ExternalRadix2Error::Invalid(_))
        ));
        assert_eq!(polls, 0);
        assert_eq!(values, original);

        let mut values = input(8, 3);
        let original = values.clone();
        assert!(
            dft_goldilocks_natural_rows_in_place_cancellable(&mut values, 8, 3, || true).unwrap()
        );
        assert_eq!(values, original);
    }

    #[test]
    fn natural_rows_reject_invalid_inputs_without_mutation() {
        fn assert_rejected(mut values: Vec<u64>, height: usize, width: usize) {
            let original = values.clone();
            assert!(matches!(
                dft_goldilocks_natural_rows_in_place(&mut values, height, width),
                Err(ExternalRadix2Error::Invalid(_))
            ));
            assert_eq!(values, original);
        }

        assert_rejected(vec![1, 2], 2, 0);
        assert_rejected(vec![], 0, 1);
        assert_rejected(vec![1], 1, 1);
        assert_rejected(vec![1, 2, 3], 3, 1);
        assert_rejected(vec![1; 7], 4, 2);
        assert_rejected(vec![1; 9], 4, 2);
        assert_rejected(vec![1, GOLDILOCKS_MODULUS], 2, 1);
        assert_rejected(vec![1, 2], 2, usize::MAX);

        if let Some(over_two_adic_height) =
            1_usize.checked_shl((Goldilocks::TWO_ADICITY + 1) as u32)
        {
            assert_rejected(vec![], over_two_adic_height, 1);
        }
    }

    #[test]
    fn production_geometry_fuses_nine_stages_but_remains_io_heavy() {
        const PRODUCTION_HEIGHT: usize = 1 << 29;
        const EXTENSION_WIDTH: usize = 12;
        const PRODUCTION_BUFFER_VALUES: usize = EXTENSION_WIDTH * 512;

        let rows = fused_block_rows(
            PRODUCTION_HEIGHT,
            PRODUCTION_BUFFER_VALUES / EXTENSION_WIDTH,
        );
        assert_eq!(rows, 512);
        assert_eq!(rows.ilog2(), 9);
        // One fused pass plus twenty still-external stages. This is a bounded
        // reference engine, not a production-latency claim.
        assert_eq!(1 + PRODUCTION_HEIGHT.ilog2() - rows.ilog2(), 21);
    }

    #[test]
    fn rejects_noncanonical_staged_limbs() {
        const DATA_OFFSET: u64 = 160;
        let path = test_path("noncanonical");
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(DATA_OFFSET + 2 * 12 * 8).unwrap();
        file.seek(SeekFrom::Start(DATA_OFFSET)).unwrap();
        file.write_all(&GOLDILOCKS_MODULUS.to_le_bytes()).unwrap();
        assert!(matches!(
            dft_goldilocks_rows_in_place(&mut file, &path, DATA_OFFSET, 2, 12, 12),
            Err(ExternalRadix2Error::Invalid(_))
        ));
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn truncated_region_fails_before_any_bytes_change() {
        const DATA_OFFSET: u64 = 29;
        const HEIGHT: usize = 8;
        const WIDTH: usize = 4;
        let required_end = DATA_OFFSET + (HEIGHT * WIDTH * 8) as u64;
        let original = vec![0xa5_u8; required_end as usize - 1];
        let path = test_path("truncated");
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&original).unwrap();
        assert!(matches!(
            dft_goldilocks_rows_in_place(&mut file, &path, DATA_OFFSET, HEIGHT, WIDTH, WIDTH,),
            Err(ExternalRadix2Error::Invalid(_))
        ));
        assert_eq!(file_bytes(&mut file), original);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn overflowing_and_invalid_geometry_are_non_mutating() {
        let original = (0_u8..64).collect::<Vec<_>>();
        let path = test_path("geometry");
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&original).unwrap();
        for (data_offset, height, width, buffer_values) in
            [(u64::MAX - 7, 2, 1, 1), (0, 3, 1, 1), (0, 2, 0, 1)]
        {
            assert!(matches!(
                dft_goldilocks_rows_in_place(
                    &mut file,
                    &path,
                    data_offset,
                    height,
                    width,
                    buffer_values,
                ),
                Err(ExternalRadix2Error::Invalid(_))
            ));
            assert_eq!(file_bytes(&mut file), original);
        }
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
