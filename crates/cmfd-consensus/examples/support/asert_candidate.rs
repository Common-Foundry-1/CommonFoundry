//! Offline-only ASERT arithmetic candidate. Not selected by any network.
//!
//! Numerical formulation and polynomial constants: Bitcoin Cash Node pow.cpp,
//! https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/pow.cpp
//! Copyright (c) 2017-2020 The Bitcoin developers, MIT license.
//! This full-width implementation does not adopt BCH's compact target encoding,
//! activation policy, half-life, or timestamp policy for Common Foundry.

use primitive_types::{U256, U512};

pub fn target(
    reference: [u8; 32],
    schedule_error_seconds: i128,
    half_life_seconds: u32,
    limit: [u8; 32],
) -> Result<[u8; 32], &'static str> {
    let reference = U256::from_big_endian(&reference);
    let limit = U256::from_big_endian(&limit);
    if reference.is_zero() || limit.is_zero() || reference > limit || half_life_seconds == 0 {
        return Err("invalid ASERT reference, limit, or half-life");
    }
    let half_life = i128::from(half_life_seconds);
    // These comparisons happen before multiplication, including for i128::MIN.
    if schedule_error_seconds >= half_life * 512 {
        return Ok(limit.to_big_endian());
    }
    if schedule_error_seconds <= -half_life * 512 {
        return Ok(U256::one().to_big_endian());
    }
    // Match reference C++ truncation toward zero here, then floor the signed
    // integer/fraction decomposition using an arithmetic right shift.
    let exponent = (schedule_error_seconds * 65_536) / half_life;
    let integral = exponent >> 16;
    let fraction = (exponent - integral * 65_536) as u128;
    let polynomial = 195_766_423_245_049u128 * fraction
        + 971_821_376u128 * fraction * fraction
        + 5_127u128 * fraction * fraction * fraction
        + (1u128 << 47);
    let multiplier = 65_536u128 + (polynomial >> 48);
    let product = U512::from(reference) * U512::from(multiplier);
    let shift = integral - 16;
    let adjusted = if shift > 0 {
        let shift = usize::try_from(shift).map_err(|_| "ASERT shift overflow")?;
        if product.bits() + shift > 256 {
            return Ok(limit.to_big_endian());
        }
        product << shift
    } else {
        let shift = usize::try_from(-shift).map_err(|_| "ASERT shift overflow")?;
        if shift >= 512 {
            U512::zero()
        } else {
            product >> shift
        }
    };
    let bounded = adjusted.max(U512::one()).min(U512::from(limit));
    Ok(U256::try_from(bounded)
        .map_err(|_| "ASERT target overflow")?
        .to_big_endian())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_half_lives_are_exact() {
        let limit = ((U256::one() << 246) - U256::one()).to_big_endian();
        let initial = (U256::from_big_endian(&limit) >> 4).to_big_endian();
        assert_eq!(target(initial, 0, 1800, limit).unwrap(), initial);
        assert_eq!(
            U256::from_big_endian(&target(initial, 1800, 1800, limit).unwrap()),
            U256::from_big_endian(&initial) * 2
        );
        assert_eq!(
            U256::from_big_endian(&target(initial, -1800, 1800, limit).unwrap()),
            U256::from_big_endian(&initial) / 2
        );
    }

    #[test]
    fn invalid_inputs_and_full_width_extremes_are_bounded() {
        assert!(target([0; 32], 0, 1, [0xff; 32]).is_err());
        assert!(target([0xff; 32], 0, 1, [0x7f; 32]).is_err());
        assert!(target([1; 32], 0, 0, [0xff; 32]).is_err());
        assert_eq!(
            target([0xff; 32], i128::MAX, 1, [0xff; 32]).unwrap(),
            [0xff; 32]
        );
        assert_eq!(
            target([0xff; 32], i128::MIN, 1, [0xff; 32]).unwrap(),
            U256::one().to_big_endian()
        );
        assert_eq!(target([0xff; 32], 1, 1, [0xff; 32]).unwrap(), [0xff; 32]);
    }

    #[test]
    fn signed_fraction_boundary_is_monotonic() {
        let initial = (U256::one() << 240).to_big_endian();
        let limit = ((U256::one() << 246) - U256::one()).to_big_endian();
        let mut previous = target(initial, -3601, 1800, limit).unwrap();
        for error in -3600..=3601 {
            let next = target(initial, error, 1800, limit).unwrap();
            assert!(next >= previous, "non-monotonic at {error}");
            previous = next;
        }
    }
}
