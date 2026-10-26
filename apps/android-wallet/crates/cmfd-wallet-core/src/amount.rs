use crate::network::ATOMS_PER_CMFD;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AmountError {
    #[error("amount is empty")]
    Empty,
    #[error("amount must be a non-negative decimal number")]
    Invalid,
    #[error("amount has more than eight decimal places")]
    TooPrecise,
    #[error("amount exceeds the protocol u64 range")]
    Overflow,
}

/// Parses a CMFD display amount without floating-point arithmetic.
pub fn parse_cmfd(text: &str) -> Result<u64, AmountError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(AmountError::Empty);
    }
    if text.starts_with('-') || text.starts_with('+') || text.matches('.').count() > 1 {
        return Err(AmountError::Invalid);
    }
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AmountError::Invalid);
    }
    if fraction.len() > 8 {
        return Err(AmountError::TooPrecise);
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AmountError::Invalid);
    }
    let whole = whole.parse::<u64>().map_err(|_| AmountError::Overflow)?;
    let whole_atoms = whole
        .checked_mul(ATOMS_PER_CMFD)
        .ok_or(AmountError::Overflow)?;
    let mut fractional = fraction.to_owned();
    fractional.extend(std::iter::repeat_n('0', 8 - fractional.len()));
    let fractional_atoms = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<u64>()
            .map_err(|_| AmountError::Invalid)?
    };
    whole_atoms
        .checked_add(fractional_atoms)
        .ok_or(AmountError::Overflow)
}

pub fn format_atoms(atoms: u64) -> String {
    let whole = atoms / ATOMS_PER_CMFD;
    let fraction = atoms % ATOMS_PER_CMFD;
    format!("{whole}.{fraction:08}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_only_integer_atoms() {
        for (text, atoms) in [
            ("0", 0),
            ("0.00000001", 1),
            ("0.1", 10_000_000),
            ("12.34567890", 1_234_567_890),
        ] {
            assert_eq!(parse_cmfd(text), Ok(atoms));
            assert_eq!(parse_cmfd(&format_atoms(atoms)), Ok(atoms));
        }
        assert_eq!(parse_cmfd("1.000000001"), Err(AmountError::TooPrecise));
        assert_eq!(parse_cmfd("-1"), Err(AmountError::Invalid));
        assert_eq!(parse_cmfd("1e2"), Err(AmountError::Invalid));
    }
}
