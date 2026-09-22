//! Offline comparison against published BCH ASERT vectors. Not an activation.

#[path = "support/asert_candidate.rs"]
mod asert_candidate;

use clap::Parser;
use primitive_types::U256;
use std::io::Read;

#[derive(Parser)]
struct Args {
    /// Directory containing the official run01 through run12 numeric files.
    #[arg(long)]
    vectors: std::path::PathBuf,
}

fn decode_compact(bits: u32) -> Result<U256, &'static str> {
    let size = bits >> 24;
    let word = bits & 0x007f_ffff;
    if word == 0
        || bits & 0x0080_0000 != 0
        || size > 34
        || (size > 3 && (32 - word.leading_zeros()) + 8 * (size - 3) > 256)
    {
        return Err("invalid compact reference target");
    }
    Ok(if size <= 3 {
        U256::from(word >> (8 * (3 - size)))
    } else {
        U256::from(word) << (8 * (size - 3))
    })
}

fn encode_compact(value: U256) -> u32 {
    let mut size = value.bits().div_ceil(8) as u32;
    let mut word = if size <= 3 {
        value.low_u32() << (8 * (3 - size))
    } else {
        (value >> (8 * (size - 3))).low_u32()
    };
    if word & 0x0080_0000 != 0 {
        word >>= 8;
        size += 1;
    }
    word | (size << 24)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let limit = decode_compact(0x1d00ffff)?.to_big_endian();
    let mut cases = 0u64;
    for run in 1..=12 {
        let file = args.vectors.join(format!("run{run:02}"));
        let mut bytes = Vec::new();
        std::fs::File::open(&file)?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("vector file oversized".into());
        }
        let contents = std::str::from_utf8(&bytes)?;
        let mut height = None;
        let mut parent_time = None;
        let mut bits = None;
        let mut run_cases = 0u64;
        for line in contents.lines() {
            let line = line.trim();
            if let Some((label, value)) = line.split_once(':') {
                let label = label.trim().trim_start_matches('#').trim();
                match label {
                    "anchor height" => height = Some(i128::from(value.trim().parse::<u64>()?)),
                    "anchor ancestor time" | "anchor parent time" => {
                        parent_time = Some(i128::from(value.trim().parse::<i64>()?))
                    }
                    "anchor nBits" => {
                        bits = Some(u32::from_str_radix(
                            value.trim().trim_start_matches("0x"),
                            16,
                        )?)
                    }
                    _ => (),
                }
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() != 4 {
                return Err("unexpected vector row".into());
            }
            let current_height = i128::from(columns[1].parse::<u64>()?);
            let current_time = i128::from(columns[2].parse::<i64>()?);
            if current_height < height.ok_or("missing anchor height")? {
                return Err("reference height precedes anchor".into());
            }
            let expected = u32::from_str_radix(columns[3].trim_start_matches("0x"), 16)?;
            let drift = current_time
                - parent_time.ok_or("missing anchor time")?
                - 600 * (current_height - height.ok_or("missing anchor height")? + 1);
            let actual = asert_candidate::target(
                decode_compact(bits.ok_or("missing anchor target")?)?.to_big_endian(),
                drift,
                172_800,
                limit,
            )?;
            if encode_compact(U256::from_big_endian(&actual)) != expected {
                return Err(format!("run {run} row {}: mismatch", columns[0]).into());
            }
            run_cases += 1;
        }
        if run_cases == 0 {
            return Err("empty reference vector set".into());
        }
        println!("run{run:02}: {run_cases} arithmetic vectors matched");
        cases += run_cases;
    }
    println!(
        "{}",
        serde_json::json!({"schema":"CommonFoundry/AsertArithmeticReferenceCheck/v1","sets":12,"matched_cases":cases,"network_activation":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_encoding_known_round_trips() {
        for bits in [0x01010000, 0x1d00ffff, 0x1802aee8, 0x1c7fffff] {
            assert_eq!(encode_compact(decode_compact(bits).unwrap()), bits);
        }
    }
}
