//! Statistical pre-screen using the actual consensus retarget function.
//! This does NOT mine, construct proofs, admit blocks, or approve a release.
//! The selected targets can be represented by the separately bound initial
//! target. Alternative retarget policies below are NOT active consensus rules.

#[path = "support/asert_candidate.rs"]
mod asert_candidate;

use clap::{Parser, ValueEnum};
use cmfd_consensus::{HeaderWork, MEDIAN_TIME_WINDOW, next_work_target};
use primitive_types::U256;
use serde::Serialize;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=1024))]
    trials: u32,
    /// JSON is created exclusively; existing evidence is never overwritten.
    #[arg(long)]
    output: std::path::PathBuf,
    /// Model restoring the preceding GPU count after each downward step.
    /// This does not start real GPUs. Omit for unassisted recovery scenarios.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=86400))]
    backup_after_seconds: Option<u32>,
    #[arg(long, value_enum, default_value_t = Retarget::Dgw180)]
    retarget: Retarget,
    /// Offline ASERT candidate parameter, not an approved network setting.
    #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u32).range(60..=86400))]
    half_life_seconds: u32,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum Retarget {
    Dgw180,
    AsertRaw,
    AsertMedian,
}

#[derive(Clone, Copy)]
struct Model {
    rate: f64,
    latency: f64,
    retarget: Retarget,
    half_life: u32,
}

#[derive(Serialize)]
struct Distribution {
    median: f64,
    p95: f64,
    maximum: f64,
}

fn distribution(mut values: Vec<f64>) -> Distribution {
    values.sort_by(f64::total_cmp);
    let percentile = |fraction: f64| {
        values[((values.len() as f64 * fraction).ceil() as usize).saturating_sub(1)]
    };
    Distribution {
        median: percentile(0.5),
        p95: percentile(0.95),
        maximum: *values.last().unwrap(),
    }
}

struct Random(u64);

impl Random {
    fn exponential(&mut self) -> f64 {
        // SplitMix64, deterministic non-cryptographic simulation randomness.
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let uniform = ((z >> 11) as f64 + 1.0) / ((1u64 << 53) as f64 + 2.0);
        -uniform.ln()
    }
}

fn target_for_rc_multiple(multiple: u64) -> [u8; 32] {
    // RC target + 1 = 2^246; integer rounding is toward harder work.
    (((U256::one() << 246) / U256::from(multiple)) - U256::one()).to_big_endian()
}

fn expected_attempts(target: [u8; 32]) -> f64 {
    let value = target
        .iter()
        .fold(0.0, |sum, byte| sum * 256.0 + f64::from(*byte));
    2.0_f64.powi(256) / (value + 1.0)
}

fn median_time(raw: &[u64]) -> u64 {
    let mut window = raw[raw.len().saturating_sub(MEDIAN_TIME_WINDOW)..].to_vec();
    window.sort_unstable();
    window[window.len() / 2]
}

#[derive(Serialize)]
struct Phase {
    gpus: u32,
    blocks: usize,
    first_block_seconds: Distribution,
    first_10_blocks_minutes: Distribution,
    first_180_blocks_minutes: Distribution,
    last_180_mean_seconds: Distribution,
    longest_interval_seconds: Distribution,
    /// First complete 60-interval window averaging <=90 s after a downshift.
    /// This is descriptive, not an acceptance threshold or permanent settling.
    first_60_interval_mean_at_most_90_seconds_minutes: Option<Distribution>,
    trials_reaching_that_window: usize,
}

#[derive(Default)]
struct Samples {
    first: Vec<f64>,
    ten: Vec<f64>,
    first_window: Vec<f64>,
    last_mean: Vec<f64>,
    maximum: Vec<f64>,
    recovery: Vec<f64>,
}

impl Samples {
    fn collect(&mut self, intervals: &[f64]) {
        self.first.push(intervals[0]);
        self.ten.push(intervals[..10].iter().sum::<f64>() / 60.0);
        self.first_window
            .push(intervals[..180].iter().sum::<f64>() / 60.0);
        self.last_mean
            .push(intervals[intervals.len() - 180..].iter().sum::<f64>() / 180.0);
        self.maximum
            .push(intervals.iter().copied().fold(0.0, f64::max));
        if let Some(index) = intervals
            .windows(60)
            .position(|w| w.iter().sum::<f64>() <= 90.0 * 60.0)
        {
            self.recovery
                .push(intervals[..index + 60].iter().sum::<f64>() / 60.0);
        }
    }

    fn finish(self, gpus: u32, blocks: usize) -> Phase {
        let reached = self.recovery.len();
        Phase {
            gpus,
            blocks,
            first_block_seconds: distribution(self.first),
            first_10_blocks_minutes: distribution(self.ten),
            first_180_blocks_minutes: distribution(self.first_window),
            last_180_mean_seconds: distribution(self.last_mean),
            longest_interval_seconds: distribution(self.maximum),
            first_60_interval_mean_at_most_90_seconds_minutes: if reached == 0 {
                None
            } else {
                Some(distribution(self.recovery))
            },
            trials_reaching_that_window: reached,
        }
    }
}

#[derive(Serialize)]
struct Scenario {
    initial_rc_multiple: u64,
    minimum_rc_multiple: u64,
    assumed_per_gpu_fw_per_second: f64,
    assumed_serial_proof_verify_propagation_seconds: f64,
    backup_after_seconds: Option<u32>,
    retarget: Retarget,
    candidate_half_life_seconds: Option<u32>,
    phases: Vec<Phase>,
}

fn search_seconds(work: f64, low_rate: f64, high_rate: f64, until_backup: Option<f64>) -> f64 {
    match until_backup {
        Some(delay) if work > low_rate * delay.max(0.0) => {
            delay.max(0.0) + (work - low_rate * delay.max(0.0)) / high_rate
        }
        _ => work / low_rate,
    }
}

fn simulate(
    trials: u32,
    initial: u64,
    minimum: u64,
    model: Model,
    schedule: &[(u32, usize)],
    backup_after_seconds: Option<u32>,
) -> Scenario {
    let mut samples: Vec<Samples> = schedule.iter().map(|_| Samples::default()).collect();
    for trial in 0..trials {
        let mut rng = Random(0x434d46445f444157 ^ u64::from(trial));
        let mut now: f64 = 0.0;
        let mut raw = vec![0];
        let mut history = vec![HeaderWork {
            timestamp: 0,
            target: target_for_rc_multiple(initial),
        }];
        let mut previous_gpus = schedule[0].0;
        for ((gpus, blocks), sample) in schedule.iter().zip(&mut samples) {
            let backup_time = backup_after_seconds
                .filter(|_| previous_gpus > *gpus)
                .map(|seconds| now + f64::from(seconds));
            let mut intervals = Vec::with_capacity(*blocks);
            for _ in 0..*blocks {
                let target = match model.retarget {
                    Retarget::Dgw180 => {
                        next_work_target(&history, target_for_rc_multiple(minimum)).unwrap()
                    }
                    Retarget::AsertRaw | Retarget::AsertMedian => {
                        let observed = match model.retarget {
                            Retarget::AsertRaw => *raw.last().unwrap(),
                            _ => history.last().unwrap().timestamp,
                        };
                        // New-chain anchor: chosen block-1 target at genesis,
                        // then elapsed time versus produced blocks * 60 seconds.
                        let drift = i128::from(observed)
                            - i128::from(raw[0])
                            - (raw.len() as i128 - 1) * 60;
                        asert_candidate::target(
                            target_for_rc_multiple(initial),
                            drift,
                            model.half_life,
                            target_for_rc_multiple(minimum),
                        )
                        .unwrap()
                    }
                };
                // A job uses its issuance timestamp, not a fabricated solve time.
                let timestamp = (now.floor() as u64).max(median_time(&raw) + 1);
                let interval = search_seconds(
                    expected_attempts(target) * rng.exponential(),
                    model.rate * f64::from(*gpus),
                    model.rate * f64::from(previous_gpus),
                    backup_time.map(|deadline| deadline - now),
                ) + model.latency;
                now += interval;
                raw.push(timestamp);
                history.push(HeaderWork {
                    timestamp: median_time(&raw),
                    target,
                });
                intervals.push(interval);
            }
            sample.collect(&intervals);
            if !backup_time.is_some_and(|deadline| now >= deadline) {
                previous_gpus = *gpus;
            }
        }
    }
    Scenario {
        initial_rc_multiple: initial,
        minimum_rc_multiple: minimum,
        assumed_per_gpu_fw_per_second: model.rate,
        assumed_serial_proof_verify_propagation_seconds: model.latency,
        backup_after_seconds,
        retarget: model.retarget,
        candidate_half_life_seconds: match model.retarget {
            Retarget::Dgw180 => None,
            _ => Some(model.half_life),
        },
        phases: schedule
            .iter()
            .zip(samples)
            .map(|((gpus, blocks), s)| s.finish(*gpus, *blocks))
            .collect(),
    }
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    full_block_production_verified: bool,
    final_setting_approved: bool,
    trials_per_scenario: u32,
    assumptions: Vec<&'static str>,
    scenarios: Vec<Scenario>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let args = Args::parse();
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    let mut scenarios = Vec::new();
    for rate in [20.0, 25.0, 35.0] {
        for latency in [8.0, 16.0] {
            for (initial, minimum) in [(5, 1), (5, 5), (1, 1)] {
                for schedule in [
                    vec![(5, 540), (20, 540), (5, 540)],
                    vec![(20, 540), (1, 540), (5, 540)],
                ] {
                    scenarios.push(simulate(
                        args.trials,
                        initial,
                        minimum,
                        Model {
                            rate,
                            latency,
                            retarget: args.retarget,
                            half_life: args.half_life_seconds,
                        },
                        &schedule,
                        args.backup_after_seconds,
                    ));
                }
            }
        }
    }
    let report = Report {
        schema: "CommonFoundry/DifficultyRehearsal/StatisticalPrescreen/v2",
        full_block_production_verified: false,
        final_setting_approved: false,
        trials_per_scenario: args.trials,
        assumptions: vec![
            "DGW uses the current integer consensus next_work_target; ASERT options use offline-only candidate arithmetic, never activated by this harness.",
            "Initial/minimum targets are represented explicitly; no live network configuration is changed.",
            "Historical-rate scenarios assume independent Poisson search and additive GPU rates, not measured rig scaling.",
            "Fixed serial latency includes modeled proving/verification/propagation; it is not a measured end-to-end benchmark.",
            "No competing templates, stale blocks, peer traffic, payouts, adversarial timestamps, or real cryptographic proofs are modeled.",
            "Phases change after 540 modeled blocks, not fixed wall time; heavy-tailed delays and recovery are reported, not certified.",
            "Optional backup restores the preceding phase's GPU count after a configured wall-clock delay, including during a search; no real fleet activation is performed.",
            "ASERT raw and median options use a genesis-anchored schedule; half-life, timestamp attacks, floor wind-up and release integration still require separate evaluation.",
        ],
        scenarios,
    };
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!(
        "Statistical pre-screen saved to {}; full-block approval remains false",
        args.output.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_math_and_proposed_first_target_are_exact() {
        assert_eq!(expected_attempts(target_for_rc_multiple(1)), 1024.0);
        assert!((expected_attempts(target_for_rc_multiple(5)) - 5120.0).abs() < 1e-9);
        let initial = target_for_rc_multiple(5);
        let history = [HeaderWork {
            timestamp: 0,
            target: initial,
        }];
        assert_eq!(
            next_work_target(&history, target_for_rc_multiple(1)).unwrap(),
            initial
        );
    }

    #[test]
    fn median_semantics_include_genesis_and_even_window_upper_middle() {
        assert_eq!(median_time(&[0, 1]), 1);
        assert_eq!(median_time(&[0, 1, 2]), 1);
        assert_eq!(median_time(&(0..20).collect::<Vec<_>>()), 14);
    }

    #[test]
    fn rng_is_reproducible_and_positive() {
        let mut a = Random(123);
        let mut b = Random(123);
        for _ in 0..1000 {
            let value = a.exponential();
            assert!(value.is_finite() && value > 0.0);
            assert_eq!(value, b.exponential());
        }
    }

    #[test]
    fn simulation_is_repeatable_and_does_not_claim_proof_verification() {
        let model = Model {
            rate: 25.0,
            latency: 8.0,
            retarget: Retarget::Dgw180,
            half_life: 1800,
        };
        let a = simulate(2, 5, 1, model, &[(5, 180)], None);
        let b = simulate(2, 5, 1, model, &[(5, 180)], None);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        assert_eq!(a.phases[0].blocks, 180);
    }

    #[test]
    fn backup_can_arrive_mid_search_without_resetting_or_discarding_work() {
        assert_eq!(search_seconds(1000.0, 10.0, 100.0, None), 100.0);
        assert_eq!(search_seconds(1000.0, 10.0, 100.0, Some(20.0)), 28.0);
        assert_eq!(search_seconds(100.0, 10.0, 100.0, Some(20.0)), 10.0);
        assert_eq!(search_seconds(1000.0, 10.0, 100.0, Some(-20.0)), 10.0);
    }

    #[test]
    fn candidate_choices_are_explicit_and_do_not_replace_current_retarget() {
        for retarget in [Retarget::Dgw180, Retarget::AsertRaw, Retarget::AsertMedian] {
            let model = Model {
                rate: 25.0,
                latency: 8.0,
                retarget,
                half_life: 1800,
            };
            let result = simulate(2, 5, 1, model, &[(5, 180)], None);
            assert!(result.phases[0].first_block_seconds.maximum.is_finite());
            match retarget {
                Retarget::Dgw180 => assert_eq!(result.candidate_half_life_seconds, None),
                _ => assert_eq!(result.candidate_half_life_seconds, Some(1800)),
            }
        }
    }
}
