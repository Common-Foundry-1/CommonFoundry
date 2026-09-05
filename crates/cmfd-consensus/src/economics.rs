use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const COIN: u64 = 100_000_000;
/// Flat minimum burn per non-coinbase transaction on RCNet-1, starting with RC5.
pub const MIN_TRANSACTION_FEE_ATOMS: u64 = COIN / 10;

/// Historical development networks retain their original transaction rules.
pub fn minimum_transaction_fee(network_id: [u8; 32]) -> u64 {
    if network_id == crate::PRODUCTION_V4_RCNET1_NETWORK_ID {
        MIN_TRANSACTION_FEE_ATOMS
    } else {
        0
    }
}
pub const BLOCKS_PER_365_DAY_YEAR: u64 = 365 * 24 * 60;
pub const INITIAL_EMISSION_YEARS: u64 = 5;
pub const INITIAL_EMISSION_BLOCKS: u64 = BLOCKS_PER_365_DAY_YEAR * INITIAL_EMISSION_YEARS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonetaryPolicy {
    pub initial_subsidy: u64,
    pub tail_height: u64,
    pub tail_subsidy: u64,
    pub steward_percent: u8,
    pub community_percent: u8,
}

pub const DEFAULT_MONETARY_POLICY: MonetaryPolicy = MonetaryPolicy {
    initial_subsidy: 500 * COIN,
    // Heights 1 through INITIAL_EMISSION_BLOCKS are the five-year declining
    // phase. The miner-only tail starts on the following block.
    tail_height: INITIAL_EMISSION_BLOCKS + 1,
    tail_subsidy: 5 * COIN,
    steward_percent: 25,
    community_percent: 5,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    pub subsidy: u64,
    pub miner: u64,
    pub steward: u64,
    pub community: u64,
    pub fees_burned: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinbaseClaim {
    pub miner: u64,
    pub steward: u64,
    pub community: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EconomicsError {
    #[error("coinbase miner output is {actual}, expected {expected}")]
    Miner { actual: u64, expected: u64 },
    #[error("coinbase steward output is {actual}, expected {expected}")]
    Steward { actual: u64, expected: u64 },
    #[error("coinbase community output is {actual}, expected {expected}")]
    Community { actual: u64, expected: u64 },
    #[error("monetary policy percentages exceed 100")]
    InvalidPercentages,
    #[error("monetary policy initial subsidy must be nonzero")]
    ZeroInitialSubsidy,
    #[error("monetary policy tail height must leave at least one declining-emission block")]
    InvalidEmissionWindow,
    #[error("monetary policy tail subsidy must be nonzero")]
    ZeroTailSubsidy,
    #[error("the declining emission reaches zero before the configured tail height")]
    EmissionReachesZeroEarly,
    #[error("the final pre-tail block would contain a zero-valued configured reward")]
    VanishingPreTailReward,
}

impl MonetaryPolicy {
    pub fn validate(self) -> Result<(), EconomicsError> {
        if self.initial_subsidy == 0 {
            return Err(EconomicsError::ZeroInitialSubsidy);
        }
        if self.tail_height <= 1 {
            return Err(EconomicsError::InvalidEmissionWindow);
        }
        if self.tail_subsidy == 0 {
            return Err(EconomicsError::ZeroTailSubsidy);
        }
        if u16::from(self.steward_percent) + u16::from(self.community_percent) > 100 {
            return Err(EconomicsError::InvalidPercentages);
        }
        let preceding_subsidy = self.declining_subsidy_unchecked(self.tail_height - 1);
        if preceding_subsidy == 0 {
            return Err(EconomicsError::EmissionReachesZeroEarly);
        }
        let steward =
            (u128::from(preceding_subsidy) * u128::from(self.steward_percent) / 100) as u64;
        let community =
            (u128::from(preceding_subsidy) * u128::from(self.community_percent) / 100) as u64;
        let miner = preceding_subsidy - steward - community;
        if miner == 0
            || (self.steward_percent != 0 && steward == 0)
            || (self.community_percent != 0 && community == 0)
        {
            return Err(EconomicsError::VanishingPreTailReward);
        }
        Ok(())
    }

    pub fn subsidy(self, height: u64) -> Result<u64, EconomicsError> {
        self.validate()?;
        Ok(self.subsidy_unchecked(height))
    }

    fn subsidy_unchecked(self, height: u64) -> u64 {
        if height >= self.tail_height {
            return self.tail_subsidy;
        }
        self.declining_subsidy_unchecked(height)
    }

    fn declining_subsidy_unchecked(self, height: u64) -> u64 {
        let emission_blocks = self.tail_height - 1;
        // Height zero is the virtual genesis and has no coinbase. Treat it as
        // the launch value so real block one also starts at the exact configured
        // subsidy, then decrease linearly through the final pre-tail block.
        let elapsed = height.saturating_sub(1).min(emission_blocks);
        let remaining = emission_blocks - elapsed;
        (u128::from(self.initial_subsidy) * u128::from(remaining) / u128::from(emission_blocks))
            as u64
    }

    pub fn allocation(self, height: u64, fees: u64) -> Result<Allocation, EconomicsError> {
        self.validate()?;
        let subsidy = self.subsidy_unchecked(height);

        if height >= self.tail_height {
            return Ok(Allocation {
                subsidy,
                miner: subsidy,
                steward: 0,
                community: 0,
                fees_burned: fees,
            });
        }

        let steward = (u128::from(subsidy) * u128::from(self.steward_percent) / 100) as u64;
        let community = (u128::from(subsidy) * u128::from(self.community_percent) / 100) as u64;
        let miner = subsidy - steward - community;
        Ok(Allocation {
            subsidy,
            miner,
            steward,
            community,
            fees_burned: fees,
        })
    }

    pub fn validate_coinbase(
        self,
        height: u64,
        fees: u64,
        claim: CoinbaseClaim,
    ) -> Result<Allocation, EconomicsError> {
        let expected = self.allocation(height, fees)?;
        if claim.miner != expected.miner {
            return Err(EconomicsError::Miner {
                actual: claim.miner,
                expected: expected.miner,
            });
        }
        if claim.steward != expected.steward {
            return Err(EconomicsError::Steward {
                actual: claim.steward,
                expected: expected.steward,
            });
        }
        if claim.community != expected.community {
            return Err(EconomicsError::Community {
                actual: claim.community,
                expected: expected.community,
            });
        }
        Ok(expected)
    }

    pub fn scheduled_supply_before_tail(self) -> Result<u128, EconomicsError> {
        self.validate()?;
        let emission_blocks = self.tail_height - 1;
        // Sum floor(initial_subsidy * k / emission_blocks) for k=1..=N
        // without iterating over a potentially large consensus interval.
        Ok(linear_supply(self.initial_subsidy, emission_blocks))
    }
}

fn linear_supply(initial_subsidy: u64, emission_blocks: u64) -> u128 {
    let subsidy = u128::from(initial_subsidy);
    let blocks = u128::from(emission_blocks);
    (subsidy * blocks + subsidy - blocks
        + u128::from(greatest_common_divisor(initial_subsidy, emission_blocks)))
        / 2
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_schedule_and_tail_are_exact() {
        let p = DEFAULT_MONETARY_POLICY;
        assert_eq!(INITIAL_EMISSION_BLOCKS, 2_628_000);
        assert_eq!(p.tail_height, 2_628_001);
        assert_eq!(p.subsidy(0).unwrap(), 500 * COIN);
        assert_eq!(p.subsidy(1).unwrap(), 500 * COIN);
        assert_eq!(p.subsidy(2).unwrap(), 49_999_980_974);
        assert_eq!(
            p.subsidy(INITIAL_EMISSION_BLOCKS / 2).unwrap(),
            25_000_019_025
        );
        assert_eq!(p.subsidy(p.tail_height - 1).unwrap(), 19_025);
        assert_eq!(p.subsidy(p.tail_height).unwrap(), 5 * COIN);
        assert_eq!(p.subsidy(u64::MAX).unwrap(), 5 * COIN);
        assert_eq!(
            p.scheduled_supply_before_tail().unwrap(),
            65_700_024_998_688_000
        );
    }

    #[test]
    fn default_decline_is_strictly_monotonic_until_tail() {
        let p = DEFAULT_MONETARY_POLICY;
        let mut previous = p.subsidy(1).unwrap();
        for height in 2..p.tail_height {
            let current = p.subsidy(height).unwrap();
            assert!(current > 0);
            assert!(current < previous);
            previous = current;
        }
    }

    #[test]
    fn zero_subsidies_are_rejected() {
        let zero_initial = MonetaryPolicy {
            initial_subsidy: 0,
            ..DEFAULT_MONETARY_POLICY
        };
        assert_eq!(
            zero_initial.validate(),
            Err(EconomicsError::ZeroInitialSubsidy)
        );

        let zero_tail = MonetaryPolicy {
            tail_subsidy: 0,
            ..DEFAULT_MONETARY_POLICY
        };
        assert_eq!(zero_tail.validate(), Err(EconomicsError::ZeroTailSubsidy));
    }

    #[test]
    fn emission_window_must_contain_a_real_block() {
        for tail_height in [0, 1] {
            let policy = MonetaryPolicy {
                tail_height,
                ..DEFAULT_MONETARY_POLICY
            };
            assert_eq!(
                policy.validate(),
                Err(EconomicsError::InvalidEmissionWindow)
            );
            assert_eq!(
                policy.scheduled_supply_before_tail(),
                Err(EconomicsError::InvalidEmissionWindow)
            );
        }
    }

    #[test]
    fn decline_must_not_round_to_zero_early() {
        let policy = MonetaryPolicy {
            initial_subsidy: 100,
            tail_height: 102,
            tail_subsidy: 1,
            steward_percent: 0,
            community_percent: 0,
        };
        assert_eq!(
            policy.validate(),
            Err(EconomicsError::EmissionReachesZeroEarly)
        );
    }

    #[test]
    fn tail_starts_when_the_linear_component_reaches_zero() {
        let policy = MonetaryPolicy {
            initial_subsidy: 100,
            tail_height: 11,
            tail_subsidy: 51,
            steward_percent: 0,
            community_percent: 0,
        };
        policy.validate().unwrap();
        assert_eq!(policy.subsidy(1).unwrap(), 100);
        assert_eq!(policy.subsidy(10).unwrap(), 10);
        assert_eq!(policy.subsidy(11).unwrap(), 51);
    }

    #[test]
    fn configured_pre_tail_rewards_cannot_round_to_zero() {
        let policy = MonetaryPolicy {
            initial_subsidy: 100,
            tail_height: 11,
            tail_subsidy: 1,
            steward_percent: 1,
            community_percent: 1,
        };
        assert_eq!(
            policy.validate(),
            Err(EconomicsError::VanishingPreTailReward)
        );
    }

    #[test]
    fn exact_supply_formula_matches_brute_force() {
        for initial_subsidy in 1_u64..=32 {
            for emission_blocks in 1_u64..=initial_subsidy {
                let expected: u128 = (1..=emission_blocks)
                    .map(|remaining| {
                        u128::from(initial_subsidy) * u128::from(remaining)
                            / u128::from(emission_blocks)
                    })
                    .sum();
                assert_eq!(linear_supply(initial_subsidy, emission_blocks), expected);
            }
        }

        let large = MonetaryPolicy {
            initial_subsidy: u64::MAX,
            tail_height: u64::MAX,
            tail_subsidy: 1,
            steward_percent: 0,
            community_percent: 0,
        };
        large.validate().unwrap();
        assert!(large.scheduled_supply_before_tail().unwrap() > u128::from(u64::MAX));
    }

    #[test]
    fn zero_tail_height_is_not_silently_treated_as_tail() {
        let zero_tail = MonetaryPolicy {
            tail_height: 0,
            ..DEFAULT_MONETARY_POLICY
        };
        assert_eq!(
            zero_tail.subsidy(0),
            Err(EconomicsError::InvalidEmissionWindow)
        );
        assert_eq!(
            zero_tail.allocation(0, 0),
            Err(EconomicsError::InvalidEmissionWindow)
        );
    }

    #[test]
    fn fees_are_burned_and_never_enter_coinbase() {
        let p = DEFAULT_MONETARY_POLICY;
        let fees = 12 * COIN;
        let allocation = p.allocation(0, fees).unwrap();
        assert_eq!(allocation.miner, 350 * COIN);
        assert_eq!(allocation.steward, 125 * COIN);
        assert_eq!(allocation.community, 25 * COIN);
        assert_eq!(allocation.fees_burned, fees);

        let bad = CoinbaseClaim {
            miner: allocation.miner + fees,
            steward: allocation.steward,
            community: allocation.community,
        };
        assert_eq!(
            p.validate_coinbase(0, fees, bad),
            Err(EconomicsError::Miner {
                actual: 362 * COIN,
                expected: 350 * COIN,
            })
        );
    }

    #[test]
    fn tail_is_miner_only() {
        let p = DEFAULT_MONETARY_POLICY;
        let a = p.allocation(p.tail_height, COIN).unwrap();
        assert_eq!(a.miner, 5 * COIN);
        assert_eq!(a.steward, 0);
        assert_eq!(a.community, 0);
        assert_eq!(a.fees_burned, COIN);
    }
}
