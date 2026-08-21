use blake3::Hasher;

const PINNED_PREPROCESSED_REGISTRY_DOMAIN: &str = "CMFD/FORGEMATRIX/BLAKE3-PREPROCESSED-KEYS/V1";

pub const STRUCTURED_BLAKE3_VERSION: u32 = 4;
pub(crate) const STRUCTURED_BLAKE3_PROOF_MAGIC: &[u8; 8] = b"CMFDB3S4";
pub(crate) const NARROW_BLAKE3_PROOF_VERSION: u32 = 4;
pub(crate) const NARROW_BLAKE3_PROOF_MAGIC: &[u8; 8] = b"CMFDB3N4";
pub(crate) const PINNED_PREPROCESSED_REGISTRY_VERSION: u32 = 1;
pub(crate) const PINNED_PREPROCESSED_WIDTH: usize = 84;
pub(crate) const PINNED_PREPROCESSED_LOG_BLOWUP: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinnedPreprocessedKey {
    pub(crate) activation_len: usize,
    pub(crate) trace_rows: usize,
    pub(crate) root: [u64; 4],
}

pub(crate) const PINNED_PREPROCESSED_KEYS: [PinnedPreprocessedKey; 15] = [
    PinnedPreprocessedKey {
        activation_len: 1 << 5,
        trace_rows: 1 << 8,
        root: [
            17_803_216_872_856_136_108,
            13_629_457_461_237_106_599,
            254_224_475_892_070_081,
            9_422_095_840_849_876_732,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 6,
        trace_rows: 1 << 8,
        root: [
            18_017_135_276_257_273_429,
            14_601_280_340_656_292_183,
            3_756_879_995_978_476_420,
            10_661_213_073_934_328_546,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 7,
        trace_rows: 1 << 9,
        root: [
            5_045_238_721_739_697_215,
            11_524_693_166_473_071_324,
            15_330_344_690_106_625_494,
            15_810_080_622_461_686_692,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 8,
        trace_rows: 1 << 10,
        root: [
            12_827_577_792_750_841_882,
            9_232_580_139_066_585_264,
            14_692_723_552_075_372_443,
            2_050_032_024_803_390_887,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 9,
        trace_rows: 1 << 11,
        root: [
            6_803_057_463_467_252_389,
            3_916_014_319_910_044_355,
            5_113_280_541_612_318_078,
            7_766_693_309_674_731_258,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 10,
        trace_rows: 1 << 12,
        root: [
            17_267_681_632_248_361_573,
            2_543_732_917_123_174_804,
            432_981_079_889_719_886,
            8_584_702_860_840_278_635,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 11,
        trace_rows: 1 << 13,
        root: [
            14_343_792_561_658_396_943,
            5_224_614_365_248_183_612,
            7_354_571_599_300_035_652,
            16_141_147_831_556_347_447,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 12,
        trace_rows: 1 << 14,
        root: [
            12_140_553_806_911_057_691,
            17_939_374_227_175_176_958,
            13_196_371_364_083_120_087,
            6_427_928_215_882_691_598,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 13,
        trace_rows: 1 << 15,
        root: [
            4_050_366_509_581_011_090,
            10_025_101_551_445_962_956,
            7_661_460_851_282_630_783,
            14_453_734_219_739_434_606,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 14,
        trace_rows: 1 << 15,
        root: [
            3_676_373_462_919_335_727,
            17_049_786_132_244_900_873,
            5_098_792_490_007_487_691,
            1_446_160_892_273_805_470,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 15,
        trace_rows: 1 << 16,
        root: [
            11_959_309_644_684_284_508,
            7_321_730_091_555_308_417,
            681_555_874_540_424_413,
            14_019_781_937_774_964_390,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 16,
        trace_rows: 1 << 17,
        root: [
            13_578_230_257_316_942_723,
            4_468_261_189_661_707_530,
            2_757_811_110_504_579_466,
            10_078_813_841_461_853_471,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 17,
        trace_rows: 1 << 18,
        root: [
            819_893_897_249_792_822,
            5_158_665_891_176_462_592,
            3_435_395_196_844_124_461,
            9_014_235_854_438_932_712,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 18,
        trace_rows: 1 << 19,
        root: [
            7_786_672_364_682_365_712,
            9_567_202_892_443_527_987,
            14_465_988_292_812_763_432,
            18_251_996_250_654_057_153,
        ],
    },
    PinnedPreprocessedKey {
        activation_len: 1 << 19,
        trace_rows: 1 << 20,
        root: [
            3_237_927_895_780_606_966,
            12_601_477_073_708_255_793,
            1_717_043_511_563_849_449,
            17_591_210_984_902_976_185,
        ],
    },
];

#[cfg(any(feature = "whir-prototype", test))]
pub(crate) fn pinned_preprocessed_key(
    activation_len: usize,
    trace_rows: usize,
) -> Option<&'static PinnedPreprocessedKey> {
    PINNED_PREPROCESSED_KEYS.iter().find(|key| {
        key.activation_len == activation_len && key.trace_rows == trace_rows && key.root != [0; 4]
    })
}

pub(crate) fn pinned_preprocessed_registry_digest() -> [u8; 32] {
    registry_digest(&PINNED_PREPROCESSED_KEYS)
}

fn registry_digest(keys: &[PinnedPreprocessedKey]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(PINNED_PREPROCESSED_REGISTRY_DOMAIN);
    hasher.update(&STRUCTURED_BLAKE3_VERSION.to_le_bytes());
    hasher.update(STRUCTURED_BLAKE3_PROOF_MAGIC);
    hasher.update(&NARROW_BLAKE3_PROOF_VERSION.to_le_bytes());
    hasher.update(NARROW_BLAKE3_PROOF_MAGIC);
    hasher.update(&PINNED_PREPROCESSED_REGISTRY_VERSION.to_le_bytes());
    hasher.update(
        &u64::try_from(PINNED_PREPROCESSED_WIDTH)
            .expect("preprocessed width fits u64")
            .to_le_bytes(),
    );
    hasher.update(
        &u64::try_from(PINNED_PREPROCESSED_LOG_BLOWUP)
            .expect("preprocessed blowup fits u64")
            .to_le_bytes(),
    );
    hasher.update(
        &u64::try_from(keys.len())
            .expect("registry length fits u64")
            .to_le_bytes(),
    );
    for key in keys {
        hasher.update(
            &u64::try_from(key.activation_len)
                .expect("activation length fits u64")
                .to_le_bytes(),
        );
        hasher.update(
            &u64::try_from(key.trace_rows)
                .expect("trace row count fits u64")
                .to_le_bytes(),
        );
        for word in key.root {
            hasher.update(&word.to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GOLDILOCKS_MODULUS;

    #[test]
    fn registry_is_ordered_canonical_and_complete() {
        assert_eq!(PINNED_PREPROCESSED_KEYS.len(), 15);
        for (index, key) in PINNED_PREPROCESSED_KEYS.iter().enumerate() {
            assert_eq!(key.activation_len, 1 << (index + 5));
            assert!(key.trace_rows.is_power_of_two());
            assert!(key.root.into_iter().all(|word| word < GOLDILOCKS_MODULUS));
            assert_eq!(
                pinned_preprocessed_key(key.activation_len, key.trace_rows),
                Some(key)
            );
            assert!(pinned_preprocessed_key(key.activation_len, key.trace_rows << 1).is_none());
        }
    }

    #[test]
    fn registry_digest_commits_every_entry() {
        let baseline = pinned_preprocessed_registry_digest();
        assert_eq!(
            baseline,
            [
                0x2a, 0x80, 0x3a, 0x1b, 0xf8, 0x98, 0xcc, 0xdb, 0xc7, 0xb2, 0x48, 0x0d, 0x93, 0x4e,
                0x95, 0x9f, 0xfd, 0x10, 0xa2, 0x49, 0x2d, 0xb8, 0x77, 0x50, 0xa0, 0x43, 0x92, 0x8f,
                0x76, 0xbf, 0x49, 0x93,
            ]
        );
        assert_eq!(baseline, pinned_preprocessed_registry_digest());

        let mut mutated = PINNED_PREPROCESSED_KEYS;
        mutated[0].root[0] ^= 1;
        assert_ne!(registry_digest(&mutated), baseline);

        mutated = PINNED_PREPROCESSED_KEYS;
        mutated[14].root[0] ^= 1;
        assert_ne!(registry_digest(&mutated), baseline);
    }
}
