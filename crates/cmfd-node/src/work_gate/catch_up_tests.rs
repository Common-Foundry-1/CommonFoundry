//! Tests of the desktop wallet catch-up: the pure rules, the grant file, and
//! a wallet node fed blocks the way a sync session feeds them, with source
//! reports given directly.

use std::fs::{self, OpenOptions};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use cmfd_consensus::{Block, ForgeMatrixV4WorkRule, OutPoint};
use primitive_types::U512;

use super::catch_up::{
    CatchUpFacts, CatchUpFollow, Coverage, CoverageIndex, CoverageTracker, GrantFile, GrantRefusal,
    WalletCatchUp, catch_up_row, easing_ok, prune_lag_ok, reference, release_fresh,
    release_fresh_at, run_qualifies, topmost_qualifying_run, valid_sources,
};
use super::test_support::{
    ScriptedEngine, count_lone_refusal, install, rule_from_genesis, set_halted,
};
use super::tests::{cpu, devnet};
use super::{
    CATCH_UP_GRANTS_FILE, CatchUpSource, FetchedFrom, PRUNE_LAG_FACTOR, STALE_AFTER, TOP_RUN_CAP,
    TOP_RUN_STALL, WALLET_CATCH_UP_DEPTH, WORK_STATUS_FILE, WalletCatchUpStatus, WorkBacklog,
    WorkBacklogOutcome, WorkBacklogTurn, WorkStatus,
};
use crate::honest_work::{HonestWorkChecker, WorkEngineError, WorkEngineState};
use crate::tests::clean_test_dir;
use crate::{
    BLOCK_LOG_FILE, DEVNET_PROFILE, Node, NodeError, RemoteProofPeerId, RemoteProofRequest,
    submit_shared_block, submit_shared_peer_block_from, unix_time_seconds,
};

/// The depth the integration tests use.
const D: u64 = 3;
/// The serving source and the voucher, in groups 0 and 1.
const P: u8 = 0;
const Q: u8 = 1;
const NETWORK: [u8; 32] = [0x41; 32];
const CHECKPOINT_ID: [u8; 32] = [0x42; 32];

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn work(value: u64) -> U512 {
    U512::from(value)
}

/// Loopback sources, one per entry of `groups`.
fn sources(groups: &[u8]) -> Vec<CatchUpSource> {
    groups
        .iter()
        .enumerate()
        .map(|(index, group)| CatchUpSource {
            addr: SocketAddr::from(([127, 0, 0, 1], 21_000 + index as u16)),
            group: *group,
        })
        .collect()
}

/// Turns the catch-up on over sources in `groups`; whether it is on.
fn enabled(node: &mut Node, groups: &[u8]) -> bool {
    node.enable_wallet_catch_up(sources(groups)).unwrap()
}

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cmfd-catch-up-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_grants(path: &Path, live: impl Fn(u64, [u8; 32]) -> bool) -> GrantFile {
    GrantFile::open(path, NETWORK, CHECKPOINT_ID, live).unwrap()
}

/// A catch-up over `groups` with the grant file in `dir`, at depth `D`.
fn catch_up_in(dir: &Path, groups: &[u8]) -> WalletCatchUp {
    let grants = open_grants(&dir.join(CATCH_UP_GRANTS_FILE), |_, _| true);
    let catch_up = WalletCatchUp::new(valid_sources(sources(groups)).unwrap(), grants);
    catch_up.set_depth(D);
    catch_up
}

#[test]
fn pure_rules_for_admitting_a_block_without_an_engine_run() {
    // Easing: half the reference passes, less does not, and no product
    // overflows.
    assert!(easing_ok(work(50), work(100)));
    assert!(!easing_ok(work(49), work(100)));
    assert!(easing_ok(U512::MAX, U512::MAX));
    assert!(!easing_ok(U512::zero(), work(1)));

    // A release is fresh up to STALE_AFTER after its checkpoint block, and
    // while the clock is behind that block; without a clock or a checkpoint
    // time it is not.
    let time_c = 1_800_000_000;
    assert!(release_fresh(time_c + STALE_AFTER, time_c));
    assert!(!release_fresh(time_c + STALE_AFTER + 1, time_c));
    assert!(release_fresh(time_c - 7_200, time_c));
    assert!(release_fresh(0, u64::MAX));
    assert!(release_fresh_at(Some(time_c + 1), Some(time_c)));
    assert!(!release_fresh_at(None, Some(time_c)));
    assert!(!release_fresh_at(Some(time_c), None));

    // The pruner keeps up while the tip is at most two windows above the
    // prune height; before any prune it counts from 0; no pruning, no bound.
    let keep = 720;
    assert_eq!(PRUNE_LAG_FACTOR, 2);
    assert!(prune_lag_ok(1_000 + 2 * keep, Some(1_000), Some(keep)));
    assert!(!prune_lag_ok(1_000 + 2 * keep + 1, Some(1_000), Some(keep)));
    assert!(prune_lag_ok(2 * keep, None, Some(keep)));
    assert!(!prune_lag_ok(2 * keep + 1, None, Some(keep)));
    assert!(prune_lag_ok(u64::MAX, None, None));
    assert!(prune_lag_ok(5, Some(10), Some(1)));

    // The reference never falls below the checkpoint block's work, and is
    // unknown unless both blocks are known; never the validated block's alone.
    assert_eq!(
        reference(Some(work(3)), Some(work(1_000))),
        Some(work(1_000))
    );
    assert_eq!(reference(Some(work(9)), Some(work(4))), Some(work(9)));
    assert_eq!(reference(Some(work(3)), None), None);
    assert_eq!(reference(None, Some(work(3))), None);
    assert_eq!(WALLET_CATCH_UP_DEPTH, 60);

    // The grant conditions keep their numbers.
    assert_eq!(GrantRefusal::NotVouched.condition(), 2);
    assert_eq!(GrantRefusal::Easing.condition(), 5);
    assert_eq!(GrantRefusal::NotReady.condition(), 6);
    assert_eq!(GrantRefusal::ReleaseStale.condition(), 7);
    assert_eq!(GrantRefusal::PruneLag.condition(), 8);
}

#[test]
fn sources_need_two_groups_and_a_voucher_in_another_group_reported_deep_enough() {
    assert!(valid_sources(sources(&[0])).is_none());
    assert!(valid_sources(sources(&[0, 0])).is_none(), "one group");
    assert!(valid_sources(sources(&[0, 1, 2, 3, 4, 5, 6, 7, 8])).is_none());
    let mut repeated = sources(&[0, 1]);
    repeated.push(repeated[0]);
    assert_eq!(valid_sources(repeated).unwrap().len(), 2);
    let mut same_address = sources(&[0]);
    same_address.push(CatchUpSource {
        group: 1,
        ..same_address[0]
    });
    assert!(valid_sources(same_address).is_none(), "one address");

    let dir = scratch("vouch");
    // Sources 0 and 1 share a group, as the seed and St. Louis do.
    let catch_up = catch_up_in(&dir, &[0, 0, 1]);
    assert_eq!(catch_up.source_index(sources(&[0, 0, 1])[2].addr), Some(2));
    let other_port = SocketAddr::from(([127, 0, 0, 1], 1));
    assert_eq!(catch_up.source_index(other_port), None);
    let now = Instant::now();
    let block = id(7);
    // Listed only by a source in the serving source's own group: no; for a
    // session with the other group, yes.
    catch_up.note_view(1, 100, &[block], now);
    assert!(!catch_up.vouched_by_other(&block, 0, 10, now));
    assert!(catch_up.vouched_by_other(&block, 2, 97, now));
    drop(catch_up);

    let catch_up = catch_up_in(&dir, &[0, 0, 1]);
    catch_up.note_view(2, 100, &[block], now);
    // A source's own listing does not vouch for its own session.
    assert!(!catch_up.vouched_by_other(&block, 2, 10, now));
    // Only at least the depth below the voucher's report.
    assert!(catch_up.vouched_by_other(&block, 0, 97, now));
    assert!(!catch_up.vouched_by_other(&block, 0, 98, now));
    assert!(catch_up.vouched_by_other(&block, 1, 97, now));
    assert!(!catch_up.vouched_by_other(&id(8), 0, 10, now));
    // A lower report counts from then on.
    catch_up.note_view(2, 50, &[], now);
    assert!(!catch_up.vouched_by_other(&block, 0, 48, now));
    // A stale view vouches for nothing.
    catch_up.note_view(2, 100, &[], now);
    let later = now + Duration::from_secs(601);
    assert!(!catch_up.vouched_by_other(&block, 0, 10, later));
    catch_up.set_view_fresh(Duration::from_secs(700));
    assert!(catch_up.vouched_by_other(&block, 0, 10, later));
    drop(catch_up);

    // Behind sources need fresh views in two groups and recent delivery.
    let catch_up = catch_up_in(&dir, &[0, 0, 1]);
    catch_up.note_view(0, 10, &[], now);
    catch_up.note_view(1, 10, &[], now);
    catch_up.note_source_progress(now);
    assert!(!catch_up.sources_ahead(7, now), "one group");
    catch_up.note_view(2, 10, &[], now);
    assert!(catch_up.sources_ahead(7, now));
    assert!(!catch_up.sources_ahead(8, now), "less than the depth ahead");
    assert!(!catch_up.sources_ahead(7, now + Duration::from_secs(601)));
    drop(catch_up);
    let catch_up = catch_up_in(&dir, &[0, 1]);
    catch_up.note_view(0, 10, &[], now);
    catch_up.note_view(1, 10, &[], now);
    assert!(!catch_up.sources_ahead(7, now), "no delivery yet");
    drop(catch_up);

    // Probe order: other groups only, after the session's source, wrapping.
    let catch_up = catch_up_in(&dir, &[0, 0, 1]);
    assert_eq!(catch_up.probe_candidates(0, now), vec![2]);
    assert_eq!(catch_up.probe_candidates(1, now), vec![2]);
    assert_eq!(catch_up.probe_candidates(2, now), vec![0, 1]);
    drop(catch_up);
    let catch_up = catch_up_in(&dir, &[0, 1, 2, 1]);
    assert_eq!(catch_up.probe_candidates(2, now), vec![3, 0, 1]);
    catch_up.note_probe_failed(3, now);
    assert_eq!(catch_up.probe_candidates(2, now), vec![0, 1]);
    assert_eq!(
        catch_up.probe_candidates(2, now + Duration::from_secs(60)),
        vec![3, 0, 1]
    );
    catch_up.set_probe_fail_hold(Duration::from_secs(120));
    assert_eq!(
        catch_up.probe_candidates(2, now + Duration::from_secs(60)),
        vec![0, 1]
    );
    catch_up.note_probe_hit(now);
    drop(catch_up);

    // Vouched ids are remembered up to a cap, oldest first out.
    let catch_up = catch_up_in(&dir, &[0, 1]);
    let ids = (0..4_097_u32)
        .map(|index| {
            let mut block = [0_u8; 32];
            block[..4].copy_from_slice(&index.to_le_bytes());
            block
        })
        .collect::<Vec<_>>();
    catch_up.note_view(1, 100, &ids, now);
    assert!(!catch_up.vouched_by_other(&ids[0], 0, 10, now));
    assert!(catch_up.vouched_by_other(&ids[1], 0, 10, now));
    assert!(catch_up.vouched_by_other(&ids[4_096], 0, 10, now));
    drop(catch_up);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn grants_wait_for_their_commit_oldest_first_out() {
    let dir = scratch("grant-set");
    let catch_up = catch_up_in(&dir, &[0, 1]);
    let now = Instant::now();
    for byte in 0..65_u8 {
        catch_up.grant(10 + u64::from(byte), id(byte), now).unwrap();
    }
    assert!(!catch_up.has_grant(&id(0)), "the oldest is dropped");
    assert!(catch_up.has_grant(&id(1)) && catch_up.has_grant(&id(64)));
    assert_eq!(catch_up.pending_grants().len(), 64);
    // Every record stays in the file, which decides coverage only.
    assert!(catch_up.recorded_grant(&id(0)));
    assert!(catch_up.take_grant(&id(5)));
    assert!(!catch_up.take_grant(&id(5)));
    assert!(catch_up.recorded_grant(&id(5)));
    assert_eq!(catch_up.grant_file_syncs(), 65);
    drop(catch_up);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_grant_file_round_trips_and_is_bound_to_its_network_and_checkpoint() {
    let dir = scratch("grant-file");
    let path = dir.join(CATCH_UP_GRANTS_FILE);
    let mut grants = open_grants(&path, |_, _| true);
    grants.append(11, id(1)).unwrap();
    grants.append(12, id(2)).unwrap();
    drop(grants);
    let bytes = fs::read(&path).unwrap();
    // Plain BLAKE3 throughout, so the file reads without this code.
    assert_eq!(bytes.len(), 104 + 2 * 48);
    assert_eq!(&bytes[..8], b"CMFDCUG1");
    assert_eq!(&bytes[8..40], &NETWORK);
    assert_eq!(&bytes[40..72], &CHECKPOINT_ID);
    assert_eq!(&bytes[72..104], blake3::hash(&bytes[..72]).as_bytes());
    assert_eq!(&bytes[104..112], &11_u64.to_le_bytes());
    assert_eq!(&bytes[112..144], &id(1));
    assert_eq!(
        &bytes[144..152],
        &blake3::hash(&bytes[104..144]).as_bytes()[..8]
    );

    let grants = open_grants(&path, |_, _| true);
    assert!(grants.contains(&id(1)) && grants.contains(&id(2)));
    drop(grants);

    // Another network or checkpoint, or a damaged header: re-created empty.
    for (network, checkpoint) in [(id(9), CHECKPOINT_ID), (NETWORK, id(9))] {
        fs::write(&path, &bytes).unwrap();
        let grants = GrantFile::open(&path, network, checkpoint, |_, _| true).unwrap();
        assert!(!grants.contains(&id(1)));
        drop(grants);
        assert_eq!(fs::metadata(&path).unwrap().len(), 104);
    }
    let mut damaged = bytes.clone();
    damaged[80] ^= 1;
    fs::write(&path, &damaged).unwrap();
    let grants = open_grants(&path, |_, _| true);
    assert!(!grants.contains(&id(1)) && !grants.contains(&id(2)));
    drop(grants);
    assert_eq!(fs::metadata(&path).unwrap().len(), 104);
    assert!(!dir.join(format!("{CATCH_UP_GRANTS_FILE}.tmp")).exists());

    // A torn last record is cut off, and later records line up again.
    fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
    let mut grants = open_grants(&path, |_, _| true);
    assert!(grants.contains(&id(1)) && !grants.contains(&id(2)));
    assert_eq!(fs::metadata(&path).unwrap().len(), 104 + 48);
    grants.append(13, id(3)).unwrap();
    drop(grants);
    let grants = open_grants(&path, |_, _| true);
    assert!(grants.contains(&id(1)) && grants.contains(&id(3)));
    drop(grants);

    // A damaged record is skipped: only its block loses its grant.
    let mut damaged = bytes.clone();
    damaged[104 + 20] ^= 1;
    fs::write(&path, &damaged).unwrap();
    let grants = open_grants(&path, |_, _| true);
    assert!(!grants.contains(&id(1)) && grants.contains(&id(2)));
    drop(grants);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn each_grant_record_is_synced_and_a_failed_write_is_cut_back() {
    let dir = scratch("grant-sync");
    let catch_up = catch_up_in(&dir, &[0, 1]);
    let now = Instant::now();
    catch_up.grant(11, id(1), now).unwrap();
    assert_eq!(catch_up.grant_file_syncs(), 1);
    catch_up.grant(12, id(2), now).unwrap();
    assert_eq!(catch_up.grant_file_syncs(), 2);

    // Half a record reaches the file before the write fails: no grant, and
    // the file is cut back so the next record lines up.
    catch_up.fail_next_grant_write();
    assert!(catch_up.grant(13, id(3), now).is_err());
    assert!(!catch_up.has_grant(&id(3)) && !catch_up.recorded_grant(&id(3)));
    let path = dir.join(CATCH_UP_GRANTS_FILE);
    assert_eq!(fs::metadata(&path).unwrap().len(), 104 + 2 * 48);
    catch_up.grant(14, id(4), now).unwrap();
    drop(catch_up);
    let grants = open_grants(&path, |_, _| true);
    assert!(grants.contains(&id(1)) && grants.contains(&id(2)) && grants.contains(&id(4)));
    assert!(!grants.contains(&id(3)));
    drop(grants);

    // A file that cannot be read or made is an error.
    let blocked = scratch("grant-blocked");
    fs::create_dir(blocked.join(CATCH_UP_GRANTS_FILE)).unwrap();
    let open = |path: &Path| GrantFile::open(path, NETWORK, CHECKPOINT_ID, |_, _| true);
    assert!(open(&blocked.join(CATCH_UP_GRANTS_FILE)).is_err());
    let missing = blocked.join("missing");
    fs::create_dir_all(&missing).unwrap();
    fs::create_dir(missing.join(format!("{CATCH_UP_GRANTS_FILE}.tmp"))).unwrap();
    assert!(open(&missing.join(CATCH_UP_GRANTS_FILE)).is_err());
    fs::remove_dir_all(blocked).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_grant_file_is_compacted_only_when_opened_and_only_when_mostly_dead() {
    let dir = scratch("grant-compact");
    let path = dir.join(CATCH_UP_GRANTS_FILE);
    let mut grants = open_grants(&path, |_, _| true);
    for byte in 1..=4 {
        grants.append(10 + u64::from(byte), id(byte)).unwrap();
    }
    // Appends never compact: a record of a block not yet committed stays.
    assert_eq!(fs::metadata(&path).unwrap().len(), 104 + 4 * 48);
    drop(grants);

    // Half dead: kept as it is.
    let grants = open_grants(&path, |height, _| height > 12);
    assert!(grants.contains(&id(1)));
    drop(grants);
    assert_eq!(fs::metadata(&path).unwrap().len(), 104 + 4 * 48);

    // A rewrite that cannot be made keeps the old file in use.
    let temporary = dir.join(format!("{CATCH_UP_GRANTS_FILE}.tmp"));
    fs::create_dir(&temporary).unwrap();
    let mut grants = open_grants(&path, |height, _| height > 13);
    assert!(grants.contains(&id(1)));
    grants.append(15, id(5)).unwrap();
    drop(grants);
    fs::remove_dir(&temporary).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), 104 + 5 * 48);

    // More than half dead: only the live records are kept.
    let grants = open_grants(&path, |height, _| height > 13);
    assert!(!grants.contains(&id(3)) && grants.contains(&id(4)) && grants.contains(&id(5)));
    drop(grants);
    assert_eq!(fs::metadata(&path).unwrap().len(), 104 + 2 * 48);
    assert!(!temporary.exists());
    fs::remove_dir_all(dir).unwrap();
}

/// A wallet node and a source chain whose blocks all pay it.
struct Wallet {
    path: PathBuf,
    source_path: PathBuf,
    node: Arc<Mutex<Node>>,
    engine: Arc<ScriptedEngine>,
    checker: Arc<HonestWorkChecker>,
    chain: Vec<Block>,
    now: u64,
}

/// A wallet whose rule pins the checkpoint at height `checkpoint` of a
/// source chain of `total` blocks, with the first `stored` of them committed
/// before the catch-up is turned on over sources in `groups`.
struct WalletSetup<'a> {
    label: &'a str,
    total: u64,
    checkpoint: u64,
    stored: usize,
    groups: &'a [u8],
    /// When the blocks up to the checkpoint were mined, if not now.
    checkpoint_mined_at: Option<u64>,
    known_answers_fail: bool,
    /// The stored blocks are committed before the rule is installed, as an
    /// earlier release would have.
    stored_before_rule: bool,
    /// Every block is mined a minute after the one before, the last one now,
    /// so that a long chain keeps its difficulty.
    minute_apart: bool,
}

impl<'a> WalletSetup<'a> {
    fn new(label: &'a str) -> Self {
        Self {
            label,
            total: 8,
            checkpoint: 2,
            stored: 2,
            groups: &[0, 1],
            checkpoint_mined_at: None,
            known_answers_fail: false,
            stored_before_rule: false,
            minute_apart: false,
        }
    }

    fn open(self) -> Wallet {
        let now = unix_time_seconds().unwrap();
        let (source_path, mut source) = devnet(&format!("{}-source", self.label));
        let (path, node) = devnet(self.label);
        let destination = node.wallet_destination();
        let chain = (0..self.total)
            .map(|offset| {
                let at = match self.checkpoint_mined_at {
                    _ if self.minute_apart => now - 60 * (self.total - offset),
                    Some(start) if offset < self.checkpoint => start + offset,
                    _ => now + offset,
                };
                source
                    .mine_once(destination, at, crate::DEFAULT_MINING_ATTEMPTS)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        drop(source);
        let checkpoint_id = chain[self.checkpoint as usize - 1].block_id();
        let rule =
            ForgeMatrixV4WorkRule::with_pinned_heights(self.checkpoint, checkpoint_id, []).unwrap();
        let engine = cpu();
        for block in &chain {
            engine.answer(block, true);
        }
        if self.known_answers_fail {
            engine.fail_known_answers();
        }
        let node = Arc::new(Mutex::new(node));
        let store = || {
            for block in &chain[..self.stored] {
                submit_shared_block(&node, block.clone(), now).unwrap();
            }
        };
        if self.stored_before_rule {
            store();
        }
        let checker = install(
            &mut node.lock().unwrap(),
            Some(rule),
            Some(engine.clone()),
            None,
        );
        if !self.stored_before_rule {
            store();
        }
        assert!(enabled(&mut node.lock().unwrap(), self.groups));
        let wallet = Wallet {
            path,
            source_path,
            node,
            engine,
            checker,
            chain,
            now,
        };
        wallet.catch_up().set_depth(D);
        wallet
    }
}

impl Wallet {
    fn catch_up(&self) -> Arc<WalletCatchUp> {
        self.node.lock().unwrap().wallet_catch_up().unwrap()
    }

    fn tip_height(&self) -> u64 {
        self.node
            .lock()
            .unwrap()
            .state
            .next_height()
            .saturating_sub(1)
    }

    /// A session with `source`, which reports `reported`.
    fn from(&self, source: u8, reported: u64) -> FetchedFrom {
        FetchedFrom {
            sender: IpAddr::from([127, 0, 0, 1]),
            trusted: true,
            heavier: false,
            catch_up: Some(CatchUpFollow {
                below: reported - D,
                source,
            }),
        }
    }

    /// `source` reports `reported` and lists every block of the chain.
    fn vouch(&self, source: u8, reported: u64) {
        let ids = self.chain.iter().map(Block::block_id).collect::<Vec<_>>();
        self.catch_up()
            .note_view(source, reported, &ids, Instant::now());
    }

    /// The prewarm a sync session runs before submitting `block`.
    fn prewarm_block(&self, block: &Block, from: FetchedFrom) {
        let prewarm = self
            .node
            .lock()
            .unwrap()
            .work_prewarm(block, self.now, from);
        if let Some(prewarm) = prewarm {
            prewarm.run(
                RemoteProofRequest::new(Instant::now() + Duration::from_secs(30)),
                &|| false,
            );
        }
    }

    /// The submission that follows it.
    fn submit_block(&self, block: &Block, from: FetchedFrom) -> Result<u64, NodeError> {
        static PEER: AtomicU64 = AtomicU64::new(50_000);
        submit_shared_peer_block_from(
            &self.node,
            block.clone(),
            self.now,
            RemoteProofPeerId::new(PEER.fetch_add(1, Ordering::Relaxed)).unwrap(),
            RemoteProofRequest::new(Instant::now() + Duration::from_secs(30)),
            from.trusted,
            Some(from.block_sender()),
        )
    }

    /// Prewarms and submits `block` as a sync session fetching it `from`.
    fn fetch_block(&self, block: &Block, from: FetchedFrom) -> Result<u64, NodeError> {
        self.prewarm_block(block, from);
        self.submit_block(block, from)
    }

    fn fetch(&self, index: usize, from: FetchedFrom) -> Result<u64, NodeError> {
        self.fetch_block(&self.chain[index].clone(), from)
    }

    /// A session that grants nothing.
    fn strict(&self) -> FetchedFrom {
        FetchedFrom {
            catch_up: None,
            ..self.from(P, 8)
        }
    }

    fn available(&self) -> u64 {
        self.node.lock().unwrap().wallet_available_height().unwrap()
    }

    fn status_at(&self, now: Instant) -> WalletCatchUpStatus {
        self.node
            .lock()
            .unwrap()
            .work_rule_status_at(now)
            .unwrap()
            .wallet_catch_up
            .unwrap()
    }

    fn pending(&self, now: Instant) -> bool {
        self.node.lock().unwrap().wallet_burial_pending(now)
    }

    /// The height of the block the background check would take next at
    /// `now`.
    fn next_checked(&self, now: Instant) -> Option<u64> {
        self.node
            .lock()
            .unwrap()
            .next_work_backlog_block(now)
            .map(|(height, _)| height)
    }

    fn granted(&self, index: usize) -> bool {
        self.catch_up()
            .recorded_grant(&self.chain[index].block_id())
    }

    fn status(&self, index: usize) -> Option<WorkStatus> {
        self.node
            .lock()
            .unwrap()
            .work_gate
            .as_ref()
            .unwrap()
            .status(&self.chain[index].block_id())
    }

    fn mark_unsettled(&self, index: usize) {
        let node = self.node.lock().unwrap();
        let store = node.work_gate.as_ref().unwrap().store.clone().unwrap();
        store
            .lock()
            .unwrap()
            .mark_unsettled(index as u64 + 1, self.chain[index].block_id())
            .unwrap();
    }

    fn validated(&self) -> u64 {
        self.node.lock().unwrap().work_validated_height().unwrap()
    }

    fn rule(&self) -> ForgeMatrixV4WorkRule {
        self.node
            .lock()
            .unwrap()
            .work_gate
            .as_ref()
            .unwrap()
            .rule
            .as_ref()
            .clone()
    }

    /// Closes the node, leaving a placeholder in its place.
    fn stop(&mut self) {
        let placeholder =
            Node::open_with_profile(self.path.with_extension("swap"), DEVNET_PROFILE).unwrap();
        drop(std::mem::replace(
            &mut self.node,
            Arc::new(Mutex::new(placeholder)),
        ));
    }

    /// Opens the node again under `rule`, with the catch-up on if
    /// `catch_up`.
    fn start(&mut self, rule: ForgeMatrixV4WorkRule, catch_up: bool) {
        let node = Node::open_with_profile(&self.path, DEVNET_PROFILE).unwrap();
        drop(std::mem::replace(
            &mut self.node,
            Arc::new(Mutex::new(node)),
        ));
        clean_test_dir(&self.path.with_extension("swap"));
        let mut node = self.node.lock().unwrap();
        self.checker = install(&mut node, Some(rule), Some(self.engine.clone()), None);
        if catch_up {
            assert!(enabled(&mut node, &[0, 1]));
            node.wallet_catch_up().unwrap().set_depth(D);
        }
    }

    fn reopen(&mut self, catch_up: bool) {
        let rule = self.rule();
        self.stop();
        self.start(rule, catch_up);
    }

    fn close(self) {
        drop(self.node);
        clean_test_dir(&self.path);
        clean_test_dir(&self.source_path);
    }
}

#[test]
fn the_catch_up_needs_a_rule_a_store_two_groups_a_grant_file_and_a_real_checkpoint() {
    let now = unix_time_seconds().unwrap();
    let (source_path, mut source) = devnet("catch-up-enable-source");
    let chain = super::tests::mine(&mut source, 2, now);
    drop(source);
    let pinned = || ForgeMatrixV4WorkRule::with_pinned_heights(2, chain[1].block_id(), []).unwrap();

    let (path, mut node) = devnet("catch-up-enable");
    assert!(!enabled(&mut node, &[0, 1]), "no rule");
    node.install_work_rule_for_test(Some(pinned()));
    assert!(!enabled(&mut node, &[0, 1]), "no store");
    let genesis = rule_from_genesis(&node);
    install(&mut node, Some(genesis), Some(cpu()), None);
    assert!(
        !enabled(&mut node, &[0, 1]),
        "the checkpoint is virtual genesis"
    );
    install(&mut node, Some(pinned()), Some(cpu()), None);
    assert!(!enabled(&mut node, &[0]), "one source");
    assert!(!enabled(&mut node, &[1, 1]), "one group");
    fs::create_dir(path.join(CATCH_UP_GRANTS_FILE)).unwrap();
    assert!(!enabled(&mut node, &[0, 1]), "unreadable grant file");
    fs::remove_dir(path.join(CATCH_UP_GRANTS_FILE)).unwrap();
    fs::create_dir(path.join(format!("{CATCH_UP_GRANTS_FILE}.tmp"))).unwrap();
    assert!(
        !enabled(&mut node, &[0, 1]),
        "the grant file cannot be made"
    );
    assert!(node.wallet_catch_up().is_none());
    fs::remove_dir(path.join(format!("{CATCH_UP_GRANTS_FILE}.tmp"))).unwrap();
    // The block at the checkpoint need not be stored yet.
    assert!(enabled(&mut node, &[0, 1]));
    assert!(path.join(CATCH_UP_GRANTS_FILE).exists());
    assert!(enabled(&mut node, &[0, 1]));
    drop(node);
    clean_test_dir(&path);
    clean_test_dir(&source_path);
}

#[test]
fn the_reference_work_and_the_checkpoint_time_wait_for_the_checkpoint_block() {
    let wallet = WalletSetup {
        stored: 1,
        ..WalletSetup::new("catch-up-reference")
    }
    .open();
    let catch_up = wallet.catch_up();
    // Below the checkpoint the validated height is the tip, whose work is
    // known, but the checkpoint block's is not: no reference at all.
    assert_eq!(wallet.validated(), 1);
    assert_eq!(wallet.node.lock().unwrap().wallet_reference_work(), None);
    assert_eq!(catch_up.checkpoint_time(), None);
    wallet.vouch(Q, 8);
    submit_shared_block(&wallet.node, wallet.chain[1].clone(), wallet.now).unwrap();
    let pow = cmfd_consensus::block_work(wallet.chain[1].challenge.target).unwrap();
    assert_eq!(
        wallet.node.lock().unwrap().wallet_reference_work(),
        Some(pow)
    );
    assert_eq!(
        catch_up.checkpoint_time(),
        Some(wallet.chain[1].challenge.timestamp)
    );
    wallet.fetch(2, wallet.from(P, 8)).unwrap();
    assert!(wallet.granted(2));
    // Held while a granted block lies above the validated height.
    catch_up.set_reference_work(Some(pow + 1));
    assert_eq!(
        wallet.node.lock().unwrap().wallet_reference_work(),
        Some(pow + 1)
    );
    drop(catch_up);
    wallet.close();
}

#[test]
fn a_vouched_block_below_the_depth_limit_is_admitted_with_no_engine_run() {
    let wallet = WalletSetup::new("catch-up-grant").open();
    let catch_up = wallet.catch_up();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    // Synced before the prewarm returns, so before the block commits.
    wallet.prewarm_block(&wallet.chain[2], from);
    assert_eq!(catch_up.grant_file_syncs(), 1);
    assert!(catch_up.has_grant(&wallet.chain[2].block_id()));
    wallet.submit_block(&wallet.chain[2], from).unwrap();
    assert_eq!(wallet.engine.block_calls(), 0);
    assert!(wallet.granted(2));
    assert_eq!(wallet.status(2), None, "no work-status record");
    assert!(catch_up.pending_grants().is_empty(), "the commit used it");
    assert_eq!(catch_up.coverage().top_granted, 3);
    {
        let node = wallet.node.lock().unwrap();
        assert_eq!(node.state.tip(), wallet.chain[2].block_id());
        assert_eq!(node.work_validated_height(), Some(2));
        assert_eq!(node.exchange_served_cap(), 2);
        assert!(matches!(
            node.require_exchange_tip_checked(),
            Err(NodeError::WorkCheckPending)
        ));
        let coin = OutPoint {
            txid: wallet.chain[2].coinbase_outpoint_id(),
            index: 0,
        };
        assert!(
            node.wallet_coin_check()(&coin, node.wallet_destination()),
            "its coin waits for the check"
        );
    }
    // Up to the depth limit only; the newest blocks are checked.
    for index in 3..5 {
        wallet.fetch(index, from).unwrap();
    }
    assert_eq!(wallet.engine.block_calls(), 0);
    assert_eq!(catch_up.coverage().top_granted, 5);
    for index in 5..8 {
        wallet.fetch(index, from).unwrap();
        assert_eq!(wallet.status(index), Some(WorkStatus::Verified));
    }
    assert_eq!(wallet.engine.block_calls(), 3);
    assert!(!wallet.granted(5));
    assert_eq!(wallet.validated(), 2);
    assert_eq!(wallet.node.lock().unwrap().exchange_served_cap(), 2);
    assert_eq!(catch_up.grant_file_syncs(), 3);
    drop(catch_up);
    wallet.close();
}

/// Fetches block `index` and checks that its work was computed and nothing
/// was granted.
fn assert_checked(wallet: &Wallet, index: usize, from: FetchedFrom, case: &str) {
    let calls = wallet.engine.block_calls();
    wallet.fetch(index, from).unwrap();
    assert_eq!(wallet.engine.block_calls(), calls + 1, "{case}");
    assert!(!wallet.granted(index), "{case}");
    assert_eq!(wallet.status(index), Some(WorkStatus::Verified), "{case}");
}

#[test]
fn each_grant_condition_failing_alone_makes_the_engine_run() {
    // Nobody else listed it.
    let wallet = WalletSetup::new("catch-up-alone-unvouched").open();
    wallet.catch_up().note_view(Q, 8, &[], Instant::now());
    assert_checked(&wallet, 2, wallet.from(P, 8), "not vouched");
    wallet.close();

    // Listed only by a source in the serving source's group.
    let wallet = WalletSetup {
        groups: &[0, 0, 1],
        ..WalletSetup::new("catch-up-alone-same-group")
    }
    .open();
    wallet.vouch(1, 8);
    wallet.catch_up().note_view(2, 8, &[], Instant::now());
    assert_checked(&wallet, 2, wallet.from(0, 8), "same group");
    wallet.close();

    // Above the serving source's limit, above the only voucher's limit, or
    // vouched by a stale view.
    let wallet = WalletSetup::new("catch-up-alone-depth").open();
    wallet.vouch(Q, 8);
    assert_checked(&wallet, 2, wallet.from(P, 5), "above H_P - D");
    wallet.vouch(Q, 6);
    assert_checked(&wallet, 3, wallet.from(P, 8), "above H_Q - D");
    wallet.catch_up().set_view_fresh(Duration::from_millis(1));
    wallet.vouch(Q, 8);
    thread::sleep(Duration::from_millis(20));
    assert_checked(&wallet, 4, wallet.from(P, 8), "stale voucher");
    wallet.close();

    // A failed unsettled write.
    let wallet = WalletSetup::new("catch-up-alone-store").open();
    wallet.vouch(Q, 8);
    wallet.catch_up().set_store_failed();
    assert_checked(&wallet, 2, wallet.from(P, 8), "store failed");
    wallet.close();

    // Not a tip extension: a block on another branch from the checkpoint.
    let wallet = WalletSetup::new("catch-up-alone-side").open();
    let (fork_path, mut fork) = devnet("catch-up-alone-side-fork");
    for block in &wallet.chain[..2] {
        fork.submit_block(block.clone(), wallet.now).unwrap();
    }
    let side = fork
        .mine_once(crate::default_miner_destination(), wallet.now + 50, 10_000)
        .unwrap();
    drop(fork);
    clean_test_dir(&fork_path);
    wallet.engine.answer(&side, true);
    wallet.vouch(Q, 8);
    wallet
        .catch_up()
        .note_view(Q, 8, &[side.block_id()], Instant::now());
    wallet.fetch(2, wallet.from(P, 8)).unwrap();
    assert!(wallet.granted(2));
    wallet.fetch_block(&side, wallet.from(P, 8)).unwrap();
    assert_eq!(wallet.engine.block_calls(), 1, "not a tip extension");
    assert!(!wallet.catch_up().recorded_grant(&side.block_id()));
    wallet.close();

    // Recorded unsettled, or remembered as refused on one engine's word
    // even once that refusal is stale.
    let wallet = WalletSetup::new("catch-up-alone-known").open();
    wallet.vouch(Q, 8);
    wallet.mark_unsettled(2);
    assert_checked(&wallet, 2, wallet.from(P, 8), "unsettled");
    {
        let mut node = wallet.node.lock().unwrap();
        let block_id = wallet.chain[3].block_id();
        let claim = node
            .work_gate
            .as_ref()
            .unwrap()
            .claim(&wallet.chain[3])
            .unwrap();
        node.remember_work_rejection(block_id, super::WorkRejectionKind::Unconfirmed(claim));
        assert!(node.stale_work_rejection(&block_id));
    }
    assert_checked(&wallet, 3, wallet.from(P, 8), "stale lone refusal");
    wallet.close();

    // An unsettled active block above the validated height, however far
    // above it.
    let wallet = WalletSetup::new("catch-up-alone-frontier").open();
    wallet.vouch(Q, 8);
    wallet.fetch(2, wallet.from(P, 8)).unwrap();
    wallet.fetch(3, wallet.from(P, 8)).unwrap();
    assert!(wallet.granted(3));
    wallet.mark_unsettled(3);
    assert_eq!(
        wallet
            .node
            .lock()
            .unwrap()
            .work_rule_status()
            .unwrap()
            .unsettled_height,
        Some(4)
    );
    assert_checked(&wallet, 4, wallet.from(P, 8), "unsettled above V");
    wallet.close();

    // The pruner falls behind: the tip is more than two windows above the
    // prune height (0, with no prune yet).
    let wallet = WalletSetup::new("catch-up-alone-prune").open();
    wallet.vouch(Q, 8);
    wallet.fetch(2, wallet.from(P, 8)).unwrap();
    assert!(wallet.granted(2));
    wallet.node.lock().unwrap().prune_keep_blocks = Some(1);
    assert_checked(&wallet, 3, wallet.from(P, 8), "prune lag");
    wallet.node.lock().unwrap().prune_keep_blocks = Some(2);
    wallet.fetch(4, wallet.from(P, 8)).unwrap();
    assert!(wallet.granted(4), "tip 4 is two windows of 2 above 0");
    wallet.close();

    // The held reference is unknown.
    let wallet = WalletSetup::new("catch-up-alone-reference").open();
    wallet.vouch(Q, 8);
    wallet.fetch(2, wallet.from(P, 8)).unwrap();
    wallet.catch_up().set_reference_work(None);
    assert_checked(&wallet, 3, wallet.from(P, 8), "no reference");
    wallet.close();

    // The checkpoint block was mined more than STALE_AFTER ago.
    let wallet = WalletSetup {
        checkpoint_mined_at: Some(unix_time_seconds().unwrap() - 61 * 24 * 60 * 60),
        ..WalletSetup::new("catch-up-alone-stale")
    }
    .open();
    wallet.vouch(Q, 8);
    assert_checked(&wallet, 2, wallet.from(P, 8), "stale release");
    wallet.close();
}

#[test]
fn the_session_summary_counts_grants_and_why_blocks_were_checked() {
    let wallet = WalletSetup::new("catch-up-counts").open();
    let catch_up = wallet.catch_up();
    wallet.vouch(Q, 8);
    wallet.fetch(2, wallet.from(P, 8)).unwrap();
    // Above the voucher's limit: condition 2.
    wallet.vouch(Q, 6);
    wallet.fetch(3, wallet.from(P, 8)).unwrap();
    // The reference unknown: condition 5.
    wallet.vouch(Q, 8);
    catch_up.set_reference_work(None);
    wallet.fetch(4, wallet.from(P, 8)).unwrap();
    // Above the session's own limit: not counted.
    wallet.fetch(5, wallet.from(P, 5)).unwrap();
    // A sender that used up its one-engine refusals: left for later.
    {
        let node = wallet.node.lock().unwrap();
        for byte in [0xa1, 0xa2] {
            count_lone_refusal(&node, IpAddr::from([127, 0, 0, 1]), [byte; 32]);
        }
    }
    let calls = wallet.engine.block_calls();
    let untrusted = FetchedFrom {
        trusted: false,
        ..wallet.from(P, 20)
    };
    wallet.prewarm_block(&wallet.chain[6], untrusted);
    assert_eq!(wallet.engine.block_calls(), calls);
    let counts = catch_up.counts();
    assert_eq!(counts.granted, 1);
    assert_eq!((counts.refused(2), counts.refused(5)), (1, 1));
    assert_eq!(counts.refused.iter().sum::<u64>(), 2);
    assert_eq!(counts.throttled, 1);
    assert_eq!(GrantRefusal::GrantFile.condition(), 9, "counted on its own");

    // One summary per source a minute.
    let now = Instant::now();
    assert!(catch_up.log_session_summary(P, 8, Some((Q, 8)), now));
    assert!(!catch_up.log_session_summary(P, 8, None, now + Duration::from_secs(59)));
    assert!(catch_up.log_session_summary(Q, 8, None, now));
    assert!(catch_up.log_session_summary(P, 8, None, now + Duration::from_secs(60)));
    drop(catch_up);
    wallet.close();
}

#[test]
fn nothing_is_granted_while_admission_is_halted_or_the_engines_are_not_ready() {
    // Halted: nothing is admitted at all.
    let wallet = WalletSetup::new("catch-up-halted").open();
    wallet.vouch(Q, 8);
    set_halted(&wallet.node.lock().unwrap(), true);
    assert!(wallet.fetch(2, wallet.from(P, 8)).is_err());
    assert!(!wallet.granted(2));
    wallet.close();

    // Qualifying: the engines never passed their known answers.
    let wallet = WalletSetup {
        known_answers_fail: true,
        ..WalletSetup::new("catch-up-qualifying")
    }
    .open();
    assert_eq!(wallet.checker.engine_state(), WorkEngineState::Qualifying);
    wallet.vouch(Q, 8);
    assert!(wallet.fetch(2, wallet.from(P, 8)).is_err());
    assert!(!wallet.granted(2));
    assert_eq!(wallet.tip_height(), 2);
    wallet.close();

    // Failed: the engine failed a job.
    let wallet = WalletSetup::new("catch-up-failed").open();
    wallet.vouch(Q, 8);
    wallet
        .engine
        .fail_next(WorkEngineError::Integrity("layer 1".to_owned()));
    let unvouched = FetchedFrom {
        catch_up: None,
        ..wallet.from(P, 8)
    };
    assert!(wallet.fetch(2, unvouched).is_err());
    assert_eq!(wallet.checker.engine_state(), WorkEngineState::Failed);
    assert!(wallet.fetch(2, wallet.from(P, 8)).is_err());
    assert!(!wallet.granted(2));
    wallet.close();
}

#[test]
fn a_grant_is_used_only_by_its_commit_while_it_still_extends_the_tip() {
    // Without a grant the commit refuses a block with no verdict.
    let wallet = WalletSetup::new("catch-up-use").open();
    assert!(matches!(
        wallet
            .node
            .lock()
            .unwrap()
            .submit_block(wallet.chain[2].clone(), wallet.now),
        Err(NodeError::WorkCheckRequired)
    ));
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);

    // A grant left after the tip moved is not used.
    wallet.prewarm_block(&wallet.chain[2], from);
    assert!(wallet.catch_up().has_grant(&wallet.chain[2].block_id()));
    let (fork_path, mut fork) = devnet("catch-up-use-fork");
    for block in &wallet.chain[..2] {
        fork.submit_block(block.clone(), wallet.now).unwrap();
    }
    let competing = fork
        .mine_once(crate::default_miner_destination(), wallet.now + 50, 10_000)
        .unwrap();
    drop(fork);
    clean_test_dir(&fork_path);
    wallet.engine.answer(&competing, true);
    let strict = FetchedFrom {
        catch_up: None,
        ..from
    };
    wallet.fetch_block(&competing, strict).unwrap();
    {
        let mut node = wallet.node.lock().unwrap();
        assert!(matches!(
            node.submit_block(wallet.chain[2].clone(), wallet.now),
            Err(NodeError::WorkCheckRequired)
        ));
        assert!(!node.contains_block(wallet.chain[2].block_id()));
    }
    assert!(wallet.catch_up().has_grant(&wallet.chain[2].block_id()));
    wallet.close();

    // A grant left over is not used once a block above the validated height
    // is unsettled, or once the engine failed.
    let wallet = WalletSetup::new("catch-up-use-frontier").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    wallet.fetch(2, from).unwrap();
    wallet.prewarm_block(&wallet.chain[3], from);
    assert!(wallet.catch_up().has_grant(&wallet.chain[3].block_id()));
    wallet.mark_unsettled(2);
    {
        let mut node = wallet.node.lock().unwrap();
        assert!(matches!(
            node.work_admission(&wallet.chain[3], false, crate::BlockOrigin::InProcess),
            Ok(Some(_))
        ));
        assert!(matches!(
            node.submit_block(wallet.chain[3].clone(), wallet.now),
            Err(NodeError::WorkCheckRequired)
        ));
    }
    wallet.close();

    let wallet = WalletSetup::new("catch-up-use-failed").open();
    wallet.vouch(Q, 8);
    wallet.prewarm_block(&wallet.chain[2], wallet.from(P, 8));
    assert!(wallet.catch_up().has_grant(&wallet.chain[2].block_id()));
    wallet
        .engine
        .fail_next(WorkEngineError::Integrity("layer 1".to_owned()));
    let claim = wallet
        .node
        .lock()
        .unwrap()
        .work_gate
        .as_ref()
        .unwrap()
        .claim(&wallet.chain[7])
        .unwrap();
    let _ = wallet.checker.check_cancellable(claim, &|| false);
    assert_eq!(wallet.checker.engine_state(), WorkEngineState::Failed);
    assert!(matches!(
        wallet
            .node
            .lock()
            .unwrap()
            .submit_block(wallet.chain[2].clone(), wallet.now),
        Err(NodeError::WorkCheckRequired)
    ));
    wallet.close();
}

#[test]
fn a_commit_that_fails_after_using_its_grant_leaves_the_granted_top_alone() {
    let wallet = WalletSetup::new("catch-up-commit-fails").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    wallet.fetch(2, from).unwrap();
    wallet.prewarm_block(&wallet.chain[3], from);
    let catch_up = wallet.catch_up();
    assert!(catch_up.has_grant(&wallet.chain[3].block_id()));
    assert_eq!(catch_up.coverage().top_granted, 3);
    {
        let mut node = wallet.node.lock().unwrap();
        let read_only = OpenOptions::new()
            .read(true)
            .open(wallet.path.join(BLOCK_LOG_FILE))
            .unwrap();
        drop(std::mem::replace(&mut node.log, read_only));
        assert!(matches!(
            node.submit_block(wallet.chain[3].clone(), wallet.now),
            Err(NodeError::Io {
                operation: "append block record",
                ..
            })
        ));
        assert!(!node.contains_block(wallet.chain[3].block_id()));
    }
    assert!(!catch_up.has_grant(&wallet.chain[3].block_id()));
    assert_eq!(catch_up.coverage().top_granted, 3);
    drop(catch_up);
    wallet.close();
}

#[test]
fn the_wallet_frontier_is_the_lowest_unsettled_active_block_above_the_validated_height() {
    let mut wallet = WalletSetup::new("catch-up-frontier").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    for index in 2..5 {
        wallet.fetch(index, from).unwrap();
    }
    // Three blocks above the validated height.
    wallet.mark_unsettled(4);
    {
        let node = wallet.node.lock().unwrap();
        let status = node.work_rule_status().unwrap();
        assert_eq!(status.validated_height, 2);
        assert_eq!(status.unsettled_height, Some(5));
        assert_eq!(
            status.unsettled_block_id,
            Some(hex::encode(wallet.chain[4].block_id()))
        );
        assert!(node.work_validated_height_held_by_unsettled_block());
    }
    // With the catch-up off, only the block just above it counts.
    wallet.reopen(false);
    {
        let node = wallet.node.lock().unwrap();
        let status = node.work_rule_status().unwrap();
        assert_eq!(status.unsettled_height, None);
        assert!(!node.work_validated_height_held_by_unsettled_block());
    }
    wallet.close();
}

#[test]
fn a_wallet_catching_up_keeps_its_prune_window_and_relays_only_blocks_it_checked() {
    let mut wallet = WalletSetup::new("catch-up-relay").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    for index in 2..8 {
        wallet.fetch(index, from).unwrap();
    }
    let ids = wallet.chain.iter().map(Block::block_id).collect::<Vec<_>>();
    let address = "127.0.0.1:21999";
    {
        let node = wallet.node.lock().unwrap();
        assert_eq!(node.lowest_unverified_full_height(), None);
        // Up to the first block above the checkpoint without a verified
        // record: the checkpoint block itself is relayed.
        assert_eq!(node.peer_relay_inventory(address, ids[0], 16).0, ids[1..2]);
        // Granted blocks never are.
        assert!(node.peer_relay_inventory(address, ids[2], 16).0.is_empty());
        // Checked blocks above them are.
        assert_eq!(node.peer_relay_inventory(address, ids[4], 16).0, ids[5..8]);
    }
    // With the catch-up off, nothing changes.
    wallet.reopen(false);
    {
        let node = wallet.node.lock().unwrap();
        assert_eq!(node.lowest_unverified_full_height(), Some(3));
        assert_eq!(node.peer_relay_inventory(address, ids[0], 16).0, ids[1..8]);
    }
    wallet.close();
}

#[test]
fn grant_records_cover_committed_blocks_only_and_survive_a_failed_write() {
    let mut wallet = WalletSetup::new("catch-up-records").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    // A failed record: no grant, the engine runs.
    wallet.catch_up().fail_next_grant_write();
    assert_checked(&wallet, 2, from, "failed record");
    // The next grant still lines up in the file.
    wallet.fetch(3, from).unwrap();
    assert!(wallet.granted(3));
    // A record synced for a block that never committed.
    wallet.prewarm_block(&wallet.chain[4], from);
    assert!(wallet.granted(4));
    wallet.reopen(true);
    assert!(wallet.granted(3));
    let coverage = wallet.catch_up().coverage();
    assert_eq!(wallet.validated(), 3);
    assert_eq!(
        coverage.uncovered_floor, 3,
        "everything above it is covered"
    );
    assert_eq!(coverage.top_granted, 4);
    // The record alone admits nothing: without a fresh voucher the block is
    // checked.
    let calls = wallet.engine.block_calls();
    wallet.fetch(4, from).unwrap();
    assert_eq!(wallet.engine.block_calls(), calls + 1);
    assert_eq!(wallet.status(4), Some(WorkStatus::Verified));
    wallet.close();
}

#[test]
fn a_store_repair_drops_the_grants_and_uncovers_their_blocks() {
    for reconsider in [false, true] {
        let label = if reconsider {
            "catch-up-repair-reconsider"
        } else {
            "catch-up-repair-torn"
        };
        let mut wallet = WalletSetup::new(label).open();
        wallet.vouch(Q, 8);
        let from = wallet.from(P, 8);
        for index in 2..5 {
            wallet.fetch(index, from).unwrap();
        }
        // A granted block found not to match here.
        wallet.mark_unsettled(3);
        let rule = wallet.rule();
        wallet.stop();
        if reconsider {
            // `work-reconsider` on the stopped data directory.
            super::OPEN_WITH_WORK_RULE.with(|slot| *slot.borrow_mut() = Some(rule.clone()));
            let report = crate::storage::reconsider_work_block(
                &wallet.path,
                DEVNET_PROFILE,
                wallet.chain[3].block_id(),
            );
            super::OPEN_WITH_WORK_RULE.with(|slot| *slot.borrow_mut() = None);
            assert!(report.unwrap().record_cleared);
            assert!(!wallet.path.join(CATCH_UP_GRANTS_FILE).exists());
            wallet.start(rule, false);
        } else {
            // The unsettled record is torn, and a run with the catch-up off
            // repairs the store.
            let status_path = wallet.path.join(WORK_STATUS_FILE);
            let length = fs::metadata(&status_path).unwrap().len();
            OpenOptions::new()
                .write(true)
                .open(&status_path)
                .unwrap()
                .set_len(length - 5)
                .unwrap();
            assert!(wallet.path.join(CATCH_UP_GRANTS_FILE).exists());
            wallet.start(rule, false);
            assert!(!wallet.path.join(CATCH_UP_GRANTS_FILE).exists(), "{label}");
        }
        // Then a run with it on: the granted blocks are uncovered.
        assert!(enabled(&mut wallet.node.lock().unwrap(), &[0, 1]));
        let coverage = wallet.catch_up().coverage();
        assert_eq!(wallet.validated(), 2, "{label}");
        assert!(coverage.uncovered_floor >= 4, "{label}: {coverage:?}");
        assert_eq!(coverage.top_granted, 0, "{label}");
        // Re-executed blocks on top do not make them available.
        wallet.catch_up().set_depth(D);
        for index in 5..8 {
            wallet.fetch(index, wallet.strict()).unwrap();
        }
        assert_eq!(wallet.status(7), Some(WorkStatus::Verified), "{label}");
        assert_eq!(wallet.available(), 2, "{label}");
        wallet.close();
    }
}

#[test]
fn a_resync_sets_the_grant_file_aside_with_the_chain() {
    let mut wallet = WalletSetup::new("catch-up-set-aside").open();
    fs::write(
        wallet.path.join(format!("{CATCH_UP_GRANTS_FILE}.tmp")),
        b"left over",
    )
    .unwrap();
    wallet.stop();
    let report = crate::storage::set_chain_data_aside(&wallet.path).unwrap();
    for name in [
        CATCH_UP_GRANTS_FILE.to_owned(),
        format!("{CATCH_UP_GRANTS_FILE}.tmp"),
    ] {
        assert!(report.moved.contains(&name), "{name}: {report:?}");
        assert!(!wallet.path.join(&name).exists());
        assert!(report.folder.join(&name).exists());
    }
    let swap = wallet.path.with_extension("swap");
    wallet.close();
    clean_test_dir(&swap);
}

#[test]
fn a_refused_block_loses_its_grant_and_a_leftover_grant_is_not_used_for_it() {
    let wallet = WalletSetup::new("catch-up-refused").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    wallet.fetch(2, from).unwrap();
    let refused = wallet.chain[3].clone();
    let refused_id = refused.block_id();
    wallet.engine.answer(&refused, false);
    wallet.prewarm_block(&refused, from);
    let catch_up = wallet.catch_up();
    assert!(catch_up.has_grant(&refused_id));

    // The grant cannot be used at its submission, so the engine runs and
    // refuses the block: the grant goes with the refusal.
    wallet.mark_unsettled(2);
    assert!(matches!(
        wallet.submit_block(&refused, from),
        Err(NodeError::WorkMismatchUnconfirmed(id)) if id == refused_id
    ));
    assert!(!catch_up.has_grant(&refused_id));

    // Once the refusal is stale and the block above the validated height is
    // settled, a grant left for the block is still not used: the memo holds
    // a result that differs from it.
    {
        let node = wallet.node.lock().unwrap();
        let store = node.work_gate.as_ref().unwrap().store.clone().unwrap();
        store
            .lock()
            .unwrap()
            .mark_verified(3, wallet.chain[2].block_id())
            .unwrap();
    }
    assert_eq!(wallet.validated(), 3);
    wallet.checker.age_known_answers();
    assert!(
        wallet
            .node
            .lock()
            .unwrap()
            .stale_work_rejection(&refused_id)
    );
    catch_up.grant(4, refused_id, Instant::now()).unwrap();
    let result = wallet.submit_block(&refused, from);
    assert!(
        matches!(result, Err(NodeError::WorkMismatchUnconfirmed(id)) if id == refused_id),
        "{result:?}"
    );
    assert!(!wallet.node.lock().unwrap().contains_block(refused_id));
    drop(catch_up);
    wallet.close();
}

#[test]
fn installing_the_work_checker_again_turns_the_catch_up_off() {
    let wallet = WalletSetup::new("catch-up-reinstall").open();
    let mut node = wallet.node.lock().unwrap();
    assert!(node.wallet_catch_up().is_some());
    node.install_work_checker(Arc::clone(&wallet.checker))
        .unwrap();
    assert!(node.wallet_catch_up().is_none());
    assert!(enabled(&mut node, &[0, 1]));
    drop(node);
    wallet.close();
}

#[test]
fn failed_reads_and_records_are_retried_without_repeating_their_warning() {
    let dir = scratch("catch-up-retry");
    let catch_up = catch_up_in(&dir, &[0, 1]);
    let now = Instant::now();
    assert!(catch_up.checkpoint_time_read_due(now));
    assert!(catch_up.note_checkpoint_time_failed(now));
    assert!(!catch_up.checkpoint_time_read_due(now + Duration::from_secs(59)));
    assert!(catch_up.checkpoint_time_read_due(now + super::catch_up::CHECKPOINT_TIME_RETRY));
    assert!(!catch_up.note_checkpoint_time_failed(now + Duration::from_secs(60)));

    assert!(catch_up.first_grant_file_failure());
    assert!(!catch_up.first_grant_file_failure());
    catch_up.grant(3, id(1), now).unwrap();
    assert!(catch_up.first_grant_file_failure());
    catch_up.fail_next_grant_write();
    assert!(catch_up.grant(4, id(2), now).is_err());
    assert!(!catch_up.grant_file_stopped(), "a failed write is cut back");
    drop(catch_up);
    clean_test_dir(&dir);
}

#[test]
fn a_run_qualifies_with_enough_blocks_and_work_and_only_the_topmost_counts() {
    let d = WALLET_CATCH_UP_DEPTH;
    let w_ref = work(1_000);
    assert!(!run_qualifies(59, Some(work(1_000_000)), w_ref, d));
    assert!(!run_qualifies(60, Some(work(60 * 1_000 - 1)), w_ref, d));
    assert!(run_qualifies(60, Some(work(60 * 1_000)), w_ref, d));
    // A run of eased blocks needs proportionally more of them.
    assert!(!run_qualifies(119, Some(work(119 * 500)), w_ref, d));
    assert!(run_qualifies(120, Some(work(120 * 500)), w_ref, d));
    // Unreadable work, or a product past U512, is never enough.
    assert!(!run_qualifies(60, None, w_ref, d));
    assert!(!run_qualifies(60, Some(U512::MAX), U512::MAX, d));

    // Validated up to 10; 11..=100 admitted without a check; 101..=170
    // checked here; 171..=180 not; an island of 181..=200 checked here.
    let mut chain = Synthetic::new(10, 1_000);
    chain.push(90, false, false, 1_000);
    chain.push(70, true, false, 1_000);
    chain.push(10, false, true, 1_000);
    chain.push(20, true, false, 1_000);
    let found = |chain: &Synthetic, validated: u64, w_ref: u64| {
        topmost_qualifying_run(
            validated,
            chain.tip(),
            |height| chain.checked(height),
            |height| chain.cumulative_work(height),
            work(w_ref),
            d,
            || {},
        )
    };
    assert_eq!(
        found(&chain, 10, 1_000),
        Some((101, 170)),
        "the island is skipped"
    );
    // A qualifying run above it is the topmost.
    chain.push(10, false, true, 1_000);
    chain.push(65, true, false, 1_000);
    assert_eq!(found(&chain, 10, 1_000), Some((211, 275)));
    // Too little work: an eased run of 65 blocks does not qualify.
    let mut eased = Synthetic::new(10, 1_000);
    eased.push(5, false, true, 1_000);
    eased.push(65, true, false, 900);
    assert_eq!(found(&eased, 10, 1_000), None);
    assert_eq!(found(&eased, 10, 900), Some((16, 80)));
    // A run reaching down to the block above the validated height does not
    // count (it would have moved the validated height).
    let mut low = Synthetic::new(10, 1_000);
    low.push(70, true, false, 1_000);
    assert_eq!(found(&low, 10, 1_000), None);
}

/// A synthetic active chain for the coverage: each height's id, whether the
/// block was checked here, whether it has a grant record, and the
/// cumulative work.
struct Synthetic {
    blocks: Vec<([u8; 32], bool, bool, U512)>,
    /// Ids of blocks replaced by a reorganisation get a new tag.
    tag: u8,
    provisional: Option<u64>,
}

impl Synthetic {
    /// Genesis and `validated` checked blocks of work `each`.
    fn new(validated: u64, each: u64) -> Self {
        let mut chain = Self {
            blocks: vec![(Self::id(0, 0), true, false, U512::zero())],
            tag: 0,
            provisional: None,
        };
        chain.push(validated, true, false, each);
        chain
    }

    fn id(height: u64, tag: u8) -> [u8; 32] {
        let mut id = [0_u8; 32];
        id[..8].copy_from_slice(&height.to_le_bytes());
        id[8] = tag;
        id
    }

    fn tip(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    /// Appends `count` blocks of work `each`.
    fn push(&mut self, count: u64, checked: bool, granted: bool, each: u64) {
        for _ in 0..count {
            let height = self.blocks.len() as u64;
            let cumulative = self.blocks.last().unwrap().3 + work(each);
            self.blocks
                .push((Self::id(height, self.tag), checked, granted, cumulative));
        }
    }

    /// Replaces the block at `height` and those above it.
    fn reorganise(&mut self, height: u64) {
        self.tag += 1;
        for (position, block) in self.blocks.iter_mut().enumerate().skip(height as usize) {
            block.0 = Self::id(position as u64, self.tag);
        }
    }

    fn block(&self, block_id: &[u8; 32]) -> Option<&([u8; 32], bool, bool, U512)> {
        let height = u64::from_le_bytes(block_id[..8].try_into().unwrap());
        self.blocks
            .get(height as usize)
            .filter(|block| block.0 == *block_id)
    }

    fn checked(&self, height: u64) -> bool {
        self.active(height)
            .is_some_and(|id| self.verified(&id) && !self.provisional(&id))
    }
}

impl CoverageIndex for Synthetic {
    fn active(&self, height: u64) -> Option<[u8; 32]> {
        self.blocks.get(height as usize).map(|block| block.0)
    }

    fn verified(&self, block_id: &[u8; 32]) -> bool {
        self.block(block_id).is_some_and(|block| block.1)
    }

    fn provisional(&self, block_id: &[u8; 32]) -> bool {
        self.provisional
            .is_some_and(|height| self.active(height) == Some(*block_id))
    }

    fn granted(&self, block_id: &[u8; 32]) -> bool {
        self.block(block_id).is_some_and(|block| block.2)
    }

    fn cumulative_work(&self, height: u64) -> Option<U512> {
        self.blocks.get(height as usize).map(|block| block.3)
    }
}

#[test]
fn coverage_follows_the_tip_block_by_block_and_scans_again_only_when_it_must() {
    let now = Instant::now();
    let d = WALLET_CATCH_UP_DEPTH;
    let w_ref = work(1_000);
    // 50,000 granted blocks above the validated height.
    let mut chain = Synthetic::new(10, 1_000);
    chain.push(50_000, false, true, 1_000);
    let mut tracker = CoverageTracker::default();
    let refresh = |tracker: &mut CoverageTracker, chain: &Synthetic, validated, revocations, w| {
        tracker.refresh(
            chain,
            validated,
            chain.tip(),
            revocations,
            d,
            now,
            |_, _| Some(work(w)),
        )
    };
    let view = tracker.refresh(&chain, 10, chain.tip(), 0, d, now, |coverage, first| {
        assert!(first);
        assert_eq!(coverage.top_granted, 50_010, "the coverage is read first");
        Some(w_ref)
    });
    assert_eq!(
        view.coverage,
        Coverage {
            uncovered_floor: 10,
            top_granted: 50_010
        }
    );
    assert_eq!((view.best_run, view.top_run), (None, None));
    assert_eq!(tracker.full_scans, 1);

    // Each one-block extension reads the new block only.
    for _ in 0..70 {
        chain.push(1, true, false, 1_000);
        let visits = tracker.visits;
        let view = tracker.refresh(&chain, 10, chain.tip(), 0, d, now, |_, first| {
            assert!(!first);
            Some(w_ref)
        });
        assert!(tracker.visits - visits <= 2, "{}", tracker.visits - visits);
        assert_eq!(view.top_run.unwrap().top, chain.tip());
    }
    assert_eq!(tracker.full_scans, 1);
    let view = tracker.view();
    assert_eq!(view.best_run, Some((50_011, 50_080)));
    assert_eq!(view.top_run.unwrap().len(), 70);

    // New grants above it leave it qualified.
    chain.push(5, false, true, 1_000);
    let view = refresh(&mut tracker, &chain, 10, 0, 1_000);
    assert_eq!(view.best_run, Some((50_011, 50_080)));
    assert_eq!(view.top_run, None);
    assert_eq!(view.coverage.top_granted, 50_085);
    // A block neither granted nor checked raises the uncovered floor.
    chain.push(1, false, false, 1_000);
    assert_eq!(
        refresh(&mut tracker, &chain, 10, 0, 1_000)
            .coverage
            .uncovered_floor,
        50_086
    );
    assert_eq!(tracker.full_scans, 1);

    // The validated height moving over harder blocks leaves the held
    // reference, and so the run, alone; a rescan with the same reference
    // (after a store revocation) finds the same run.
    let view = refresh(&mut tracker, &chain, 5_000, 0, 1_000);
    assert_eq!(view.best_run, Some((50_011, 50_080)));
    assert_eq!(tracker.full_scans, 1);
    let view = refresh(&mut tracker, &chain, 10, 1, 1_000);
    assert_eq!(tracker.full_scans, 2);
    assert_eq!(view.best_run, Some((50_011, 50_080)));
    assert_eq!(view.coverage.uncovered_floor, 50_086);
    // A changed reference scans again: ten times the work is not met.
    let view = refresh(&mut tracker, &chain, 10, 1, 10_000);
    assert_eq!(tracker.full_scans, 3);
    assert_eq!(view.best_run, None);
    let view = refresh(&mut tracker, &chain, 10, 1, 1_000);
    assert_eq!(tracker.full_scans, 4);
    assert_eq!(view.best_run, Some((50_011, 50_080)));
    // A reorganisation of the blocks last read scans again.
    chain.reorganise(50_086);
    refresh(&mut tracker, &chain, 10, 1, 1_000);
    assert_eq!(tracker.full_scans, 5);
    // A reorganisation that lowers the granted top is seen before the
    // reference is read.
    chain.blocks.truncate(50_050);
    chain.reorganise(50_040);
    chain.push(1, false, false, 1_000);
    let view = tracker.refresh(&chain, 10, chain.tip(), 1, d, now, |coverage, _| {
        assert_eq!(coverage.top_granted, 50_010);
        Some(w_ref)
    });
    assert_eq!(view.coverage.top_granted, 50_010);
    assert_eq!(view.best_run, None, "the run is gone with its blocks");
    assert_eq!(tracker.full_scans, 6);
}

#[test]
fn the_tip_run_records_when_it_was_first_seen_and_last_grew() {
    let t0 = Instant::now();
    let mut chain = Synthetic::new(10, 1_000);
    chain.push(5, false, true, 1_000);
    chain.push(2, true, false, 1_000);
    let mut tracker = CoverageTracker::default();
    let mut refresh = |chain: &Synthetic, now: Instant, revocations: u64| {
        tracker.refresh(chain, 10, chain.tip(), revocations, 60, now, |_, _| {
            Some(work(1_000))
        })
    };
    let run = refresh(&chain, t0, 0).top_run.unwrap();
    assert_eq!(
        (run.start, run.top, run.first_seen, run.last_growth),
        (16, 17, t0, t0)
    );
    let t1 = t0 + Duration::from_secs(30);
    let run = refresh(&chain, t1, 0).top_run.unwrap();
    assert_eq!(run.last_growth, t0, "no growth");
    chain.push(1, true, false, 1_000);
    let run = refresh(&chain, t1, 0).top_run.unwrap();
    assert_eq!((run.top, run.first_seen, run.last_growth), (18, t0, t1));
    // A rescan keeps the times of the same run.
    let t2 = t0 + Duration::from_secs(60);
    let run = refresh(&chain, t2, 1).top_run.unwrap();
    assert_eq!((run.start, run.first_seen, run.last_growth), (16, t0, t1));
    // A provisional block ends it.
    chain.push(1, true, false, 1_000);
    chain.provisional = Some(chain.tip());
    assert_eq!(refresh(&chain, t2, 1).top_run, None);
}

#[test]
fn the_status_row_is_the_first_that_matches() {
    let base = CatchUpFacts {
        tip: 100,
        validated: 40,
        available: 40,
        depth: 60,
        highest_view: Some(130),
        release_fresh: Some(true),
        reference_known: true,
        probe_hit_fresh: true,
        tip_granted: false,
        burial_pending: false,
        top_run_len: 0,
        top_run_work_ok: false,
        uncovered_floor: 40,
    };
    let row = |facts: CatchUpFacts| catch_up_row(&facts);
    let behind = CatchUpFacts {
        highest_view: Some(200),
        ..base
    };
    // Behind on a stale release, or with no voucher found lately.
    assert_eq!(
        row(CatchUpFacts {
            release_fresh: Some(false),
            ..behind
        }),
        ("release_stale", None, 100)
    );
    assert_eq!(
        row(CatchUpFacts {
            probe_hit_fresh: false,
            tip_granted: true,
            ..behind
        }),
        ("single_source", None, 100)
    );
    // Neither while the checkpoint block is not stored yet.
    assert_eq!(
        row(CatchUpFacts {
            release_fresh: None,
            reference_known: false,
            probe_hit_fresh: false,
            available: 100,
            ..behind
        }),
        ("caught_up", None, 60)
    );
    // Not behind: neither applies.
    assert_eq!(
        row(CatchUpFacts {
            release_fresh: Some(false),
            probe_hit_fresh: false,
            tip_granted: true,
            ..base
        }),
        ("catching_up", None, 30)
    );
    assert_eq!(
        row(CatchUpFacts {
            tip_granted: true,
            highest_view: None,
            ..base
        }),
        ("catching_up", None, 0)
    );
    assert_eq!(
        row(CatchUpFacts {
            available: 100,
            ..behind
        }),
        ("caught_up", None, 60)
    );
    // The newest blocks are being checked.
    let forming = CatchUpFacts {
        burial_pending: true,
        top_run_len: 20,
        ..base
    };
    assert_eq!(row(forming), ("checking_newest", None, 40));
    // A run of the depth with too little work is a difficulty, not a check
    // still running.
    assert_eq!(
        row(CatchUpFacts {
            top_run_len: 60,
            ..forming
        }),
        ("waiting_for_check", Some("difficulty"), 60)
    );
    assert_eq!(
        row(CatchUpFacts {
            top_run_len: 75,
            burial_pending: false,
            ..base
        }),
        ("waiting_for_check", Some("difficulty"), 60)
    );
    // Earlier blocks first; the rest is "other".
    assert_eq!(
        row(CatchUpFacts {
            top_run_len: 75,
            uncovered_floor: 70,
            ..base
        }),
        ("waiting_for_check", Some("earlier_blocks"), 30)
    );
    assert_eq!(
        row(CatchUpFacts {
            top_run_len: 75,
            top_run_work_ok: true,
            ..base
        }),
        ("waiting_for_check", Some("other"), 60)
    );
    assert_eq!(
        row(CatchUpFacts {
            top_run_len: 75,
            reference_known: false,
            ..base
        }),
        ("waiting_for_check", Some("other"), 60)
    );
    assert_eq!(row(base), ("waiting_for_check", Some("other"), 60));
}

#[test]
fn the_available_height_waits_for_a_qualifying_run_on_top_and_does_not_fall_back() {
    let wallet = WalletSetup {
        total: 12,
        ..WalletSetup::new("catch-up-available")
    }
    .open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    for index in 2..5 {
        wallet.fetch(index, from).unwrap();
        assert_eq!(wallet.available(), 2);
    }
    for index in 5..7 {
        wallet.fetch(index, from).unwrap();
        assert_eq!(wallet.status(index), Some(WorkStatus::Verified));
        assert_eq!(wallet.available(), 2, "{index}");
    }
    wallet.fetch(7, from).unwrap();
    assert_eq!(wallet.available(), 8);
    {
        // The exchange view stays at the validated height.
        let node = wallet.node.lock().unwrap();
        assert_eq!(node.work_validated_height(), Some(2));
        assert_eq!(node.exchange_served_cap(), 2);
        assert!(matches!(
            node.require_exchange_tip_checked(),
            Err(NodeError::WorkCheckPending)
        ));
    }
    // A later grant on top (a wallet waking up) leaves it where it was.
    wallet.vouch(Q, 12);
    wallet.fetch(8, wallet.from(P, 12)).unwrap();
    assert!(wallet.granted(8));
    assert_eq!(wallet.available(), 8);
    assert!(wallet.status_at(Instant::now()).granted_above_available);
    // The validated height while admission is halted.
    set_halted(&wallet.node.lock().unwrap(), true);
    assert_eq!(wallet.available(), 2);
    set_halted(&wallet.node.lock().unwrap(), false);
    assert_eq!(wallet.available(), 8);
    // And once any block above the validated height is unsettled, not only
    // the one just above it.
    wallet.mark_unsettled(4);
    assert_eq!(wallet.available(), 2);
    wallet.close();
}

#[test]
fn the_reference_is_held_while_a_granted_block_lies_above_the_validated_height() {
    let wallet = WalletSetup::new("catch-up-held-reference").open();
    let pow = cmfd_consensus::block_work(wallet.chain[1].challenge.target).unwrap();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    wallet.fetch(2, from).unwrap();
    wallet.fetch(3, from).unwrap();
    let catch_up = wallet.catch_up();
    catch_up.set_reference_work(Some(pow + 1));
    assert_eq!(
        wallet.node.lock().unwrap().wallet_reference_work(),
        Some(pow + 1)
    );
    // The background check passes the granted blocks: read again.
    let mut backlog = WorkBacklog::new();
    for _ in 0..2 {
        assert_eq!(
            backlog.run_turn(&wallet.node, &|| false).unwrap(),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
        );
    }
    assert_eq!(wallet.validated(), 4);
    assert_eq!(
        wallet.node.lock().unwrap().wallet_reference_work(),
        Some(pow)
    );
    drop(catch_up);
    wallet.close();
}

#[test]
fn blocks_stored_without_a_grant_or_a_check_are_never_buried() {
    // Stored by an earlier release: 3..=5 above the checkpoint.
    let wallet = WalletSetup {
        stored: 5,
        stored_before_rule: true,
        ..WalletSetup::new("catch-up-pre-upgrade")
    }
    .open();
    let now = Instant::now();
    let catch_up = wallet.catch_up();
    assert_eq!(catch_up.coverage().uncovered_floor, 5);
    assert_eq!(wallet.available(), 2);
    let earlier = |status: WalletCatchUpStatus| {
        assert_eq!(
            (status.state, status.reason, status.blocks_left),
            ("waiting_for_check", Some("earlier_blocks"), 3),
            "{status:?}"
        );
        assert!(!status.granted_above_available);
    };
    earlier(wallet.status_at(now));
    // Behind fresh sources, with a probe hit; or after their views are old.
    wallet.vouch(Q, 9);
    catch_up.note_view(P, 9, &[], now);
    catch_up.note_probe_hit(now);
    earlier(wallet.status_at(now));
    earlier(wallet.status_at(now + Duration::from_secs(11 * 60)));
    // Checked blocks on top do not make them available, and the background
    // check is never put off.
    for index in 5..8 {
        wallet.fetch(index, wallet.strict()).unwrap();
        assert_eq!(wallet.status(index), Some(WorkStatus::Verified));
    }
    assert_eq!(wallet.available(), 2);
    assert!(!wallet.pending(Instant::now()));
    assert_eq!(wallet.next_checked(Instant::now()), Some(3));
    earlier(wallet.status_at(Instant::now()));
    // Until the validated height passes them.
    let mut backlog = WorkBacklog::new();
    while backlog.run_turn(&wallet.node, &|| false).unwrap() != WorkBacklogTurn::Idle {}
    assert_eq!(wallet.validated(), 8);
    assert_eq!(wallet.available(), 8);
    drop(catch_up);
    wallet.close();

    // A block log that gained blocks with the catch-up off (an earlier
    // release run in between): the grant file is still valid, but the new
    // blocks are not covered by it.
    let mut wallet = WalletSetup {
        total: 9,
        ..WalletSetup::new("catch-up-copied-log")
    }
    .open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    wallet.fetch(2, from).unwrap();
    wallet.fetch(3, from).unwrap();
    let rule = wallet.rule();
    wallet.stop();
    {
        let mut plain = Node::open_with_profile(&wallet.path, DEVNET_PROFILE).unwrap();
        assert!(plain.work_gate.is_none());
        for block in &wallet.chain[4..6] {
            plain.submit_block(block.clone(), wallet.now).unwrap();
        }
    }
    wallet.start(rule, true);
    assert!(wallet.granted(2) && wallet.granted(3));
    let coverage = wallet.catch_up().coverage();
    assert_eq!((coverage.uncovered_floor, coverage.top_granted), (6, 4));
    for index in 6..9 {
        wallet.fetch(index, wallet.strict()).unwrap();
    }
    assert_eq!(wallet.available(), 2);
    wallet.close();
}

#[test]
fn a_failed_unsettled_write_stops_grants_and_holds_the_available_height() {
    let wallet = WalletSetup::new("catch-up-store-failed").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    wallet.fetch(2, from).unwrap();
    wallet.fetch(3, from).unwrap();
    // The background check finds the first granted block wrong, and its
    // record cannot be written.
    wallet.engine.answer(&wallet.chain[2], false);
    {
        let node = wallet.node.lock().unwrap();
        let store = node.work_gate.as_ref().unwrap().store.clone().unwrap();
        store.lock().unwrap().fail_next_write();
    }
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&wallet.node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)
    );
    let catch_up = wallet.catch_up();
    assert!(catch_up.store_failed());
    {
        let node = wallet.node.lock().unwrap();
        assert_eq!(node.work_rule_status().unwrap().unsettled_height, None);
    }
    assert_checked(&wallet, 4, from, "store failed");
    assert_eq!(wallet.available(), 2);
    let now = Instant::now();
    catch_up.note_probe_hit(now);
    let status = wallet.status_at(now);
    assert_eq!(
        (status.state, status.reason),
        ("waiting_for_check", Some("other")),
        "{status:?}"
    );
    drop(catch_up);
    wallet.close();
}

#[test]
fn the_wallet_backlog_ascends_and_stops_at_the_lowest_unsettled_block() {
    let mut wallet = WalletSetup {
        stored: 8,
        stored_before_rule: true,
        ..WalletSetup::new("catch-up-backlog-order")
    }
    .open();
    wallet.engine.answer(&wallet.chain[4], false);
    let mut backlog = WorkBacklog::new();
    for height in 3..5 {
        assert_eq!(wallet.next_checked(Instant::now()), Some(height));
        assert_eq!(
            backlog.run_turn(&wallet.node, &|| false).unwrap(),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
        );
        assert_eq!(wallet.validated(), height);
    }
    assert_eq!(wallet.next_checked(Instant::now()), Some(5));
    assert_eq!(
        backlog.run_turn(&wallet.node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)
    );
    // Nothing above it, and it waits for its retry.
    assert_eq!(wallet.next_checked(Instant::now()), None);
    assert_eq!(
        backlog.run_turn(&wallet.node, &|| false).unwrap(),
        WorkBacklogTurn::Idle
    );
    // Retried once after a start, then the same.
    wallet.reopen(true);
    assert_eq!(wallet.next_checked(Instant::now()), Some(5));
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&wallet.node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)
    );
    assert_eq!(wallet.next_checked(Instant::now()), None);
    // With the catch-up off, the blocks above it are checked.
    wallet.reopen(false);
    let mut backlog = WorkBacklog::new();
    assert_eq!(
        backlog.run_turn(&wallet.node, &|| false).unwrap(),
        WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled)
    );
    assert_eq!(wallet.next_checked(Instant::now()), Some(6));
    wallet.close();
}

#[test]
fn the_wallet_backlog_peels_side_branches_from_their_lowest_block() {
    for honest in [false, true] {
        let label = if honest {
            "catch-up-peel-honest"
        } else {
            "catch-up-peel-wrong"
        };
        let wallet = WalletSetup::new(label).open();
        wallet.vouch(Q, 8);
        let from = wallet.from(P, 8);
        for index in 2..5 {
            wallet.fetch(index, from).unwrap();
        }
        // A heavier branch from the checkpoint, followed strictly.
        let (fork_path, mut fork) = devnet(&format!("{label}-fork"));
        for block in &wallet.chain[..2] {
            fork.submit_block(block.clone(), wallet.now).unwrap();
        }
        let branch = (0..4)
            .map(|offset| {
                fork.mine_once(
                    crate::default_miner_destination(),
                    wallet.now + 100 + offset,
                    10_000,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        drop(fork);
        clean_test_dir(&fork_path);
        let heavier = FetchedFrom {
            heavier: true,
            ..wallet.strict()
        };
        for block in &branch {
            wallet.engine.answer(block, true);
            wallet.fetch_block(block, heavier).unwrap();
        }
        assert_eq!(
            wallet.node.lock().unwrap().state.tip(),
            branch[3].block_id(),
            "{label}"
        );
        assert_eq!(wallet.validated(), 6, "{label}");
        // The granted blocks are side blocks now: only the lowest is offered.
        wallet.engine.answer(&wallet.chain[2], honest);
        let mut backlog = WorkBacklog::new();
        for index in 2..5 {
            let next = wallet
                .node
                .lock()
                .unwrap()
                .next_work_backlog_block(Instant::now());
            assert_eq!(
                next,
                Some((index as u64 + 1, wallet.chain[index].block_id())),
                "{label}"
            );
            let turn = backlog.run_turn(&wallet.node, &|| false).unwrap();
            if !honest {
                assert_eq!(
                    turn,
                    WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled),
                    "{label}"
                );
                // Its descendants are never offered while it stands.
                assert_eq!(wallet.next_checked(Instant::now()), None, "{label}");
                break;
            }
            assert_eq!(
                turn,
                WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified),
                "{label}"
            );
        }
        assert_eq!(
            backlog.run_turn(&wallet.node, &|| false).unwrap(),
            WorkBacklogTurn::Idle,
            "{label}"
        );
        assert_eq!(wallet.engine.block_calls(), if honest { 7 } else { 5 });
        wallet.close();
    }
}

#[test]
fn the_backlog_gives_way_only_to_a_growing_young_run_at_the_tip() {
    let wallet = WalletSetup {
        total: 30,
        ..WalletSetup::new("catch-up-burial")
    }
    .open();
    wallet.vouch(Q, 30);
    let from = wallet.from(P, 14);
    let t0 = Instant::now();
    for index in 2..11 {
        wallet.fetch(index, from).unwrap();
        // While the download lasts, the background check runs.
        assert!(!wallet.pending(t0));
    }
    assert_eq!(wallet.next_checked(t0), Some(3));
    // The run at the tip needs 20 blocks from here.
    wallet.catch_up().set_depth(20);
    wallet.fetch(11, wallet.strict()).unwrap();
    assert!(wallet.pending(t0));
    assert_eq!(wallet.next_checked(t0), None);
    // A stall of more than two minutes ends it.
    let stalled = t0 + TOP_RUN_STALL + Duration::from_secs(1);
    assert!(!wallet.pending(stalled));
    assert_eq!(wallet.next_checked(stalled), Some(3));
    // Growth keeps it for at most half an hour.
    for step in 1..=17_u64 {
        wallet.fetch(11 + step as usize, wallet.strict()).unwrap();
        let at = t0 + Duration::from_secs(110 * step);
        if step == 3 {
            // Not while burial cannot happen.
            set_halted(&wallet.node.lock().unwrap(), true);
            assert!(!wallet.pending(at));
            set_halted(&wallet.node.lock().unwrap(), false);
        }
        assert_eq!(
            wallet.pending(at),
            Duration::from_secs(110 * step) < TOP_RUN_CAP,
            "{step}"
        );
    }
    assert_eq!(wallet.next_checked(t0 + TOP_RUN_CAP), Some(3));
    let capped = wallet.status_at(t0 + TOP_RUN_CAP);
    assert_eq!(
        (capped.state, capped.reason),
        ("waiting_for_check", Some("other")),
        "{capped:?}"
    );
    wallet.close();
}

#[test]
fn a_restart_mid_catch_up_finds_the_same_available_height() {
    let mut wallet = WalletSetup::new("catch-up-restart").open();
    wallet.vouch(Q, 8);
    let from = wallet.from(P, 8);
    for index in 2..6 {
        wallet.fetch(index, from).unwrap();
    }
    assert_eq!(wallet.available(), 2);
    let calls = wallet.engine.block_calls();
    wallet.reopen(true);
    assert_eq!(wallet.engine.block_calls(), calls, "no engine runs at open");
    assert!((2..5).all(|index| wallet.granted(index)));
    assert_eq!(wallet.catch_up().coverage().uncovered_floor, 2);
    assert_eq!(wallet.available(), 2);
    assert!(wallet.pending(Instant::now()), "the tip run is found again");
    for index in 6..8 {
        wallet.fetch(index, wallet.strict()).unwrap();
    }
    assert_eq!(wallet.available(), 8);
    let tip = wallet.node.lock().unwrap().state.tip();
    wallet.reopen(true);
    assert_eq!(wallet.available(), 8);
    // The background check ascends to the tip.
    let mut backlog = WorkBacklog::new();
    for height in 3..6 {
        assert_eq!(
            backlog.run_turn(&wallet.node, &|| false).unwrap(),
            WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)
        );
        assert_eq!(wallet.validated(), if height == 5 { 8 } else { height });
    }
    assert_eq!(wallet.node.lock().unwrap().state.tip(), tip);
    assert_eq!(wallet.available(), 8);
    wallet.close();
}

#[test]
fn granting_one_more_block_over_a_long_stored_region_reads_only_that_block() {
    // Blocks an earlier release stored above the checkpoint: about 2,000
    // with CMFD_CATCH_UP_LONG set (mining them takes minutes in a debug
    // build), 100 otherwise.
    let stored = if std::env::var_os("CMFD_CATCH_UP_LONG").is_some() {
        2_000
    } else {
        100
    };
    let wallet = WalletSetup {
        total: stored as u64 + 4,
        stored,
        stored_before_rule: true,
        minute_apart: true,
        ..WalletSetup::new("catch-up-long-region")
    }
    .open();
    let catch_up = wallet.catch_up();
    assert_eq!(wallet.available(), 2);
    assert_eq!(catch_up.coverage().uncovered_floor, stored as u64);
    let (scans, visits) = catch_up.coverage_reads();
    wallet.vouch(Q, stored as u64 + 4);
    wallet
        .fetch(stored, wallet.from(P, stored as u64 + 4))
        .unwrap();
    assert!(wallet.granted(stored));
    assert_eq!(wallet.available(), 2);
    let (scans_after, visits_after) = catch_up.coverage_reads();
    assert_eq!(scans_after, scans, "no full scan");
    assert!(visits_after - visits <= 6, "{}", visits_after - visits);
    assert_eq!(catch_up.coverage().top_granted, stored as u64 + 1);
    drop(catch_up);
    wallet.close();
}

#[test]
fn the_catch_up_status_reports_a_defined_row_for_every_case() {
    // Downloading, then checking the newest blocks, then caught up.
    let wallet = WalletSetup::new("catch-up-status").open();
    let catch_up = wallet.catch_up();
    let now = Instant::now();
    wallet.vouch(Q, 8);
    catch_up.note_view(P, 8, &[], now);
    catch_up.note_probe_hit(now);
    let from = wallet.from(P, 8);
    for index in 2..5 {
        wallet.fetch(index, from).unwrap();
    }
    let status = wallet.status_at(now);
    assert_eq!(
        status,
        WalletCatchUpStatus {
            state: "catching_up",
            reason: None,
            available_height: 2,
            blocks_left: 3,
            newest_checked: 0,
            newest_needed: D,
            sources_answering: 2,
            granted_above_available: true,
        }
    );
    // Halted while the tip is granted: still the download row.
    set_halted(&wallet.node.lock().unwrap(), true);
    assert_eq!(wallet.status_at(now).state, "catching_up");
    set_halted(&wallet.node.lock().unwrap(), false);
    wallet.fetch(5, from).unwrap();
    let status = wallet.status_at(now);
    assert_eq!(
        (status.state, status.blocks_left, status.newest_checked),
        ("checking_newest", 2, 1),
        "{status:?}"
    );
    // Halted with a checked tip.
    set_halted(&wallet.node.lock().unwrap(), true);
    let status = wallet.status_at(now);
    assert_eq!(
        (status.state, status.reason, status.blocks_left),
        ("waiting_for_check", Some("other"), 4)
    );
    set_halted(&wallet.node.lock().unwrap(), false);
    // A stalled run past the cap.
    let late = now + TOP_RUN_CAP + Duration::from_secs(1);
    let status = wallet.status_at(late);
    assert_eq!(
        (status.state, status.reason),
        ("waiting_for_check", Some("other"))
    );
    assert_eq!(status.sources_answering, 0, "the views are old by then");
    for index in 6..8 {
        wallet.fetch(index, from).unwrap();
    }
    let status = wallet.status_at(now);
    assert_eq!(
        (
            status.state,
            status.available_height,
            status.blocks_left,
            status.newest_checked,
            status.granted_above_available
        ),
        ("caught_up", 8, 6, 3, false)
    );
    // Held by an unsettled block with a checked tip.
    wallet.mark_unsettled(3);
    let status = wallet.status_at(now);
    assert_eq!(
        (status.state, status.reason, status.available_height),
        ("waiting_for_check", Some("other"), 2)
    );
    drop(catch_up);
    wallet.close();

    // Behind, and no source in another group listed anything new lately:
    // with one source answering, or two where the other group's is pruned.
    let wallet = WalletSetup::new("catch-up-status-single").open();
    let catch_up = wallet.catch_up();
    let now = Instant::now();
    catch_up.note_view(P, 8, &[], now);
    let status = wallet.status_at(now);
    assert_eq!(
        (status.state, status.blocks_left, status.sources_answering),
        ("single_source", 6, 1)
    );
    catch_up.note_view(Q, 8, &[], now);
    assert_eq!(wallet.status_at(now).sources_answering, 2);
    assert_eq!(wallet.status_at(now).state, "single_source");
    catch_up.note_probe_hit(now);
    assert_eq!(wallet.status_at(now).state, "caught_up");
    // A failed engine.
    wallet
        .engine
        .fail_next(WorkEngineError::Integrity("layer 1".to_owned()));
    let unvouched = FetchedFrom {
        catch_up: None,
        ..wallet.from(P, 8)
    };
    assert!(wallet.fetch(2, unvouched).is_err());
    assert_eq!(wallet.checker.engine_state(), WorkEngineState::Failed);
    assert_eq!(wallet.status_at(now).state, "caught_up");
    drop(catch_up);
    wallet.close();

    // Before the checkpoint block is stored there is no probe to judge by.
    let wallet = WalletSetup {
        stored: 1,
        ..WalletSetup::new("catch-up-status-pre-checkpoint")
    }
    .open();
    let now = Instant::now();
    wallet.catch_up().note_view(P, 8, &[], now);
    assert_eq!(wallet.status_at(now).state, "caught_up");
    wallet.close();

    // A stale release, while behind.
    let now_unix = unix_time_seconds().unwrap();
    let wallet = WalletSetup {
        checkpoint_mined_at: Some(now_unix - 61 * 24 * 60 * 60),
        ..WalletSetup::new("catch-up-status-stale")
    }
    .open();
    let now = Instant::now();
    assert_eq!(wallet.status_at(now).state, "caught_up");
    wallet.catch_up().note_view(P, 8, &[], now);
    let status = wallet.status_at(now);
    assert_eq!((status.state, status.blocks_left), ("release_stale", 6));
    wallet.close();

    // Engines still qualifying: nothing above the checkpoint is admitted.
    let wallet = WalletSetup {
        known_answers_fail: true,
        ..WalletSetup::new("catch-up-status-qualifying")
    }
    .open();
    assert_eq!(wallet.checker.engine_state(), WorkEngineState::Qualifying);
    assert_eq!(wallet.status_at(Instant::now()).state, "caught_up");
    wallet.close();

    // With the catch-up off there is no such part.
    let mut wallet = WalletSetup::new("catch-up-status-off").open();
    wallet.reopen(false);
    assert!(
        wallet
            .node
            .lock()
            .unwrap()
            .work_rule_status()
            .unwrap()
            .wallet_catch_up
            .is_none()
    );
    wallet.close();
}
