//! Sync sessions of a desktop wallet catching up, on loopback and Devnet
//! with a scripted work engine: the corroborating connections, the depth
//! limit and the sessions with peers that are not sources.

use super::*;
use crate::submit_shared_block;
use crate::tests::clean_test_dir;
use crate::work_gate::test_support::{ScriptedEngine, install};
use crate::work_gate::tests::{cpu, devnet, mine};
use crate::work_gate::{CatchUpSource, STALE_AFTER, WalletCatchUp};
use cmfd_consensus::ForgeMatrixV4WorkRule;

/// The catch-up depth the tests use.
const D: u64 = 3;
const WALLET_NONCE: [u8; 32] = [0x71; 32];

/// Blocks mined one second apart from `start` on a scratch node.
fn chain_from(label: &str, parents: &[Block], count: u64, start: u64) -> Vec<Block> {
    let (path, mut miner) = devnet(label);
    for block in parents {
        miner.submit_block(block.clone(), start).unwrap();
    }
    let blocks = mine(&mut miner, count, start);
    drop(miner);
    clean_test_dir(&path);
    blocks
}

fn chain(label: &str, count: u64) -> Vec<Block> {
    chain_from(label, &[], count, unix_time_seconds().unwrap())
}

fn ids(blocks: &[Block]) -> Vec<[u8; 32]> {
    blocks.iter().map(Block::block_id).collect()
}

/// A node on loopback holding `blocks`, with the default peer limits.
struct Source {
    path: PathBuf,
    node: Arc<Mutex<Node>>,
    listener: Option<InboundPeerHandle>,
    addr: SocketAddr,
}

impl Source {
    fn serve(label: &str, blocks: &[Block], nonce: u8) -> Self {
        Self::serve_with(label, blocks, nonce, PeerLimits::default())
    }

    fn serve_with(label: &str, blocks: &[Block], nonce: u8, limits: PeerLimits) -> Self {
        let (path, node) = devnet(label);
        let node = Arc::new(Mutex::new(node));
        let now = unix_time_seconds().unwrap();
        for block in blocks {
            submit_shared_block(&node, block.clone(), now).unwrap();
        }
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let listener =
            spawn_inbound_listener_inner(Arc::clone(&node), socket, limits, Some([nonce; 32]))
                .unwrap();
        Self {
            path,
            node,
            listener: Some(listener),
            addr,
        }
    }

    /// Inbound sessions that got past the hello, and inbound sessions that
    /// failed.
    fn sessions(&self) -> (u64, u64) {
        self.node
            .lock()
            .unwrap()
            .peer_observations()
            .into_iter()
            .filter(|peer| peer.direction == PeerDirection::Inbound)
            .fold((0, 0), |(ok, failed), peer| {
                (ok + peer.successful_sessions, failed + peer.failed_sessions)
            })
    }

    fn hello(&self, nonce: u8) -> PeerHello {
        with_nonce(self.node.lock().unwrap().peer_hello(), Some([nonce; 32]))
    }

    fn close(mut self) {
        self.listener.take().unwrap().stop().unwrap();
        drop(self.node);
        clean_test_dir(&self.path);
    }
}

/// What a scripted peer does with each connection.
#[derive(Clone)]
enum Script {
    /// Keeps it open and never answers.
    Blackhole,
    /// Closes it before its hello.
    CloseBeforeHello,
    /// Answers the hello and one headers request, each after `delay`, with
    /// `block_ids`.
    Answer {
        delay: Duration,
        block_ids: Vec<[u8; 32]>,
    },
}

/// A listener on loopback that follows a [`Script`] and counts the
/// connections it accepts.
struct ScriptedPeer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ScriptedPeer {
    fn new(hello: PeerHello, script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_accepted, thread_stop) = (Arc::clone(&accepted), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            let mut held = Vec::new();
            let mut workers = Vec::new();
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_accepted.fetch_add(1, Ordering::SeqCst);
                        stream.set_nonblocking(false).unwrap();
                        match script.clone() {
                            Script::Blackhole => held.push(stream),
                            Script::CloseBeforeHello => {
                                let _ = stream.shutdown(Shutdown::Both);
                            }
                            Script::Answer { delay, block_ids } => {
                                workers.push(thread::spawn(move || {
                                    let _ = answer(stream, hello, delay, block_ids);
                                }));
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("scripted peer: {error}"),
                }
            }
            drop(held);
            for worker in workers {
                let _ = worker.join();
            }
        });
        Self {
            addr,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn close(mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn answer(
    stream: TcpStream,
    hello: PeerHello,
    delay: Duration,
    block_ids: Vec<[u8; 32]>,
) -> Result<(), PeerError> {
    let session = PeerSession::new(hello, PeerLimits::default())?;
    let mut connection = PeerConnection::from_stream(stream, session)?;
    connection.receive()?;
    thread::sleep(delay);
    connection.send_hello()?;
    connection.receive()?;
    thread::sleep(delay);
    connection.send(PeerMessage::Inventory { block_ids })?;
    while connection.receive().is_ok() {}
    Ok(())
}

/// An address nothing listens on.
fn closed_address() -> SocketAddr {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

/// A wallet node under a rule that pins block `checkpoint` of `chain`, with
/// the first `stored` blocks committed and every block of `chain` answered
/// as honest.
struct Wallet {
    path: PathBuf,
    node: Arc<Mutex<Node>>,
    engine: Arc<ScriptedEngine>,
}

impl Wallet {
    fn open(label: &str, chain: &[Block], checkpoint: u64, stored: usize) -> Self {
        let (path, mut node) = devnet(label);
        let rule = ForgeMatrixV4WorkRule::with_pinned_heights(
            checkpoint,
            chain[checkpoint as usize - 1].block_id(),
            [],
        )
        .unwrap();
        let engine = cpu();
        for block in chain {
            engine.answer(block, true);
        }
        install(&mut node, Some(rule), Some(engine.clone()), None);
        let node = Arc::new(Mutex::new(node));
        let now = unix_time_seconds().unwrap();
        for block in &chain[..stored] {
            submit_shared_block(&node, block.clone(), now).unwrap();
        }
        Self { path, node, engine }
    }

    /// Turns the catch-up on over `sources` at depth [`D`]; whether it is on.
    fn enable(&self, sources: &[(SocketAddr, u8)]) -> bool {
        let sources = sources
            .iter()
            .map(|&(addr, group)| CatchUpSource { addr, group })
            .collect();
        let mut node = self.node.lock().unwrap();
        let on = node.enable_wallet_catch_up(sources).unwrap();
        if on {
            node.wallet_catch_up().unwrap().set_depth(D);
        }
        on
    }

    fn catch_up(&self) -> Arc<WalletCatchUp> {
        self.node.lock().unwrap().wallet_catch_up().unwrap()
    }

    fn sync(&self, addr: SocketAddr) -> Result<SyncReport, P2pError> {
        self.sync_with(addr, PeerLimits::default())
    }

    /// One session with the peer at `addr`, as the wallet's poller runs it
    /// with a bootstrap peer.
    fn sync_with(&self, addr: SocketAddr, limits: PeerLimits) -> Result<SyncReport, P2pError> {
        sync_from_peer_once_inner_with_policy(
            Arc::clone(&self.node),
            addr,
            limits,
            PeerAddressPolicy::PrivateOnly,
            Some(WALLET_NONCE),
            None,
            true,
        )
    }

    fn height(&self) -> u64 {
        self.node.lock().unwrap().peer_hello().height
    }

    fn tip(&self) -> [u8; 32] {
        self.node.lock().unwrap().state.tip()
    }

    fn holds(&self, block: &Block) -> bool {
        self.node.lock().unwrap().contains_block(block.block_id())
    }

    /// The heights of `chain` whose blocks have a grant record.
    fn granted(&self, chain: &[Block]) -> Vec<u64> {
        let catch_up = self.catch_up();
        (1..=chain.len() as u64)
            .filter(|height| catch_up.recorded_grant(&chain[*height as usize - 1].block_id()))
            .collect()
    }

    fn close(self) {
        drop(self.node);
        clean_test_dir(&self.path);
    }
}

#[test]
fn a_source_session_admits_blocks_corroborated_deep_enough_and_checks_the_newest() {
    let chain = chain("catch-up-session-chain", 10);
    let p = Source::serve("catch-up-session-p", &chain, 0x51);
    let q = Source::serve("catch-up-session-q", &chain[..9], 0x52);
    let wallet = Wallet::open("catch-up-session", &chain, 2, 2);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));

    let report = wallet.sync(p.addr).unwrap();
    assert_eq!(report.accepted_blocks, 8);
    assert_eq!(wallet.height(), 10);
    // Up to min(10, 9) - D without an engine run; the rest are checked.
    assert_eq!(wallet.granted(&chain), vec![3, 4, 5, 6]);
    assert_eq!(wallet.engine.block_calls(), 4);
    assert_eq!(q.sessions(), (1, 0), "one corroborating connection");
    let catch_up = wallet.catch_up();
    let counts = catch_up.counts();
    assert_eq!(counts.granted, 4);
    assert_eq!(counts.refused(2), 1, "height 7 is above Q's limit");
    assert_eq!((counts.probe_attempts, counts.probe_misses), (1, 0));
    assert_eq!(catch_up.fresh_views(Instant::now()), (Some(10), 2));
    // The session's summary was logged; the next waits a minute.
    assert!(!catch_up.log_session_summary(0, 10, None, Instant::now()));
    drop(catch_up);
    wallet.close();
    p.close();
    q.close();
}

#[test]
fn without_two_groups_or_from_another_peer_every_block_is_checked() {
    let chain = chain("catch-up-strict-chain", 8);
    let p = Source::serve("catch-up-strict-p", &chain, 0x51);
    let q = Source::serve("catch-up-strict-q", &chain, 0x52);

    // Two sources in one group: the catch-up stays off.
    let wallet = Wallet::open("catch-up-strict-one-group", &chain, 2, 2);
    assert!(!wallet.enable(&[(p.addr, 0), (q.addr, 0)]));
    wallet.sync(p.addr).unwrap();
    assert_eq!(wallet.engine.block_calls(), 6);
    assert_eq!(q.sessions(), (0, 0));
    wallet.close();

    // Off.
    let wallet = Wallet::open("catch-up-strict-off", &chain, 2, 2);
    wallet.sync(p.addr).unwrap();
    assert_eq!(wallet.engine.block_calls(), 6);
    assert_eq!(q.sessions(), (0, 0));
    wallet.close();

    // On, from a peer that is not a source: nothing shows the wallet behind.
    let other = Source::serve("catch-up-strict-other", &chain, 0x53);
    let wallet = Wallet::open("catch-up-strict-unlisted", &chain, 2, 2);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));
    let before = (p.sessions(), q.sessions());
    let report = wallet.sync(other.addr).unwrap();
    assert_eq!(report.accepted_blocks, 6);
    assert_eq!(wallet.engine.block_calls(), 6);
    assert!(wallet.granted(&chain).is_empty());
    assert_eq!((p.sessions(), q.sessions()), before);
    assert_eq!(q.sessions(), (0, 0));
    assert_eq!(wallet.catch_up().counts().probe_attempts, 0);
    wallet.close();
    other.close();
    p.close();
    q.close();
}

#[test]
fn with_the_other_group_down_a_session_asks_no_source_of_its_own_group() {
    let chain = chain("catch-up-group-down-chain", 8);
    let s0 = Source::serve("catch-up-group-down-s0", &chain, 0x51);
    let s1 = Source::serve("catch-up-group-down-s1", &chain, 0x52);
    let wallet = Wallet::open("catch-up-group-down", &chain, 2, 2);
    assert!(wallet.enable(&[(s0.addr, 0), (s1.addr, 0), (closed_address(), 1)]));

    let report = wallet.sync(s0.addr).unwrap();
    assert_eq!(report.accepted_blocks, 6);
    assert_eq!(wallet.engine.block_calls(), 6);
    assert!(wallet.granted(&chain).is_empty());
    assert_eq!(s1.sessions(), (0, 0), "its own group is not asked");
    let counts = wallet.catch_up().counts();
    assert_eq!((counts.probe_attempts, counts.probe_failures), (1, 1));
    assert_eq!(counts.refused(2), 3, "heights 3 to 5 had no voucher");
    wallet.close();
    s0.close();
    s1.close();
}

#[test]
fn sources_polled_in_turn_each_get_their_blocks_corroborated() {
    // Four blocks a session and four ids an inventory, as mainnet's 16, so
    // three rounds of three sources stay far behind and a source's own sync
    // cursor falls more than one inventory behind the tip; the fourth round
    // reaches the tip.
    let chain = chain("catch-up-turns-chain", 44);
    let limits = PeerLimits {
        max_blocks_per_session: 4,
        ..PeerLimits::default()
    };
    let sources = [
        Source::serve_with("catch-up-turns-s0", &chain, 0x51, limits),
        Source::serve_with("catch-up-turns-s1", &chain, 0x52, limits),
        Source::serve_with("catch-up-turns-s2", &chain, 0x53, limits),
    ];
    let wallet = Wallet::open("catch-up-turns", &chain, 2, 2);
    assert!(wallet.enable(&[
        (sources[0].addr, 0),
        (sources[1].addr, 0),
        (sources[2].addr, 1),
    ]));
    let catch_up = wallet.catch_up();
    for round in 0..3 {
        for (index, source) in sources.iter().enumerate() {
            let granted = catch_up.counts().granted;
            let report = wallet.sync_with(source.addr, limits).unwrap();
            assert_eq!(report.accepted_blocks, 4, "round {round}, source {index}");
            assert_eq!(
                catch_up.counts().granted,
                granted + 4,
                "round {round}, source {index}"
            );
            assert_eq!(
                wallet.engine.block_calls(),
                0,
                "round {round}, source {index}"
            );
        }
    }
    assert_eq!(wallet.height(), 38);
    for source in &sources {
        wallet.sync_with(source.addr, limits).unwrap();
    }
    assert_eq!(wallet.height(), 44);
    assert_eq!(wallet.granted(&chain), (3..=41).collect::<Vec<_>>());
    assert_eq!(wallet.engine.block_calls(), D as usize, "only the newest");
    drop(catch_up);
    wallet.close();
    for source in sources {
        source.close();
    }
}

#[test]
fn a_source_on_another_branch_corroborates_nothing_and_its_blocks_are_checked() {
    let now = unix_time_seconds().unwrap();
    let chain = chain_from("catch-up-branch-a", &[], 10, now);
    let branch = chain_from("catch-up-branch-b", &chain[..2], 10, now + 1_000);
    let mut b_chain = chain[..2].to_vec();
    b_chain.extend(branch.iter().cloned());
    let p = Source::serve("catch-up-branch-p", &chain, 0x51);
    let q = Source::serve("catch-up-branch-q", &b_chain, 0x52);
    let wallet = Wallet::open("catch-up-branch", &chain, 2, 2);
    for block in &branch {
        wallet.engine.answer(block, false);
    }
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));

    // Q lists its own branch, which vouches for none of P's blocks.
    wallet.sync(p.addr).unwrap();
    assert_eq!(wallet.height(), 10);
    assert_eq!(wallet.engine.block_calls(), 8);
    // Q's heavier branch is checked, and its first block is refused.
    assert!(wallet.sync(q.addr).is_err());
    assert!(!wallet.holds(&branch[0]));
    assert_eq!(wallet.tip(), chain[9].block_id());
    assert!(wallet.granted(&chain).is_empty() && wallet.granted(&b_chain).is_empty());
    assert_eq!(wallet.catch_up().counts().granted, 0);
    wallet.close();
    p.close();
    q.close();
}

#[test]
fn a_voucher_reporting_a_greater_height_does_not_raise_the_sources_limit() {
    let chain = chain("catch-up-inflated-chain", 10);
    let p = Source::serve("catch-up-inflated-p", &chain, 0x51);
    let mut hello = p.hello(0x52);
    hello.height = 1_000;
    let q = ScriptedPeer::new(
        hello,
        Script::Answer {
            delay: Duration::ZERO,
            block_ids: ids(&chain[2..]),
        },
    );
    let wallet = Wallet::open("catch-up-inflated", &chain, 2, 2);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));
    wallet.sync(p.addr).unwrap();
    assert_eq!(wallet.granted(&chain), vec![3, 4, 5, 6, 7]);
    assert_eq!(wallet.engine.block_calls(), 3);
    wallet.close();
    p.close();
    q.close();
}

#[test]
fn no_corroboration_is_asked_for_when_no_block_could_be_admitted_without_a_check() {
    let now = unix_time_seconds().unwrap();
    let chain = chain_from("catch-up-no-probe-chain", &[], 10, now);
    let p = Source::serve("catch-up-no-probe-p", &chain, 0x51);
    let q = Source::serve("catch-up-no-probe-q", &chain, 0x52);
    let check = |wallet: &Wallet, case: &str| {
        let report = wallet.sync(p.addr).unwrap();
        assert!(report.accepted_blocks > 0, "{case}");
        assert_eq!(q.sessions(), (0, 0), "{case}");
        let catch_up = wallet.catch_up();
        assert_eq!(catch_up.counts().probe_attempts, 0, "{case}");
        assert_eq!(
            catch_up.fresh_views(Instant::now()),
            (Some(10), 1),
            "{case}: the source's report is recorded"
        );
        assert!(wallet.granted(&chain).is_empty(), "{case}");
    };

    // Caught up: less than the depth behind.
    let wallet = Wallet::open("catch-up-no-probe-near", &chain, 2, 8);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));
    check(&wallet, "caught up");
    wallet.close();

    // Far behind, but the checkpoint block is not stored yet.
    let wallet = Wallet::open("catch-up-no-probe-early", &chain, 6, 2);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));
    check(&wallet, "before the checkpoint block");
    wallet.close();
    p.close();
    q.close();

    // Far behind on a stale release.
    let old = now - STALE_AFTER - 24 * 60 * 60;
    let early = chain_from("catch-up-no-probe-old", &[], 2, old);
    let mut chain = early.clone();
    chain.extend(chain_from("catch-up-no-probe-new", &early, 8, now));
    let p = Source::serve("catch-up-no-probe-stale-p", &chain, 0x51);
    let q = Source::serve("catch-up-no-probe-stale-q", &chain, 0x52);
    let wallet = Wallet::open("catch-up-no-probe-stale", &chain, 2, 2);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));
    let report = wallet.sync(p.addr).unwrap();
    assert_eq!(report.accepted_blocks, 8);
    assert_eq!(q.sessions(), (0, 0), "stale release");
    assert_eq!(wallet.catch_up().counts().probe_attempts, 0);
    assert_eq!(wallet.catch_up().fresh_views(Instant::now()), (Some(10), 1));
    assert_eq!(wallet.engine.block_calls(), 8);
    wallet.close();
    p.close();
    q.close();
}

/// The corroborating sources a wallet catching up with sources at `qs` (in
/// groups 1, 2, ...) asks in a session with `p`, and what came of it.
fn probe_case(
    label: &str,
    chain: &[Block],
    p: &Source,
    qs: &[SocketAddr],
) -> (Wallet, Result<SyncReport, P2pError>) {
    let wallet = Wallet::open(label, chain, 2, 2);
    let mut sources = vec![(p.addr, 0)];
    sources.extend(qs.iter().zip(1..).map(|(addr, group)| (*addr, group)));
    assert!(wallet.enable(&sources));
    let result = wallet.sync(p.addr);
    (wallet, result)
}

#[test]
fn a_source_that_lists_nothing_new_is_a_miss_and_the_next_is_asked() {
    let chain = chain("catch-up-miss-chain", 10);
    let p = Source::serve("catch-up-miss-p", &chain, 0x51);
    let q = Source::serve("catch-up-miss-q", &chain, 0x52);
    let behind = Source::serve("catch-up-miss-behind", &chain[..1], 0x53);
    let answering = |block_ids: Vec<[u8; 32]>| {
        ScriptedPeer::new(
            p.hello(0x54),
            Script::Answer {
                delay: Duration::ZERO,
                block_ids,
            },
        )
    };
    let pruned = answering(Vec::new());
    let stored = answering(ids(&chain[..2]));

    // A source that is down fails; one that is pruned (an empty list), one
    // block behind the wallet, or that lists only blocks stored here, misses.
    for (case, first, misses) in [
        ("down", closed_address(), 0),
        ("pruned", pruned.addr, 1),
        ("behind", behind.addr, 1),
        ("stored", stored.addr, 1),
    ] {
        let label = format!("catch-up-miss-{case}");
        let (wallet, result) = probe_case(&label, &chain, &p, &[first, q.addr]);
        let report = result.unwrap();
        assert_eq!(report.accepted_blocks, 8, "{case}");
        assert_eq!(wallet.granted(&chain), vec![3, 4, 5, 6, 7], "{case}");
        let counts = wallet.catch_up().counts();
        assert_eq!(counts.probe_attempts, 2, "{case}");
        assert_eq!(counts.probe_misses, misses, "{case}");
        assert_eq!(counts.probe_failures, 1 - misses, "{case}");
        wallet.close();
    }
    pruned.close();
    stored.close();
    behind.close();
    p.close();
    q.close();
}

#[test]
fn a_source_that_never_answers_costs_one_hold_and_the_session_survives() {
    let chain = chain("catch-up-blackhole-chain", 8);
    let p = Source::serve("catch-up-blackhole-p", &chain, 0x51);
    let silent = ScriptedPeer::new(p.hello(0x52), Script::Blackhole);
    let (wallet, result) = probe_case("catch-up-blackhole", &chain, &p, &[silent.addr]);
    let report = result.unwrap();
    assert_eq!(report.accepted_blocks, 6);
    assert_eq!(wallet.engine.block_calls(), 6, "nothing corroborated");
    let catch_up = wallet.catch_up();
    let counts = catch_up.counts();
    assert_eq!((counts.probe_attempts, counts.probe_failures), (1, 1));
    assert!(counts.last_probe_ms < PROBE_BUDGET.as_millis() as u64);
    assert!(catch_up.probe_candidates(0, Instant::now()).is_empty());
    drop(catch_up);
    wallet.close();
    silent.close();
    p.close();
}

#[test]
fn slow_sources_are_cut_off_at_the_deadline_and_the_session_completes() {
    let chain = chain("catch-up-slow-chain", 8);
    let p = Source::serve("catch-up-slow-p", &chain, 0x51);
    let slow = |delay| {
        ScriptedPeer::new(
            p.hello(0x52),
            Script::Answer {
                delay,
                block_ids: ids(&chain[..2]),
            },
        )
    };
    // The first answers after about 3 s; the second would answer after
    // about 3.8 s more, past the deadline.
    let (first, second) = (
        slow(Duration::from_millis(1_500)),
        slow(Duration::from_millis(1_900)),
    );
    let started = Instant::now();
    let (wallet, result) = probe_case("catch-up-slow", &chain, &p, &[first.addr, second.addr]);
    let report = result.unwrap();
    assert_eq!(report.accepted_blocks, 6);
    assert_eq!(wallet.engine.block_calls(), 6, "nothing corroborated");
    let counts = wallet.catch_up().counts();
    assert_eq!(counts.probe_attempts, 2);
    assert_eq!(
        (counts.probe_misses, counts.probe_failures),
        (1, 1),
        "the first answered in time, the second did not"
    );
    assert!(counts.last_probe_ms >= 5_000, "{}", counts.last_probe_ms);
    assert!(
        counts.last_probe_ms <= PROBE_BUDGET.as_millis() as u64 + 300,
        "{}",
        counts.last_probe_ms
    );
    assert!(started.elapsed() < Duration::from_secs(30));
    wallet.close();
    first.close();
    second.close();
    p.close();
}

#[test]
fn a_source_that_closes_before_its_hello_is_not_asked_again_within_the_hold() {
    let chain = chain("catch-up-close-chain", 12);
    let p = Source::serve("catch-up-close-p", &chain, 0x51);
    let q = Source::serve("catch-up-close-q", &chain, 0x52);
    let full = ScriptedPeer::new(p.hello(0x53), Script::CloseBeforeHello);
    let wallet = Wallet::open("catch-up-close", &chain, 2, 2);
    assert!(wallet.enable(&[(p.addr, 0), (full.addr, 1), (q.addr, 2)]));
    // Two sessions of four blocks each.
    let limits = PeerLimits {
        max_blocks_per_session: 4,
        ..PeerLimits::default()
    };
    let accepted = full.accepted();
    wallet.sync_with(p.addr, limits).unwrap();
    assert_eq!(full.accepted(), accepted + 1);
    wallet.sync_with(p.addr, limits).unwrap();
    assert_eq!(full.accepted(), accepted + 1, "held");
    let counts = wallet.catch_up().counts();
    assert_eq!((counts.probe_attempts, counts.probe_failures), (3, 1));
    // Up to 12 - D; height 10 was checked.
    assert_eq!(wallet.granted(&chain), (3..=9).collect::<Vec<_>>());
    assert_eq!(wallet.engine.block_calls(), 1);
    wallet.close();
    full.close();
    p.close();
    q.close();
}

#[test]
fn other_peers_deliver_no_blocks_while_sources_in_two_groups_lead_and_deliver() {
    let chain = chain("catch-up-skip-chain", 30);
    let s0 = Source::serve("catch-up-skip-s0", &chain, 0x51);
    let s1 = Source::serve("catch-up-skip-s1", &chain, 0x52);
    let other = Source::serve("catch-up-skip-other", &chain, 0x53);
    let limits = PeerLimits {
        max_blocks_per_session: 4,
        ..PeerLimits::default()
    };
    let wallet = Wallet::open("catch-up-skip", &chain, 2, 2);
    assert!(wallet.enable(&[(s0.addr, 0), (s1.addr, 1)]));
    // The session with s0 asks s1, so both reports are fresh.
    assert_eq!(
        wallet.sync_with(s0.addr, limits).unwrap().accepted_blocks,
        4
    );
    let report = wallet.sync_with(other.addr, limits).unwrap();
    assert_eq!((report.inventory_items, report.requested_blocks), (0, 0));
    assert_eq!(other.sessions(), (1, 0), "the mempool is still exchanged");
    assert_eq!(wallet.height(), 6);

    // Once the reports and the delivery are old, it downloads again.
    wallet.catch_up().set_view_fresh(Duration::from_millis(1));
    thread::sleep(Duration::from_millis(20));
    let report = wallet.sync_with(other.addr, limits).unwrap();
    assert_eq!(report.accepted_blocks, 4);
    assert_eq!(wallet.engine.block_calls(), 4);
    wallet.close();

    // Off: unchanged.
    let wallet = Wallet::open("catch-up-skip-off", &chain, 2, 2);
    assert_eq!(
        wallet
            .sync_with(other.addr, limits)
            .unwrap()
            .accepted_blocks,
        4
    );
    wallet.close();
    s0.close();
    s1.close();
    other.close();
}

#[test]
fn a_corroborating_connection_and_a_later_session_with_the_same_source_both_work() {
    let chain = chain("catch-up-nonce-chain", 8);
    let p = Source::serve("catch-up-nonce-p", &chain, 0x51);
    let q = Source::serve("catch-up-nonce-q", &chain, 0x52);
    let wallet = Wallet::open("catch-up-nonce", &chain, 2, 2);
    assert!(wallet.enable(&[(p.addr, 0), (q.addr, 1)]));
    wallet.sync(p.addr).unwrap();
    assert_eq!(wallet.granted(&chain), vec![3, 4, 5]);
    // The same hello, nonce included, opens a real session with Q.
    wallet.sync(q.addr).unwrap();
    assert_eq!(q.sessions(), (2, 0));
    wallet.close();
    p.close();
    q.close();
}

#[test]
fn a_grant_gone_stale_before_its_commit_ends_the_session_with_no_penalty() {
    let now = unix_time_seconds().unwrap();
    let chain = chain_from("catch-up-stale-grant-chain", &[], 8, now);
    let competing = chain_from("catch-up-stale-grant-fork", &chain[..2], 1, now + 50).remove(0);
    let wallet = Wallet::open("catch-up-stale-grant", &chain, 2, 2);
    wallet.engine.answer(&competing, true);
    // No connection is made.
    let unused = |port| SocketAddr::from(([127, 0, 0, 1], port));
    assert!(wallet.enable(&[(unused(1), 0), (unused(2), 1)]));
    wallet
        .catch_up()
        .note_view(1, 8, &ids(&chain), Instant::now());
    let from = FetchedFrom {
        sender: IpAddr::from([127, 0, 0, 1]),
        trusted: true,
        heavier: false,
        catch_up: Some(CatchUpFollow {
            below: 8 - D,
            source: 0,
        }),
    };
    let preverifier = wallet.node.lock().unwrap().block_preverifier();
    prewarm_fetched_work(&wallet.node, &preverifier, &chain[2], from, None).unwrap();
    assert!(wallet.catch_up().has_grant(&chain[2].block_id()));
    // A local block takes the tip after the admission let the grant through.
    let node = Arc::clone(&wallet.node);
    wallet.node.lock().unwrap().after_work_admission = Some(Box::new(move || {
        submit_shared_block(&node, competing, now).unwrap();
    }));
    let peer = next_remote_proof_peer_id().unwrap();
    let error = submit_fetched_block(&wallet.node, chain[2].clone(), peer, from, None).unwrap_err();
    assert!(
        matches!(error, P2pError::Node(NodeError::WorkCheckRequired)),
        "{error}"
    );
    assert_eq!(outbound_reputation_penalty(&error).0, 0);
    assert!(!wallet.holds(&chain[2]));
    assert_eq!(wallet.engine.block_calls(), 1, "only the local block");
    wallet.close();
}
