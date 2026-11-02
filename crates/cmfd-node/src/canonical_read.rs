//! Authenticated peer block reads without holding the shared node lock.
//!
//! Disk reads remain serialized per node, retaining the old memory/I/O bound.
//! A tracked log handle prevents pruning from replacing the file mid-read.
use std::sync::{Arc, Mutex};

use crate::{
    BLOCK_LOG_FILE, BlockRecordVersion, Node, NodeError, ProofProfile, read_located_record,
};

pub(crate) fn read_shared(
    shared: &Arc<Mutex<Node>>,
    block_id: [u8; 32],
) -> Result<Option<Vec<u8>>, NodeError> {
    read_with(shared, block_id, || {})
}

fn read_with(
    shared: &Arc<Mutex<Node>>,
    block_id: [u8; 32],
    before_read: impl FnOnce(),
) -> Result<Option<Vec<u8>>, NodeError> {
    let lane = Arc::clone(
        &shared
            .lock()
            .map_err(|_| NodeError::SharedNodePoisoned)?
            .peer_block_read_lane,
    );
    // Never wait for this lane while holding the node lock.
    let _permit = lane.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
    let (instance, epoch, log, path, locator, network, require_v2) = {
        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        if !Arc::ptr_eq(&lane, &node.peer_block_read_lane) {
            return Err(interrupted());
        }
        if node.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let Some(indexed) = node.index.blocks.get(&block_id) else {
            return Ok(None);
        };
        if indexed.locator.version == BlockRecordVersion::Pruned {
            return Err(NodeError::BlockProofPruned(block_id));
        }
        if indexed.block_id() != block_id {
            return node.latch_authenticated_storage_failure(Err(NodeError::CorruptLog(
                "fork index key does not match its durable record locator".to_owned(),
            )));
        }
        (
            node.instance_id,
            node.log_epoch,
            node.clone_log_for_read().map_err(NodeError::RpcIo)?,
            node.data_dir.join(BLOCK_LOG_FILE),
            indexed.locator,
            node.params.network_id,
            matches!(node.profile.proof, ProofProfile::ProductionV3),
        )
    };
    before_read();
    let result = read_located_record(&log, &path, &locator, network, require_v2)
        .map(|(record, _)| Some(record.block_bytes));
    let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
    // The tracked handle pins pruning. Still bind failures to the exact node
    // instance/epoch so replacing a node cannot fault an unrelated new one.
    if node.instance_id != instance || node.log_epoch != epoch {
        return Err(interrupted());
    }
    if node.storage_faulted {
        return Err(NodeError::StorageFaulted);
    }
    node.latch_authenticated_storage_failure(result)
}

fn interrupted() -> NodeError {
    NodeError::RpcIo(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "node changed during an authenticated peer block read; retry",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clean_test_dir, test_dir};
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, default_miner_destination};
    #[cfg(unix)]
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::time::Duration;

    fn fixture(name: &str) -> (std::path::PathBuf, Arc<Mutex<Node>>, [u8; 32]) {
        let path = test_dir(name);
        let mut node = Node::open(&path).unwrap();
        let block = node
            .mine_once(
                default_miner_destination(),
                DEVNET_GENESIS_TIMESTAMP + 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        (path, Arc::new(Mutex::new(node)), block.block_id())
    }

    #[test]
    fn blocked_disk_read_leaves_status_available_and_pins_pruning() {
        let (path, shared, id) = fixture("peer-read-off-node-lock");
        let expected = shared.lock().unwrap().canonical_block(id).unwrap();
        let (entered, ready) = std::sync::mpsc::channel();
        let (resume, release) = std::sync::mpsc::channel();
        let worker_node = Arc::clone(&shared);
        let worker = std::thread::spawn(move || {
            read_with(&worker_node, id, || {
                entered.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            })
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        {
            let node = shared
                .try_lock()
                .expect("a stalled disk read must not block status or sync scheduling");
            assert!(
                node.log_readers_outstanding(),
                "pruning cannot replace the file during authentication"
            );
            assert_eq!(node.peer_hello().height, 1);
        }
        resume.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap(), expected);
        assert!(!shared.lock().unwrap().log_readers_outstanding());
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    #[cfg(unix)]
    fn corrupt_peer_read_still_latches_the_storage_fault() {
        let (path, shared, id) = fixture("peer-read-corruption-fault");
        let locator = shared.lock().unwrap().index.blocks[&id].locator;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.join(BLOCK_LOG_FILE))
            .unwrap();
        file.seek(SeekFrom::Start(locator.offset + locator.length - 1))
            .unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::Current(-1)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(read_shared(&shared, id).is_err());
        assert!(shared.lock().unwrap().storage_faulted);
        drop(shared);
        clean_test_dir(&path);
    }

    #[test]
    fn corrupt_locator_cannot_bypass_authentication_or_hide_a_storage_fault() {
        let (path, shared, id) = fixture("peer-read-forged-locator");
        {
            let mut node = shared.lock().unwrap();
            Arc::make_mut(node.index.blocks.get_mut(&id).unwrap())
                .locator
                .complete_digest[0] ^= 1;
        }
        assert!(matches!(
            read_shared(&shared, id),
            Err(NodeError::CorruptLog(_))
        ));
        assert!(shared.lock().unwrap().storage_faulted);
        drop(shared);
        clean_test_dir(&path);
    }
    #[test]
    fn an_inflight_read_cannot_serve_after_another_operation_faults_storage() {
        let (path, shared, id) = fixture("peer-read-concurrent-storage-fault");
        let changed = Arc::clone(&shared);
        let result = read_with(&shared, id, move || {
            changed.lock().unwrap().storage_faulted = true;
        });
        assert!(matches!(result, Err(NodeError::StorageFaulted)));
        assert!(shared.lock().unwrap().storage_faulted);
        drop(shared);
        clean_test_dir(&path);
    }
    #[test]
    fn a_completion_for_a_replaced_node_cannot_fault_the_replacement() {
        let (path, shared, id) = fixture("peer-read-replaced-old");
        let new_path = test_dir("peer-read-replaced-new");
        let replacement = Node::open(&new_path).unwrap();
        let changed = Arc::clone(&shared);
        let result = read_with(&shared, id, move || *changed.lock().unwrap() = replacement);
        assert!(
            matches!(result, Err(NodeError::RpcIo(error)) if error.kind() == std::io::ErrorKind::Interrupted)
        );
        assert!(!shared.lock().unwrap().storage_faulted);
        assert_eq!(shared.lock().unwrap().peer_hello().height, 0);
        drop(shared);
        clean_test_dir(&path);
        clean_test_dir(&new_path);
    }
}
