use super::*;
use dory_pcs::primitives::arithmetic::Field;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const FOLD_HEADER_BYTES: u64 = 100;
const FOLD_SCALAR_BYTES: usize = 32;
const FOLD_FOOTER_BYTES: u64 = 32;
static SCRATCH_NONCE: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let nonce = SCRATCH_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cmfd-blake3-execution-round-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn entries(&self) -> usize {
        std::fs::read_dir(&self.0).unwrap().count()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn row(seed: u64) -> BlsDoryBlake3ExecutionRoundRow {
    std::array::from_fn(|column| BlsDoryFr::from_u64(seed + column as u64))
}

fn root_artifact(
    directory: &TestDirectory,
    root_lineage: [u8; 32],
    rows: &[BlsDoryBlake3ExecutionRoundRow],
) -> BlsDoryBlake3ExecutionRoundArtifact {
    let mut writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        &directory.0,
        rows.len() as u64,
        0,
        BlsDoryBlake3ExecutionRoundParent::Root(root_lineage),
    )
    .unwrap();
    for row in rows {
        writer.write_row(row).unwrap();
    }
    writer.finish().unwrap()
}

fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn flip_at(path: &Path, offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn execution_round_artifact_preserves_shape_order_and_lineage() {
    let directory = TestDirectory::create();
    let root_lineage = [0x41; 32];
    let rows = [row(0), row(1_000), row(2_000), row(3_000)];
    let root = root_artifact(&directory, root_lineage, &rows);
    let root_spec = root.spec();
    assert_ne!(root_spec.context_digest, [0; 32]);
    assert_eq!(
        root_spec.context_digest,
        bls_dory_blake3_execution_round_context(root_lineage)
    );
    assert_eq!(
        root_spec.table_index,
        BLS_DORY_BLAKE3_EXECUTION_ROUND_TABLE_INDEX
    );
    assert_eq!(root_spec.generation, 1);
    assert_eq!(root_spec.scalar_count, 4 * 1_024);
    assert_eq!(root_spec.explicit_scalar_count, 4 * 746);
    assert_eq!(root_spec.parent_digest, root_lineage);

    let mut visited = 0usize;
    root.for_each_row_pair(|lower, upper| {
        assert_eq!(lower, &rows[visited]);
        assert_eq!(upper, &rows[visited + 1]);
        visited += 2;
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, rows.len());

    let child_rows = [row(10_000), row(20_000)];
    let mut child_writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        &directory.0,
        2,
        1,
        BlsDoryBlake3ExecutionRoundParent::Previous(&root),
    )
    .unwrap();
    for child_row in &child_rows {
        child_writer.write_row(child_row).unwrap();
    }
    let child = child_writer.finish().unwrap();
    assert_eq!(child.spec().generation, 2);
    assert_eq!(child.spec().parent_digest, root.digest());
    assert_eq!(child.spec().context_digest, root.spec().context_digest);

    let terminal = row(30_000);
    let mut terminal_writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        &directory.0,
        1,
        2,
        BlsDoryBlake3ExecutionRoundParent::Previous(&child),
    )
    .unwrap();
    terminal_writer.write_row(&terminal).unwrap();
    let terminal_artifact = terminal_writer.finish().unwrap();
    assert_eq!(terminal_artifact.spec().generation, 3);
    assert_eq!(terminal_artifact.spec().parent_digest, child.digest());
    assert_eq!(terminal_artifact.terminal_row().unwrap(), terminal);

    drop((terminal_artifact, child, root));
    assert_eq!(directory.entries(), 0);
}

#[test]
fn execution_round_artifact_rejects_invalid_parent_generation_and_row_shape() {
    let directory = TestDirectory::create();
    let root_lineage = [0x52; 32];
    for active_rows in [0, 3] {
        assert!(matches!(
            BlsDoryBlake3ExecutionRoundArtifactWriter::create(
                &directory.0,
                active_rows,
                0,
                BlsDoryBlake3ExecutionRoundParent::Root(root_lineage),
            ),
            Err(BlsDoryFoldArtifactError::InvalidSpec)
        ));
    }
    assert!(matches!(
        BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            1,
            0,
            BlsDoryBlake3ExecutionRoundParent::Root([0; 32]),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));
    assert!(matches!(
        BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            1,
            u32::MAX as usize,
            BlsDoryBlake3ExecutionRoundParent::Root(root_lineage),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));
    assert!(matches!(
        BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            1,
            1,
            BlsDoryBlake3ExecutionRoundParent::Root(root_lineage),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));

    let root = root_artifact(
        &directory,
        root_lineage,
        &[row(0), row(1_000), row(2_000), row(3_000)],
    );
    assert!(matches!(
        BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            2,
            0,
            BlsDoryBlake3ExecutionRoundParent::Previous(&root),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));
    assert!(matches!(
        BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            2,
            2,
            BlsDoryBlake3ExecutionRoundParent::Previous(&root),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));
    assert!(matches!(
        BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            1,
            1,
            BlsDoryBlake3ExecutionRoundParent::Previous(&root),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));

    let mut writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        &directory.0,
        1,
        0,
        BlsDoryBlake3ExecutionRoundParent::Root([0x53; 32]),
    )
    .unwrap();
    assert!(matches!(
        writer.write_row(&vec![BlsDoryFr::zero(); 745]),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    assert!(matches!(
        writer.write_row(&vec![BlsDoryFr::zero(); 747]),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    writer.write_row(&row(7_000)).unwrap();
    assert!(matches!(
        writer.write_row(&row(8_000)),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    let artifact = writer.finish().unwrap();
    assert!(matches!(
        artifact.for_each_row_pair(|_, _| Ok(())),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    drop((artifact, root));
    assert_eq!(directory.entries(), 0);
}

#[test]
fn execution_round_writer_and_artifact_are_raii_owned() {
    let directory = TestDirectory::create();
    {
        let mut writer = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
            &directory.0,
            2,
            0,
            BlsDoryBlake3ExecutionRoundParent::Root([0x61; 32]),
        )
        .unwrap();
        writer.write_row(&row(0)).unwrap();
        assert_eq!(directory.entries(), 1);
    }
    assert_eq!(directory.entries(), 0);

    let incomplete = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        &directory.0,
        1,
        0,
        BlsDoryBlake3ExecutionRoundParent::Root([0x62; 32]),
    )
    .unwrap();
    assert!(matches!(
        incomplete.finish(),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    assert_eq!(directory.entries(), 0);

    let artifact = root_artifact(&directory, [0x63; 32], &[row(0)]);
    assert_eq!(directory.entries(), 1);
    drop(artifact);
    assert_eq!(directory.entries(), 0);
}

#[test]
fn execution_round_reader_rejects_corrupt_framing_and_scalars() {
    let run_case = |mutate: &dyn Fn(&Path), expected: fn(&BlsDoryFoldArtifactError) -> bool| {
        let directory = TestDirectory::create();
        let artifact = root_artifact(
            &directory,
            [0x71; 32],
            &[std::array::from_fn(|_| BlsDoryFr::zero())],
        );
        mutate(artifact.path());
        let error = artifact.terminal_row().unwrap_err();
        assert!(expected(&error), "unexpected error: {error:?}");
    };

    run_case(&|path| write_at(path, 0, b"X"), |error| {
        matches!(error, BlsDoryFoldArtifactError::Authentication)
    });
    run_case(&|path| write_at(path, FOLD_HEADER_BYTES, &[1]), |error| {
        matches!(error, BlsDoryFoldArtifactError::Authentication)
    });
    run_case(
        &|path| {
            let length = std::fs::metadata(path).unwrap().len();
            flip_at(path, length - FOLD_FOOTER_BYTES);
        },
        |error| matches!(error, BlsDoryFoldArtifactError::Authentication),
    );
    run_case(
        &|path| {
            let file = OpenOptions::new().write(true).open(path).unwrap();
            let length = file.metadata().unwrap().len();
            file.set_len(length - 1).unwrap();
            file.sync_all().unwrap();
        },
        |error| matches!(error, BlsDoryFoldArtifactError::InvalidArtifact),
    );
    run_case(
        &|path| write_at(path, FOLD_HEADER_BYTES, &[0xff; FOLD_SCALAR_BYTES]),
        |error| matches!(error, BlsDoryFoldArtifactError::InvalidScalar),
    );
}

#[test]
fn failed_parent_authentication_removes_unfinished_child() {
    let directory = TestDirectory::create();
    let parent = root_artifact(&directory, [0x81; 32], &[row(0), row(1_000)]);
    let parent_length = std::fs::metadata(parent.path()).unwrap().len();
    flip_at(parent.path(), parent_length - 1);

    let mut child = BlsDoryBlake3ExecutionRoundArtifactWriter::create(
        &directory.0,
        1,
        1,
        BlsDoryBlake3ExecutionRoundParent::Previous(&parent),
    )
    .unwrap();
    assert_eq!(directory.entries(), 2);
    let mut callbacks = 0usize;
    let traversal = parent.for_each_row_pair(|lower, upper| {
        callbacks += 1;
        let folded: BlsDoryBlake3ExecutionRoundRow =
            std::array::from_fn(|column| lower[column] + upper[column]);
        child.write_row(&folded)
    });
    assert_eq!(callbacks, 1);
    assert!(matches!(
        traversal,
        Err(BlsDoryFoldArtifactError::Authentication)
    ));
    drop(child);
    assert_eq!(directory.entries(), 1);
    drop(parent);
    assert_eq!(directory.entries(), 0);
}

#[test]
fn transactional_artifact_fold_rejects_corrupt_parent_and_removes_child() {
    let directory = TestDirectory::create();
    let parent = root_artifact(&directory, [0x91; 32], &[row(0), row(1_000)]);
    let parent_length = std::fs::metadata(parent.path()).unwrap().len();
    flip_at(parent.path(), parent_length - 1);

    assert!(matches!(
        fold_native_blake3_execution_artifact(&parent, &directory.0, BlsDoryFr::from_u64(7),),
        Err(BlsDoryAggregateError::ProverStorage)
    ));
    assert_eq!(directory.entries(), 1);
    drop(parent);
    assert_eq!(directory.entries(), 0);
}
