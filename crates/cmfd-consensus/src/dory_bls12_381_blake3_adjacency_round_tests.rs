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
            "cmfd-blake3-adjacency-round-test-{}-{nonce}",
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

fn row(seed: u64) -> BlsDoryBlake3AdjacencyRoundRow {
    std::array::from_fn(|column| BlsDoryFr::from_u64(seed + column as u64))
}

fn root_artifact(
    directory: &TestDirectory,
    root_lineage: [u8; 32],
    rows: &[BlsDoryBlake3AdjacencyRoundRow],
) -> BlsDoryBlake3AdjacencyRoundArtifact {
    let mut writer = BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
        &directory.0,
        rows.len() as u64,
        0,
        BlsDoryBlake3AdjacencyRoundParent::Root(root_lineage),
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
fn adjacency_round_artifact_preserves_shape_order_and_lineage() {
    let directory = TestDirectory::create();
    let root_lineage = [0x41; 32];
    let rows = [row(0), row(1_000), row(2_000), row(3_000)];
    let root = root_artifact(&directory, root_lineage, &rows);
    let root_spec = root.spec();
    assert_ne!(root_spec.context_digest, [0; 32]);
    assert_eq!(
        root_spec.context_digest,
        bls_dory_blake3_adjacency_round_context(root_lineage)
    );
    assert_eq!(
        root_spec.table_index,
        BLS_DORY_BLAKE3_ADJACENCY_ROUND_TABLE_INDEX
    );
    assert_eq!(root_spec.generation, 1);
    assert_eq!(root_spec.scalar_count, 4 * 1_024);
    assert_eq!(root_spec.explicit_scalar_count, 4 * 580);
    assert_eq!(root_spec.parent_digest, root_lineage);
    assert_eq!(root.active_rows(), 4);
    assert_eq!(root.round_index(), 0);

    let mut visited = 0usize;
    root.for_each_row_pair(|lower, upper| {
        assert_eq!(lower, &rows[visited]);
        assert_eq!(upper, &rows[visited + 1]);
        visited += 2;
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, rows.len());

    let child =
        fold_native_blake3_adjacency_artifact(&root, &directory.0, BlsDoryFr::from_u64(3)).unwrap();
    assert_eq!(child.spec().generation, 2);
    assert_eq!(child.spec().parent_digest, root.digest());
    assert_eq!(child.spec().context_digest, root.spec().context_digest);
    assert_eq!(child.active_rows(), 2);
    assert_eq!(child.round_index(), 1);

    let terminal =
        fold_native_blake3_adjacency_artifact(&child, &directory.0, BlsDoryFr::from_u64(5))
            .unwrap();
    let child_rows: [BlsDoryBlake3AdjacencyRoundRow; 2] = std::array::from_fn(|pair| {
        std::array::from_fn(|column| {
            rows[2 * pair][column]
                + BlsDoryFr::from_u64(3) * (rows[2 * pair + 1][column] - rows[2 * pair][column])
        })
    });
    let expected_terminal: BlsDoryBlake3AdjacencyRoundRow = std::array::from_fn(|column| {
        child_rows[0][column]
            + BlsDoryFr::from_u64(5) * (child_rows[1][column] - child_rows[0][column])
    });
    assert_eq!(terminal.terminal_row().unwrap(), expected_terminal);

    drop((terminal, child, root));
    assert_eq!(directory.entries(), 0);
}

#[test]
fn adjacency_round_artifact_rejects_invalid_parent_generation_and_row_shape() {
    let directory = TestDirectory::create();
    let root_lineage = [0x52; 32];
    for active_rows in [0, 3] {
        assert!(matches!(
            BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
                &directory.0,
                active_rows,
                0,
                BlsDoryBlake3AdjacencyRoundParent::Root(root_lineage),
            ),
            Err(BlsDoryFoldArtifactError::InvalidSpec)
        ));
    }
    assert!(matches!(
        BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
            &directory.0,
            1,
            0,
            BlsDoryBlake3AdjacencyRoundParent::Root([0; 32]),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));
    assert!(matches!(
        BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
            &directory.0,
            1,
            u32::MAX as usize,
            BlsDoryBlake3AdjacencyRoundParent::Root(root_lineage),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));
    assert!(matches!(
        BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
            &directory.0,
            1,
            1,
            BlsDoryBlake3AdjacencyRoundParent::Root(root_lineage),
        ),
        Err(BlsDoryFoldArtifactError::InvalidSpec)
    ));

    let root = root_artifact(
        &directory,
        root_lineage,
        &[row(0), row(1_000), row(2_000), row(3_000)],
    );
    for (active_rows, round_index) in [(2, 0), (2, 2), (1, 1)] {
        assert!(matches!(
            BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
                &directory.0,
                active_rows,
                round_index,
                BlsDoryBlake3AdjacencyRoundParent::Previous(&root),
            ),
            Err(BlsDoryFoldArtifactError::InvalidSpec)
        ));
    }

    let mut writer = BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
        &directory.0,
        1,
        0,
        BlsDoryBlake3AdjacencyRoundParent::Root([0x53; 32]),
    )
    .unwrap();
    assert!(matches!(
        writer.write_row(&vec![BlsDoryFr::zero(); 579]),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    assert!(matches!(
        writer.write_row(&vec![BlsDoryFr::zero(); 581]),
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
    assert!(matches!(
        fold_native_blake3_adjacency_artifact(&artifact, &directory.0, BlsDoryFr::from_u64(1)),
        Err(BlsDoryFoldArtifactError::InvalidArtifact)
    ));
    drop((artifact, root));
    assert_eq!(directory.entries(), 0);
}

#[test]
fn adjacency_round_writer_and_artifact_are_raii_owned() {
    let directory = TestDirectory::create();
    {
        let mut writer = BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
            &directory.0,
            2,
            0,
            BlsDoryBlake3AdjacencyRoundParent::Root([0x61; 32]),
        )
        .unwrap();
        writer.write_row(&row(0)).unwrap();
        assert_eq!(directory.entries(), 1);
    }
    assert_eq!(directory.entries(), 0);

    let incomplete = BlsDoryBlake3AdjacencyRoundArtifactWriter::create(
        &directory.0,
        1,
        0,
        BlsDoryBlake3AdjacencyRoundParent::Root([0x62; 32]),
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
fn adjacency_round_reader_rejects_corrupt_framing_and_scalars() {
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
fn corrupt_parent_fold_removes_unfinished_child() {
    let directory = TestDirectory::create();
    let parent = root_artifact(&directory, [0x81; 32], &[row(0), row(1_000)]);
    let parent_length = std::fs::metadata(parent.path()).unwrap().len();
    flip_at(parent.path(), parent_length - 1);

    assert!(matches!(
        fold_native_blake3_adjacency_artifact(&parent, &directory.0, BlsDoryFr::from_u64(7),),
        Err(BlsDoryFoldArtifactError::Authentication)
    ));
    assert_eq!(directory.entries(), 1);
    drop(parent);
    assert_eq!(directory.entries(), 0);
}
