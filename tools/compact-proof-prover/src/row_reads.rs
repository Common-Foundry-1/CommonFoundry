//! Bounded positional row reads. Output order and duplicates match the input.
use std::{fs::File, os::unix::fs::FileExt, sync::atomic::{AtomicUsize, Ordering}, thread};

pub fn read_rows(file: &File, indices: &[usize], total_rows: usize, row_bytes: usize,
                 workers: usize) -> Option<Vec<Vec<u8>>> {
    if row_bytes == 0 || !(1..=32).contains(&workers) || indices.iter().any(|i| *i >= total_rows) {
        return None;
    }
    let expected = total_rows.checked_mul(row_bytes)?;
    if file.metadata().ok()?.len() != u64::try_from(expected).ok()? { return None; }
    if indices.is_empty() { return Some(Vec::new()); }
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        let mut tasks = Vec::new();
        for _ in 0..workers.min(indices.len()) {
            tasks.push(scope.spawn(|| -> Option<Vec<(usize, Vec<u8>)>> {
                let mut completed = Vec::new();
                loop {
                    let slot = next.fetch_add(1, Ordering::Relaxed);
                    if slot >= indices.len() { break; }
                    let offset = indices[slot].checked_mul(row_bytes)?;
                    let mut bytes = vec![0; row_bytes];
                    file.read_exact_at(&mut bytes, u64::try_from(offset).ok()?).ok()?;
                    completed.push((slot, bytes));
                }
                Some(completed)
            }));
        }
        let mut ordered: Vec<Option<Vec<u8>>> = (0..indices.len()).map(|_| None).collect();
        for task in tasks {
            for (slot, bytes) in task.join().ok()?? {
                if ordered[slot].replace(bytes).is_some() { return None; }
            }
        }
        ordered.into_iter().collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::{self,OpenOptions},io::Write,path::PathBuf,time::{SystemTime,UNIX_EPOCH}};
    struct Fixture { path: PathBuf, file: File, bytes: Vec<u8> }
    impl Fixture {
        fn new() -> Self {
            let name=format!("cmfd-row-read-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
            let path=std::env::temp_dir().join(name);
            let mut file=OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
            let bytes=(0..257*1024).map(|i|((i*31+(i/1024)*7)%251)as u8).collect::<Vec<_>>();
            file.write_all(&bytes).unwrap();Self{path,file,bytes}
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { fs::remove_file(&self.path).unwrap(); } }
    #[test] fn order_duplicates_edges_and_all_worker_counts_match_exact_bytes() {
        let f=Fixture::new();let q=[256,0,7,7,128,255,1,2,256];
        for n in [1,2,4,8,16,32] {
            let got=read_rows(&f.file,&q,257,1024,n).unwrap();
            for (i,row) in got.iter().enumerate(){assert_eq!(row,&f.bytes[q[i]*1024..(q[i]+1)*1024]);}
        }
    }
    #[test] fn empty_and_complete_permutations_preserve_every_row() {
        let f=Fixture::new();assert!(read_rows(&f.file,&[],257,1024,8).unwrap().is_empty());
        let q=(0..257).map(|x|(x*101)%257).collect::<Vec<_>>();
        let got=read_rows(&f.file,&q,257,1024,16).unwrap();
        assert_eq!(got.len(),257);
        for (i,row)in got.iter().enumerate(){assert_eq!(row,&f.bytes[q[i]*1024..(q[i]+1)*1024]);}
    }
    #[test] fn invalid_index_geometry_and_worker_limits_fail_closed() {
        let f=Fixture::new();
        for q in [vec![257],vec![usize::MAX],vec![0,257]] { assert!(read_rows(&f.file,&q,257,1024,4).is_none()); }
        for n in [0,33,usize::MAX] { assert!(read_rows(&f.file,&[0],257,1024,n).is_none()); }
        assert!(read_rows(&f.file,&[0],257,0,4).is_none());
        assert!(read_rows(&f.file,&[0],usize::MAX,1024,4).is_none());
        assert!(read_rows(&f.file,&[0],258,1024,4).is_none());
    }
    #[test] fn truncated_data_is_never_zero_filled_or_silently_accepted() {
        let f=Fixture::new();f.file.set_len(257*1024-1).unwrap();
        assert!(read_rows(&f.file,&[256],257,1024,16).is_none());
    }
}
