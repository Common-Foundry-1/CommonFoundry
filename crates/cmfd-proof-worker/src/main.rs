#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if let Err(error) = cmfd_proof_worker::configure_noninteractive_fault_reporting() {
        eprintln!("could not suppress interactive Windows fault reporting: {error}");
        std::process::exit(1);
    }
    std::process::exit(cmfd_proof_worker::worker_main());
}
