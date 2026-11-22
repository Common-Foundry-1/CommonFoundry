#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() {
    common_foundry_android_wallet_lib::run();
}
