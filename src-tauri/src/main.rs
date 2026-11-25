#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(err) = winpulse_sentinel_lib::run() {
        eprintln!("WinPulse Sentinel fatal startup error: {err}");
        std::process::exit(1);
    }
}
