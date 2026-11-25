fn main() {
    println!("cargo:rerun-if-changed=winpulse-sentinel.exe.manifest");
    println!("cargo:rerun-if-env-changed=WINPULSE_UAC_MANIFEST");

    let profile = std::env::var("PROFILE").unwrap_or_default();
    let force_uac = std::env::var("WINPULSE_UAC_MANIFEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut windows = tauri_build::WindowsAttributes::new();
    if profile == "release" || force_uac {
        windows = windows.app_manifest(include_str!("winpulse-sentinel.exe.manifest"));
    }

    if let Err(err) =
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
    {
        eprintln!("tauri_build failed: {err:#}");
        std::process::exit(1);
    }
}
