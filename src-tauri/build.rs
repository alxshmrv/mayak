fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/WifiBridge.m")
            .flag("-fobjc-arc")
            .warnings(true)
            .compile("mayak_wifi_bridge");

        println!("cargo:rustc-link-lib=framework=CoreWLAN");
        println!("cargo:rustc-link-lib=framework=CoreLocation");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }

    tauri_build::build();
}
