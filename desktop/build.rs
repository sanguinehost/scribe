fn main() {
    // Tell Cargo to rerun this build script if the backend source changes
    println!("cargo:rerun-if-changed=../backend/src");
    println!("cargo:rerun-if-changed=../backend/Cargo.toml");

    // NOTE: We do NOT spawn `cargo build` here because it causes a deadlock:
    // - Parent cargo holds write lock on target/debug/.cargo-lock
    // - Child cargo (spawned here) waits for the same lock
    // - Result: infinite stall
    //
    // Instead, Cargo's workspace dependency resolution automatically builds
    // the scribe-backend library when desktop depends on it.
    //
    // The backend binary (bin/scribe-backend) must be built separately before
    // packaging the desktop app, typically via:
    //   cargo build -p scribe-backend --no-default-features --features desktop --bin scribe-backend

    // Run the Tauri build WITH codegen to embed frontend assets
    // CRITICAL: Must use try_build with .codegen() - build() doesn't include asset codegen!
    println!("cargo:warning=Starting tauri_build with codegen...");
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .codegen(tauri_build::CodegenContext::new())
    )
    .expect("failed to run tauri-build");

    println!("cargo:warning=tauri_build completed successfully");
}
