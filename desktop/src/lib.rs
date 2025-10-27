use std::env;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

/// Start the backend server as a separate process
fn start_backend_process() -> anyhow::Result<Child> {
    // Get the path to the backend binary
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let project_root = manifest_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get project root"))?;

    let backend_bin = if cfg!(debug_assertions) {
        project_root.join("target/debug/scribe-backend")
    } else {
        project_root.join("target/release/scribe-backend")
    };

    log::info!("Starting backend server from: {}", backend_bin.display());

    // Set environment variables for the backend
    let child = Command::new(backend_bin)
        .env("ENVIRONMENT", "local")
        .env("RUST_LOG", "info")
        .current_dir(project_root)
        .spawn()?;

    log::info!("Backend server started with PID: {}", child.id());

    // Give the backend a moment to start listening
    thread::sleep(Duration::from_secs(3));

    Ok(child)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Start the backend server
    let mut backend_process = match start_backend_process() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to start backend server: {:#}", e);
            log::error!("Failed to start backend server: {}", e);
            std::process::exit(1);
        }
    };

    // Build and run Tauri app
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Clean up backend process when window closes
            if let tauri::WindowEvent::Destroyed = event {
                log::info!("Window destroyed, cleaning up...");
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    // Kill the backend process when the app exits
    log::info!("Shutting down backend server...");
    let _ = backend_process.kill();
    let _ = backend_process.wait();
}
