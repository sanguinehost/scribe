// backend/build.rs
// Build script for automatic llama.cpp compilation and packaging

#[cfg(feature = "local-llm")]
use std::env;
#[cfg(feature = "local-llm")]
use std::ffi::OsStr;
#[cfg(feature = "local-llm")]
use std::path::{Path, PathBuf};
#[cfg(feature = "local-llm")]
use std::process::Command;

fn main() {
    // Only build llama.cpp when local-llm feature is enabled
    #[cfg(feature = "local-llm")]
    {
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-env-changed=CUDA_PATH");
        println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");
        
        if let Err(e) = build_llamacpp() {
            println!("cargo:warning=Failed to build llama.cpp: {}", e);
            // Don't fail the build completely - just warn
            // Users can still use external llama.cpp installations
        }
    }
}

#[cfg(feature = "local-llm")]
fn build_llamacpp() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:warning=Building llama.cpp with local-llm feature enabled...");
    
    let out_dir = env::var("OUT_DIR")?;
    let out_path = Path::new(&out_dir);
    
    // Check if CMAKE is available
    if !is_command_available("cmake") {
        return Err("CMAKE not found. Please install CMAKE to build llama.cpp.".into());
    }
    
    // Detect build environment
    let build_config = detect_build_configuration()?;
    println!("cargo:warning=Detected build configuration: {:?}", build_config);
    
    // Setup llama.cpp source
    let llamacpp_dir = setup_llamacpp_source(&out_path)?;
    
    // Configure and build
    let build_dir = llamacpp_dir.join("build");
    configure_llamacpp(&llamacpp_dir, &build_dir, &build_config)?;
    build_llamacpp_project(&build_dir)?;
    
    // Copy the built server binary to a location we can find at runtime
    copy_server_binary(&build_dir, &out_path)?;
    
    println!("cargo:warning=llama.cpp build completed successfully");
    Ok(())
}

#[cfg(feature = "local-llm")]
#[derive(Debug)]
struct BuildConfiguration {
    platform: Platform,
    acceleration: Acceleration,
    threads: Option<usize>,
}

#[cfg(feature = "local-llm")]
#[derive(Debug)]
enum Platform {
    Linux,
    MacOS,
    Windows,
}

#[cfg(feature = "local-llm")]
#[derive(Debug)]
enum Acceleration {
    Cuda,
    Metal,
    OpenCL,
    CPU,
}

#[cfg(feature = "local-llm")]
fn detect_build_configuration() -> Result<BuildConfiguration, Box<dyn std::error::Error>> {
    let platform = if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        return Err("Unsupported platform".into());
    };
    
    let acceleration = detect_acceleration_support()?;
    let threads = std::thread::available_parallelism().ok().map(|n| n.get());
    
    Ok(BuildConfiguration {
        platform,
        acceleration,
        threads,
    })
}

#[cfg(feature = "local-llm")]
fn detect_acceleration_support() -> Result<Acceleration, Box<dyn std::error::Error>> {
    // Check for CUDA
    if cfg!(target_os = "linux") || cfg!(target_os = "windows") {
        if is_cuda_available() {
            return Ok(Acceleration::Cuda);
        }
    }
    
    // Check for Metal on macOS
    if cfg!(target_os = "macos") {
        return Ok(Acceleration::Metal);
    }
    
    // Check for OpenCL
    if is_opencl_available() {
        return Ok(Acceleration::OpenCL);
    }
    
    // Fall back to CPU
    Ok(Acceleration::CPU)
}

#[cfg(feature = "local-llm")]
fn is_cuda_available() -> bool {
    // Check for CUDA toolkit
    if let Ok(cuda_path) = env::var("CUDA_PATH") {
        let nvcc_path = Path::new(&cuda_path).join("bin").join("nvcc");
        return nvcc_path.exists();
    }
    
    // Check for nvcc in PATH
    is_command_available("nvcc")
}

#[cfg(feature = "local-llm")]
fn is_opencl_available() -> bool {
    // Simple check - in a real implementation we'd check for OpenCL headers/libraries
    cfg!(target_os = "linux") && Path::new("/usr/include/CL/cl.h").exists()
}

#[cfg(feature = "local-llm")]
fn setup_llamacpp_source(out_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let llamacpp_dir = out_path.join("llama.cpp");
    
    // Check if we already have llama.cpp source
    if llamacpp_dir.exists() && llamacpp_dir.join("CMakeLists.txt").exists() {
        println!("cargo:warning=Using existing llama.cpp source at {}", llamacpp_dir.display());
        return Ok(llamacpp_dir);
    }
    
    // Try cloning from GitHub first (production approach)
    if let Ok(source_dir) = clone_llamacpp_from_github(&llamacpp_dir) {
        return Ok(source_dir);
    }
    
    // Fall back to relative path for development
    let local_llamacpp = Path::new("../llama.cpp");
    if local_llamacpp.exists() && local_llamacpp.join("CMakeLists.txt").exists() {
        println!("cargo:warning=Using local llama.cpp source (selective copy) at {}", local_llamacpp.display());
        selective_copy_llamacpp(local_llamacpp, &llamacpp_dir)?;
        return Ok(llamacpp_dir);
    }
    
    Err("llama.cpp source not found. GitHub clone failed and no ../llama.cpp directory found.".into())
}

#[cfg(feature = "local-llm")]
fn clone_llamacpp_from_github(dest_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    println!("cargo:warning=Cloning llama.cpp from GitHub...");
    
    // Check if git is available
    if !is_command_available("git") {
        return Err("Git not found. Please install git to clone llama.cpp.".into());
    }
    
    // Remove destination if it exists
    if dest_dir.exists() {
        std::fs::remove_dir_all(dest_dir)?;
    }
    
    // Clone with shallow history for faster download
    let mut git_cmd = Command::new("git");
    git_cmd
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg("master") // or use a specific tag like "b3902"
        .arg("https://github.com/ggerganov/llama.cpp.git")
        .arg(dest_dir);
    
    println!("cargo:warning=Running: {:?}", git_cmd);
    let output = git_cmd.output()?;
    
    if !output.status.success() {
        eprintln!("Git clone failed:");
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Git clone failed".into());
    }
    
    println!("cargo:warning=llama.cpp cloned successfully");
    Ok(dest_dir.to_path_buf())
}

#[cfg(feature = "local-llm")]
fn selective_copy_llamacpp(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    
    println!("cargo:warning=Selectively copying llama.cpp source files...");
    
    if !src.is_dir() {
        return Err("Source is not a directory".into());
    }
    
    fs::create_dir_all(dst)?;
    
    // Directories to include (whitelist)
    let include_dirs = ["src", "include", "ggml", "common", "cmake", "tools"];
    
    // Files to always include
    let include_files = ["CMakeLists.txt", "CMakePresets.json", "LICENSE"];
    
    // Directories to skip (blacklist)
    let skip_dirs = ["build", ".git", "models", "tests", "examples", ".devops", "docs"];
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let dest_path = dst.join(file_name);
        
        if path.is_dir() {
            if include_dirs.contains(&file_name) {
                println!("cargo:warning=Copying directory: {}", file_name);
                copy_directory(&path, &dest_path)?;
            } else if !skip_dirs.contains(&file_name) {
                println!("cargo:warning=Skipping directory: {}", file_name);
            }
        } else if include_files.contains(&file_name) {
            println!("cargo:warning=Copying file: {}", file_name);
            fs::copy(&path, &dest_path)?;
        }
    }
    
    println!("cargo:warning=Selective copy completed");
    Ok(())
}

#[cfg(feature = "local-llm")]
fn copy_directory(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    
    if !src.is_dir() {
        return Err("Source is not a directory".into());
    }
    
    fs::create_dir_all(dst)?;
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().ok_or("Invalid file name")?;
        let dest_path = dst.join(file_name);
        
        if path.is_dir() {
            copy_directory(&path, &dest_path)?;
        } else {
            fs::copy(&path, &dest_path)?;
        }
    }
    
    Ok(())
}

#[cfg(feature = "local-llm")]
fn configure_llamacpp(
    source_dir: &Path,
    build_dir: &Path,
    config: &BuildConfiguration,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    
    println!("cargo:warning=Configuring llama.cpp build...");
    fs::create_dir_all(build_dir)?;
    
    let mut cmake_cmd = Command::new("cmake");
    cmake_cmd
        .args(["-B", &build_dir.to_string_lossy()])
        .arg(source_dir)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg("-DGGML_NATIVE=ON") // Enable native optimizations
        .arg("-DLLAMA_SERVER=ON"); // Explicitly enable server
    
    // Add acceleration-specific flags
    match config.acceleration {
        Acceleration::Cuda => {
            cmake_cmd.arg("-DGGML_CUDA=ON");
        }
        Acceleration::Metal => {
            cmake_cmd.arg("-DGGML_METAL=ON");
        }
        Acceleration::OpenCL => {
            cmake_cmd.arg("-DGGML_OPENCL=ON");
        }
        Acceleration::CPU => {
            // CPU-only build, no special flags needed
        }
    }
    
    // Platform-specific configurations
    match config.platform {
        Platform::Windows => {
            cmake_cmd.arg("-G").arg("Visual Studio 17 2022");
        }
        Platform::MacOS => {
            cmake_cmd.arg("-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0");
        }
        Platform::Linux => {
            cmake_cmd.arg("-G").arg("Unix Makefiles");
        }
    }
    
    println!("cargo:warning=Running: {:?}", cmake_cmd);
    let output = cmake_cmd.output()?;
    
    if !output.status.success() {
        println!("cargo:warning=CMAKE configure failed:");
        println!("cargo:warning=Command: {:?}", cmake_cmd);
        println!("cargo:warning=Exit code: {:?}", output.status.code());
        println!("cargo:warning=STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        println!("cargo:warning=STDERR: {}", String::from_utf8_lossy(&output.stderr));
        return Err(format!("CMAKE configuration failed with exit code: {:?}", output.status.code()).into());
    }
    
    println!("cargo:warning=CMAKE configuration completed successfully");
    Ok(())
}

#[cfg(feature = "local-llm")]
fn build_llamacpp_project(build_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:warning=Building llama.cpp project...");
    
    // Determine number of parallel jobs
    let jobs = std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| "4".to_string());
    
    let mut build_cmd = Command::new("cmake");
    build_cmd
        .arg("--build")
        .arg(build_dir)
        .arg("--config")
        .arg("Release")
        .arg("--target")
        .arg("llama-server") // Only build the server target
        .arg("-j")
        .arg(&jobs);
    
    println!("cargo:warning=Running: {:?}", build_cmd);
    let output = build_cmd.output()?;
    
    if !output.status.success() {
        println!("cargo:warning=CMAKE build failed:");
        println!("cargo:warning=Command: {:?}", build_cmd);
        println!("cargo:warning=Exit code: {:?}", output.status.code());
        println!("cargo:warning=STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        println!("cargo:warning=STDERR: {}", String::from_utf8_lossy(&output.stderr));
        return Err(format!("CMAKE build failed with exit code: {:?}", output.status.code()).into());
    }
    
    println!("cargo:warning=llama.cpp build completed successfully");
    Ok(())
}

#[cfg(feature = "local-llm")]
fn copy_server_binary(build_dir: &Path, out_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    
    println!("cargo:warning=Copying server binary...");
    
    // Find the llama-server binary (location varies by platform)
    let server_binary_name = if cfg!(target_os = "windows") {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    
    let possible_paths = [
        build_dir.join("tools").join("server").join(server_binary_name),
        build_dir.join("bin").join(server_binary_name),
        build_dir.join(server_binary_name),
        build_dir.join("Release").join(server_binary_name), // Visual Studio layout
    ];
    
    let server_binary = possible_paths
        .iter()
        .find(|p| p.exists())
        .ok_or("Could not find llama-server binary")?;
    
    let dest_binary = out_path.join(server_binary_name);
    fs::copy(server_binary, &dest_binary)?;
    
    // Make executable on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest_binary)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest_binary, perms)?;
    }
    
    println!("cargo:warning=Server binary copied to: {}", dest_binary.display());
    
    // Set environment variable so our Rust code can find the binary
    println!("cargo:rustc-env=LLAMA_SERVER_PATH={}", dest_binary.display());
    
    Ok(())
}

#[cfg(feature = "local-llm")]
fn is_command_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}