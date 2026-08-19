use cfg_aliases::cfg_aliases;
use rand::Rng;
use std::fs;
use std::path::Path;
use std::process::Command;

fn write_if_changed(src: &Path, dst: &Path) {
    let src_bytes = fs::read(src).expect("read generated proto failed");
    let same = fs::read(dst)
        .map(|dst_bytes| dst_bytes == src_bytes)
        .unwrap_or(false);
    if !same {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).expect("create proto output dir failed");
        }
        fs::write(dst, src_bytes).expect("write proto output failed");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto/message.proto");
    emit_git_rerun_hints();

    let now_time = chrono::Local::now();
    let serial_number = format!(
        "{}-{}",
        now_time.format("%y%m%d%H%M"),
        rand::thread_rng().gen_range(100..1000)
    );
    println!("cargo:rustc-env=SDL_BUILD_SERIAL={serial_number}");
    println!(
        "cargo:rustc-env=SDL_BUILD_GIT_TAG={}",
        git_output(&["describe", "--tags", "--exact-match"]).unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=SDL_BUILD_GIT_COMMIT={}",
        git_output(&["rev-parse", "--short", "HEAD"]).unwrap_or_default()
    );

    cfg_aliases! {
        cipher: {
            any(feature = "aes_gcm",
            feature = "chacha20_poly1305",
            feature = "aes_cbc",
            feature = "aes_ecb",
            feature = "sm4_cbc"
        )},
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let generated_dir = Path::new(&out_dir).join("proto-gen");
    fs::create_dir_all(&generated_dir).expect("create proto temp output dir failed");

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&generated_dir)
        .inputs(&["proto/message.proto"])
        .include("proto")
        // .customize(
        //     protobuf_codegen::Customize::default()
        //         .tokio_bytes(true)
        // )
        .run()
        .expect("Codegen failed.");

    let generated = generated_dir.join("message.rs");
    let target = Path::new("src/proto/message.rs");
    write_if_changed(&generated, target);
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn emit_git_rerun_hints() {
    let Some(head_path) = git_output(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    println!("cargo:rerun-if-changed={head_path}");

    // A checkout normally updates the branch ref rather than HEAD itself. Track
    // that ref too, as well as packed refs and tag refs used by `git describe`.
    if let Ok(head) = fs::read_to_string(&head_path) {
        if let Some(reference) = head.strip_prefix("ref: ").map(str::trim) {
            if let Some(reference_path) = git_output(&["rev-parse", "--git-path", reference]) {
                println!("cargo:rerun-if-changed={reference_path}");
            }
        }
    }
    for path in ["packed-refs", "refs/tags"] {
        if let Some(path) = git_output(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}
