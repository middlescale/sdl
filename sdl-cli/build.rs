use rand::Rng;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let now_time = chrono::Local::now();
    let serial_number = format!(
        "{}-{}",
        &now_time.format("%y%m%d%H%M").to_string(),
        rand::thread_rng().gen_range(100..1000)
    );
    let git_tag = git_output(&["describe", "--tags", "--exact-match"]).unwrap_or_default();
    let git_commit = git_output(&["rev-parse", "--short", "HEAD"]).unwrap_or_default();
    let generated_code = format!(
        r#"pub const SERIAL_NUMBER: &str = "{serial_number}";
pub const GIT_TAG: &str = "{git_tag}";
pub const GIT_COMMIT: &str = "{git_commit}";
"#
    );
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("generated_serial_number.rs");
    let mut file = File::create(dest_path).unwrap();
    file.write_all(generated_code.as_bytes()).unwrap();
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
