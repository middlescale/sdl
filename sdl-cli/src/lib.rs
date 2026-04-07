pub mod app;
pub mod callback;
pub mod cli;
#[cfg(feature = "command")]
pub mod command;
pub mod config;
#[cfg(feature = "command")]
pub mod console_out;
pub mod frontend;
pub mod fs_access;
pub mod identifier;
pub mod root_check;

mod args_parse;
mod generated_serial_number {
    include!(concat!(env!("OUT_DIR"), "/generated_serial_number.rs"));
}

pub(crate) fn build_version_string() -> String {
    let version = if generated_serial_number::GIT_TAG.is_empty() {
        "main".to_string()
    } else {
        generated_serial_number::GIT_TAG.to_string()
    };

    if generated_serial_number::GIT_COMMIT.is_empty() {
        format!(
            "{version} (serial {})",
            generated_serial_number::SERIAL_NUMBER
        )
    } else {
        format!(
            "{version} (commit {}, serial {})",
            generated_serial_number::GIT_COMMIT,
            generated_serial_number::SERIAL_NUMBER
        )
    }
}
