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
