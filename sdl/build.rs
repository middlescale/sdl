use cfg_aliases::cfg_aliases;
use std::fs;
use std::path::Path;

fn write_if_changed(src: &Path, dst: &Path) {
    let src_bytes = fs::read(src).expect("read generated proto failed");
    let same = fs::read(dst).map(|dst_bytes| dst_bytes == src_bytes).unwrap_or(false);
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
