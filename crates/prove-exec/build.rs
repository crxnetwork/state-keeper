//! The guest ELF is NEVER rebuilt here — a rebuild changes the vkey and the chain
//! rejects every proof. This script sha-guards the vendored `elf/scenario-es-program`
//! (sha256 6068e927e1d962783b9b144efd36395ac013f65011e1a1ba567858e735b1ccaa, vkey
//! 0x005283d662917901042cc66534ede1c3ee827fb129293f70239d745485d85a8e) and aborts on
//! drift. Reproducible via SP1's `cargo prove build --docker`, image v6.3.0.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const EXPECTED_SHA256: &str = "6068e927e1d962783b9b144efd36395ac013f65011e1a1ba567858e735b1ccaa";

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let elf_path = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("elf")
        .join("scenario-es-program");

    if !elf_path.exists() {
        panic!(
            "vendored ELF not found at {} — it must be committed; do NOT rebuild the guest",
            elf_path.display()
        );
    }
    let bytes = std::fs::read(&elf_path).expect("read vendored ELF");
    let digest = sha256_hex(&bytes);
    if digest != EXPECTED_SHA256 {
        panic!(
            "ELF sha256 mismatch: expected {EXPECTED_SHA256}, got {digest}. \
             The vendored ELF must be byte-identical to the proven artifact."
        );
    }

    let p = elf_path.to_str().expect("utf-8 path");
    println!("cargo:rustc-env=SP1_ELF_scenario-es-program={p}");
    println!("cargo:rerun-if-changed={p}");
}

fn sha256_hex(data: &[u8]) -> String {
    use std::io::Write;
    let try_cmd = |prog: &str, args: &[&str]| -> Option<String> {
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(data).ok()?;
        let out = child.wait_with_output().ok()?;
        if out.status.success() {
            Some(String::from_utf8(out.stdout).ok()?.trim().split_whitespace().next()?.to_string())
        } else {
            None
        }
    };
    try_cmd("sha256sum", &["-b", "-"])
        .or_else(|| try_cmd("shasum", &["-a", "256", "-b", "-"]))
        .expect("no sha256 tool available (need sha256sum or shasum)")
}
