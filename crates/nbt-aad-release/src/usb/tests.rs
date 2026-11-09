#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use nbt_aad_core::release::{FileDigest, PLUGIN_FILES};
use nbt_aad_core::transport::sha256_hex;

const OP: &str = "20261109T170000Z-abc123";

fn content(n: &str) -> Vec<u8> {
    format!("synthetic {n}\n").into_bytes()
}

fn fd(n: &'static str) -> FileDigest {
    let d = content(n);
    FileDigest {
        name: n,
        size: d.len() as u64,
        sha256: Box::leak(sha256_hex(&d).into_boxed_str()),
    }
}

fn table() -> &'static [KnownRelease] {
    static T: std::sync::LazyLock<Vec<KnownRelease>> = std::sync::LazyLock::new(|| {
        vec![KnownRelease {
            tag: "t1",
            title: "t",
            daemon_build: "Build: v0",
            plugin_marker: "rhmiapp-0",
            daemon: fd("nbt-aad"),
            archive: fd("Releases.zip"),
            plugin: PLUGIN_FILES.map(fd),
        }]
    });
    T.as_slice()
}

fn fetched() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("nbt-aad"), content("nbt-aad")).unwrap();
    std::fs::create_dir(d.path().join("Releases")).unwrap();
    for n in PLUGIN_FILES {
        std::fs::write(d.path().join("Releases").join(n), content(n)).unwrap();
    }
    d
}

fn names(p: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn prepares_the_layout_the_plan_expects_and_keeps_unrelated_files() {
    let f = fetched();
    let usb = tempfile::tempdir().unwrap();
    std::fs::write(usb.path().join("music.mp3"), b"keep me").unwrap();
    let p = prepare(table(), "t1", f.path(), usb.path(), OP).unwrap();
    assert_eq!(p.dir, usb.path().join(format!("nbt-aad-{OP}")));
    assert_eq!(
        names(&p.dir),
        ["COMPLETE", "MANIFEST", "Releases", "nbt-aad"]
    );
    let mut want: Vec<String> = PLUGIN_FILES.iter().map(|s| (*s).to_owned()).collect();
    want.sort();
    assert_eq!(names(&p.dir.join("Releases")), want);
    assert_eq!(
        std::fs::read(p.dir.join("nbt-aad")).unwrap(),
        content("nbt-aad")
    );
    let m = std::fs::read_to_string(p.dir.join("MANIFEST")).unwrap();
    assert!(m.starts_with(&format!("nbt-aad-manager operation {OP}\nrelease t1\n")));
    assert_eq!(m.lines().count(), 8);
    assert_eq!(
        std::fs::read(usb.path().join("music.mp3")).unwrap(),
        b"keep me"
    );
    assert_eq!(
        names(usb.path()),
        ["music.mp3".to_owned(), format!("nbt-aad-{OP}")]
    );
}

#[test]
fn tampered_or_incomplete_fetch_writes_nothing() {
    for what in ["tamper", "missing"] {
        let f = fetched();
        let target = f.path().join("Releases/libNbtAad.so");
        if what == "tamper" {
            std::fs::write(&target, b"evil").unwrap();
        } else {
            std::fs::remove_file(&target).unwrap();
        }
        let usb = tempfile::tempdir().unwrap();
        assert!(
            prepare(table(), "t1", f.path(), usb.path(), OP).is_err(),
            "{what}"
        );
        assert!(
            names(usb.path()).is_empty(),
            "{what}: {:?}",
            names(usb.path())
        );
    }
}

#[test]
fn existing_target_in_any_case_is_never_touched() {
    for existing in [
        format!("nbt-aad-{OP}"),
        format!("NBT-AAD-{}", OP.to_uppercase()),
    ] {
        let f = fetched();
        let usb = tempfile::tempdir().unwrap();
        std::fs::create_dir(usb.path().join(&existing)).unwrap();
        std::fs::write(usb.path().join(&existing).join("x"), b"user").unwrap();
        assert!(matches!(
            prepare(table(), "t1", f.path(), usb.path(), OP),
            Err(FetchError::Exists(_))
        ));
        assert_eq!(names(usb.path()), std::slice::from_ref(&existing));
        assert_eq!(
            std::fs::read(usb.path().join(&existing).join("x")).unwrap(),
            b"user"
        );
    }
}

#[test]
fn refusals_before_any_write() {
    let f = fetched();
    let usb = tempfile::tempdir().unwrap();
    for bad in [
        "",
        "x",
        "20261109T170000Z-ABC123",
        "20261109T170000Z-abc12/",
        "../20261109T170000Z-a",
    ] {
        assert!(
            prepare(table(), "t1", f.path(), usb.path(), bad).is_err(),
            "{bad}"
        );
    }
    assert!(prepare(table(), "nope", f.path(), usb.path(), OP).is_err());
    assert!(prepare(table(), "t1", f.path(), &usb.path().join("missing"), OP).is_err());
    assert!(names(usb.path()).is_empty());
}
