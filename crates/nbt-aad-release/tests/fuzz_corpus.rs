//! Bounded, deterministic replay of the checked-in fuzz corpus on stable
//! (TEST_STRATEGY 5). Same assertions as `fuzz/fuzz_targets/*`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use nbt_aad_core::probe::{LsEntry, parse_ls};
use nbt_aad_core::profile::Observation;
use nbt_aad_core::release::{KNOWN, select_assets, validate_archive_layout};
use nbt_aad_release::{Limits, parse_release_json, read_zip};

fn corpus(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let mut v: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| {
            let p = e.unwrap().path();
            let d = std::fs::read(&p).unwrap();
            (p, d)
        })
        .collect();
    v.sort();
    assert!(!v.is_empty(), "empty corpus {target}");
    v
}

#[test]
fn read_zip_corpus() {
    for (p, d) in corpus("read_zip") {
        if let Ok(entries) = read_zip(&d, &Limits::default()) {
            for (n, _) in &entries {
                assert!(
                    !n.starts_with('/') && !n.contains("..") && !n.contains('\\'),
                    "{}",
                    p.display()
                );
            }
            let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
            let _ = validate_archive_layout(&names);
        }
    }
}

#[test]
fn release_json_corpus() {
    for (_, d) in corpus("release_json") {
        if let Ok(meta) = parse_release_json(&d) {
            let _ = select_assets(KNOWN, &meta.tag, &meta);
        }
    }
}

#[test]
fn archive_layout_corpus() {
    for (p, d) in corpus("archive_layout") {
        let s = String::from_utf8_lossy(&d);
        let entries: Vec<&str> = s.lines().collect();
        if validate_archive_layout(&entries).is_ok() {
            assert!(
                entries
                    .iter()
                    .all(|e| !e.contains("..") && !e.starts_with('/')),
                "{}",
                p.display()
            );
        }
    }
}

#[test]
fn parse_ls_corpus() {
    for (p, d) in corpus("parse_ls") {
        for e in parse_ls(&String::from_utf8_lossy(&d)) {
            if let LsEntry::File { name, .. } = e {
                assert!(!name.chars().any(char::is_whitespace), "{}", p.display());
            }
        }
    }
}

#[test]
fn readback_tsv_corpus() {
    for (_, d) in corpus("readback_tsv") {
        let mut o = Observation::default();
        let _ = o.add_readback_tsv(&String::from_utf8_lossy(&d));
    }
}

#[test]
fn corpus_expectations() {
    let good = corpus("read_zip")
        .into_iter()
        .find(|(p, _)| p.ends_with("synthetic-good.zip"))
        .unwrap()
        .1;
    let e = read_zip(&good, &Limits::default()).unwrap();
    let names: Vec<&str> = e.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(validate_archive_layout(&names).unwrap(), "Releases");
    let bad = corpus("read_zip")
        .into_iter()
        .find(|(p, _)| p.ends_with("traversal.zip"))
        .unwrap()
        .1;
    assert!(read_zip(&bad, &Limits::default()).is_err());
}
