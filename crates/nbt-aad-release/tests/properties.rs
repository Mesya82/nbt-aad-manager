//! Property tests for untrusted network/archive input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use nbt_aad_release::{Limits, parse_release_json, read_zip};
use proptest::prelude::*;

proptest! {
    // Fixed seed: CI runs are reproducible (TEST_STRATEGY 4). Longer, random
    // campaigns: PROPTEST_CASES=100000 with a different seed locally.
    #![proptest_config(ProptestConfig {
        cases: 2000,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x6e62_7461_6164),
        ..ProptestConfig::default()
    })]

    #[test]
    fn read_zip_never_panics_on_arbitrary_bytes(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = read_zip(&b, &Limits::default());
    }

    /// Mutating a valid archive either fails or still yields only safe names.
    #[test]
    fn read_zip_on_mutated_archives_yields_only_safe_names(pos in any::<prop::sample::Index>(), byte: u8) {
        let mut z = small_zip();
        let i = pos.index(z.len());
        z[i] = byte;
        if let Ok(entries) = read_zip(&z, &Limits::default()) {
            for (n, _) in entries {
                prop_assert!(!n.starts_with('/') && !n.contains("..") && !n.contains('\\'), "{n:?}");
            }
        }
    }

    #[test]
    fn release_json_parser_never_panics(s in "\\PC{0,300}") {
        let _ = parse_release_json(s.as_bytes());
    }
}

fn small_zip() -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let o = zip::write::SimpleFileOptions::default();
    w.add_directory("Releases", o).unwrap();
    w.start_file("Releases/NbtAad.xml", o).unwrap();
    w.write_all(b"<x/>").unwrap();
    w.finish().unwrap().into_inner()
}
