//! Property-based tests for the parsers and validators that face untrusted
//! input (TEST_STRATEGY 4). Failing seeds are persisted under
//! `tests/properties.proptest-regressions` and must be committed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use nbt_aad_core::probe::{LsEntry, parse_ls};
use nbt_aad_core::profile::{Observation, PILOT_G31, classify};
use nbt_aad_core::release::{
    ARCHIVE_DIRS, AssetMeta, Identification, KNOWN, Observed, PLUGIN_FILES, ReleaseMeta, identify,
    select_assets, validate_archive_layout,
};
use proptest::prelude::*;

/// Path-ish strings biased towards the dangerous characters.
fn pathish() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just("Releases".to_owned()),
            Just("release".to_owned()),
            Just("..".to_owned()),
            Just(".".to_owned()),
            Just("".to_owned()),
            Just("\\".to_owned()),
            Just("libNbtAad.so".to_owned()),
            Just("LibNbtAad.so".to_owned()),
            Just("NbtAad.xml".to_owned()),
            "[A-Za-z0-9._ -]{0,12}",
        ],
        0..5,
    )
    .prop_map(|v| v.join("/"))
}

proptest! {
    // Fixed seed: CI runs are reproducible (TEST_STRATEGY 4). Longer, random
    // campaigns: PROPTEST_CASES=100000 with a different seed locally.
    #![proptest_config(ProptestConfig {
        cases: 2000,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x6e62_7461_6164),
        ..ProptestConfig::default()
    })]

    #[test]
    fn layout_accepts_only_the_exact_shape(entries in proptest::collection::vec(pathish(), 0..9)) {
        let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        if let Ok(top) = validate_archive_layout(&refs) {
            prop_assert!(ARCHIVE_DIRS.contains(&top.as_str()));
            let mut files: Vec<&str> = Vec::new();
            for e in &refs {
                prop_assert!(!e.contains(".."), "{e}");
                prop_assert!(!e.starts_with('/'), "{e}");
                prop_assert!(!e.contains('\\'), "{e}");
                let rest = e.strip_prefix(&format!("{top}/")).unwrap();
                if !rest.is_empty() {
                    files.push(rest);
                }
            }
            files.sort_unstable();
            let mut want = PLUGIN_FILES.to_vec();
            want.sort_unstable();
            prop_assert_eq!(files, want);
        }
    }

    #[test]
    fn layout_accepts_any_permutation_of_the_real_shape(seed in any::<u64>(), dir in 0..4usize, with_dir_entry: bool) {
        let top = ARCHIVE_DIRS[dir];
        let mut v: Vec<String> = PLUGIN_FILES.iter().map(|f| format!("{top}/{f}")).collect();
        if with_dir_entry { v.push(format!("{top}/")); }
        // Deterministic shuffle from the seed.
        let mut s = seed;
        for i in (1..v.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.swap(i, (s >> 33) as usize % (i + 1));
        }
        let refs: Vec<&str> = v.iter().map(String::as_str).collect();
        prop_assert_eq!(validate_archive_layout(&refs).unwrap(), top);
    }

    #[test]
    fn ls_parser_never_panics_and_file_names_are_single_tokens(s in "\\PC{0,400}") {
        for e in parse_ls(&s) {
            if let LsEntry::File { name, .. } = e {
                prop_assert!(!name.is_empty());
                prop_assert!(!name.chars().any(char::is_whitespace), "{name:?}");
            }
        }
    }

    #[test]
    fn readback_tsv_parser_never_panics(s in "\\PC{0,300}") {
        let mut o = Observation::default();
        let _ = o.add_readback_tsv(&s);
    }

    /// Any single perturbation of the real installed set is never `Known`.
    #[test]
    fn identify_never_accepts_a_perturbed_set(which in 0..6usize, field in 0..3usize, delta in 1..255u8) {
        let k = &KNOWN[1];
        let to_obs = |f: &nbt_aad_core::release::FileDigest| Observed { name: f.name.into(), size: f.size, sha256: f.sha256.into() };
        let mut d = to_obs(&k.daemon);
        let mut p: Vec<Observed> = k.plugin.iter().map(to_obs).collect();
        prop_assert!(matches!(identify(&d, &p), Identification::Known(_)));
        let target = if which == 5 { &mut d } else { &mut p[which] };
        match field {
            0 => target.size = target.size.wrapping_add(u64::from(delta)),
            1 => {
                let mut b = target.sha256.clone().into_bytes();
                b[usize::from(delta) % 64] = if b[usize::from(delta) % 64] == b'0' { b'1' } else { b'0' };
                target.sha256 = String::from_utf8(b).unwrap();
            }
            _ => target.name.push(char::from(b'a' + delta % 26)),
        }
        prop_assert!(!matches!(identify(&d, &p), Identification::Known(_)));
    }

    /// Arbitrary metadata never selects assets whose digest is not the pin's.
    #[test]
    fn select_assets_only_returns_pinned_digests(
        names in proptest::collection::vec(prop_oneof![Just("nbt-aad"), Just("Releases.zip"), Just("release.zip"), Just("pf_aa")], 0..5),
        digests in proptest::collection::vec(prop_oneof![Just(None), Just(Some("sha256:".to_owned() + &"0".repeat(64))), Just(Some("sha256:".to_owned() + KNOWN[1].daemon.sha256)), Just(Some("sha256:".to_owned() + KNOWN[1].archive.sha256))], 5),
        sizes in proptest::collection::vec(prop_oneof![Just(KNOWN[1].daemon.size), Just(KNOWN[1].archive.size), Just(1u64)], 5),
        draft: bool,
    ) {
        let meta = ReleaseMeta {
            tag: "gps".into(),
            draft,
            assets: names.iter().enumerate().map(|(i, n)| AssetMeta {
                name: (*n).into(), size: sizes[i], digest: digests[i].clone(), url: "https://x/y".into(),
            }).collect(),
        };
        if let Ok(s) = select_assets(KNOWN, "gps", &meta) {
            prop_assert!(!draft);
            prop_assert_eq!(s.daemon.digest.as_deref().unwrap(), format!("sha256:{}", KNOWN[1].daemon.sha256));
            prop_assert_eq!(s.archive.digest.as_deref().unwrap(), format!("sha256:{}", KNOWN[1].archive.sha256));
            prop_assert_eq!(s.daemon.size, KNOWN[1].daemon.size);
        }
    }

    /// Without read-backs, nothing is ever classified as verified.
    #[test]
    fn classify_never_verifies_without_digests(listing in "\\PC{0,300}") {
        let mut o = Observation::default();
        for id in ["hu-ls-opt-aa", "hu-ls-plugin-nbtaad", "hu-ls-nbtaad-old"] {
            o.records.insert(id.into(), nbt_aad_core::profile::Rec { rc: 0, stdout: listing.clone(), stderr: String::new() });
        }
        let verified = matches!(
            classify(&PILOT_G31, &o),
            nbt_aad_core::profile::InstallState::Verified { .. }
        );
        prop_assert!(!verified);
    }
}
