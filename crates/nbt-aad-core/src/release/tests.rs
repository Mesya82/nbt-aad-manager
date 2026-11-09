use super::*;

/// Real read-backs from the pilot car after the operator's update (run 4).
const RUN4_READBACK: &str =
    include_str!("../../../../tests/fixtures/pilot-g31/run4-20261109-aa-running-usb/readback.tsv");

fn readback(prefix: &str) -> Vec<Observed> {
    RUN4_READBACK
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            let (path, rc, size, sha) = (c[0], c[1], c[2], c[3]);
            let name = path.strip_prefix(prefix)?;
            (rc == "0" && !name.contains('/')).then(|| Observed {
                name: name.to_owned(),
                size: size.parse().unwrap(),
                sha256: sha.to_owned(),
            })
        })
        .collect()
}

fn one(prefix: &str, name: &str) -> Observed {
    let mut v: Vec<_> = readback(prefix)
        .into_iter()
        .filter(|o| o.name == name)
        .collect();
    v.dedup();
    assert_eq!(v.len(), 1, "{prefix}{name}");
    v.remove(0)
}

fn installed() -> (Observed, Vec<Observed>) {
    (
        one("/opt/aa/", "nbt-aad"),
        readback("/opt/hmi/ID5/data/ro/Plugins/NbtAad/"),
    )
}

fn backup() -> (Observed, Vec<Observed>) {
    let mut d = one("/opt/aa/", "nbt-aad.old");
    d.name = "nbt-aad".into();
    (d, readback("/opt/aa/NbtAad.old/"))
}

fn tag(i: &Identification) -> &str {
    match i {
        Identification::Known(k) => k.tag,
        other => panic!("not known: {other:?}"),
    }
}

#[test]
fn pilot_installed_set_is_the_gps_release() {
    let (d, p) = installed();
    let id = identify(&d, &p);
    assert_eq!(tag(&id), "gps");
    if let Identification::Known(k) = id {
        // Title, tag and embedded build disagree: identification is by digest only.
        assert_eq!(k.title, "v1.9.35-combined-prs");
        assert_eq!(k.daemon_build, "Build: v1.9.36-combo");
    }
}

#[test]
fn pilot_backup_set_is_volsliderfixforreal() {
    let (d, p) = backup();
    assert_eq!(tag(&identify(&d, &p)), "volsliderfixforreal");
}

#[test]
fn mixed_daemon_and_plugin_is_reported_as_mixed() {
    let (d, _) = installed();
    let (_, p) = backup();
    assert!(matches!(
        identify(&d, &p),
        Identification::Mixed { daemon, plugin } if daemon.tag == "gps" && plugin.tag == "volsliderfixforreal"
    ));
}

#[test]
fn any_single_deviation_makes_it_unknown() {
    let (d, p) = installed();
    // Plugin deviations.
    let mut cases: Vec<(&str, Observed, Vec<Observed>)> = Vec::new();
    for i in 0..p.len() {
        let mut q = p.clone();
        let flip = if p[i].sha256.starts_with('0') {
            "1"
        } else {
            "0"
        };
        q[i].sha256.replace_range(0..1, flip);
        cases.push(("flipped digest", d.clone(), q));
        let mut q = p.clone();
        q[i].size += 1;
        cases.push(("size", d.clone(), q));
        let mut q = p.clone();
        q[i].name = q[i].name.to_ascii_lowercase();
        if q[i].name != p[i].name {
            cases.push(("case variant", d.clone(), q));
        }
        let mut q = p.clone();
        q.remove(i);
        cases.push(("missing file", d.clone(), q));
    }
    let mut q = p.clone();
    q.push(Observed {
        name: "LibNbtAad.so.old".into(),
        size: 1,
        sha256: "00".repeat(32),
    });
    cases.push(("extra file", d.clone(), q));
    let mut q = p.clone();
    q.push(p[0].clone());
    cases.push(("duplicate file", d.clone(), q));
    // Daemon deviations.
    let mut d2 = d.clone();
    d2.size -= 1;
    cases.push(("daemon size", d2, p.clone()));
    let mut d2 = d.clone();
    d2.name = "nbt-aad.old".into();
    cases.push(("daemon name", d2, p.clone()));

    for (what, d, p) in cases {
        let id = identify(&d, &p);
        assert!(
            matches!(
                id,
                Identification::Unknown(_) | Identification::Mixed { .. }
            ),
            "{what}: {id:?}"
        );
        assert!(!matches!(id, Identification::Known(_)), "{what}");
    }
}

#[test]
fn unknown_reasons_name_each_failing_part() {
    let o = Observed {
        name: "nbt-aad".into(),
        size: 1,
        sha256: "00".repeat(32),
    };
    let Identification::Unknown(why) = identify(&o, &[]) else {
        panic!()
    };
    assert_eq!(why.len(), 2, "{why:?}");
}

#[test]
fn digest_comparison_ignores_hex_case_only() {
    let (mut d, p) = installed();
    d.sha256 = d.sha256.to_ascii_uppercase();
    assert_eq!(tag(&identify(&d, &p)), "gps");
}

#[test]
fn table_invariants() {
    let mut tags: Vec<_> = KNOWN.iter().map(|k| k.tag).collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), KNOWN.len(), "duplicate tags");
    for k in KNOWN {
        assert_eq!(k.daemon.name, "nbt-aad");
        assert!(
            ARCHIVE_DIRS
                .iter()
                .any(|d| k.archive.name.eq_ignore_ascii_case(&format!("{d}.zip")))
        );
        for (i, fd) in k.plugin.iter().enumerate() {
            assert_eq!(fd.name, PLUGIN_FILES[i], "{}", k.tag);
        }
        for fd in k.plugin.iter().chain([&k.daemon, &k.archive]) {
            assert_eq!(fd.sha256.len(), 64, "{} {}", k.tag, fd.name);
            assert!(
                fd.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert!(fd.size > 0);
        }
    }
    // No two releases share a daemon digest (identification must be unambiguous).
    for (i, a) in KNOWN.iter().enumerate() {
        for b in &KNOWN[i + 1..] {
            assert_ne!(a.daemon.sha256, b.daemon.sha256);
        }
    }
}

// ---- archive layout ----

/// Entry lists of the real upstream archives (`unzip -Z1`).
const GPS_ZIP: &[&str] = &[
    "Releases/NbtAad.manifest",
    "Releases/NbtAad.xml",
    "Releases/NbtAad_ALL_Images.zip",
    "Releases/NbtAad_ALL_Texts.zip",
    "Releases/libNbtAad.so",
];
const VOLSLIDER_ZIP: &[&str] = &[
    "Releases/",
    "Releases/libNbtAad.so",
    "Releases/NbtAad.manifest",
    "Releases/NbtAad.xml",
    "Releases/NbtAad_ALL_Images.zip",
    "Releases/NbtAad_ALL_Texts.zip",
];

#[test]
fn real_archives_validate() {
    assert_eq!(validate_archive_layout(GPS_ZIP).unwrap(), "Releases");
    assert_eq!(validate_archive_layout(VOLSLIDER_ZIP).unwrap(), "Releases");
}

#[test]
fn all_observed_top_dir_spellings_accepted() {
    for d in ARCHIVE_DIRS {
        let v: Vec<String> = PLUGIN_FILES.iter().map(|f| format!("{d}/{f}")).collect();
        let r: Vec<&str> = v.iter().map(String::as_str).collect();
        assert_eq!(validate_archive_layout(&r).unwrap(), d);
    }
}

#[test]
fn layout_rejections() {
    use LayoutError as E;
    let with = |extra: &str| {
        let mut v = GPS_ZIP.to_vec();
        v.push(extra);
        validate_archive_layout(&v)
    };
    let without = |i: usize| {
        let mut v = GPS_ZIP.to_vec();
        v.remove(i);
        validate_archive_layout(&v)
    };
    assert!(matches!(with("Releases/../x"), Err(E::UnsafePath(_))));
    assert!(matches!(with("/Releases/x"), Err(E::UnsafePath(_))));
    assert!(matches!(
        with("Releases\\libNbtAad.so"),
        Err(E::UnsafePath(_))
    ));
    assert!(matches!(
        with("Releases/./libNbtAad.so"),
        Err(E::UnsafePath(_))
    ));
    assert!(matches!(with(""), Err(E::UnsafePath(_))));
    assert!(matches!(with("nbt-aad"), Err(E::NoTopDir)));
    assert!(matches!(with("Release/NbtAad.xml"), Err(E::SeveralTopDirs)));
    assert!(matches!(
        with("RELEASES/NbtAad.xml"),
        Err(E::UnknownTopDir(_))
    ));
    assert!(matches!(
        with("Releases/LibNbtAad.so"),
        Err(E::Unexpected(_))
    ));
    assert!(matches!(
        with("Releases/sub/libNbtAad.so"),
        Err(E::Unexpected(_))
    ));
    assert!(matches!(with("Releases/pf_aa"), Err(E::Unexpected(_))));
    assert!(matches!(
        with("Releases/libNbtAad.so"),
        Err(E::Duplicate(_))
    ));
    for i in 0..GPS_ZIP.len() {
        assert!(matches!(without(i), Err(E::Missing(_))), "{i}");
    }
    assert!(matches!(validate_archive_layout(&[]), Err(E::NoTopDir)));
    assert!(matches!(
        validate_archive_layout(&["Releases/"]),
        Err(E::Missing(_))
    ));
}

// ---- metadata selection and content verification ----

/// The `gps` release metadata as GitHub publishes it (2026-11-09).
fn gps_meta() -> ReleaseMeta {
    let a = |name: &str, size: u64, d: &str| AssetMeta {
        name: name.into(),
        size,
        digest: Some(format!("sha256:{d}")),
        url: format!("https://example.invalid/{name}"),
    };
    ReleaseMeta {
        tag: "gps".into(),
        draft: false,
        assets: vec![
            a(
                "nbt-aad",
                773_142,
                "1ec14876503b0bac597e8871b7099deb334c6401e3696bd2d8cf2db8cbc972b3",
            ),
            a(
                "pf_aa",
                39_844,
                "5ae04c87476a041cad945e2afe6da7067ac3defdd9beea96407d8b3a3df339bb",
            ),
            a(
                "Releases.zip",
                92_668,
                "02baed4a40ec4ac53bbafe5cdfacd96d0280af3c9d2e88e3e767d77906cf1f92",
            ),
        ],
    }
}

#[test]
fn real_metadata_selects_daemon_and_archive_only() {
    let s = select_assets(KNOWN, "gps", &gps_meta()).unwrap();
    assert_eq!(s.known.tag, "gps");
    assert_eq!(s.daemon.name, "nbt-aad");
    assert_eq!(s.archive.name, "Releases.zip");
}

#[test]
fn metadata_deviations_are_refused_before_download() {
    use VerifyError as E;
    type M = fn(&mut ReleaseMeta);
    type Check = fn(&VerifyError) -> bool;
    let cases: &[(&str, M, Check)] = &[
        (
            "tag mismatch",
            |m| m.tag = "gps2".into(),
            |e| matches!(e, E::TagMismatch { .. }),
        ),
        ("draft", |m| m.draft = true, |e| matches!(e, E::Draft(_))),
        (
            "missing daemon",
            |m| m.assets.retain(|a| a.name != "nbt-aad"),
            |e| matches!(e, E::MissingAsset(_)),
        ),
        (
            "renamed archive",
            |m| m.assets[2].name = "release.zip".into(),
            |e| matches!(e, E::MissingAsset(_)),
        ),
        (
            "duplicate daemon",
            |m| {
                let d = m.assets[0].clone();
                m.assets.push(d);
            },
            |e| matches!(e, E::DuplicateAsset(_)),
        ),
        (
            "size",
            |m| m.assets[0].size += 1,
            |e| matches!(e, E::MetaDiffers { what: "size", .. }),
        ),
        (
            "no digest",
            |m| m.assets[2].digest = None,
            |e| matches!(e, E::NoDigest { .. }),
        ),
        (
            "non-sha256 digest",
            |m| m.assets[0].digest = Some("sha512:00".into()),
            |e| matches!(e, E::NoDigest { .. }),
        ),
        (
            "bare hex digest",
            |m| m.assets[0].digest = m.assets[0].digest.as_ref().map(|d| d[7..].to_owned()),
            |e| matches!(e, E::NoDigest { .. }),
        ),
        (
            "digest differs",
            |m| m.assets[2].digest = Some(format!("sha256:{}", "0".repeat(64))),
            |e| matches!(e, E::MetaDiffers { what: "sha256", .. }),
        ),
    ];
    for (what, f, ok) in cases {
        let mut m = gps_meta();
        f(&mut m);
        let e = select_assets(KNOWN, "gps", &m).unwrap_err();
        assert!(ok(&e), "{what}: {e:?}");
    }
    assert!(matches!(
        select_assets(KNOWN, "brwsr-ap", &gps_meta()),
        Err(VerifyError::UnknownTag(_))
    ));
}

#[test]
fn digest_prefix_is_case_insensitive_hex_only() {
    let mut m = gps_meta();
    for a in &mut m.assets {
        a.digest = a
            .digest
            .as_ref()
            .map(|d| format!("sha256:{}", d[7..].to_uppercase()));
    }
    assert!(select_assets(KNOWN, "gps", &m).is_ok());
}

/// A synthetic pinned release (no upstream bytes in the repository).
fn synthetic() -> (KnownRelease, Vec<(String, Vec<u8>)>) {
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let content = |n: &str| format!("synthetic {n}\n").into_bytes();
    let fd = |n: &'static str, d: &[u8]| FileDigest {
        name: n,
        size: d.len() as u64,
        sha256: leak(crate::transport::sha256_hex(d)),
    };
    let plugin = PLUGIN_FILES.map(|n| fd(n, &content(n)));
    let k = KnownRelease {
        tag: "synthetic",
        title: "t",
        daemon_build: "Build: v0",
        plugin_marker: "rhmiapp-0",
        daemon: fd("nbt-aad", b"daemon"),
        archive: fd("Releases.zip", b"zip"),
        plugin,
    };
    let entries = PLUGIN_FILES
        .iter()
        .rev()
        .map(|n| (format!("Releases/{n}"), content(n)))
        .collect();
    (k, entries)
}

#[test]
fn archive_contents_verify_and_come_back_in_canonical_order() {
    let (k, e) = synthetic();
    let out = verify_archive_contents(&k, &e).unwrap();
    let names: Vec<_> = out.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, PLUGIN_FILES);
    assert_eq!(out[4].1, b"synthetic libNbtAad.so\n");
}

#[test]
fn archive_content_deviations_are_refused() {
    let (k, e) = synthetic();
    for i in 0..e.len() {
        let mut e2 = e.clone();
        e2[i].1[0] ^= 1;
        assert!(
            matches!(
                verify_archive_contents(&k, &e2),
                Err(VerifyError::ContentDiffers { what: "sha256", .. })
            ),
            "{i}"
        );
        let mut e2 = e.clone();
        e2[i].1.push(b'x');
        assert!(
            matches!(
                verify_archive_contents(&k, &e2),
                Err(VerifyError::ContentDiffers { what: "size", .. })
            ),
            "{i}"
        );
    }
    let mut e2 = e.clone();
    e2.push(("Releases/extra".into(), vec![]));
    assert!(matches!(
        verify_archive_contents(&k, &e2),
        Err(VerifyError::Layout(_))
    ));
    // A pinned digest never matches content from another release.
    let (_, e3) = synthetic();
    let real = find_known(KNOWN, "gps").unwrap();
    assert!(verify_archive_contents(real, &e3).is_err());
}

#[test]
fn verify_blob_checks_size_then_digest() {
    let (k, _) = synthetic();
    assert!(verify_blob(&k.daemon, b"daemon").is_ok());
    assert!(matches!(
        verify_blob(&k.daemon, b"daemoN"),
        Err(VerifyError::ContentDiffers { what: "sha256", .. })
    ));
    assert!(matches!(
        verify_blob(&k.daemon, b"daemon!"),
        Err(VerifyError::ContentDiffers { what: "size", .. })
    ));
}
