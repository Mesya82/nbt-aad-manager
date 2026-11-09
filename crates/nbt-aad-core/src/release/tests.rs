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
