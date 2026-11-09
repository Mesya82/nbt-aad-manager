//! End-to-end fetch tests against a local HTTP server serving synthetic
//! releases (no upstream bytes, no internet).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use nbt_aad_core::release::{FileDigest, KnownRelease, PLUGIN_FILES, VerifyError};
use nbt_aad_core::transport::sha256_hex;
use nbt_aad_release::{FetchError, Limits, Source, UreqHttp, fetch, parse_release_json, read_zip};
use zip::write::SimpleFileOptions;

type Routes = Arc<Mutex<BTreeMap<String, (u16, Vec<u8>)>>>;

struct Server {
    port: u16,
    routes: Routes,
    hits: Arc<Mutex<Vec<String>>>,
}

fn serve() -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let routes: Routes = Arc::default();
    let hits: Arc<Mutex<Vec<String>>> = Arc::default();
    let (r, h) = (routes.clone(), hits.clone());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut rd = BufReader::new(s.try_clone().unwrap());
            let mut first = String::new();
            if rd.read_line(&mut first).is_err() {
                continue;
            }
            loop {
                let mut line = String::new();
                if rd.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let path = first.split_whitespace().nth(1).unwrap_or("").to_owned();
            h.lock().unwrap().push(path.clone());
            let (code, body) = r
                .lock()
                .unwrap()
                .get(&path)
                .cloned()
                .unwrap_or((404, b"not found".to_vec()));
            let _ = write!(
                s,
                "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(&body);
        }
    });
    Server { port, routes, hits }
}

impl Server {
    fn route(&self, path: &str, body: Vec<u8>) {
        self.routes.lock().unwrap().insert(path.into(), (200, body));
    }
    fn hits(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }
    fn source(&self) -> Source {
        Source {
            api_base: format!("http://127.0.0.1:{}", self.port),
            repo: "o/r".into(),
            download_prefix: format!("http://127.0.0.1:{}/dl/", self.port),
            allow_http_loopback: true,
        }
    }
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn fd(name: &'static str, data: &[u8]) -> FileDigest {
    FileDigest {
        name,
        size: data.len() as u64,
        sha256: leak(sha256_hex(data)),
    }
}

fn plugin_content(n: &str) -> Vec<u8> {
    format!("synthetic plugin {n}\n").repeat(50).into_bytes()
}

/// Build a ZIP from (name, data); a name ending in `/` is a directory.
fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let o = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (n, d) in entries {
        if let Some(dir) = n.strip_suffix('/') {
            w.add_directory(dir, o).unwrap();
        } else {
            w.start_file(*n, o).unwrap();
            w.write_all(d).unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

fn good_zip() -> Vec<u8> {
    let c: Vec<(String, Vec<u8>)> = PLUGIN_FILES
        .iter()
        .map(|n| (format!("Releases/{n}"), plugin_content(n)))
        .collect();
    let mut e: Vec<(&str, &[u8])> = vec![("Releases/", b"")];
    e.extend(c.iter().map(|(n, d)| (n.as_str(), d.as_slice())));
    make_zip(&e)
}

const DAEMON: &[u8] = b"\x7fELF synthetic daemon Build: v0.0.0-test\n";

/// A pinned table for `archive`, and a server publishing it as tag `t1`.
fn setup(archive: Vec<u8>) -> (Server, &'static [KnownRelease], Vec<u8>) {
    let srv = serve();
    let k = KnownRelease {
        tag: "t1",
        title: "test",
        daemon_build: "Build: v0.0.0-test",
        plugin_marker: "rhmiapp-0",
        daemon: fd("nbt-aad", DAEMON),
        archive: fd("Releases.zip", &archive),
        plugin: PLUGIN_FILES.map(|n| fd(n, &plugin_content(n))),
    };
    let table: &'static [KnownRelease] = Box::leak(vec![k].into_boxed_slice());
    srv.route("/dl/t1/nbt-aad", DAEMON.to_vec());
    srv.route("/dl/t1/Releases.zip", archive.clone());
    srv.route("/repos/o/r/releases/tags/t1", meta_json(&srv, &k, None));
    (srv, table, archive)
}

fn meta_json(srv: &Server, k: &KnownRelease, digest_override: Option<&str>) -> Vec<u8> {
    let a = |f: &FileDigest| {
        let d = digest_override.map_or(format!("\"sha256:{}\"", f.sha256), str::to_owned);
        format!(
            r#"{{"name":"{}","size":{},"digest":{},"browser_download_url":"http://127.0.0.1:{}/dl/t1/{}"}}"#,
            f.name, f.size, d, srv.port, f.name
        )
    };
    format!(
        r#"{{"tag_name":"t1","draft":false,"assets":[{},{},{{"name":"pf_aa","size":1,"digest":null,"browser_download_url":"x"}}]}}"#,
        a(&k.daemon),
        a(&k.archive)
    )
    .into_bytes()
}

fn run(
    srv: &Server,
    table: &'static [KnownRelease],
    out: &std::path::Path,
) -> Result<nbt_aad_release::Fetched, FetchError> {
    fetch(
        &mut UreqHttp::new(true),
        &srv.source(),
        table,
        "t1",
        out,
        &Limits::default(),
    )
}

#[test]
fn happy_path_stages_verified_files_atomically() {
    let (srv, table, archive) = setup(good_zip());
    let tmp = tempfile::tempdir().unwrap();
    let f = run(&srv, table, tmp.path()).unwrap();
    let d = tmp.path().join("t1");
    assert_eq!(f.dir, d);
    assert_eq!(std::fs::read(d.join("nbt-aad")).unwrap(), DAEMON);
    assert_eq!(std::fs::read(d.join("Releases.zip")).unwrap(), archive);
    for n in PLUGIN_FILES {
        assert_eq!(
            std::fs::read(d.join("Releases").join(n)).unwrap(),
            plugin_content(n)
        );
    }
    let sums = std::fs::read_to_string(d.join("SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 7);
    assert!(sums.contains(&format!("{}  nbt-aad\n", sha256_hex(DAEMON))));
    let names: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("t1")],
        "no staging left behind"
    );
    // pf_aa (firewall installer) is never downloaded.
    assert!(!srv.hits().iter().any(|h| h.contains("pf_aa")));
}

fn assert_nothing_written(out: &std::path::Path) {
    let left: Vec<_> = std::fs::read_dir(out)
        .map(|r| r.map(|e| e.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "left behind: {left:?}");
}

#[test]
fn tampered_daemon_is_refused_before_archive_download() {
    let (srv, table, _) = setup(good_zip());
    srv.route("/dl/t1/nbt-aad", {
        let mut d = DAEMON.to_vec();
        d[5] ^= 1;
        d
    });
    let tmp = tempfile::tempdir().unwrap();
    let e = run(&srv, table, tmp.path()).unwrap_err();
    assert!(
        matches!(e, FetchError::Verify(VerifyError::ContentDiffers { .. })),
        "{e}"
    );
    assert!(!srv.hits().iter().any(|h| h.ends_with("Releases.zip")));
    assert_nothing_written(tmp.path());
}

#[test]
fn oversized_body_is_cut_off() {
    let (srv, table, _) = setup(good_zip());
    let mut d = DAEMON.to_vec();
    d.extend(vec![0u8; 1 << 20]);
    srv.route("/dl/t1/nbt-aad", d);
    let tmp = tempfile::tempdir().unwrap();
    let e = run(&srv, table, tmp.path()).unwrap_err();
    assert!(
        matches!(&e, FetchError::Http { msg, .. } if msg.contains("limit")),
        "{e}"
    );
    assert_nothing_written(tmp.path());
}

#[test]
fn metadata_problems_stop_before_any_asset_download() {
    for (what, digest) in [
        ("missing digest", Some("null")),
        (
            "wrong digest",
            Some("\"sha256:0000000000000000000000000000000000000000000000000000000000000000\""),
        ),
    ] {
        let (srv, table, _) = setup(good_zip());
        let k = table[0];
        srv.route("/repos/o/r/releases/tags/t1", meta_json(&srv, &k, digest));
        let tmp = tempfile::tempdir().unwrap();
        let e = run(&srv, table, tmp.path()).unwrap_err();
        assert!(matches!(e, FetchError::Verify(_)), "{what}: {e}");
        assert_eq!(srv.hits(), vec!["/repos/o/r/releases/tags/t1"], "{what}");
        assert_nothing_written(tmp.path());
    }
}

#[test]
fn asset_url_outside_prefix_is_refused() {
    let (srv, table, _) = setup(good_zip());
    let k = table[0];
    let j = String::from_utf8(meta_json(&srv, &k, None))
        .unwrap()
        .replace("/dl/t1/nbt-aad", "/evil/nbt-aad");
    srv.route("/repos/o/r/releases/tags/t1", j.into_bytes());
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        run(&srv, table, tmp.path()),
        Err(FetchError::UrlRefused(_))
    ));
    assert_eq!(srv.hits().len(), 1);
}

#[test]
fn http_is_refused_unless_loopback_is_explicitly_allowed() {
    let (srv, table, _) = setup(good_zip());
    let mut src = srv.source();
    src.allow_http_loopback = false;
    let tmp = tempfile::tempdir().unwrap();
    let e = fetch(
        &mut UreqHttp::new(false),
        &src,
        table,
        "t1",
        tmp.path(),
        &Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(e, FetchError::UrlRefused(_)), "{e}");
    assert!(srv.hits().is_empty());
}

#[test]
fn unknown_tag_and_existing_output_make_no_requests() {
    let (srv, table, _) = setup(good_zip());
    let tmp = tempfile::tempdir().unwrap();
    let e = fetch(
        &mut UreqHttp::new(true),
        &srv.source(),
        table,
        "t2",
        tmp.path(),
        &Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(e, FetchError::Verify(VerifyError::UnknownTag(_))));
    std::fs::create_dir(tmp.path().join("t1")).unwrap();
    std::fs::write(tmp.path().join("t1/keep"), b"user data").unwrap();
    assert!(matches!(
        run(&srv, table, tmp.path()),
        Err(FetchError::Exists(_))
    ));
    assert!(srv.hits().is_empty());
    assert_eq!(
        std::fs::read(tmp.path().join("t1/keep")).unwrap(),
        b"user data"
    );
}

#[test]
fn metadata_http_error_is_reported() {
    let (srv, table, _) = setup(good_zip());
    srv.routes
        .lock()
        .unwrap()
        .insert("/repos/o/r/releases/tags/t1".into(), (404, b"{}".to_vec()));
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        run(&srv, table, tmp.path()),
        Err(FetchError::Http { .. })
    ));
}

#[test]
fn foreign_staging_leftovers_are_never_touched() {
    // Unique staging names: a leftover (or a concurrent fetch's staging) is
    // neither reused nor deleted.
    let (srv, table, _) = setup(good_zip());
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".t1.partial")).unwrap();
    std::fs::write(tmp.path().join(".t1.partial/junk"), b"x").unwrap();
    let f = run(&srv, table, tmp.path()).unwrap();
    assert!(!f.dir.join("junk").exists());
    assert_eq!(
        std::fs::read(tmp.path().join(".t1.partial/junk")).unwrap(),
        b"x"
    );
    let names: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

#[test]
fn existing_empty_directory_is_not_replaced() {
    let (srv, table, _) = setup(good_zip());
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("t1")).unwrap();
    assert!(matches!(
        run(&srv, table, tmp.path()),
        Err(FetchError::Exists(_))
    ));
    assert_eq!(std::fs::read_dir(tmp.path().join("t1")).unwrap().count(), 0);
    assert!(srv.hits().is_empty());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_at_target_is_not_replaced() {
    let (srv, table, _) = setup(good_zip());
    let tmp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/nonexistent/target", tmp.path().join("t1")).unwrap();
    assert!(matches!(
        run(&srv, table, tmp.path()),
        Err(FetchError::Exists(_))
    ));
    assert!(
        std::fs::symlink_metadata(tmp.path().join("t1"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn asset_url_for_another_tag_is_refused() {
    let (srv, table, _) = setup(good_zip());
    let k = table[0];
    let j = String::from_utf8(meta_json(&srv, &k, None))
        .unwrap()
        .replace("/dl/t1/nbt-aad", "/dl/t0/nbt-aad");
    srv.route("/repos/o/r/releases/tags/t1", j.into_bytes());
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        run(&srv, table, tmp.path()),
        Err(FetchError::UrlRefused(_))
    ));
    assert_eq!(srv.hits().len(), 1, "only the metadata request");
}

#[test]
fn pinned_archive_with_bad_layout_is_still_refused() {
    // Even if the pin matched a malformed archive, layout validation stops it.
    let c = plugin_content("NbtAad.xml");
    let mut e: Vec<(&str, &[u8])> = PLUGIN_FILES
        .iter()
        .map(|n| {
            (
                leak(format!("Releases/{n}")),
                Box::leak(plugin_content(n).into_boxed_slice()) as &[u8],
            )
        })
        .collect();
    e.push(("Releases/extra.sh", &c));
    let (srv, table, _) = setup(make_zip(&e));
    let tmp = tempfile::tempdir().unwrap();
    let err = run(&srv, table, tmp.path()).unwrap_err();
    assert!(
        matches!(err, FetchError::Verify(VerifyError::Layout(_))),
        "{err}"
    );
    assert_nothing_written(tmp.path());
}

// ---- read_zip hardening ----

#[test]
fn zip_symlinks_are_rejected() {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.add_symlink(
        "Releases/libNbtAad.so",
        "/etc/passwd",
        SimpleFileOptions::default(),
    )
    .unwrap();
    let z = w.finish().unwrap().into_inner();
    let e = read_zip(&z, &Limits::default()).unwrap_err();
    assert!(e.to_string().contains("symlink"), "{e}");
}

#[test]
fn zip_unsafe_names_are_rejected() {
    for n in ["../x", "/abs/x", "Releases/../../x"] {
        let z = make_zip(&[(n, b"x")]);
        assert!(read_zip(&z, &Limits::default()).is_err(), "{n}");
    }
}

#[test]
fn zip_limits_are_enforced() {
    let big = vec![0u8; 200_000]; // compresses to almost nothing
    let z = make_zip(&[("Releases/libNbtAad.so", &big)]);
    let l = Limits {
        max_entry: 100_000,
        ..Limits::default()
    };
    assert!(read_zip(&z, &l).is_err(), "entry limit");
    let l = Limits {
        max_uncompressed_total: 100_000,
        ..Limits::default()
    };
    assert!(read_zip(&z, &l).is_err(), "total limit");
    let many: Vec<(String, Vec<u8>)> = (0..40)
        .map(|i| (format!("Releases/f{i}"), vec![]))
        .collect();
    let refs: Vec<(&str, &[u8])> = many
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    assert!(
        read_zip(&make_zip(&refs), &Limits::default()).is_err(),
        "entry count"
    );
    assert!(read_zip(b"not a zip", &Limits::default()).is_err());
}

#[test]
fn zip_reads_directories_and_files() {
    let out = read_zip(&good_zip(), &Limits::default()).unwrap();
    assert_eq!(out[0], ("Releases/".to_owned(), vec![]));
    assert_eq!(out.len(), 6);
}

#[test]
fn release_json_must_have_required_fields() {
    assert!(parse_release_json(b"{}").is_err());
    assert!(
        parse_release_json(br#"{"tag_name":"t","draft":false,"assets":[{"name":"a"}]}"#).is_err()
    );
    assert!(parse_release_json(br#"{"tag_name":"t","draft":"no","assets":[]}"#).is_err());
    let m = parse_release_json(
        br#"{"tag_name":"t","draft":false,"extra":1,"assets":[{"name":"a","size":1,"digest":null,"browser_download_url":"u"}]}"#,
    )
    .unwrap();
    assert_eq!(m.assets[0].digest, None);
}

#[test]
fn repacked_archive_with_correct_files_is_still_refused() {
    // Same five plugin files, different archive bytes (re-zipped, stored):
    // the archive itself must match its pin, not only its contents.
    let (srv, table, _) = setup(good_zip());
    let c: Vec<(String, Vec<u8>)> = PLUGIN_FILES
        .iter()
        .map(|n| (format!("Releases/{n}"), plugin_content(n)))
        .collect();
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    // Same entries and compression, different timestamps: same size,
    // different bytes.
    let o = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::from_date_and_time(2001, 2, 3, 4, 5, 6).unwrap());
    w.add_directory("Releases", o).unwrap();
    for (n, d) in &c {
        w.start_file(n.as_str(), o).unwrap();
        w.write_all(d).unwrap();
    }
    let repacked = w.finish().unwrap().into_inner();
    assert_eq!(repacked.len(), good_zip().len());
    assert_ne!(repacked, good_zip());
    srv.route("/dl/t1/Releases.zip", repacked);
    let tmp = tempfile::tempdir().unwrap();
    let e = run(&srv, table, tmp.path()).unwrap_err();
    assert!(
        matches!(
            e,
            FetchError::Verify(VerifyError::ContentDiffers { what: "sha256", .. })
        ),
        "{e}"
    );
    assert_nothing_written(tmp.path());
}
