//! Filesystem transcript sink. Layout matches `tools/probe/nbt-probe.sh`:
//!
//! ```text
//! report/exec/NNNN-id/{cmd,rc,ms,started_utc,policy,stdout.sha256,stdout.bytes,
//!                      stderr.sha256,stderr.bytes,stderr[,stdout][,transport_error][,dropped]}
//! report/exec-log.tsv         record, policy, rc, ms, stdout_bytes, stderr_bytes, cmd
//! private/exec/NNNN-id.{cmd,stderr[,stdout]}   raw, unredacted
//! private/readback/<label>    raw read-back bytes (binary policy)
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nbt_aad_core::guard::SafeName;
use nbt_aad_core::probe::{ReportFile, Reports};
use nbt_aad_core::redact::{redact, redact_bytes};
use nbt_aad_core::transport::{ExecRecord, Policy, SinkError, TranscriptSink};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub struct FsSink {
    report: PathBuf,
    private: PathBuf,
    exec_log: File,
}

fn err(e: impl std::fmt::Display) -> SinkError {
    SinkError(e.to_string())
}

/// Windows-reserved device names (any extension) and names ending in `.`
/// or space get a `_` prefix; applied on every OS for identical layouts.
pub fn host_safe_component(name: &str) -> String {
    let stem = name.split('.').next().unwrap_or("").to_ascii_lowercase();
    let reserved = matches!(
        stem.as_str(),
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
    ) || ((stem.starts_with("com") || stem.starts_with("lpt"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit());
    if reserved || name.ends_with('.') || name.ends_with(' ') {
        format!("_{name}")
    } else {
        name.to_owned()
    }
}

fn safe_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn write(path: &Path, data: &[u8]) -> Result<(), SinkError> {
    fs::write(path, data).map_err(|e| err(format!("{}: {e}", path.display())))
}

pub fn utc(t: std::time::SystemTime) -> String {
    OffsetDateTime::from(t).format(&Rfc3339).unwrap_or_default()
}

impl FsSink {
    pub fn new(report: &Path, private: &Path) -> Result<Self, SinkError> {
        fs::create_dir_all(report.join("exec")).map_err(err)?;
        fs::create_dir_all(private.join("exec")).map_err(err)?;
        let exec_log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(report.join("exec-log.tsv"))
            .map_err(err)?;
        Ok(Self {
            report: report.to_owned(),
            private: private.to_owned(),
            exec_log,
        })
    }

    /// Private copy path for a read-back label. Components are re-validated
    /// and made safe on every host OS: Windows device names (`nul`, `con`,
    /// `com1`, ...) and trailing dots/spaces are prefixed with `_`, and an
    /// existing file (e.g. a case-insensitive collision on NTFS) is never
    /// overwritten (`.dupN` suffix).
    fn label_path(&self, label: &str) -> Result<PathBuf, SinkError> {
        let mut p = self.private.join("readback");
        for part in label.split('/') {
            let n = SafeName::new(part).ok_or_else(|| err(format!("unsafe label {label:?}")))?;
            p.push(host_safe_component(n.as_str()));
        }
        let base = p
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut candidate = p.clone();
        let mut i = 1;
        while candidate.exists() {
            candidate = p.with_file_name(format!("{base}.dup{i}"));
            i += 1;
        }
        Ok(candidate)
    }
}

impl TranscriptSink for FsSink {
    fn record(&mut self, r: &ExecRecord, stdout: &[u8], stderr: &[u8]) -> Result<(), SinkError> {
        let rec = format!("{:04}-{}", r.seq, safe_id(&r.id));
        let d = self.report.join("exec").join(&rec);
        let p = self.private.join("exec");
        fs::create_dir_all(&d).map_err(err)?;
        let rc = r
            .outcome
            .as_ref()
            .map_or("error".to_owned(), |o| o.to_string());
        let cmd_red = redact(&r.command);
        let ms = r.duration.as_millis().to_string();
        write(
            &p.join(format!("{rec}.cmd")),
            format!("{}\n", r.command).as_bytes(),
        )?;
        write(&d.join("cmd"), format!("{cmd_red}\n").as_bytes())?;
        write(&d.join("rc"), format!("{rc}\n").as_bytes())?;
        write(&d.join("ms"), format!("{ms}\n").as_bytes())?;
        write(
            &d.join("started_utc"),
            format!("{}\n", utc(r.started)).as_bytes(),
        )?;
        write(
            &d.join("policy"),
            format!("{}\n", r.policy.name()).as_bytes(),
        )?;
        write(&d.join("context"), format!("{}\n", r.context).as_bytes())?;
        write(
            &d.join("stdout.sha256"),
            format!("{}\n", r.stdout_sha256).as_bytes(),
        )?;
        write(
            &d.join("stdout.bytes"),
            format!("{}\n", r.stdout_len).as_bytes(),
        )?;
        write(
            &d.join("stderr.sha256"),
            format!("{}\n", r.stderr_sha256).as_bytes(),
        )?;
        write(
            &d.join("stderr.bytes"),
            format!("{}\n", r.stderr_len).as_bytes(),
        )?;
        write(&p.join(format!("{rec}.stderr")), stderr)?;
        write(&d.join("stderr"), redact_bytes(stderr).as_bytes())?;
        if r.stdout_dropped > 0 || r.stderr_dropped > 0 {
            write(
                &d.join("dropped"),
                format!("stdout={} stderr={}\n", r.stdout_dropped, r.stderr_dropped).as_bytes(),
            )?;
        }
        if let Some(e) = &r.transport_error {
            write(
                &d.join("transport_error"),
                format!("{}\n", redact(e)).as_bytes(),
            )?;
        }
        match &r.policy {
            Policy::Text => {
                write(&p.join(format!("{rec}.stdout")), stdout)?;
                write(&d.join("stdout"), redact_bytes(stdout).as_bytes())?;
            }
            Policy::Binary { label } => {
                let dest = self.label_path(label)?;
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent).map_err(err)?;
                }
                write(&dest, stdout)?;
            }
            Policy::Secret => {}
        }
        let line = format!(
            "{rec}\t{}\t{rc}\t{ms}\t{}\t{}\t{cmd_red}\n",
            r.policy.name(),
            r.stdout_len,
            r.stderr_len
        );
        self.exec_log.write_all(line.as_bytes()).map_err(err)?;
        self.exec_log.sync_data().map_err(err)?;
        Ok(())
    }
}

impl Reports for FsSink {
    fn append(&mut self, file: ReportFile, text: &str) -> Result<(), SinkError> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.report.join(file.file_name()))
            .map_err(err)?;
        f.write_all(text.as_bytes()).map_err(err)
    }

    fn write_text(&mut self, name: &SafeName, content: &str) -> Result<(), SinkError> {
        let dir = self.report.join("text");
        fs::create_dir_all(&dir).map_err(err)?;
        write(&dir.join(name.as_str()), content.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::host_safe_component as h;

    #[test]
    fn windows_device_names_and_trailing_dots_are_escaped() {
        for (i, o) in [
            ("nul", "_nul"),
            ("CON", "_CON"),
            ("aux.txt", "_aux.txt"),
            ("com1", "_com1"),
            ("lpt9.log", "_lpt9.log"),
            ("x.", "_x."),
        ] {
            assert_eq!(h(i), o);
        }
        for keep in [
            "nbt-aad",
            "console.log",
            "com",
            "com10",
            "bootguard",
            "NbtAad.xml",
        ] {
            assert_eq!(h(keep), keep);
        }
    }
}
