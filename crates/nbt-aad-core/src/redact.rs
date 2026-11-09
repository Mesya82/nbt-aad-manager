//! Best-effort redaction of text written to shareable reports.
//!
//! Line-oriented port of `redact()` in `tools/probe/nbt-probe.sh` (GNU sed -E
//! semantics: `^`/`$` per line, `I` = case-insensitive). Raw data stays in the
//! private area; redaction only protects the shareable `report/`.

use std::sync::LazyLock;

use regex::Regex;

struct Rule {
    rx: Regex,
    replacement: &'static str,
    global: bool,
}

fn rule(pattern: &str, replacement: &'static str, global: bool) -> Rule {
    #[allow(clippy::expect_used)]
    let rx = Regex::new(pattern).expect("static regex");
    Rule {
        rx,
        replacement,
        global,
    }
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // VIN-like: 17 chars of the VIN alphabet, not adjacent to alphanumerics.
        rule(
            r"(^|[^A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}([^A-Za-z0-9]|$)",
            "${1}<REDACTED-VIN17>${2}",
            true,
        ),
        // MAC address with separators.
        rule(
            r"(^|[^0-9A-Fa-f])([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}([^0-9A-Fa-f]|$)",
            "${1}<REDACTED-MAC>${3}",
            true,
        ),
        // 12 hex digits (MAC without separators).
        rule(
            r"(^|[^0-9A-Fa-f])[0-9A-Fa-f]{12}([^0-9A-Fa-f]|$)",
            "${1}<REDACTED-HEX12>${2}",
            true,
        ),
        // env-style KEY=value where the key looks sensitive.
        rule(
            r"(?i)^([[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(PASS|PSK|KEY|SECRET|TOKEN|SSID|PIN|WIFI_NAME|PHONE)[A-Za-z0-9_]*[[:space:]]*=).*",
            "${1}<REDACTED>",
            false,
        ),
        // key: value / "key": "value" -> rest of line.
        rule(
            r#"(?i)(["']?(pass(word|phrase|wd)?|psk|ssid|secret|token|pin|passkey)["']?[[:space:]]*[=:][[:space:]]*).*"#,
            "${1}<REDACTED>",
            false,
        ),
        // <psk>value</psk>
        rule(
            r"(?i)<(pass(word|phrase)?|psk|ssid|key|secret|passkey)>[^<]*<",
            "<${1}><REDACTED><",
            true,
        ),
    ]
});

fn redact_line(line: &str) -> String {
    let mut s = line.to_owned();
    for r in RULES.iter() {
        s = if r.global {
            r.rx.replace_all(&s, r.replacement).into_owned()
        } else {
            r.rx.replace(&s, r.replacement).into_owned()
        };
    }
    s
}

/// Redact text line by line, preserving line terminators.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        out.push_str(&redact_line(body));
        out.push_str(nl);
    }
    out
}

/// Redact arbitrary bytes (lossy UTF-8 decoding).
pub fn redact_bytes(bytes: &[u8]) -> String {
    redact(&String::from_utf8_lossy(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_unrelated_config_and_redacts_secrets() {
        let input = "NBT_ALT_WIFI=CARPLAY\nNBT_WFD_PASS=hunter2\nVIN WBAJA11010B123456 x\nmac 00:11:22:AA:BB:CC\npassword: s3cr3t\n";
        let r = redact(input);
        assert!(r.contains("NBT_ALT_WIFI=CARPLAY"));
        assert!(r.contains("NBT_WFD_PASS=<REDACTED>"));
        for leak in [
            "hunter2",
            "WBAJA11010B123456",
            "00:11:22:AA:BB:CC",
            "s3cr3t",
        ] {
            assert!(!r.contains(leak), "leaked {leak}: {r}");
        }
        assert!(r.ends_with('\n'));
    }

    #[test]
    fn formats_found_by_review() {
        let input = "{\"password\": \"hunter3\", \"ssid\": \"MyNet4\"}\n<psk>abc12345</psk>\npassword: two words5\nmac 001122AABBC6\nvin_WBAJA11010B654321_x\n";
        let r = redact(input);
        for leak in [
            "hunter3",
            "MyNet4",
            "abc12345",
            "words5",
            "001122AABBC6",
            "WBAJA11010B654321",
        ] {
            assert!(!r.contains(leak), "leaked {leak}: {r}");
        }
    }

    #[test]
    fn mac_in_file_name_and_dash_form() {
        let r = redact("cat /var/opt/aa/00-11-22-33-44-55.bin\n");
        assert!(!r.contains("00-11-22-33-44-55"), "{r}");
    }

    #[test]
    fn sha256_hex_is_not_mangled() {
        let h = "1ec14876503b0bac597e8871b7099deb334c6401e3696bd2d8cf2db8cbc972b3";
        assert_eq!(redact(h), h);
    }

    #[test]
    fn per_line_anchoring() {
        // A keyword on one line must not swallow the next line.
        let r = redact("password: x\nNBT_ALT_WIFI=CARPLAY");
        assert_eq!(r, "password: <REDACTED>\nNBT_ALT_WIFI=CARPLAY");
    }
}
