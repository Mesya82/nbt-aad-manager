//! Unauthenticated SSH algorithm discovery (sans-IO).
//!
//! Parses the server identification line and its first binary packet
//! (`SSH_MSG_KEXINIT`, RFC 4253 §4.2, §7.1), which every SSH server sends in
//! clear text before any authentication. This yields the server's algorithm
//! lists independently of any SSH library, so evidence is collected even when
//! negotiation would fail.

use std::fmt;

const MAX_PRE_BANNER: usize = 16 * 1024;
const MAX_PACKET: usize = 35_000;
const MSG_KEXINIT: u8 = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAlgorithms {
    /// Server identification string, e.g. `SSH-2.0-OpenSSH_5.1`.
    pub banner: String,
    /// Lines the server sent before its identification string.
    pub pre_banner_lines: Vec<String>,
    pub kex: Vec<String>,
    pub host_key: Vec<String>,
    pub cipher_ctos: Vec<String>,
    pub cipher_stoc: Vec<String>,
    pub mac_ctos: Vec<String>,
    pub mac_stoc: Vec<String>,
    pub compression_ctos: Vec<String>,
    pub compression_stoc: Vec<String>,
    pub first_kex_follows: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KexInitError {
    #[error("no SSH identification line within {MAX_PRE_BANNER} bytes")]
    NoBanner,
    #[error("unsupported protocol in identification line: {0:?}")]
    Protocol(String),
    #[error("malformed KEXINIT packet: {0}")]
    Malformed(&'static str),
    #[error("first packet is message {0}, not KEXINIT")]
    NotKexInit(u8),
}

/// Result of feeding bytes to the parser.
#[derive(Debug, PartialEq, Eq)]
pub enum Parse {
    NeedMore,
    Done(Box<ServerAlgorithms>),
}

/// Try to parse a complete server greeting + KEXINIT from `buf`.
pub fn parse(buf: &[u8]) -> Result<Parse, KexInitError> {
    let mut pos = 0;
    let mut pre = Vec::new();
    let banner = loop {
        let Some(nl) = buf[pos..].iter().position(|&b| b == b'\n') else {
            if buf.len() > MAX_PRE_BANNER {
                return Err(KexInitError::NoBanner);
            }
            return Ok(Parse::NeedMore);
        };
        let line = String::from_utf8_lossy(&buf[pos..pos + nl])
            .trim_end_matches('\r')
            .to_owned();
        pos += nl + 1;
        if pos > MAX_PRE_BANNER {
            return Err(KexInitError::NoBanner);
        }
        if line.starts_with("SSH-") {
            if !(line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-")) {
                return Err(KexInitError::Protocol(line));
            }
            break line;
        }
        pre.push(line);
    };
    let rest = &buf[pos..];
    if rest.len() < 5 {
        return Ok(Parse::NeedMore);
    }
    let packet_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if !(16..=MAX_PACKET).contains(&packet_len) {
        return Err(KexInitError::Malformed("packet length out of range"));
    }
    if rest.len() < 4 + packet_len {
        return Ok(Parse::NeedMore);
    }
    let padding = rest[4] as usize;
    if padding + 1 > packet_len {
        return Err(KexInitError::Malformed("padding exceeds packet"));
    }
    let payload = &rest[5..4 + packet_len - padding];
    let mut r = Reader {
        data: payload,
        pos: 0,
    };
    let msg = r.u8()?;
    if msg != MSG_KEXINIT {
        return Err(KexInitError::NotKexInit(msg));
    }
    r.skip(16)?; // cookie
    let mut lists: Vec<Vec<String>> = Vec::with_capacity(10);
    for _ in 0..10 {
        lists.push(r.name_list()?);
    }
    let first_kex_follows = r.u8()? != 0;
    let mut it = lists.into_iter();
    let mut next = || it.next().unwrap_or_default();
    Ok(Parse::Done(Box::new(ServerAlgorithms {
        banner,
        pre_banner_lines: pre,
        kex: next(),
        host_key: next(),
        cipher_ctos: next(),
        cipher_stoc: next(),
        mac_ctos: next(),
        mac_stoc: next(),
        compression_ctos: next(),
        compression_stoc: next(),
        first_kex_follows,
    })))
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, KexInitError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(KexInitError::Malformed("truncated"))?;
        self.pos += 1;
        Ok(b)
    }
    fn skip(&mut self, n: usize) -> Result<(), KexInitError> {
        if self.pos + n > self.data.len() {
            return Err(KexInitError::Malformed("truncated"));
        }
        self.pos += n;
        Ok(())
    }
    fn name_list(&mut self) -> Result<Vec<String>, KexInitError> {
        if self.pos + 4 > self.data.len() {
            return Err(KexInitError::Malformed("truncated name-list length"));
        }
        let d = &self.data[self.pos..self.pos + 4];
        let len = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize;
        self.pos += 4;
        if self.pos + len > self.data.len() {
            return Err(KexInitError::Malformed("truncated name-list"));
        }
        let raw = &self.data[self.pos..self.pos + len];
        self.pos += len;
        if !raw.iter().all(|b| b.is_ascii_graphic()) {
            return Err(KexInitError::Malformed("non-ASCII name-list"));
        }
        let s = std::str::from_utf8(raw).map_err(|_| KexInitError::Malformed("name-list utf8"))?;
        Ok(if s.is_empty() {
            Vec::new()
        } else {
            s.split(',').map(str::to_owned).collect()
        })
    }
}

/// Client algorithm preferences, most preferred first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmProfile {
    pub name: &'static str,
    pub kex: Vec<&'static str>,
    pub host_key: Vec<&'static str>,
    pub cipher: Vec<&'static str>,
    pub mac: Vec<&'static str>,
}

/// Algorithms considered weak; negotiating one is reported as a warning.
pub const WEAK: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "ssh-rsa",
    "ssh-dss",
    "hmac-sha1",
    "hmac-sha1-etm@openssh.com",
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
];

impl AlgorithmProfile {
    /// Modern algorithms plus exactly the SHA-1 legacy that upstream's own
    /// update guide enables (`+ssh-rsa` host keys, `hmac-sha1`). SHA-1 key
    /// exchange is NOT included (upstream's modern OpenSSH clients do not
    /// offer it by default either).
    pub fn upstream_documented() -> Self {
        Self {
            name: "upstream-documented",
            kex: vec![
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group14-sha256",
            ],
            host_key: vec![
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ssh-rsa",
            ],
            cipher: vec![
                "chacha20-poly1305@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-gcm@openssh.com",
                "aes256-ctr",
                "aes192-ctr",
                "aes128-ctr",
            ],
            mac: vec![
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-512",
                "hmac-sha2-256",
                "hmac-sha1",
            ],
        }
    }

    /// Additionally allows SHA-1 key exchange, DSA host keys and CBC/3DES ciphers.
    /// Opt-in only (`--allow-legacy-weak`), never default.
    pub fn legacy_weak() -> Self {
        let mut p = Self::upstream_documented();
        p.name = "legacy-weak";
        p.kex.extend([
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
        ]);
        p.host_key.push("ssh-dss");
        p.cipher
            .extend(["aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc"]);
        p
    }
}

/// Outcome of negotiating one algorithm category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub category: &'static str,
    pub chosen: Option<String>,
}

impl fmt::Display for Choice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.chosen {
            Some(c) if WEAK.contains(&c.as_str()) => write!(f, "{}={} (WEAK)", self.category, c),
            Some(c) => write!(f, "{}={}", self.category, c),
            None => write!(f, "{}=<no common algorithm>", self.category),
        }
    }
}

/// Predict what the client (russh 0.65) will negotiate. RFC 4253 §7.1 picks
/// the first client algorithm the server supports. russh additionally:
/// - selects ONE cipher from the client-to-server list and uses it in both
///   directions, so the server's server-to-client list must contain it too;
/// - selects a MAC per direction, required only for non-AEAD ciphers;
/// - only offers `none` compression, which both server lists must contain.
pub fn negotiate(client: &AlgorithmProfile, server: &ServerAlgorithms) -> Vec<Choice> {
    fn pick(category: &'static str, client: &[&str], server: &[String]) -> Choice {
        let chosen = client
            .iter()
            .find(|c| server.iter().any(|s| s == *c))
            .map(|c| (*c).to_owned());
        Choice { category, chosen }
    }
    let cipher = pick("cipher", &client.cipher, &server.cipher_ctos);
    let cipher_stoc = Choice {
        category: "cipher_stoc_accepts",
        chosen: cipher
            .chosen
            .clone()
            .filter(|c| server.cipher_stoc.contains(c)),
    };
    vec![
        pick("kex", &client.kex, &server.kex),
        pick("host_key", &client.host_key, &server.host_key),
        cipher,
        cipher_stoc,
        pick("mac_ctos", &client.mac, &server.mac_ctos),
        pick("mac_stoc", &client.mac, &server.mac_stoc),
        pick("compression_ctos", &["none"], &server.compression_ctos),
        pick("compression_stoc", &["none"], &server.compression_stoc),
    ]
}

/// Whether every category can be negotiated. AEAD ciphers need no MAC.
pub fn negotiable(choices: &[Choice]) -> bool {
    let aead = |c: &Choice| {
        c.chosen
            .as_deref()
            .is_some_and(|n| n.contains("gcm@") || n.contains("chacha20-poly1305"))
    };
    let cipher_aead = choices
        .iter()
        .find(|c| c.category == "cipher")
        .is_some_and(aead);
    choices
        .iter()
        .all(|c| c.chosen.is_some() || (cipher_aead && c.category.starts_with("mac_")))
}

/// Render a human-readable evidence file.
pub fn describe(server: &ServerAlgorithms) -> String {
    let mut s = String::new();
    for l in &server.pre_banner_lines {
        s.push_str(&format!("pre_banner: {l}\n"));
    }
    s.push_str(&format!("banner: {}\n", server.banner));
    let lists: [(&str, &Vec<String>); 8] = [
        ("kex", &server.kex),
        ("host_key", &server.host_key),
        ("cipher_ctos", &server.cipher_ctos),
        ("cipher_stoc", &server.cipher_stoc),
        ("mac_ctos", &server.mac_ctos),
        ("mac_stoc", &server.mac_stoc),
        ("compression_ctos", &server.compression_ctos),
        ("compression_stoc", &server.compression_stoc),
    ];
    for (k, v) in lists {
        s.push_str(&format!("{k}: {}\n", v.join(",")));
    }
    s.push_str(&format!(
        "first_kex_packet_follows: {}\n",
        server.first_kex_follows
    ));
    s
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a server greeting + KEXINIT exactly as on the wire.
    pub(crate) fn wire(banner: &str, lists: [&str; 10]) -> Vec<u8> {
        let mut payload = vec![MSG_KEXINIT];
        payload.extend([0xAB; 16]);
        for l in lists {
            payload.extend((l.len() as u32).to_be_bytes());
            payload.extend(l.as_bytes());
        }
        payload.push(0);
        payload.extend(0u32.to_be_bytes());
        let mut padding = 8 - ((payload.len() + 5) % 8);
        if padding < 4 {
            padding += 8;
        }
        let packet_len = payload.len() + padding + 1;
        let mut out = format!("{banner}\r\n").into_bytes();
        out.extend((packet_len as u32).to_be_bytes());
        out.push(padding as u8);
        out.extend(payload);
        out.extend(vec![0; padding]);
        out
    }

    const OLD_OPENSSH: [&str; 10] = [
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
        "ssh-rsa,ssh-dss",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc",
        "hmac-md5,hmac-sha1,hmac-ripemd160",
        "hmac-md5,hmac-sha1,hmac-ripemd160",
        "none,zlib@openssh.com",
        "none,zlib@openssh.com",
        "",
        "",
    ];

    #[test]
    fn parses_old_openssh_greeting() {
        let mut buf = b"some motd\r\n".to_vec();
        buf.extend(wire("SSH-2.0-OpenSSH_5.1", OLD_OPENSSH));
        let Parse::Done(s) = parse(&buf).unwrap() else {
            panic!("incomplete")
        };
        assert_eq!(s.banner, "SSH-2.0-OpenSSH_5.1");
        assert_eq!(s.pre_banner_lines, vec!["some motd".to_owned()]);
        assert_eq!(s.host_key, vec!["ssh-rsa", "ssh-dss"]);
        assert_eq!(s.mac_ctos[1], "hmac-sha1");
        assert!(!s.first_kex_follows);
    }

    #[test]
    fn incremental_input_needs_more_until_complete() {
        let buf = wire("SSH-2.0-x", OLD_OPENSSH);
        for cut in [0, 5, 12, buf.len() - 1] {
            assert_eq!(parse(&buf[..cut]).unwrap(), Parse::NeedMore, "cut {cut}");
        }
        assert!(matches!(parse(&buf).unwrap(), Parse::Done(_)));
    }

    #[test]
    fn rejects_malformed_and_ssh1() {
        assert!(matches!(
            parse(b"SSH-1.5-old\r\n"),
            Err(KexInitError::Protocol(_))
        ));
        let mut buf = wire("SSH-2.0-x", OLD_OPENSSH);
        let off = "SSH-2.0-x\r\n".len();
        buf[off..off + 4].copy_from_slice(&1_000_000u32.to_be_bytes());
        assert!(matches!(parse(&buf), Err(KexInitError::Malformed(_))));
        let mut buf = wire("SSH-2.0-x", OLD_OPENSSH);
        buf[off + 5] = 21; // NEWKEYS instead of KEXINIT
        assert_eq!(parse(&buf), Err(KexInitError::NotKexInit(21)));
        assert_eq!(
            parse(&vec![b'x'; MAX_PRE_BANNER + 1]),
            Err(KexInitError::NoBanner)
        );
    }

    #[test]
    fn negotiation_old_openssh_with_default_profile_uses_documented_legacy() {
        let buf = wire("SSH-2.0-OpenSSH_5.1", OLD_OPENSSH);
        let Parse::Done(s) = parse(&buf).unwrap() else {
            panic!()
        };
        let c = negotiate(&AlgorithmProfile::upstream_documented(), &s);
        assert!(negotiable(&c));
        let get = |k: &str| {
            c.iter()
                .find(|x| x.category == k)
                .unwrap()
                .chosen
                .clone()
                .unwrap()
        };
        assert_eq!(get("kex"), "diffie-hellman-group-exchange-sha256");
        assert_eq!(get("host_key"), "ssh-rsa");
        assert_eq!(get("cipher"), "aes256-ctr");
        assert_eq!(get("mac_ctos"), "hmac-sha1");
        assert!(c.iter().any(|x| x.to_string().contains("(WEAK)")));
    }

    #[test]
    fn dsa_only_server_needs_legacy_weak() {
        let mut lists = OLD_OPENSSH;
        lists[1] = "ssh-dss";
        let buf = wire("SSH-2.0-OpenSSH_4.3", lists);
        let Parse::Done(s) = parse(&buf).unwrap() else {
            panic!()
        };
        assert!(!negotiable(&negotiate(
            &AlgorithmProfile::upstream_documented(),
            &s
        )));
        assert!(negotiable(&negotiate(&AlgorithmProfile::legacy_weak(), &s)));
    }

    #[test]
    fn sha1_only_kex_needs_legacy_weak() {
        let mut lists = OLD_OPENSSH;
        lists[0] = "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
        let Parse::Done(s) = parse(&wire("SSH-2.0-OpenSSH_4.3", lists)).unwrap() else {
            panic!()
        };
        assert!(!negotiable(&negotiate(
            &AlgorithmProfile::upstream_documented(),
            &s
        )));
        assert!(negotiable(&negotiate(&AlgorithmProfile::legacy_weak(), &s)));
    }

    #[test]
    fn asymmetric_cipher_lists_and_missing_none_compression_are_not_negotiable() {
        let mut lists = OLD_OPENSSH;
        lists[3] = "3des-cbc"; // server-to-client lacks the chosen aes256-ctr
        let Parse::Done(s) = parse(&wire("SSH-2.0-x", lists)).unwrap() else {
            panic!()
        };
        assert!(!negotiable(&negotiate(
            &AlgorithmProfile::upstream_documented(),
            &s
        )));
        let mut lists = OLD_OPENSSH;
        lists[6] = "zlib";
        let Parse::Done(s) = parse(&wire("SSH-2.0-x", lists)).unwrap() else {
            panic!()
        };
        assert!(!negotiable(&negotiate(
            &AlgorithmProfile::upstream_documented(),
            &s
        )));
    }

    #[test]
    fn aead_cipher_needs_no_mac() {
        let lists = [
            "curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
            "chacha20-poly1305@openssh.com",
            "umac-64@openssh.com",
            "umac-64@openssh.com",
            "none",
            "none",
            "",
            "",
        ];
        let Parse::Done(s) = parse(&wire("SSH-2.0-OpenSSH_10.2", lists)).unwrap() else {
            panic!()
        };
        assert!(negotiable(&negotiate(
            &AlgorithmProfile::upstream_documented(),
            &s
        )));
    }
}
