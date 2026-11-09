//! Read-only command guard.
//!
//! A [`GuardedCommand`] can only be constructed by passing the full command
//! text through an allowlist of exact, read-only command *shapes* (program and
//! arguments). Transports accept nothing else, so an unguarded string can never
//! reach a head unit. This is a port of the guard in `tools/probe/nbt-probe.sh`
//! and must stay behaviourally identical to it; both are tested against the
//! same cases.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;

/// A QNX node path usable with `on -f`, e.g. `/net/hu-omap/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodePath(String);

impl NodePath {
    pub fn new(path: &str) -> Result<Self, GuardError> {
        static RX: LazyLock<Regex> = LazyLock::new(|| re(r"^/net/[A-Za-z0-9_-]+/$"));
        if RX.is_match(path) {
            Ok(Self(path.to_owned()))
        } else {
            Err(GuardError::new(format!("invalid node path: {path:?}")))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for NodePath {
    fn default() -> Self {
        Self("/net/hu-omap/".to_owned())
    }
}

/// Where a command runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Context {
    /// Directly in the SSH login shell.
    Login,
    /// Wrapped as `on -f <node> <body>`.
    Node(NodePath),
}

impl Context {
    pub fn label(&self) -> &'static str {
        match self {
            Context::Login => "outer",
            Context::Node(_) => "hu",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("guard rejected command: {reason}")]
pub struct GuardError {
    pub reason: String,
}

impl GuardError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// A command that passed the read-only guard. The only type transports accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCommand {
    context: Context,
    body: String,
    rendered: String,
}

impl GuardedCommand {
    /// Render `body` in `context` and validate the full text.
    pub fn new(context: Context, body: &str) -> Result<Self, GuardError> {
        let rendered = match &context {
            Context::Login => body.to_owned(),
            Context::Node(node) => format!("on -f {} {}", node.as_str(), body),
        };
        let node = match &context {
            Context::Login => NodePath::default(),
            Context::Node(n) => n.clone(),
        };
        check(&rendered, &node)?;
        Ok(Self {
            context,
            body: body.to_owned(),
            rendered,
        })
    }

    /// `cat <path>` in `context`.
    pub fn cat(context: Context, path: &SafePath) -> Result<Self, GuardError> {
        Self::new(context, &format!("cat {}", path.as_str()))
    }

    /// `ls -la <path>` in `context`.
    pub fn ls_la(context: Context, path: &SafePath) -> Result<Self, GuardError> {
        Self::new(context, &format!("ls -la {}", path.as_str()))
    }

    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn body(&self) -> &str {
        &self.body
    }
    /// The exact text sent to the remote shell.
    pub fn as_str(&self) -> &str {
        &self.rendered
    }
}

impl fmt::Display for GuardedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rendered)
    }
}

/// A file name component: `^[A-Za-z0-9._-]+$`, not `.` or `..`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeName(String);

impl SafeName {
    pub fn new(name: &str) -> Option<Self> {
        static RX: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9._-]+$"));
        (RX.is_match(name) && name != "." && name != "..").then(|| Self(name.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An absolute path made only of `[A-Za-z0-9._/-]`, without `..`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafePath(String);

impl SafePath {
    pub fn new(path: &str) -> Option<Self> {
        static RX: LazyLock<Regex> = LazyLock::new(|| re(r"^/[A-Za-z0-9._/-]*$"));
        (RX.is_match(path) && !path.contains("..")).then(|| Self(path.to_owned()))
    }
    pub fn join(&self, name: &SafeName) -> SafePath {
        let base = self.0.trim_end_matches('/');
        SafePath(format!("{base}/{}", name.as_str()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The single quoting probe is matched literally: it needs characters the
/// shape grammar deliberately forbids.
pub const QUOTING_PROBE: &str = r#"/bin/sh -c 'for a in "a b" c "d'"'"'e"; do echo "[$a]"; done'"#;

const SH_PREFIX: &str = "/bin/sh -c '";

fn re(pattern: &str) -> Regex {
    #[allow(clippy::expect_used)]
    Regex::new(pattern).expect("static regex")
}

/// Paths the probe must never touch (Wi-Fi/CarPlay credential stores).
pub fn is_credential_path(path: &str) -> bool {
    static RX: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?i)/var/opt/conn|/opt/conn/|iap2|WFD|carplay\.ini|wpa_|hostapd"));
    RX.is_match(path)
}

/// Validate a complete rendered command. Allowed `on` prefix: `on -f <node> `.
pub fn check(cmd: &str, node: &NodePath) -> Result<(), GuardError> {
    if cmd.contains(['\n', '\r', '`', '|', '<', '*', '?', '\\']) || cmd.contains("$(") {
        return Err(GuardError::new("forbidden metacharacter"));
    }
    if cmd.replace("1>&2", "").contains('&') {
        return Err(GuardError::new("background/and operator"));
    }
    let mut body = cmd;
    if body.starts_with("on") {
        let prefix = format!("on -f {} ", node.as_str());
        match body.strip_prefix(prefix.as_str()) {
            Some(rest) => body = rest,
            None => {
                return Err(GuardError::new(format!(
                    "on: only \"on -f {}\" is allowed",
                    node.as_str()
                )));
            }
        }
    }
    if body == QUOTING_PROBE {
        return Ok(());
    }
    if body.contains('[') {
        return Err(GuardError::new("glob"));
    }
    let inner = if let Some(rest) = body.strip_prefix(SH_PREFIX) {
        match rest.strip_suffix('\'') {
            Some(inner) if body.len() > SH_PREFIX.len() => {
                if inner.contains('\'') {
                    return Err(GuardError::new("nested quote"));
                }
                inner
            }
            _ => return Err(GuardError::new("quote outside /bin/sh -c")),
        }
    } else if body.contains('\'') {
        return Err(GuardError::new("quote outside /bin/sh -c"));
    } else {
        body
    };
    for segment in inner.split(';') {
        segment_ok(segment)?;
    }
    Ok(())
}

fn segment_ok(segment: &str) -> Result<(), GuardError> {
    static ECHO: LazyLock<Regex> = LazyLock::new(|| re(r"^echo( [^']*)?$"));
    static SHAPES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        let path = r"/[A-Za-z0-9._/-]*";
        let tool = r"[A-Za-z0-9_.+-]+";
        [
            r"^(true|false|id|date|uname -a|mount|pidin|pidin -p nbt-aad arg|nonexistent-nbt-probe-cmd)$"
                .to_owned(),
            r"^exit [0-9]{1,3}$".to_owned(),
            format!(r"^command -v {tool}$"),
            format!(r"^use {tool}$"),
            format!(r"^ls( -[laRdi]+)?( {path})+$"),
            format!(r"^cat {path}$"),
            // `df` only with explicit paths: a bare `df` walks every block device
            // (DVD drive, HDD) and stalled for 7-10 s on the pilot head unit,
            // coinciding with an Android Auto disconnect.
            format!(r"^df -kP?( {path})+$"),
            format!(r"^test -[wrdef] {path}$"),
            format!(r"^(sha256sum|sha256|md5sum|md5|cksum|sum) {path}$"),
            format!(r"^openssl dgst -sha256 {path}$"),
        ]
        .iter()
        .map(|p| re(p))
        .collect()
    });

    let s = segment.trim_matches(|c: char| c.is_ascii_whitespace());
    if ECHO.is_match(s) {
        if s.replace("1>&2", "").contains('>') {
            return Err(GuardError::new("redirect in echo"));
        }
        if s.contains("1>&2") && s != "echo to-stderr 1>&2" {
            return Err(GuardError::new("redirect in echo"));
        }
        return Ok(());
    }
    if s.contains('$') {
        return Err(GuardError::new("variable outside echo"));
    }
    if s.contains('>') {
        return Err(GuardError::new("redirect"));
    }
    if SHAPES.iter().any(|rx| rx.is_match(s)) {
        for token in s.split_ascii_whitespace().filter(|t| t.starts_with('/')) {
            if token.contains("..") || token.contains("//") {
                return Err(GuardError::new(format!("path traversal: {token}")));
            }
            if is_credential_path(token) {
                return Err(GuardError::new(format!("credential path: {token}")));
            }
        }
        return Ok(());
    }
    Err(GuardError::new(format!(
        "command shape not allowlisted: {s}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodePath {
        NodePath::default()
    }

    // Kept identical to `self_test` in tools/probe/nbt-probe.sh.
    const MUST_REJECT: &[&str] = &[
        "rm -r /opt/aa/nbt-aad.old",
        "mv /opt/aa/nbt-aad /opt/aa/x",
        "cp a b",
        "mount -o remount rw /net/hu-omap/fs/sda0",
        "on -f /net/hu-omap/ mount -uw /fs/sda0",
        "kill 123",
        "slay nbt-aad",
        "echo x > /opt/aa/f",
        "cat a >>b",
        "shutdown",
        "chmod +x /opt/aa/nbt-aad",
        "/opt/aa/nbt-aad",
        "/dev/shmem/pf_aa --check",
        "pfctl -sr",
        "on -f /net/hu-omap/ /bin/sh -c 'rm x'",
        "OnOffDSICommander appreset",
        "mkdir /opt/aa/x",
        "touch /tmp/x",
        "cat /var/opt/conn/WFDPass.conf",
        "cat /fs/sda1/opt/conn/carplay/iap2_Wifi.cfg",
        "echo $(id)",
        "eval rm",
        "ls; rm x",
        "ls && mv a b",
        "ls | tee f",
        "dd if=/dev/zero of=/x",
        "sed -i s/a/b/ f",
        "umount /fs/usb0",
        "ln -s a b",
        "cd /opt/aa",
        "tar cf - /opt/aa",
        "reboot",
        "ls & /opt/aa/nbt-aad",
        "on -f /net/hu-omap/ ls & /bin/rm x",
        "command /bin/rm -rf /opt/aa",
        "command /opt/aa/nbt-aad",
        "openssl dgst -out /opt/aa/nbt-aad /opt/aa/x",
        "openssl enc -out /fs/sda0/x",
        "date 202601010000",
        "uname -S evil",
        "cat /var/opt/aa/../conn/x",
        "cat /var/opt/co*/W*",
        "cat /var/opt/c?nn/x",
        "ls /\nrm x",
        "cat /opt/aa/x$IFS",
        "on -n /net/hu-omap/ ls /",
        "on -f /net/other/ ls /",
        "on -f /net/hu-omap/ on -f /net/hu-omap/ rm x",
        "ls /opt/[a]a",
        "/bin/sh -c 'ls /' ; rm x",
        "/bin/sh -c 'ls / ; rm x'",
        "echo hi 1>&2 ; rm x",
        "echo x 1>&2",
        "ls -la /opt/aa;/opt/aa/nbt-aad",
        "pidin -p x arg",
        "df -k /x; /x",
        "cat /fs/sda1/opt/conn/WFDPass.conf",
        "sh -c ls",
        "/bin/sh -c 'cat /opt/aa/x' extra",
        "exit 1; /opt/aa/nbt-aad",
        "cat\\ /x",
        // Rust-port extras.
        "",
        "ls",
        "/bin/sh -c '",
        "ls -la /opt//aa",
        "cat /opt/aa/nbt-aad\r",
        "ls -la /opt/aa;",
        // Pilot run 2 findings.
        "df -k",
        "df -kP",
        "on -f /net/hu-omap/ df -k",
        "test -w /var/opt/conn",
        "test -x /opt/aa/nbt-aad; /opt/aa/nbt-aad",
    ];

    const MUST_ALLOW: &[&str] = &[
        "ls -la /opt/aa",
        "cat /opt/aa/nbt-aad",
        "cat /opt/aa/nbt-aad.env",
        "on -f /net/hu-omap/ cat /opt/aa/nbt-aad.old",
        "mount",
        "on -f /net/hu-omap/ mount",
        "use mv",
        "/bin/sh -c 'command -v rm'",
        "df -k /opt/aa",
        "pidin",
        "on -f /net/hu-omap/ /bin/sh -c 'echo to-stdout; echo to-stderr 1>&2; exit 3'",
        "ls -la /opt/hmi/ID5/data/ro/Plugins/NbtAad",
        "sha256sum /opt/aa/nbt-aad",
        "pidin -p nbt-aad arg",
        "ls -la /",
        r#"on -f /net/hu-omap/ /bin/sh -c 'for a in "a b" c "d'"'"'e"; do echo "[$a]"; done'"#,
    ];

    #[test]
    fn rejects_every_mutating_or_ambiguous_shape() {
        for c in MUST_REJECT {
            assert!(check(c, &node()).is_err(), "guard allowed: {c:?}");
        }
    }

    #[test]
    fn allows_the_read_only_shapes() {
        for c in MUST_ALLOW {
            assert!(
                check(c, &node()).is_ok(),
                "guard rejected: {c:?} ({:?})",
                check(c, &node())
            );
        }
    }

    #[test]
    fn constructor_renders_node_prefix_and_validates() {
        let ctx = Context::Node(node());
        let c = GuardedCommand::new(ctx.clone(), "cat /opt/aa/nbt-aad").unwrap();
        assert_eq!(c.as_str(), "on -f /net/hu-omap/ cat /opt/aa/nbt-aad");
        assert!(GuardedCommand::new(ctx, "rm /opt/aa/nbt-aad").is_err());
        assert!(GuardedCommand::new(Context::Login, "kill 1").is_err());
    }

    #[test]
    fn credential_paths_are_unreachable_through_constructors() {
        let p = SafePath::new("/var/opt/aa")
            .unwrap()
            .join(&SafeName::new("iap2.cfg").unwrap());
        assert!(GuardedCommand::cat(Context::Node(node()), &p).is_err());
    }

    #[test]
    fn safe_name_and_path() {
        assert!(SafeName::new("libNbtAad.so").is_some());
        for bad in ["..", ".", "a;b", "a b", "$(x)", "", "a/b"] {
            assert!(SafeName::new(bad).is_none(), "{bad:?}");
        }
        assert!(SafePath::new("/opt/aa").is_some());
        for bad in ["/opt/../etc", "opt/aa", "/opt/a a", "/opt/*"] {
            assert!(SafePath::new(bad).is_none(), "{bad:?}");
        }
        let joined = SafePath::new("/")
            .unwrap()
            .join(&SafeName::new("mnt").unwrap());
        assert_eq!(joined.as_str(), "/mnt");
    }

    #[test]
    fn node_path_validation() {
        assert!(NodePath::new("/net/hu-omap/").is_ok());
        for bad in ["/net/hu omap/", "/net/x", "net/x/", "/net/../", "/net/a/b/"] {
            assert!(NodePath::new(bad).is_err(), "{bad:?}");
        }
    }
}
