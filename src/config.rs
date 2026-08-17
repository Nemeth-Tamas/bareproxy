use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

const DEFAULT_MAX_CONNECTIONS: usize = 128;
const DEFAULT_CLIENT_IDLE_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_UPSTREAM_TIMEOUT_SECONDS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    routes: Vec<Route>,
    max_connections: usize,
    client_idle_timeout_seconds: u64,
    upstream_timeout_seconds: u64,
}

impl Config {
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn client_idle_timeout_seconds(&self) -> u64 {
        self.client_idle_timeout_seconds
    }

    pub fn upstream_timeout_seconds(&self) -> u64 {
        self.upstream_timeout_seconds
    }

    pub fn route_for_host(&self, host: &str) -> Result<&Route, RouteLookupError> {
        let hostname = normalize_request_host(host).ok_or(RouteLookupError::InvalidHost)?;

        self.routes
            .iter()
            .find(|route| route.hostname == hostname)
            .ok_or(RouteLookupError::NotFound(hostname))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentityFiles {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
}

impl TlsIdentityFiles {
    pub fn certificate_path(&self) -> &Path {
        &self.certificate_path
    }

    pub fn private_key_path(&self) -> &Path {
        &self.private_key_path
    }

    fn resolve_against(&mut self, base_directory: &Path) {
        if self.certificate_path.is_relative() {
            self.certificate_path = base_directory.join(&self.certificate_path);
        }

        if self.private_key_path.is_relative() {
            self.private_key_path = base_directory.join(&self.private_key_path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    hostname: String,
    upstream: Upstream,
}

impl Route {
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }
}

impl fmt::Display for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} -> {}", self.hostname, self.upstream)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    host: String,
    port: u16,
}

impl Upstream {
    pub fn address(&self) -> String {
        self.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteLookupError {
    InvalidHost,
    NotFound(String),
}

impl fmt::Display for RouteLookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost => formatter.write_str("invalid Host header"),
            Self::NotFound(hostname) => write!(formatter, "no route for {hostname}"),
        }
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Read { path: String, message: String },
    Line { line: usize, message: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, message } => {
                write!(formatter, "failed to read config {path}: {message}")
            }
            Self::Line { line, message } => {
                write!(formatter, "config line {line}: {message}")
            }
        }
    }
}

impl Error for ConfigError {}

pub fn load(path: &str) -> Result<Config, ConfigError> {
    load_with_tls(path).map(|(configuration, _)| configuration)
}

pub fn load_with_tls(path: &str) -> Result<(Config, Vec<TlsIdentityFiles>), ConfigError> {
    let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        message: source.to_string(),
    })?;

    let (configuration, mut tls_identity_files) = parse_with_tls(&contents)?;

    let base_directory = Path::new(path).parent().unwrap_or_else(|| Path::new(""));

    for identity_files in &mut tls_identity_files {
        identity_files.resolve_against(base_directory);
    }

    Ok((configuration, tls_identity_files))
}

pub fn parse(input: &str) -> Result<Config, ConfigError> {
    parse_with_tls(input).map(|(configuration, _)| configuration)
}

fn parse_with_tls(input: &str) -> Result<(Config, Vec<TlsIdentityFiles>), ConfigError> {
    let mut routes = Vec::new();
    let mut tls_identity_files = Vec::new();
    let mut hostnames = HashSet::new();
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;
    let mut max_connections_set = false;
    let mut client_idle_timeout_seconds = DEFAULT_CLIENT_IDLE_TIMEOUT_SECONDS;
    let mut client_idle_timeout_set = false;
    let mut upstream_timeout_seconds = DEFAULT_UPSTREAM_TIMEOUT_SECONDS;
    let mut upstream_timeout_set = false;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw_line).trim();

        if line.is_empty() {
            continue;
        }

        if let Some((directive, value)) = line.split_once('=')
            && directive.trim() == "tls_identity"
        {
            let identity_files =
                parse_tls_identity_files(value.trim()).map_err(|message| ConfigError::Line {
                    line: line_number,
                    message,
                })?;

            if tls_identity_files.contains(&identity_files) {
                return Err(ConfigError::Line {
                    line: line_number,
                    message: "duplicate tls_identity certificate/key pair".to_owned(),
                });
            }

            tls_identity_files.push(identity_files);
            continue;
        }

        if let Some((directive, value)) = line.split_once('=')
            && directive.trim() == "max_connections"
        {
            if max_connections_set {
                return Err(ConfigError::Line {
                    line: line_number,
                    message: "duplicate max_connections setting".to_owned(),
                });
            }

            max_connections =
                parse_max_connections(value.trim()).map_err(|message| ConfigError::Line {
                    line: line_number,
                    message,
                })?;

            max_connections_set = true;
            continue;
        }

        if let Some((directive, value)) = line.split_once('=')
            && directive.trim() == "client_idle_timeout_seconds"
        {
            if client_idle_timeout_set {
                return Err(ConfigError::Line {
                    line: line_number,
                    message: "duplicate client_idle_timeout_seconds setting".to_owned(),
                });
            }

            client_idle_timeout_seconds =
                parse_client_idle_timeout_seconds(value.trim()).map_err(|message| {
                    ConfigError::Line {
                        line: line_number,
                        message,
                    }
                })?;

            client_idle_timeout_set = true;
            continue;
        }

        if let Some((directive, value)) = line.split_once('=')
            && directive.trim() == "upstream_timeout_seconds"
        {
            if upstream_timeout_set {
                return Err(ConfigError::Line {
                    line: line_number,
                    message: "duplicate upstream_timeout_seconds setting".to_owned(),
                });
            }

            upstream_timeout_seconds =
                parse_upstream_timeout_seconds(value.trim()).map_err(|message| {
                    ConfigError::Line {
                        line: line_number,
                        message,
                    }
                })?;

            upstream_timeout_set = true;
            continue;
        }

        let (hostname, upstream) = line.split_once("->").ok_or_else(|| ConfigError::Line {
            line: line_number,
            message: "expected `hostname -> upstream:port`".to_owned(),
        })?;

        if upstream.contains("->") {
            return Err(ConfigError::Line {
                line: line_number,
                message: "route contains more than one `->` separator".to_owned(),
            });
        }

        let hostname = normalize_hostname(hostname.trim()).ok_or_else(|| ConfigError::Line {
            line: line_number,
            message: "invalid route hostname".to_owned(),
        })?;

        if !hostnames.insert(hostname.clone()) {
            return Err(ConfigError::Line {
                line: line_number,
                message: format!("duplicate route for {hostname}"),
            });
        }

        let upstream = parse_upstream(upstream.trim()).map_err(|message| ConfigError::Line {
            line: line_number,
            message,
        })?;

        routes.push(Route { hostname, upstream });
    }

    Ok((
        Config {
            routes,
            max_connections,
            client_idle_timeout_seconds,
            upstream_timeout_seconds,
        },
        tls_identity_files,
    ))
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#')
        .map_or(line, |(before_comment, _)| before_comment)
}

fn parse_tls_identity_files(input: &str) -> Result<TlsIdentityFiles, String> {
    let syntax_error = || "tls_identity must use `certificate.pem | private-key.pem`".to_owned();

    let (certificate_path, private_key_path) = input.split_once('|').ok_or_else(syntax_error)?;

    if private_key_path.contains('|') {
        return Err(syntax_error());
    }

    let certificate_path = certificate_path.trim();
    let private_key_path = private_key_path.trim();

    if certificate_path.is_empty() || private_key_path.is_empty() {
        return Err(syntax_error());
    }

    Ok(TlsIdentityFiles {
        certificate_path: PathBuf::from(certificate_path),
        private_key_path: PathBuf::from(private_key_path),
    })
}

fn normalize_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.');

    if !is_valid_hostname(hostname) {
        return None;
    }

    Some(hostname.to_ascii_lowercase())
}

fn normalize_request_host(host: &str) -> Option<String> {
    let host = host.trim();

    if host.is_empty() {
        return None;
    }

    let hostname = if let Some((hostname, port)) = host.rsplit_once(':') {
        if hostname.contains(':')
            || port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return None;
        }

        hostname
    } else {
        host
    };

    normalize_hostname(hostname)
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii() {
        return false;
    }

    hostname.split('.').all(is_valid_hostname_label)
}

fn is_valid_hostname_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    let bytes = label.as_bytes();

    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn parse_upstream(input: &str) -> Result<Upstream, String> {
    if input.is_empty() {
        return Err("missing upstream".to_owned());
    }

    let (host, port) = if let Some(rest) = input.strip_prefix('[') {
        let closing = rest
            .find(']')
            .ok_or_else(|| "invalid bracketed upstream address".to_owned())?;

        let host = &rest[..closing];
        let remainder = &rest[closing + 1..];

        let port = remainder
            .strip_prefix(':')
            .ok_or_else(|| "upstream port is required after `]`".to_owned())?;

        let address = host
            .parse::<IpAddr>()
            .map_err(|_| "invalid bracketed IP address".to_owned())?;

        if !address.is_ipv6() {
            return Err("bracketed upstream address must be IPv6".to_owned());
        }

        (host.to_owned(), port)
    } else {
        let (host, port) = input
            .rsplit_once(':')
            .ok_or_else(|| "upstream must include a port".to_owned())?;

        if host.contains(':') {
            return Err("IPv6 upstreams must use `[address]:port` syntax".to_owned());
        }

        let normalized_host =
            normalize_upstream_host(host).ok_or_else(|| "invalid upstream host".to_owned())?;

        (normalized_host, port)
    };

    let port = parse_port(port)?;

    Ok(Upstream { host, port })
}

fn normalize_upstream_host(host: &str) -> Option<String> {
    let host = host.trim();

    if host.is_empty() {
        return None;
    }

    if let Ok(address) = host.parse::<IpAddr>() {
        return Some(address.to_string());
    }

    normalize_hostname(host)
}

fn parse_port(port: &str) -> Result<u16, String> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid upstream port".to_owned());
    }

    let port = port
        .parse::<u16>()
        .map_err(|_| "upstream port must be between 1 and 65535".to_owned())?;

    if port == 0 {
        return Err("upstream port must be between 1 and 65535".to_owned());
    }

    Ok(port)
}

fn parse_max_connections(value: &str) -> Result<usize, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("max_connections must be a positive integer".to_owned());
    }

    let value = value
        .parse::<usize>()
        .map_err(|_| "max_connections must be a positive integer".to_owned())?;

    if value == 0 {
        return Err("max_connections must be a positive integer".to_owned());
    }

    Ok(value)
}

fn parse_client_idle_timeout_seconds(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("client_idle_timeout_seconds must be a positive integer".to_owned());
    }

    let value = value
        .parse::<u64>()
        .map_err(|_| "client_idle_timeout_seconds must be a positive integer".to_owned())?;

    if value == 0 {
        return Err("client_idle_timeout_seconds must be a positive integer".to_owned());
    }

    Ok(value)
}

fn parse_upstream_timeout_seconds(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("upstream_timeout_seconds must be a positive integer".to_owned());
    }

    let value = value
        .parse::<u64>()
        .map_err(|_| "upstream_timeout_seconds must be a positive integer".to_owned())?;

    if value == 0 {
        return Err("upstream_timeout_seconds must be a positive integer".to_owned());
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        Config, ConfigError, DEFAULT_CLIENT_IDLE_TIMEOUT_SECONDS, DEFAULT_MAX_CONNECTIONS,
        DEFAULT_UPSTREAM_TIMEOUT_SECONDS, Route, RouteLookupError, TlsIdentityFiles, Upstream,
        parse, parse_with_tls,
    };

    use std::path::PathBuf;

    #[test]
    fn parses_route() {
        assert_eq!(
            parse("example.test -> 127.0.0.1:3000"),
            Ok(Config {
                routes: vec![Route {
                    hostname: "example.test".to_owned(),
                    upstream: Upstream {
                        host: "127.0.0.1".to_owned(),
                        port: 3000,
                    },
                }],
                max_connections: DEFAULT_MAX_CONNECTIONS,
                client_idle_timeout_seconds: DEFAULT_CLIENT_IDLE_TIMEOUT_SECONDS,
                upstream_timeout_seconds: DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
            })
        );
    }

    #[test]
    fn uses_default_connection_limit() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(config.max_connections(), DEFAULT_MAX_CONNECTIONS);
    }

    #[test]
    fn parses_connection_limit() {
        let config = parse(
            "max_connections = 42\n\
example.test -> 127.0.0.1:3000",
        )
        .unwrap();

        assert_eq!(config.max_connections(), 42);
    }

    #[test]
    fn uses_default_client_idle_timeout() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.client_idle_timeout_seconds(),
            DEFAULT_CLIENT_IDLE_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn parses_client_idle_timeout() {
        let config = parse(
            "client_idle_timeout_seconds = 12\n\
example.test -> 127.0.0.1:3000",
        )
        .unwrap();

        assert_eq!(config.client_idle_timeout_seconds(), 12);
    }

    #[test]
    fn uses_default_upstream_timeout() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.upstream_timeout_seconds(),
            DEFAULT_UPSTREAM_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn parses_upstream_timeout() {
        let config = parse(
            "upstream_timeout_seconds = 3\n\
example.test -> 127.0.0.1:3000",
        )
        .unwrap();

        assert_eq!(config.upstream_timeout_seconds(), 3);
    }

    #[test]
    fn parses_tls_identities_separately_from_routes() {
        let (config, identities) = parse_with_tls(
            "tls_identity = certs/one.pem | certs/one-key.pem\n\
tls_identity = certs/two.pem | certs/two-key.pem\n\
example.test -> 127.0.0.1:3000",
        )
        .unwrap();

        assert_eq!(config.routes().len(), 1);

        assert_eq!(
            identities,
            vec![
                TlsIdentityFiles {
                    certificate_path: PathBuf::from("certs/one.pem"),
                    private_key_path: PathBuf::from("certs/one-key.pem"),
                },
                TlsIdentityFiles {
                    certificate_path: PathBuf::from("certs/two.pem"),
                    private_key_path: PathBuf::from("certs/two-key.pem"),
                },
            ]
        );
    }

    #[test]
    fn rejects_duplicate_tls_identity_pair() {
        assert_eq!(
            parse_with_tls(
                "tls_identity = certs/site.pem | certs/site-key.pem\n\
tls_identity = certs/site.pem | certs/site-key.pem\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 2,
                message: "duplicate tls_identity certificate/key pair".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_malformed_tls_identity() {
        assert_eq!(
            parse_with_tls(
                "tls_identity = certs/site.pem\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 1,
                message: "tls_identity must use `certificate.pem | private-key.pem`".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_zero_upstream_timeout() {
        assert_eq!(
            parse(
                "upstream_timeout_seconds = 0\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 1,
                message: "upstream_timeout_seconds must be a positive integer".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_duplicate_upstream_timeout() {
        assert_eq!(
            parse(
                "upstream_timeout_seconds = 10\n\
upstream_timeout_seconds = 20\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 2,
                message: "duplicate upstream_timeout_seconds setting".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_zero_client_idle_timeout() {
        assert_eq!(
            parse(
                "client_idle_timeout_seconds = 0\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 1,
                message: "client_idle_timeout_seconds must be a positive integer".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_duplicate_client_idle_timeout() {
        assert_eq!(
            parse(
                "client_idle_timeout_seconds = 10\n\
client_idle_timeout_seconds = 20\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 2,
                message: "duplicate client_idle_timeout_seconds setting".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_zero_connection_limit() {
        assert_eq!(
            parse(
                "max_connections = 0\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 1,
                message: "max_connections must be a positive integer".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_duplicate_connection_limit() {
        assert_eq!(
            parse(
                "max_connections = 10\n\
max_connections = 20\n\
example.test -> 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 2,
                message: "duplicate max_connections setting".to_owned(),
            })
        );
    }

    #[test]
    fn supports_blank_lines_and_comments() {
        let config = parse(
            "
# BareProxy routes

example.test -> 127.0.0.1:3000

# another comment
api.example.test -> backend.local:4000 # inline comment
",
        )
        .unwrap();

        assert_eq!(config.routes.len(), 2);
    }

    #[test]
    fn normalizes_route_and_upstream_hostnames() {
        let config = parse("EXAMPLE.Test. -> BACKEND.Local.:8080").unwrap();

        assert_eq!(config.routes[0].hostname, "example.test");
        assert_eq!(config.routes[0].upstream.host, "backend.local");
    }

    #[test]
    fn parses_ipv6_upstream() {
        let config = parse("example.test -> [::1]:8080").unwrap();

        assert_eq!(config.routes[0].upstream.host, "::1");
        assert_eq!(config.routes[0].upstream.port, 8080);
    }

    #[test]
    fn rejects_duplicate_routes_after_normalization() {
        assert_eq!(
            parse(
                "Example.Test -> 127.0.0.1:3000
example.test -> 127.0.0.1:4000"
            ),
            Err(ConfigError::Line {
                line: 2,
                message: "duplicate route for example.test".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_missing_separator_with_line_number() {
        assert_eq!(
            parse(
                "# comment
example.test 127.0.0.1:3000"
            ),
            Err(ConfigError::Line {
                line: 2,
                message: "expected `hostname -> upstream:port`".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_route_hostname() {
        assert_eq!(
            parse("-example.test -> 127.0.0.1:3000"),
            Err(ConfigError::Line {
                line: 1,
                message: "invalid route hostname".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_missing_upstream_port() {
        assert_eq!(
            parse("example.test -> 127.0.0.1"),
            Err(ConfigError::Line {
                line: 1,
                message: "upstream must include a port".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_zero_port() {
        assert_eq!(
            parse("example.test -> 127.0.0.1:0"),
            Err(ConfigError::Line {
                line: 1,
                message: "upstream port must be between 1 and 65535".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_out_of_range_port() {
        assert_eq!(
            parse("example.test -> 127.0.0.1:65536"),
            Err(ConfigError::Line {
                line: 1,
                message: "upstream port must be between 1 and 65535".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_unbracketed_ipv6_upstream() {
        assert_eq!(
            parse("example.test -> ::1:8080"),
            Err(ConfigError::Line {
                line: 1,
                message: "IPv6 upstreams must use `[address]:port` syntax".to_owned(),
            })
        );
    }

    #[test]
    fn matches_route_by_hostname() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.route_for_host("example.test").unwrap().hostname,
            "example.test"
        );
    }

    #[test]
    fn route_lookup_ignores_hostname_case() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.route_for_host("EXAMPLE.TEST").unwrap().hostname,
            "example.test"
        );
    }

    #[test]
    fn route_lookup_ignores_explicit_host_port() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.route_for_host("Example.Test:8080").unwrap().hostname,
            "example.test"
        );
    }

    #[test]
    fn route_lookup_selects_correct_route() {
        let config = parse(
            "one.test -> 127.0.0.1:3000
two.test -> 127.0.0.1:4000",
        )
        .unwrap();

        assert_eq!(
            config.route_for_host("two.test").unwrap().upstream.port,
            4000
        );
    }

    #[test]
    fn unknown_host_returns_not_found() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.route_for_host("missing.test"),
            Err(RouteLookupError::NotFound("missing.test".to_owned()))
        );
    }

    #[test]
    fn invalid_host_is_rejected() {
        let config = parse("example.test -> 127.0.0.1:3000").unwrap();

        assert_eq!(
            config.route_for_host("example.test:potato"),
            Err(RouteLookupError::InvalidHost)
        );
    }
}
