use std::fmt;
use std::net::SocketAddr;

use cmfd_node::DEFAULT_P2P_ADDRESS;
use cmfd_node::peer::{PeerAddressPolicy, PeerLimits, StaticPeerConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NodeRuntimeConfig {
    pub(super) p2p_bind: SocketAddr,
    pub(super) peers: Vec<SocketAddr>,
    pub(super) allow_public_peers: bool,
    /// `-v` count: 0 = silent, 1 = warn, 2 = info, 3 = debug, 4+ = trace on
    /// the console. The file log under the node's data directory is always
    /// debug level, regardless of this count.
    pub(super) verbose: u8,
}

impl NodeRuntimeConfig {
    pub(super) fn from_process_args() -> Result<Self, ConfigError> {
        let mut args = Vec::new();
        for argument in std::env::args_os().skip(1) {
            let argument = argument
                .into_string()
                .map_err(|_| ConfigError::NonUnicodeArgument)?;
            args.push(argument);
        }
        Self::parse(args)
    }

    fn parse<I, S>(arguments: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let default_bind = DEFAULT_P2P_ADDRESS
            .parse()
            .map_err(|_| ConfigError::InvalidBuiltInDefault)?;
        let mut p2p_bind = None;
        let mut peers = Vec::new();
        let mut allow_public_peers = false;
        let mut verbose: u8 = 0;
        let mut arguments = arguments.into_iter().map(Into::into);

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--p2p-bind" => {
                    if p2p_bind.is_some() {
                        return Err(ConfigError::DuplicateOption("--p2p-bind"));
                    }
                    let value = arguments
                        .next()
                        .ok_or(ConfigError::MissingValue("--p2p-bind"))?;
                    p2p_bind = Some(parse_address("--p2p-bind", &value)?);
                }
                "--peer" => {
                    let value = arguments
                        .next()
                        .ok_or(ConfigError::MissingValue("--peer"))?;
                    peers.push(parse_address("--peer", &value)?);
                }
                "--allow-public-peers" => {
                    if allow_public_peers {
                        return Err(ConfigError::DuplicateOption("--allow-public-peers"));
                    }
                    allow_public_peers = true;
                }
                "--verbose" => verbose = verbose.saturating_add(1),
                _ if is_short_verbose_flag(&argument) => {
                    verbose = verbose.saturating_add(argument.len() as u8 - 1);
                }
                _ if argument.starts_with("--p2p-bind=") => {
                    if p2p_bind.is_some() {
                        return Err(ConfigError::DuplicateOption("--p2p-bind"));
                    }
                    let value = argument
                        .strip_prefix("--p2p-bind=")
                        .expect("prefix was checked");
                    p2p_bind = Some(parse_address("--p2p-bind", value)?);
                }
                _ if argument.starts_with("--peer=") => {
                    let value = argument
                        .strip_prefix("--peer=")
                        .expect("prefix was checked");
                    peers.push(parse_address("--peer", value)?);
                }
                _ => return Err(ConfigError::UnknownArgument(argument)),
            }
        }

        let config = Self {
            p2p_bind: p2p_bind.unwrap_or(default_bind),
            peers,
            allow_public_peers,
            verbose,
        };
        config.static_peers(PeerLimits::default()).validate()?;
        Ok(config)
    }

    pub(super) fn static_peers(&self, limits: PeerLimits) -> StaticPeerConfig {
        StaticPeerConfig {
            listen_address: self.p2p_bind,
            peers: self.peers.clone(),
            limits,
            address_policy: self.address_policy(),
        }
    }

    pub(super) fn address_policy(&self) -> PeerAddressPolicy {
        if self.allow_public_peers {
            PeerAddressPolicy::AllowPublic
        } else {
            PeerAddressPolicy::PrivateOnly
        }
    }
}

/// Matches `-v`, `-vv`, `-vvv`, etc. — clap-style bundled short verbosity
/// flags, so `cmfd-node run -vvv` and the wallet launched with `-vvv` parse
/// the same way.
fn is_short_verbose_flag(argument: &str) -> bool {
    argument.len() >= 2
        && argument.starts_with('-')
        && !argument.starts_with("--")
        && argument[1..].bytes().all(|byte| byte == b'v')
}

fn parse_address(option: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::InvalidAddress {
        option,
        value: value.to_owned(),
    })
}

#[derive(Debug)]
pub(super) enum ConfigError {
    NonUnicodeArgument,
    InvalidBuiltInDefault,
    UnknownArgument(String),
    MissingValue(&'static str),
    DuplicateOption(&'static str),
    InvalidAddress { option: &'static str, value: String },
    InvalidPeerConfiguration(String),
}

impl From<cmfd_node::peer::PeerError> for ConfigError {
    fn from(error: cmfd_node::peer::PeerError) -> Self {
        Self::InvalidPeerConfiguration(error.to_string())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUnicodeArgument => {
                formatter.write_str("wallet node arguments must be valid Unicode")
            }
            Self::InvalidBuiltInDefault => {
                formatter.write_str("the built-in P2P listener address is invalid")
            }
            Self::UnknownArgument(argument) => {
                write!(formatter, "unknown wallet argument: {argument}")
            }
            Self::MissingValue(option) => write!(formatter, "{option} requires an IP:port value"),
            Self::DuplicateOption(option) => {
                write!(formatter, "{option} may only be specified once")
            }
            Self::InvalidAddress { option, value } => {
                write!(
                    formatter,
                    "{option} requires a numeric IP:port, received {value}"
                )
            }
            Self::InvalidPeerConfiguration(message) => formatter.write_str(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_click_defaults_to_loopback_without_outbound_peers() {
        let config = NodeRuntimeConfig::parse(Vec::<String>::new()).unwrap();

        assert_eq!(config.p2p_bind, "127.0.0.1:18444".parse().unwrap());
        assert!(config.peers.is_empty());
        assert!(!config.allow_public_peers);
        assert_eq!(config.verbose, 0);
    }

    #[test]
    fn verbosity_counts_repeated_and_bundled_short_flags() {
        assert_eq!(NodeRuntimeConfig::parse(["--verbose"]).unwrap().verbose, 1);
        assert_eq!(NodeRuntimeConfig::parse(["-v"]).unwrap().verbose, 1);
        assert_eq!(NodeRuntimeConfig::parse(["-vv"]).unwrap().verbose, 2);
        assert_eq!(NodeRuntimeConfig::parse(["-vvv"]).unwrap().verbose, 3);
        assert_eq!(
            NodeRuntimeConfig::parse(["-v", "--verbose", "-vv"])
                .unwrap()
                .verbose,
            4
        );
    }

    #[test]
    fn private_bind_and_repeatable_peers_are_accepted() {
        let config = NodeRuntimeConfig::parse([
            "--p2p-bind",
            "192.168.50.10:18444",
            "--peer=192.168.50.11:18444",
            "--peer",
            "[fd12:3456::12]:18444",
        ])
        .unwrap();

        assert_eq!(config.p2p_bind, "192.168.50.10:18444".parse().unwrap());
        assert_eq!(
            config.peers,
            [
                "192.168.50.11:18444".parse().unwrap(),
                "[fd12:3456::12]:18444".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn public_unspecified_duplicate_and_self_addresses_are_rejected() {
        for arguments in [
            vec!["--peer", "8.8.8.8:18444"],
            vec!["--p2p-bind", "0.0.0.0:18444"],
            vec!["--peer", "127.0.0.1:18444"],
            vec!["--peer", "127.0.0.1:18454", "--peer", "127.0.0.1:18454"],
        ] {
            assert!(
                matches!(
                    NodeRuntimeConfig::parse(arguments),
                    Err(ConfigError::InvalidPeerConfiguration(_))
                ),
                "configuration unexpectedly passed validation"
            );
        }
    }

    #[test]
    fn public_peers_require_explicit_opt_in_and_unsafe_binds_stay_rejected() {
        let config = NodeRuntimeConfig::parse([
            "--allow-public-peers",
            "--p2p-bind",
            "192.168.50.10:18444",
            "--peer",
            "8.8.8.8:18444",
        ])
        .unwrap();
        assert!(config.allow_public_peers);
        assert_eq!(config.peers, ["8.8.8.8:18444".parse().unwrap()]);

        assert!(matches!(
            NodeRuntimeConfig::parse(["--allow-public-peers", "--p2p-bind", "0.0.0.0:18444"]),
            Err(ConfigError::InvalidPeerConfiguration(_))
        ));
        assert!(matches!(
            NodeRuntimeConfig::parse(["--allow-public-peers", "--allow-public-peers"]),
            Err(ConfigError::DuplicateOption("--allow-public-peers"))
        ));
    }

    #[test]
    fn malformed_or_ambiguous_options_are_rejected() {
        assert!(matches!(
            NodeRuntimeConfig::parse(["--peer"]),
            Err(ConfigError::MissingValue("--peer"))
        ));
        assert!(matches!(
            NodeRuntimeConfig::parse(["--peer", "localhost:18444"]),
            Err(ConfigError::InvalidAddress {
                option: "--peer",
                ..
            })
        ));
        assert!(matches!(
            NodeRuntimeConfig::parse([
                "--p2p-bind=127.0.0.1:18445",
                "--p2p-bind",
                "127.0.0.1:18446"
            ]),
            Err(ConfigError::DuplicateOption("--p2p-bind"))
        ));
        assert!(matches!(
            NodeRuntimeConfig::parse(["--unknown"]),
            Err(ConfigError::UnknownArgument(_))
        ));
    }
}
