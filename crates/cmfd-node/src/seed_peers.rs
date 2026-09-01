//! Operational cold-start seed resolution.
//!
//! Seed endpoints and their resolved addresses are connectivity inputs only.
//! They must never be absorbed into a consensus fingerprint or immutable
//! [`crate::NetworkProfile`] identity. Resolve them before constructing a
//! [`crate::peer::StaticPeerConfig`].

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::str::FromStr;

use thiserror::Error;

use crate::network_profile::{PRODUCTION_RC_SEED_IPV4, PRODUCTION_RC_SEED_PORT};
use crate::peer::is_publicly_routable_peer_ip;

pub const MAX_SEED_ENDPOINTS: usize = 16;
pub const MAX_SEED_ANSWERS_PER_HOST: usize = 8;
/// Matches the default maximum in [`crate::peer::PeerLimits`] so resolved
/// seeds can be used directly by a default [`crate::peer::StaticPeerConfig`].
pub const MAX_RESOLVED_SEED_PEERS: usize = 16;
const MAX_DNS_NAME_BYTES: usize = 253;

/// The currently provisioned RCNet-1 cold-start endpoint.
pub const PRODUCTION_RC_SEED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(
    PRODUCTION_RC_SEED_IPV4,
    PRODUCTION_RC_SEED_PORT,
));

pub fn production_rc_seed_set() -> SeedSet {
    SeedSet {
        endpoints: vec![SeedEndpoint {
            host: SeedHost::Literal(PRODUCTION_RC_SEED.ip()),
            port: PRODUCTION_RC_SEED.port(),
        }],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeedEndpoint {
    host: SeedHost,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SeedHost {
    Literal(IpAddr),
    Dns(String),
}

impl FromStr for SeedEndpoint {
    type Err = SeedPeerError;

    fn from_str(endpoint: &str) -> Result<Self, Self::Err> {
        if endpoint.is_empty() || endpoint.trim() != endpoint {
            return Err(SeedPeerError::InvalidEndpoint(endpoint.to_owned()));
        }
        if let Ok(address) = endpoint.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err(SeedPeerError::ZeroPort);
            }
            return Ok(Self {
                host: SeedHost::Literal(canonical_ip(address.ip())),
                port: address.port(),
            });
        }

        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| SeedPeerError::InvalidEndpoint(endpoint.to_owned()))?;
        if host.is_empty() || host.contains([':', '[', ']']) {
            return Err(SeedPeerError::InvalidEndpoint(endpoint.to_owned()));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| SeedPeerError::InvalidEndpoint(endpoint.to_owned()))?;
        if port == 0 {
            return Err(SeedPeerError::ZeroPort);
        }
        let host = normalize_dns_name(host)?;
        Ok(Self {
            host: SeedHost::Dns(host),
            port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSet {
    endpoints: Vec<SeedEndpoint>,
}

impl SeedSet {
    pub fn new(endpoints: Vec<SeedEndpoint>) -> Result<Self, SeedPeerError> {
        if endpoints.len() > MAX_SEED_ENDPOINTS {
            return Err(SeedPeerError::TooManyEndpoints {
                actual: endpoints.len(),
                max: MAX_SEED_ENDPOINTS,
            });
        }

        let mut seen = HashSet::with_capacity(endpoints.len());
        let mut ordered = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if seen.insert(endpoint.clone()) {
                ordered.push(endpoint);
            }
        }
        Ok(Self { endpoints: ordered })
    }

    pub fn resolve<R: SeedResolver>(&self, resolver: &R) -> Result<Vec<SocketAddr>, SeedPeerError> {
        let mut seen = HashSet::new();
        let mut peers = Vec::new();

        for endpoint in &self.endpoints {
            match &endpoint.host {
                SeedHost::Literal(ip) => {
                    push_public_peer(&mut peers, &mut seen, SocketAddr::new(*ip, endpoint.port))?;
                }
                SeedHost::Dns(host) => {
                    let mut answers = resolver
                        .resolve(host, endpoint.port, MAX_SEED_ANSWERS_PER_HOST)
                        .map_err(|source| SeedPeerError::Resolution {
                            host: host.clone(),
                            source,
                        })?;
                    if answers.len() > MAX_SEED_ANSWERS_PER_HOST {
                        return Err(SeedPeerError::TooManyAnswers {
                            host: host.clone(),
                            actual: answers.len(),
                            max: MAX_SEED_ANSWERS_PER_HOST,
                        });
                    }
                    if answers.is_empty() {
                        return Err(SeedPeerError::NoAddresses(host.clone()));
                    }
                    for answer in &mut answers {
                        *answer = canonical_ip(*answer);
                    }
                    answers.sort_unstable();
                    answers.dedup();
                    for ip in answers {
                        push_public_peer(
                            &mut peers,
                            &mut seen,
                            SocketAddr::new(ip, endpoint.port),
                        )?;
                    }
                }
            }
        }
        Ok(peers)
    }
}

pub trait SeedResolver {
    /// Resolve both A and AAAA records. Implementations must stop after
    /// `answer_limit + 1` answers so the caller can detect an overflow.
    fn resolve(&self, host: &str, port: u16, answer_limit: usize) -> io::Result<Vec<IpAddr>>;
}

impl<F> SeedResolver for F
where
    F: Fn(&str, u16, usize) -> io::Result<Vec<IpAddr>>,
{
    fn resolve(&self, host: &str, port: u16, answer_limit: usize) -> io::Result<Vec<IpAddr>> {
        self(host, port, answer_limit)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSeedResolver;

impl SeedResolver for SystemSeedResolver {
    fn resolve(&self, host: &str, port: u16, answer_limit: usize) -> io::Result<Vec<IpAddr>> {
        Ok((host, port)
            .to_socket_addrs()?
            .take(answer_limit.saturating_add(1))
            .map(|address| address.ip())
            .collect())
    }
}

#[derive(Debug, Error)]
pub enum SeedPeerError {
    #[error("invalid seed endpoint {0:?}")]
    InvalidEndpoint(String),
    #[error("seed endpoint port must be nonzero")]
    ZeroPort,
    #[error("invalid DNS seed name {0:?}")]
    InvalidDnsName(String),
    #[error("seed endpoint count {actual} exceeds the limit of {max}")]
    TooManyEndpoints { actual: usize, max: usize },
    #[error("DNS seed {host:?} returned {actual} answers, exceeding the limit of {max}")]
    TooManyAnswers {
        host: String,
        actual: usize,
        max: usize,
    },
    #[error("DNS seed {0:?} returned no addresses")]
    NoAddresses(String),
    #[error("DNS seed {host:?} resolution failed: {source}")]
    Resolution {
        host: String,
        #[source]
        source: io::Error,
    },
    #[error("public RC seed address is not publicly routable: {0}")]
    UnsafeAddress(SocketAddr),
    #[error("resolved seed peer count exceeds the limit of {0}")]
    TooManyResolvedPeers(usize),
}

fn normalize_dns_name(host: &str) -> Result<String, SeedPeerError> {
    let normalized = host.strip_suffix('.').unwrap_or(host);
    let valid = !normalized.is_empty()
        && normalized.len() <= MAX_DNS_NAME_BYTES
        && normalized.is_ascii()
        && normalized.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if !valid {
        return Err(SeedPeerError::InvalidDnsName(host.to_owned()));
    }
    Ok(normalized.to_ascii_lowercase())
}

fn push_public_peer(
    peers: &mut Vec<SocketAddr>,
    seen: &mut HashSet<SocketAddr>,
    address: SocketAddr,
) -> Result<(), SeedPeerError> {
    validate_public_seed_address(address)?;
    if !seen.insert(address) {
        return Ok(());
    }
    if peers.len() == MAX_RESOLVED_SEED_PEERS {
        return Err(SeedPeerError::TooManyResolvedPeers(MAX_RESOLVED_SEED_PEERS));
    }
    peers.push(address);
    Ok(())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn validate_public_seed_address(address: SocketAddr) -> Result<(), SeedPeerError> {
    if address.port() == 0 || !is_publicly_routable_peer_ip(address.ip()) {
        return Err(SeedPeerError::UnsafeAddress(address));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    use super::*;

    fn endpoint(value: &str) -> SeedEndpoint {
        value.parse().unwrap()
    }

    #[test]
    fn endpoints_parse_dns_ipv4_and_bracketed_ipv6_with_required_ports() {
        assert!("seed.example.org:19444".parse::<SeedEndpoint>().is_ok());
        assert!("8.8.8.8:19444".parse::<SeedEndpoint>().is_ok());
        assert!(
            "[2606:4700:4700::1111]:19444"
                .parse::<SeedEndpoint>()
                .is_ok()
        );
        assert!(matches!(
            "seed.example.org:0".parse::<SeedEndpoint>(),
            Err(SeedPeerError::ZeroPort)
        ));
        assert!(
            "2606:4700:4700::1111:19444"
                .parse::<SeedEndpoint>()
                .is_err()
        );
        assert!("bad_name.example:19444".parse::<SeedEndpoint>().is_err());
    }

    #[test]
    fn production_rc_seed_is_public_and_resolves_without_dns() {
        assert_eq!(PRODUCTION_RC_SEED.to_string(), "173.249.35.251:19444");
        assert_eq!(
            production_rc_seed_set()
                .resolve(&|_: &str, _: u16, _: usize| unreachable!())
                .unwrap(),
            vec![PRODUCTION_RC_SEED]
        );
    }

    #[test]
    fn resolution_is_ordered_sorted_and_deduplicated_without_live_dns() {
        let seeds = SeedSet::new(vec![
            endpoint("B.Example.org.:19444"),
            endpoint("8.8.8.8:19444"),
            endpoint("a.example.org:19444"),
            endpoint("b.example.org:19444"),
        ])
        .unwrap();
        let calls = RefCell::new(Vec::new());
        let resolver = |host: &str, port: u16, limit: usize| {
            calls.borrow_mut().push((host.to_owned(), port, limit));
            Ok(match host {
                "b.example.org" => vec![
                    "2606:4700:4700::1111".parse().unwrap(),
                    "1.1.1.1".parse().unwrap(),
                    "1.1.1.1".parse().unwrap(),
                ],
                "a.example.org" => {
                    vec!["9.9.9.9".parse().unwrap(), "1.1.1.1".parse().unwrap()]
                }
                _ => unreachable!(),
            })
        };

        let resolved = seeds.resolve(&resolver).unwrap();
        assert_eq!(
            resolved,
            vec![
                "1.1.1.1:19444".parse().unwrap(),
                "[2606:4700:4700::1111]:19444".parse().unwrap(),
                "8.8.8.8:19444".parse().unwrap(),
                "9.9.9.9:19444".parse().unwrap(),
            ]
        );
        assert_eq!(
            calls.into_inner(),
            vec![
                ("b.example.org".to_owned(), 19444, MAX_SEED_ANSWERS_PER_HOST,),
                ("a.example.org".to_owned(), 19444, MAX_SEED_ANSWERS_PER_HOST,),
            ]
        );
        crate::peer::StaticPeerConfig {
            listen_address: "127.0.0.1:19444".parse().unwrap(),
            peers: resolved,
            limits: crate::peer::PeerLimits::default(),
            address_policy: crate::peer::PeerAddressPolicy::AllowPublic,
        }
        .validate_client_peers()
        .unwrap();
    }

    #[test]
    fn public_seed_policy_rejects_local_multicast_and_documentation_ranges() {
        for value in [
            "0.0.0.0:19444",
            "127.0.0.1:19444",
            "10.0.0.1:19444",
            "100.64.0.1:19444",
            "169.254.1.1:19444",
            "224.0.0.1:19444",
            "240.0.0.1:19444",
            "192.0.2.1:19444",
            "192.88.99.1:19444",
            "198.18.0.1:19444",
            "198.51.100.1:19444",
            "203.0.113.1:19444",
            "[::]:19444",
            "[::1]:19444",
            "[fc00::1]:19444",
            "[fe80::1]:19444",
            "[ff02::1]:19444",
            "[64:ff9b:1::1]:19444",
            "[100::1]:19444",
            "[100:0:0:1::1]:19444",
            "[2001::1]:19444",
            "[2001:2::1]:19444",
            "[2001:20::1]:19444",
            "[2001:db8::1]:19444",
            "[2002:c000:0204::1]:19444",
            "[3fff:fff::1]:19444",
            "[5f00::1]:19444",
        ] {
            let seeds = SeedSet::new(vec![endpoint(value)]).unwrap();
            assert!(matches!(
                seeds.resolve(&|_: &str, _: u16, _: usize| unreachable!()),
                Err(SeedPeerError::UnsafeAddress(_))
            ));
        }

        let seeds = SeedSet::new(vec![endpoint("seed.example.org:19444")]).unwrap();
        assert!(matches!(
            seeds.resolve(&|_: &str, _: u16, _: usize| { Ok(vec!["192.0.2.10".parse().unwrap()]) }),
            Err(SeedPeerError::UnsafeAddress(_))
        ));
    }

    #[test]
    fn endpoint_answer_and_total_peer_caps_fail_closed() {
        let too_many_endpoints = (0..=MAX_SEED_ENDPOINTS)
            .map(|index| endpoint(&format!("seed-{index}.example.org:19444")))
            .collect();
        assert!(matches!(
            SeedSet::new(too_many_endpoints),
            Err(SeedPeerError::TooManyEndpoints { .. })
        ));

        let one = SeedSet::new(vec![endpoint("seed.example.org:19444")]).unwrap();
        assert!(matches!(
            one.resolve(&|_: &str, _: u16, _: usize| {
                Ok(vec![
                    "8.8.8.8".parse().unwrap();
                    MAX_SEED_ANSWERS_PER_HOST + 1
                ])
            }),
            Err(SeedPeerError::TooManyAnswers { .. })
        ));

        let endpoints = (0..5)
            .map(|index| endpoint(&format!("seed-{index}.example.org:19444")))
            .collect();
        let many = SeedSet::new(endpoints).unwrap();
        assert!(matches!(
            many.resolve(&|host: &str, _, _| {
                let group = host.as_bytes()[5] - b'0';
                Ok((1..=MAX_SEED_ANSWERS_PER_HOST)
                    .map(|suffix| IpAddr::V4(Ipv4Addr::new(20 + group, 1, 1, suffix as u8)))
                    .collect())
            }),
            Err(SeedPeerError::TooManyResolvedPeers(MAX_RESOLVED_SEED_PEERS))
        ));
    }

    #[test]
    fn empty_and_failed_dns_answers_are_rejected() {
        let seeds = SeedSet::new(vec![endpoint("seed.example.org:19444")]).unwrap();
        assert!(matches!(
            seeds.resolve(&|_: &str, _: u16, _: usize| Ok(Vec::new())),
            Err(SeedPeerError::NoAddresses(_))
        ));
        assert!(matches!(
            seeds.resolve(&|_: &str, _: u16, _: usize| {
                Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
            }),
            Err(SeedPeerError::Resolution { .. })
        ));
    }
}
