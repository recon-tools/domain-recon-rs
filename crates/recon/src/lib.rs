use addr::parse_domain_name;
use std::collections::HashSet;
use std::fmt::Debug;
use std::future;
use std::path::Path;

use async_std_resolver::lookup_ip::LookupIp;
use async_std_resolver::{
    config, resolver, resolver_from_system_conf, AsyncStdResolver, ResolveError,
};
use console::{style, Emoji};
use futures::future::join_all;
use futures::FutureExt;
use itertools::Itertools;
use serde::Deserialize;
use tokio::fs::File;
use tokio::io::{self, AsyncBufReadExt, BufReader};

pub use self::resolver::DNSResolver;
pub use self::resolver::UnknownDNSResolver;

mod resolver;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Certificate {
    issuer_ca_id: i64,
    issuer_name: String,
    common_name: String,
    name_value: String,
    id: i128,
    entry_timestamp: String,
    not_before: String,
    not_after: String,
    serial_number: String,
}

#[derive(Debug)]
pub struct DomainInfo {
    pub name: String,
    pub domain_type: String,
    pub ip_addresses: Vec<String>,
}

impl DomainInfo {
    pub fn new(name: String, domain_type: String, ip_addresses: Vec<String>) -> DomainInfo {
        DomainInfo {
            name,
            domain_type,
            ip_addresses,
        }
    }
}

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍  ", "*");
static CLIP: Emoji<'_, '_> = Emoji("🔗  ", "*");
static SPARKLE: Emoji<'_, '_> = Emoji("✨ ", "*");

static BATCH_SIZE: usize = 200;

pub async fn run(
    domain: String,
    file: String,
    use_system_resolver: bool,
    dns_resolvers: Vec<DNSResolver>,
    silent: bool,
) -> Result<Vec<DomainInfo>, anyhow::Error> {
    let steps = if file.is_empty() { 2 } else { 3 };

    if !silent {
        println!(
            "{} {}{}",
            style(format!("[1/{}]", steps)).bold().dim(),
            LOOKING_GLASS,
            style("Fetching certificates...").bold()
        );
    }

    let certificates = fetch_certificates(&domain).await?;

    if !silent {
        println!(
            "\n{} {}{}",
            style(format!("[2/{}]", steps)).bold().dim(),
            CLIP,
            style("Extracting valid domains...").bold()
        );
    }

    let mut domains: HashSet<String> = HashSet::new();
    for certificate in certificates {
        domains.extend(
            certificate
                .name_value
                .split('\n')
                .map(|s| s.to_string())
                .collect::<HashSet<String>>(),
        );
        domains.insert(certificate.common_name);
    }

    let (wildcards, fqdns) = domains
        .into_iter()
        .partition(|domain| domain.starts_with('*'));

    let resolver = build_resolver(use_system_resolver, &dns_resolvers).await?;

    let mut resolvable = get_resolvable_domains(&fqdns, &resolver, silent).await;

    if !file.trim().is_empty() {
        let words_path = Path::new(&file);
        if !silent {
            println!(
                "\n{} {}{}",
                style(format!("[3/{}]", steps)).bold().dim(),
                SPARKLE,
                style("Expanding wildcards...").bold()
            );
        }

        let words = read_words(words_path).await?;
        if let Ok(domains) = expand_wildcards(&wildcards, &fqdns, &words).await {
            resolvable.extend(get_resolvable_domains(&domains, &resolver, silent).await);
        }
    }

    let result = resolvable
        .iter()
        .map(|lookup| {
            let records = lookup
                .iter()
                .map(|record| record.to_string())
                .collect::<Vec<String>>();
            DomainInfo::new(
                lookup.query().name().to_string(),
                lookup.query().query_type().to_string(),
                records,
            )
        })
        .collect();

    Ok(result)
}

async fn build_resolver(
    use_system_resolver: bool,
    dns_resolvers: &Vec<DNSResolver>,
) -> Result<AsyncStdResolver, ResolveError> {
    if use_system_resolver {
        return resolver_from_system_conf().await;
    }

    // Add all the available nameservers to the resolver
    let mut dns_cfg = config::ResolverConfig::new();

    for resolver in dns_resolvers {
        match resolver {
            DNSResolver::Google => {
                for ns in config::NameServerConfigGroup::google().to_vec() {
                    dns_cfg.add_name_server(ns);
                }
            }
            DNSResolver::CloudFlare => {
                for ns in config::NameServerConfigGroup::cloudflare().to_vec() {
                    dns_cfg.add_name_server(ns);
                }
            }
            DNSResolver::Quad9 => {
                for ns in config::NameServerConfigGroup::quad9().to_vec() {
                    dns_cfg.add_name_server(ns);
                }
            }
        }
    }

    let resolver_cfg = config::ResolverOpts::default();
    let resolver = resolver(dns_cfg, resolver_cfg).await;
    resolver
}

async fn fetch_certificates(domain: &str) -> Result<Vec<Certificate>, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://crt.sh")
        .query(&[("q", domain), ("output", "json"), ("excluded", "expired")])
        .send()
        .await;
    response?.json::<Vec<Certificate>>().await
}

async fn read_words(words_path: &Path) -> Result<HashSet<String>, io::Error> {
    let mut lines = BufReader::new(File::open(words_path).await?).lines();
    let mut words: HashSet<String> = HashSet::new();
    while let Some(line) = lines.next_line().await? {
        words.insert(line.trim().to_string());
    }
    Ok(words)
}

async fn expand_wildcards(
    wildcards: &HashSet<String>,
    fqdns: &HashSet<String>,
    words: &HashSet<String>,
) -> Result<HashSet<String>, io::Error> {
    let mut potential_domains: HashSet<String> = HashSet::new();
    for word in words {
        potential_domains.extend(
            wildcards
                .iter()
                .map(|domain| domain.replace('*', word))
                .filter(|domain| !fqdns.contains(domain))
                .collect::<HashSet<String>>(),
        );
    }
    Ok(potential_domains)
}

async fn get_resolvable_domains(
    domains: &HashSet<String>,
    resolver: &AsyncStdResolver,
    silent: bool,
) -> Vec<LookupIp> {
    let mut result: Vec<Result<LookupIp, ResolveError>> = vec![];

    // Build chunks of records in order to avoid having to many opened connections.
    let chunks = domains.into_iter().chunks(BATCH_SIZE);
    for chunk in &chunks {
        let futures = chunk
            .into_iter()
            .filter(|str| parse_domain_name(str).is_ok())
            .map(|domain| {
                resolver.lookup_ip(domain).then(|r| {
                    // Display results as soon as they appear
                    future::ready(match r {
                        Ok(ip) => {
                            pretty_print(&ip, silent);
                            Ok(ip)
                        }
                        Err(e) => {
                            // println!("{:?}", e);
                            Err(e)
                        }
                    })
                })
            })
            .collect::<Vec<_>>();
        result.extend(join_all(futures).await);
    }
    result
        .iter()
        .filter(|res| res.is_ok())
        .map(|res: &Result<LookupIp, _>| res.as_ref().unwrap().clone())
        .collect::<Vec<LookupIp>>()
}

fn pretty_print(lookup: &LookupIp, silent: bool) {
    let records = lookup
        .iter()
        .map(|record| record.to_string())
        .collect::<Vec<String>>();
    if !silent {
        println!(
            "{} {} {}",
            style(lookup.query().name().to_string()).green(),
            style(lookup.query().query_type().to_string()).blue().bold(),
            style(records.join(", ")).magenta().bright()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_expand_wildcards() {
        let wildcards = HashSet::from([String::from("*.example.com"), String::from("*.here.com")]);
        let fqdns = HashSet::from([String::from("example.com"), String::from("there.com")]);
        let words = HashSet::from([String::from("a"), String::from("b"), String::from("c")]);
        assert_eq!(
            HashSet::from([
                String::from("a.here.com"),
                String::from("c.example.com"),
                String::from("b.here.com"),
                String::from("a.example.com"),
                String::from("c.here.com"),
                String::from("b.example.com")
            ]),
            expand_wildcards(&wildcards, &fqdns, &words)
                .await
                .expect("Error")
        );
    }
}
