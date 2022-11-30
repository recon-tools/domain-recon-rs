use std::collections::HashSet;
use std::fmt::Debug;
use std::future;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;

use crate::censys_fetcher::CensysConfig;
use addr::parse_domain_name;
use anyhow::anyhow;
use async_std_resolver::lookup_ip::LookupIp;
use async_std_resolver::{
    config, resolver, resolver_from_system_conf, AsyncStdResolver, ResolveError,
};
use console::{style, Emoji};
use futures::future::join_all;
use futures::FutureExt;
use itertools::Itertools;
use reqwest::Error;
use tokio::fs::{read_to_string, File};
use tokio::io::{self, AsyncBufReadExt, BufReader};

use crate::certificate_provider::{CertificateProvider, UnknownCertificateProvider};
use crate::certspotter_fetcher::CertSpotterConfig;
use crate::resolver::{DNSResolver, UnknownDNSResolver};
use serde::{Deserialize, Serialize};

mod censys_fetcher;
mod certificate_provider;
mod certspotter_fetcher;
mod crtsh_fetcher;
mod resolver;

#[derive(Debug)]
pub struct InputArgs {
    domain: String,
    certificate_providers: Vec<CertificateProvider>,
    file: Option<String>,
    use_system_resolver: bool,
    dns_resolvers: Vec<DNSResolver>,
    silent: bool,
    config: Option<String>,
}

impl InputArgs {
    pub fn new(
        domain: String,
        certificate_providers_str: &Vec<String>,
        file: Option<String>,
        use_system_resolver: bool,
        dns_resolvers_str: &Vec<String>,
        silent: bool,
        config: Option<String>,
    ) -> anyhow::Result<InputArgs> {
        let certificate_providers_input: Result<
            Vec<CertificateProvider>,
            UnknownCertificateProvider,
        > = certificate_providers_str
            .iter()
            .map(|provider| CertificateProvider::from_str(provider))
            .collect();

        let dns_input: Result<Vec<DNSResolver>, UnknownDNSResolver> = if !use_system_resolver {
            dns_resolvers_str
                .iter()
                .map(|resolver| DNSResolver::from_str(resolver))
                .collect()
        } else {
            Ok(vec![])
        };

        Ok(InputArgs {
            domain,
            certificate_providers: certificate_providers_input.map_err(|e| anyhow!(e))?,
            file,
            use_system_resolver,
            dns_resolvers: dns_input.map_err(|e| anyhow!(e))?,
            silent,
            config,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DomainReconConfig {
    censys: Option<Vec<CensysConfig>>,
    certspotter: Option<Vec<CertSpotterConfig>>,
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

pub async fn run(input_args: InputArgs) -> anyhow::Result<Vec<DomainInfo>> {
    let steps = if input_args.file.is_none() { 2 } else { 3 };

    if !input_args.silent {
        println!(
            "{} {}{}",
            style(format!("[1/{}]", steps)).bold().dim(),
            LOOKING_GLASS,
            style("Fetching certificates...").bold()
        );
    }

    if !input_args.silent {
        println!(
            "\n{} {}{}",
            style(format!("[2/{}]", steps)).bold().dim(),
            CLIP,
            style("Extracting valid domains...").bold()
        );
    }

    let default_home_path = match home::home_dir() {
        Some(path) => path.join("domain-recon").join("config.json"),
        None => Path::new(".").to_path_buf(),
    };

    let config_path = input_args.config.map_or(default_home_path, |path_str| {
        Path::new(&path_str).to_path_buf()
    });

    let config = match read_config(config_path).await {
        Ok(c) => Some(c),
        Err(e) => {
            if input_args
                .certificate_providers
                .contains(&CertificateProvider::Censys)
            {
                println!("Warning: Config file could not be read: {:}", e.to_string());
            }
            None
        }
    };

    let (wildcards, fqdns) =
        fetch_certificates(&input_args.certificate_providers, input_args.domain, config).await?;
    let resolver =
        build_resolver(input_args.use_system_resolver, &input_args.dns_resolvers).await?;
    let mut resolvable = get_resolvable_domains(&fqdns, &resolver, input_args.silent).await;

    // If there is an input file for words, use it for extending domains, otherwise move forward
    if let Some(words_file_str) = input_args.file {
        let words_path = Path::new(&words_file_str);
        if !input_args.silent {
            println!(
                "\n{} {}{}",
                style(format!("[3/{}]", steps)).bold().dim(),
                SPARKLE,
                style("Expanding wildcards...").bold()
            );
        }

        let words = read_words(words_path).await?;
        if let Ok(domains) = expand_wildcards(&wildcards, &fqdns, &words).await {
            resolvable.extend(get_resolvable_domains(&domains, &resolver, input_args.silent).await);
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

async fn read_config<P: AsRef<Path>>(path: P) -> Result<DomainReconConfig, io::Error> {
    let contents = read_to_string(path).await?;
    let config = serde_json::from_str::<DomainReconConfig>(&*contents)?;
    Ok(config)
}

async fn fetch_certificates(
    certificate_providers: &Vec<CertificateProvider>,
    domain: String,
    config: Option<DomainReconConfig>,
) -> Result<(HashSet<String>, HashSet<String>), Error> {
    type PinFutureObj<Output> = Pin<Box<dyn Future<Output = Output>>>;

    let mut wildcards = HashSet::new();
    let mut fqdns = HashSet::new();

    let mut futures: Vec<PinFutureObj<Result<(Vec<String>, Vec<String>), Error>>> = Vec::new();

    if certificate_providers.contains(&CertificateProvider::CertSh) {
        futures.push(Box::pin(crtsh_fetcher::fetch(domain.clone())));
    }

    match config {
        None => {}
        Some(config) => {
            if certificate_providers.contains(&CertificateProvider::Censys) {
                match config.censys {
                    None => {
                        println!("Warning! No censys credentials found!")
                    }
                    Some(censys) => {
                        futures.push(Box::pin(censys_fetcher::fetch(domain.clone(), censys)));
                    }
                }
            }

            if certificate_providers.contains(&CertificateProvider::CertSpotter) {
                match config.certspotter {
                    None => {
                        println!("Warning! No censys credentials found!")
                    }
                    Some(certspotter) => {
                        futures.push(Box::pin(certspotter_fetcher::fetch(
                            domain.clone(),
                            certspotter,
                        )));
                    }
                }
            }

            let results = join_all(futures).await;

            for result in results {
                match result {
                    Ok((w, f)) => {
                        wildcards.extend(w);
                        fqdns.extend(f);
                    }
                    Err(e) => {
                        println!("Could not fetch for {}", e);
                    }
                };
            }
        }
    }

    Ok((wildcards, fqdns))
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

async fn read_words<P: AsRef<Path>>(words_path: P) -> Result<HashSet<String>, io::Error> {
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
