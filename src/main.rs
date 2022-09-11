use std::collections::HashSet;
use std::path::Path;

use async_std_resolver::{AsyncStdResolver, config, ResolveError, resolver};
use async_std_resolver::lookup_ip::LookupIp;
use clap::Parser;
use exitfailure::ExitFailure;
use futures::future::join_all;
use reqwest::Error;
use serde::Deserialize;
use tokio::fs::File;
use tokio::io::{self, AsyncBufReadExt, BufReader};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ReconArgs {
    /// Domain to be reconned
    #[clap(short, long, value_parser)]
    domain: String,

    /// Words file for extending wildcard domains
    #[clap(short, long, value_parser, default_value = "")]
    file: String
}

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

#[tokio::main]
async fn main() -> Result<(), ExitFailure> {
    let args: ReconArgs = ReconArgs::parse();

    let certificates = fetch_certificates(&args.domain).await.unwrap();

    let mut domains: HashSet<String> = HashSet::new();
    for certificate in certificates {
        domains.extend(certificate.name_value.split("\n")
            .map(|s| s.to_string())
            .collect::<HashSet<String>>());
        domains.insert(certificate.common_name);
    }

    let wildcards = domains.iter()
        .filter(|domain| domain.starts_with("*"))
        .collect::<HashSet<&String>>();

    let resolver = resolver(
        config::ResolverConfig::default(),
        config::ResolverOpts::default(),
    ).await.expect("Failed to connect resolver!");

    pretty_print(&get_resolvable_domains(&domains, &resolver).await);

    if !args.file.trim().is_empty() {
        let words_path = Path::new(&args.file);
        println!("\nExtended domains:");
        match extend_wildcards(&words_path, &wildcards).await {
            Ok(domains) => {
                pretty_print(&get_resolvable_domains(&domains, &resolver).await);
            }
            Err(e) => println!("Error: {}", e)
        }
    }

    Ok(())
}

async fn fetch_certificates(domain: &str) -> Result<Vec<Certificate>, Error> {
    let client = reqwest::Client::new();
    let response = client.get("https://crt.sh")
        .query(&[("q", domain), ("output", "json"), ("excluded", "expired")])
        .send().await;
    match response {
        Ok(r) => Ok(r.json::<Vec<Certificate>>().await?),
        Err(r) => Err(r)
    }
}

async fn extend_wildcards(words_path: &Path, wildcards: &HashSet<&String>) -> Result<HashSet<String>, io::Error> {
    let mut potential_domains: HashSet<String> = HashSet::new();
    let mut lines = BufReader::new(File::open(words_path).await?).lines();
    while let Some(line) = lines.next_line().await? {
        let word = line.trim();
        potential_domains.extend(wildcards.iter()
            .map(|domain| domain.replace("*", word))
            .collect::<HashSet<String>>());
    }
    return Ok(potential_domains);
}

async fn get_resolvable_domains(domains: &HashSet<String>, resolver: &AsyncStdResolver) -> Vec<LookupIp> {
    let futures = domains.iter().map(|domain| {
        resolver.lookup_ip(domain)
    }).collect::<Vec<_>>();
    let result: Vec<Result<LookupIp, ResolveError>> = join_all(futures).await;
    result.iter()
        .filter(|res| res.is_ok())
        .map(|res: &Result<LookupIp, _>| res.as_ref().unwrap().clone())
        .collect::<Vec<LookupIp>>()
}

fn pretty_print(domains: &Vec<LookupIp>) {
    for lookup in domains {
        let records = lookup.iter().map(|record| record.to_string()).collect::<Vec<String>>();
        println!("{} {} {}", lookup.query().name(), lookup.query().query_type(), records.join(", "));
    }
}


