use std::collections::HashSet;
use std::future;
use std::path::Path;

use async_std_resolver::lookup_ip::LookupIp;
use async_std_resolver::{config, resolver, AsyncStdResolver, ResolveError};
use csv::Writer;
use futures::future::join_all;
use futures::FutureExt;
use serde::Deserialize;
use tokio::fs::File;
use tokio::io::{self, AsyncBufReadExt, BufReader};

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

pub async fn run(domain: String, file: String, plain: bool, csv: bool) -> Result<(), ()> {
    let certificates = fetch_certificates(&domain).await.unwrap();

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

    let wildcards = domains
        .iter()
        .filter(|domain| domain.starts_with('*'))
        .collect::<HashSet<&String>>();

    let resolver = resolver(
        config::ResolverConfig::default(),
        config::ResolverOpts::default(),
    )
        .await
        .expect("Failed to connect resolver!");

    let mut resolvable = get_resolvable_domains(&domains, &resolver, plain).await;

    if !file.trim().is_empty() {
        let words_path = Path::new(&file);
        if !plain {
            println!("\nExtended domains:");
        }
        match extend_wildcards(words_path, &wildcards).await {
            Ok(domains) => {
                resolvable.extend(get_resolvable_domains(&domains, &resolver, plain).await);
            }
            Err(e) => println!("Error: {}", e),
        }
    }

    if csv {
        write_to_csv(resolvable).expect("Error: could not output write to CSV file!");
    }

    Ok(())
}

async fn fetch_certificates(domain: &str) -> Result<Vec<Certificate>, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://crt.sh")
        .query(&[("q", domain), ("output", "json"), ("excluded", "expired")])
        .send()
        .await;
    response.unwrap().json::<Vec<Certificate>>().await
}

async fn extend_wildcards(
    words_path: &Path,
    wildcards: &HashSet<&String>,
) -> Result<HashSet<String>, io::Error> {
    let mut potential_domains: HashSet<String> = HashSet::new();
    let mut lines = BufReader::new(File::open(words_path).await?).lines();
    while let Some(line) = lines.next_line().await? {
        let word = line.trim();
        potential_domains.extend(
            wildcards
                .iter()
                .map(|domain| domain.replace('*', word))
                .collect::<HashSet<String>>(),
        );
    }
    Ok(potential_domains)
}

async fn get_resolvable_domains(
    domains: &HashSet<String>,
    resolver: &AsyncStdResolver,
    plain: bool,
) -> Vec<LookupIp> {
    let futures = domains
        .iter()
        .map(|domain| {
            resolver.lookup_ip(domain).then(|r| {
                // Display results as soon as they appear
                future::ready(match r {
                    Ok(ip) => {
                        pretty_print(&ip, plain);
                        Ok(ip)
                    }
                    Err(e) => Err(e),
                })
            })
        })
        .collect::<Vec<_>>();
    let result: Vec<Result<LookupIp, ResolveError>> = join_all(futures).await;
    result
        .iter()
        .filter(|res| res.is_ok())
        .map(|res: &Result<LookupIp, _>| res.as_ref().unwrap().clone())
        .collect::<Vec<LookupIp>>()
}

fn pretty_print(lookup: &LookupIp, plain: bool) {
    let records = lookup
        .iter()
        .map(|record| record.to_string())
        .collect::<Vec<String>>();
    if plain {
        for record in &records {
            println!("{}", record);
        }
    }
    println!(
        "{} {} {}",
        lookup.query().name(),
        lookup.query().query_type(),
        records.join(", ")
    );
}

fn write_to_csv(domains: Vec<LookupIp>) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = Writer::from_path("result.csv")?;
    for lookup in domains {
        let records = lookup
            .iter()
            .map(|record| record.to_string())
            .collect::<Vec<String>>();
        writer.write_record(&[
            lookup.query().name().to_string(),
            lookup.query().query_type().to_string(),
            records.join(", "),
        ])?;
    }
    writer.flush()?;
    Ok(())
}
