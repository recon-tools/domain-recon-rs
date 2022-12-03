use serde::Deserialize;
use std::collections::HashSet;
use std::fmt::{Debug, Display};

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

pub(crate) async fn fetch<S>(domain: S) -> Result<(Vec<String>, Vec<String>), reqwest::Error>
where
    S: AsRef<str> + Display,
{
    let certificates = get_certificates(&domain).await?;

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

    let (wildcards, fqdns): (Vec<String>, Vec<String>) = domains
        .into_iter()
        .partition(|domain| domain.starts_with('*'));

    Ok((wildcards, fqdns))
}

async fn get_certificates<S>(domain: S) -> Result<Vec<Certificate>, reqwest::Error>
where
    S: AsRef<str> + Display,
{
    let client = reqwest::Client::new();
    let response = client
        .get("https://crt.sh")
        .query(&[
            ("q", domain.as_ref()),
            ("output", "json"),
            ("excluded", "expired"),
        ])
        .send()
        .await;
    response?.json::<Vec<Certificate>>().await
}
