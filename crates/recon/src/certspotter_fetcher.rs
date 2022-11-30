use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CertSpotterConfig {
    #[serde(rename = "api-key")]
    api_key: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CertSpotterCertificate {
    id: String,
    tbs_sha256: String,
    dns_names: Vec<String>,
    pubkey_sha256: String,
    not_before: String,
    not_after: String,
    revoked: bool
}

pub(crate) async fn fetch(
    domain: String,
    config: Vec<CertSpotterConfig>,
) -> Result<(Vec<String>, Vec<String>), reqwest::Error> {
    let response = fetch_certificates(&domain, &config[0].api_key).await?;

    let all_domains = response
        .into_iter()
        .flat_map(|response| response.dns_names)
        .collect::<HashSet<String>>();

    let (wildcards, fqdns): (Vec<String>, Vec<String>) = all_domains
        .into_iter()
        .partition(|domain| domain.starts_with('*'));

    Ok((wildcards, fqdns))
}

async fn fetch_certificates(
    domain: &String,
    api_key: &String,
) -> Result<Vec<CertSpotterCertificate>, reqwest::Error> {
    let client = reqwest::Client::new();
    Ok(send_request(&client, domain,api_key).await?)
}

async fn send_request(
    client: &reqwest::Client,
    domain: &String,
    api_token: &String,
) -> Result<Vec<CertSpotterCertificate>, reqwest::Error> {
    client
        .get("https://api.certspotter.com/v1/issuances")
        .query(&[("domain", domain.as_str()), ("include_subdomains", "true"), ("expand", "dns_names")])
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await?
        .json::<Vec<CertSpotterCertificate>>()
        .await
}
