use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::{Debug, Display};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CertSpotterConfig {
    #[serde(rename = "api-key")]
    pub(crate) api_key: String,
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
    revoked: bool,
}

pub(crate) async fn fetch(
    domain: String,
    config: Vec<CertSpotterConfig>,
) -> Result<(Vec<String>, Vec<String>), reqwest::Error> {
    let response = get_certificates(&domain, &config[0].api_key).await?;

    let all_domains = response
        .into_iter()
        .flat_map(|response| response.dns_names)
        .collect::<HashSet<String>>();

    let (wildcards, fqdns): (Vec<String>, Vec<String>) = all_domains
        .into_iter()
        .partition(|domain| domain.starts_with('*'));

    Ok((wildcards, fqdns))
}

async fn get_certificates<S>(
    domain: S,
    api_key: S,
) -> Result<Vec<CertSpotterCertificate>, reqwest::Error>
where
    S: AsRef<str> + Display,
{
    let client = reqwest::Client::new();
    Ok(send_request(&client, domain, api_key).await?)
}

async fn send_request<S>(
    client: &reqwest::Client,
    domain: S,
    api_token: S,
) -> Result<Vec<CertSpotterCertificate>, reqwest::Error>
where
    S: AsRef<str> + Display,
{
    client
        .get("https://api.certspotter.com/v1/issuances")
        .query(&[
            ("domain", domain.as_ref()),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
        ])
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await?
        .json::<Vec<CertSpotterCertificate>>()
        .await
}
