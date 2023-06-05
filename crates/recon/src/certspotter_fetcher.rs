use anyhow::anyhow;
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
) -> anyhow::Result<(Vec<String>, Vec<String>), anyhow::Error> {
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
) -> anyhow::Result<Vec<CertSpotterCertificate>, anyhow::Error>
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
) -> anyhow::Result<Vec<CertSpotterCertificate>, anyhow::Error>
where
    S: AsRef<str> + Display,
{
    let response = client
        .get("https://api.certspotter.com/v1/issuances")
        .query(&[
            ("domain", domain.as_ref()),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
        ])
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await;

    match response {
        Ok(response_content) => {
            if response_content.status().is_success() {
                response_content
                    .json::<Vec<CertSpotterCertificate>>()
                    .await
                    .map_err(anyhow::Error::from)
            } else {
                let code = response_content.status();
                Err(anyhow!(format!(
                    "CertSpotter responded with HTTP code \"{code}\".\n\
                 You may want to try other provider!"
                )))
            }
        }
        Err(err_content) => Err(anyhow!(err_content)),
    }
}
