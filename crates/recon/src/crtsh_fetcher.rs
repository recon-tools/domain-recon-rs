use anyhow::anyhow;
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

pub(crate) async fn fetch<S>(domain: S) -> anyhow::Result<(Vec<String>, Vec<String>), anyhow::Error>
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

async fn get_certificates<S>(domain: S) -> anyhow::Result<Vec<Certificate>, anyhow::Error>
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
    match response {
        Ok(response_content) => {
            if response_content.status().is_success() {
                response_content
                    .json::<Vec<Certificate>>()
                    .await
                    .map_err(anyhow::Error::from)
            } else {
                let code = response_content.status();
                Err(anyhow!(format!(
                    "crt.sh responded with error code {code}. You may want to try other provider!"
                )))
            }
        }
        Err(err_content) => Err(anyhow!(err_content)),
    }
}
