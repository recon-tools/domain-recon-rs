use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CensysConfig {
    #[serde(rename = "app-id")]
    pub(crate) app_id: String,
    pub(crate) secret: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone)]
struct Request {
    query: String,
    page: i32,
    flatten: bool,
    fields: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct MetaData {
    query: String,
    count: i32,
    backend_time: i32,
    page: i32,
    pages: i32,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ParsedResult {
    #[serde(rename = "parsed.extensions.subject_alt_name.dns_names")]
    dns_names: Option<Vec<String>>,
    #[serde(rename = "parsed.names")]
    names: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CensysResponse {
    status: String,
    metadata: MetaData,
    results: Vec<ParsedResult>,
}

const MAX_PARALLEL_REQUESTS: usize = 10;

pub(crate) async fn fetch(
    domain: String,
    config: Vec<CensysConfig>,
) -> Result<(Vec<String>, Vec<String>), reqwest::Error> {
    let CensysConfig { app_id, secret } = &config[0];

    let responses = fetch_certificates(&domain, app_id, secret).await?;

    let all_domains = responses
        .into_iter()
        .filter(|response| response.status == "ok")
        .flat_map(|response| response.results)
        .flat_map(|parsed_result| {
            let mut domains = HashSet::<String>::new();
            domains.extend(match parsed_result.names {
                Some(ref names) => names.to_vec(),
                None => vec![],
            });
            domains.extend(match parsed_result.dns_names {
                Some(ref names) => names.to_vec(),
                None => vec![],
            });
            domains
        })
        .collect::<HashSet<String>>();

    let (wildcards, fqdns): (Vec<String>, Vec<String>) = all_domains
        .into_iter()
        .partition(|domain| domain.starts_with('*'));

    Ok((wildcards, fqdns))
}

async fn fetch_certificates(
    domain: &str,
    api_id: &String,
    secret: &String,
) -> Result<Vec<CensysResponse>, reqwest::Error> {
    let client = reqwest::Client::new();

    let create_request = |page: i32| Request {
        query: format!("validation.nss.valid: true and parsed.names: {}", domain),
        page: page as i32,
        flatten: true,
        fields: vec![
            String::from("parsed.names"),
            String::from("parsed.extensions.subject_alt_name.dns_names"),
        ],
    };

    let first_response = send_request(&client, create_request(1), api_id, secret).await?;

    let future_responses = (2..first_response.metadata.pages)
        .map(|i| send_request(&client, create_request(i), api_id, secret))
        .collect::<Vec<_>>();

    let stream = futures::stream::iter(future_responses).buffer_unordered(MAX_PARALLEL_REQUESTS);
    let results = stream
        .collect::<Vec<Result<CensysResponse, reqwest::Error>>>()
        .await;

    let mut responses = vec![first_response];
    responses.extend(
        results
            .into_iter()
            .filter(|response| response.is_ok())
            .map(|response| response.unwrap()),
    );

    Ok(responses)
}

async fn send_request(
    client: &reqwest::Client,
    request: Request,
    api_id: &String,
    secret: &String,
) -> anyhow::Result<CensysResponse, reqwest::Error> {
    client
        .post("https://search.censys.io/api/v1/search/certificates")
        .json(&request)
        .basic_auth(api_id, Some(secret))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send()
        .await?
        .json::<CensysResponse>()
        .await
}
