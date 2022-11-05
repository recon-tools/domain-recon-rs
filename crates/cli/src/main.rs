use clap::Parser;
use csv::Writer;
use std::fmt::Debug;
use std::str::FromStr;

use crate::resolver::DNSResolver;
use recon::{run, DNSResolver, DomainInfo};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ReconArgs {
    /// Domain to be reconned
    #[clap(short, long, value_parser)]
    domain: String,

    /// Words file for extending wildcard domains
    #[clap(short, long, value_parser, default_value = "")]
    file: String,

    /// Display results in plain form
    #[clap(short, long, action)]
    plain: bool,

    /// Save output to csv
    #[clap(long, action)]
    csv: bool,

    /// Use default system resolver
    #[clap(long, action, default_value = "false")]
    use_system_resolver: bool,

    /// Specify DNS resolver. Allowed values are: google, cloudflare, quad9. Default is google
    /// Can contain multiple values delimited by comma, ex --dns-resolver="google,cloudflare,quad9"
    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "google"
    )]
    dns_resolver: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: ReconArgs = ReconArgs::parse();

    let dns_input: Result<Vec<DNSResolver>, _> = if !args.use_system_resolver {
        args.dns_resolver
            .iter()
            .map(|resolver| DNSResolver::from_str(resolver))
            .collect()
    } else {
        Ok(vec![])
    };

    let dns_resolver = match dns_input {
        Ok(r) => r,
        Err(e) => {
            panic!("{}", e)
        }
    };

    match run(
        args.domain,
        args.file,
        args.use_system_resolver,
        dns_resolver,
        args.plain,
    )
    .await
    {
        Ok(domains) => {
            if args.csv {
                write_to_csv(&domains).unwrap();
            }
        }
        Err(e) => {
            println!("Runtime Error: {}", e)
        }
    }
    Ok(())
}

fn write_to_csv(domains: &Vec<DomainInfo>) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = Writer::from_path("result.csv")?;
    for domain in domains {
        writer.write_record(&[
            &domain.name,
            &domain.domain_type,
            &domain.ip_addresses.join(", "),
        ])?;
    }
    writer.flush()?;
    Ok(())
}
