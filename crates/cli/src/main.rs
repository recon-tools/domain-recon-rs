use std::fmt::Debug;
use std::str::FromStr;
use std::string::String;

use anyhow::anyhow;
use clap::Parser;

use recon::{run, DNSResolver, UnknownDNSResolver};

use crate::writer::{CsvWriter, StdWriter, Writer};

mod writer;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ReconArgs {
    /// Domain name to be scanned
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

static BANNER: &str = r#"
     _                   _
    | |                 (_)
  _ | | ___  ____   ____ _ ____      ____ ____ ____ ___  ____
 / || |/ _ \|    \ / _  | |  _ \    / ___) _  ) ___) _ \|  _ \
( (_| | |_| | | | ( ( | | | | | |  | |  ( (/ ( (__| |_| | | | |
 \____|\___/|_|_|_|\_||_|_|_| |_|  |_|   \____)____)___/|_| |_|

"#;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: ReconArgs = ReconArgs::parse();

    if !args.plain {
        println!("{}", BANNER);
    }

    let dns_input: Result<Vec<DNSResolver>, UnknownDNSResolver> = if !args.use_system_resolver {
        args.dns_resolver
            .iter()
            .map(|resolver| DNSResolver::from_str(resolver))
            .collect()
    } else {
        Ok(vec![])
    };

    let dns_resolver = dns_input.map_err(|e| anyhow!(e))?;

    let result = run(
        args.domain,
        args.file,
        args.use_system_resolver,
        dns_resolver,
        args.plain,
    )
    .await?;

    let mut writers: Vec<Box<dyn Writer>> = vec![];
    if args.plain {
        writers.push(Box::new(StdWriter {}));
    }

    if args.csv {
        writers.push(Box::new(CsvWriter::new(String::from("result.csv"))));
    }

    for writer in writers {
        writer.write(&result)?;
    }

    Ok(())
}
