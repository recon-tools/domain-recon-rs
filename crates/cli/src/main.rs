use std::fmt::Debug;
use std::string::String;

use clap::{arg, Parser};
use console::style;

use recon::{run, InputArgsBuilder};

use crate::writer::{CsvWriter, DomainOnlyStdWriter, IPOnlyStdWriter, PlainStdWriter, Writer};

mod writer;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ReconArgs {
    /// Domain name to be scanned
    #[clap(short, long, value_parser)]
    domain: String,

    /// Optional path to a words file used for expand wildcard domains. If there is no path
    /// provided, there will be no attempt to expand wildcard domains.
    #[clap(short, long, value_parser)]
    file: Option<String>,

    /// Display results in plain form (no banner, no color)
    #[clap(
        short,
        long,
        action,
        default_value = "false",
        conflicts_with = "domains_only",
        conflicts_with = "ips_only"
    )]
    plain: bool,

    /// Display a plain list with domain names only
    #[clap(long, action, default_value = "false", conflicts_with = "ips_only")]
    domains_only: bool,

    /// Display a plain list with unique IP addresses only
    #[clap(long, action, default_value = "false")]
    ips_only: bool,

    /// Save output to csv.
    #[clap(long, action, default_value = "false")]
    csv: bool,

    /// Use default system DNS resolver.
    #[clap(long, action, default_value = "false")]
    use_system_resolver: bool,

    /// Specify a remote DNS resolver. Allowed values are: google, cloudflare, quad9. Default is
    /// google .Can contain multiple values delimited by comma,
    /// ex --dns-resolver="google,cloudflare,quad9"
    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "google"
    )]
    dns_resolver: Vec<String>,

    /// Certificate provider. Allowed values are: certsh, censys, certspotter. Default is certsh.
    /// Can contain multiple values delimited by comma, ex --provider=certsh,censys,certspotter
    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "certsh"
    )]
    provider: Vec<String>,

    /// Optional path to config file. If no path is given, certificate providers such as censys or
    /// certspotter can not be used.
    #[clap(short, long, value_parser)]
    config: Option<String>,

    /// Number of maximum parallel requests when doing DNS resolution.
    #[arg(short, long, default_value_t = 10)]
    number_of_parallel_requests: usize,
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

    let display_rich = !args.plain && !args.ips_only && !args.domains_only;

    if display_rich {
        println!("{}", style(BANNER).cyan().bold());
    }

    let input_args = InputArgsBuilder::new(args.domain)
        .certificate_providers(&args.provider)
        .file(args.file)
        .use_system_resolver(args.use_system_resolver)
        .dns_resolvers(&args.dns_resolver)
        .silent(!display_rich)
        .config(args.config)
        .number_of_parallel_requests(args.number_of_parallel_requests)
        .build();

    let result = run(input_args?).await?;

    let mut writers: Vec<Box<dyn Writer>> = vec![];
    if !display_rich {
        if args.plain {
            writers.push(Box::new(PlainStdWriter {}));
        }

        if args.domains_only {
            writers.push(Box::new(DomainOnlyStdWriter {}));
        }

        if args.ips_only {
            writers.push(Box::new(IPOnlyStdWriter {}));
        }
    }

    if args.csv {
        writers.push(Box::new(CsvWriter::new(String::from("result.csv"))));
    }

    for writer in writers {
        writer.write(&result)?;
    }

    Ok(())
}
