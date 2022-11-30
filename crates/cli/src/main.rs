use std::fmt::Debug;
use std::string::String;

use clap::Parser;
use console::style;

use recon::{run, InputArgs};

use crate::writer::{CsvWriter, StdWriter, Writer};

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

    /// Display results in plain form. Recommended, if the output is going to be provided as an
    /// input for another application.
    #[clap(short, long, action, default_value="false")]
    plain: bool,

    /// Save output to csv.
    #[clap(long, action, default_value="false")]
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

    /// Certificate provider. Allowed values are: certsh, censys. Default is certsh.
    /// Can contain multiple values delimited by comma, ex --provider=certsh,censys
    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "certsh"
    )]
    provider: Vec<String>,

    /// Path to config file
    #[clap(short, long, value_parser)]
    config: Option<String>,
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
        println!("{}", style(BANNER).cyan().bold());
    }

    let input_args = InputArgs::new(
        args.domain,
        &args.provider,
        args.file,
        args.use_system_resolver,
        &args.dns_resolver,
        args.plain,
        args.config,
    )?;

    let result = run(input_args).await?;

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
