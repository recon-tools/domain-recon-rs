use clap::Parser;
use csv::Writer;

use recon::{run, DomainInfo};

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
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: ReconArgs = ReconArgs::parse();

    let result = run(args.domain, args.file, args.use_system_resolver, args.plain).await;

    if args.csv {
        if let Ok(domains) = result {
            write_to_csv(&domains).expect("Error!");
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
