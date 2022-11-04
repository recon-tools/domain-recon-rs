use clap::Parser;

use recon::run;

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
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: ReconArgs = ReconArgs::parse();

    run(args.domain, args.file, args.plain, args.csv).await
}
