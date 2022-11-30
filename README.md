# domain-recon-rs

## Intro

`domain-recon-rs` is a tool which can be used for passive host reconnaissance. It helps extend the attack surface by
fetching all the available active certificates for the host. Using certificate parsing, it extracts
all available domains from "Common Name" and "Matching Identities" fields.
Moreover, in a lot of cases, it may encounter certificates issued for wildcard domains (example: `*.example.com`).
For these domains, it can use a word list to extend these wildcards by filling in words from the list and generate
potential subdomains.

For more information, please read the blogpost: [https://ervinszilagyi.dev/articles/certificate-parsing-with-domain-recon](https://ervinszilagyi.dev/articles/certificate-parsing-with-domain-recon)

### Example of usage:

```bash
domain-recon -d wikipedia.org -f words.txt
```

![Example of usage GIF](images/example.gif)

Currently, certificates are fetched from [crt.sh](https://crt.sh/) and [censys](https://search.censys.io/api). By default,
`domain-recon` will use crt.sh only, censys and certspotter being additional options. In order to use censys or certspotter,
we have to provide a configuration file, that contains our API credentials. `domain-recond` reads this information from 
the `$HOME/domain-recon/config.json` folder. The structure of this file should be as follows:

config.json
```json
{
    "censys": [
        {
            "app-id": "84f2fe92-9c4e...",
            "secret": "bmwjq...."
        }
    ],
    "certspotter": [
        {
            "api-key": "k47370_..."
        }
    ]
}
```

### All the Arguments

```bash
$ domain-recon -h
Extract domains and subdomains from certificates.

Usage: domain-recon.exe [OPTIONS] --domain <DOMAIN>

Options:
  -d, --domain <DOMAIN>
          Domain name to be scanned
  -f, --file <FILE>
          Optional path to a words file used for expand wildcard domains. If there is no path provided, there will be no attempt to expand wildcard domains
  -p, --plain
          Display results in plain form. Recommended, if the output is going to be provided as an input for another application
      --csv
          Save output to csv
      --use-system-resolver
          Use default system DNS resolver
      --dns-resolver <DNS_RESOLVER>
          Specify a remote DNS resolver. Allowed values are: google, cloudflare, quad9. Default is google .Can contain multiple values delimited by comma, ex --dns-resolver="google,cloudflare,quad9" [default: google]
      --provider <PROVIDER>
          Certificate provider. Allowed values are: certsh, censys, certspotter. Default is certsh. Can contain multiple values delimited by comma, ex --provider=certsh,censys,certspotter [default: certsh]
  -c, --config <CONFIG>
          Optional path to config file. If no path is given, certificate providers such as censys or certspotter can not be used
  -n, --number-of-parallel-requests <NUMBER_OF_PARALLEL_REQUESTS>
          Number of maximum parallel requests when doing DNS resolution [default: 10]
  -h, --help
          Print help information
  -V, --version
          Print version information
PS E:\Projects\rust\domain-recon-rs>
```

## Building the Project

This project requires Rust 1.64 or above.

```bash
cd domain-recon-rs
cargo build --release
```
