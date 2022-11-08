# domain-recon-rs

## Intro

`domain-recon-rs` is a tool which can be used for reconnaissance. It helps extend the attack surface for in case of a
certain domain. It fetches all the available active certificates for a host and, using certificate parsing, extracts
all available domains from "Common Name" and "Matching Identities" fields.
Moreover, in a lot of cases it may encounter certificates issued for wildcard domains (example: `*.example.com`).
For these domains, it can use a word list to extend these wildcards by filling on words from the list and generate
potential subdomains.

For more information, please read the blogpost: [https://ervinszilagyi.dev/articles/certificate-parsing-with-domain-recon](https://ervinszilagyi.dev/articles/certificate-parsing-with-domain-recon)

### Example of usage:

```bash
domain-recon -d wikipedia.org -f words.txt
```

The output of this will look similar to this:

```bash

     _                   _
    | |                 (_)
  _ | | ___  ____   ____ _ ____      ____ ____ ____ ___  ____
 / || |/ _ \|    \ / _  | |  _ \    / ___) _  ) ___) _ \|  _ \
( (_| | |_| | | | ( ( | | | | | |  | |  ( (/ ( (__| |_| | | | |
 \____|\___/|_|_|_|\_||_|_|_| |_|  |_|   \____)____)___/|_| |_|


[1/3] 🔍  Fetching certificates...

[2/3] 🔗  Extracting valid domains...
wikipedia.org A 91.198.174.192
c.ssl.shopify.com A 23.227.38.74
m.wikipedia.org A 91.198.174.192
zero.wikipedia.org A 91.198.174.192
store.wikipedia.org A 91.198.174.192

[3/3] ✨ Expanding wildcards...
new.m.wikipedia.org A 91.198.174.192
en.wikipedia.org A 91.198.174.192
stats.wikipedia.org A 91.198.174.192
new.wikipedia.org A 91.198.174.192
download.wikipedia.org A 91.198.174.192
my.wikipedia.org A 91.198.174.192
en.m.wikipedia.org A 91.198.174.192
my.m.wikipedia.org A 91.198.174.192
www.wikipedia.org A 91.198.174.192
mail.wikipedia.org A 91.198.174.192
test.wikipedia.org A 91.198.174.192
test.m.wikipedia.org A 91.198.174.192
shop.wikipedia.org A 91.198.174.192
```

## Building the Project

This project requires Rust 1.64 or above.

```bash
cd domain-recon-rs
cargo build --release
```
