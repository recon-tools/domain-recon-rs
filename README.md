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

![Example of usage GIF](images/example.gif)

## Building the Project

This project requires Rust 1.64 or above.

```bash
cd domain-recon-rs
cargo build --release
```
