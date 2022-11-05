use std::str::FromStr;

#[derive(Debug)]
pub struct UnknownDNSResolver {
    pub resolver_name: String,
}

impl UnknownDNSResolver {
    fn new(resolver_name: String) -> UnknownDNSResolver {
        UnknownDNSResolver { resolver_name }
    }
}

impl std::fmt::Display for UnknownDNSResolver {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "Unknown DNS resolver!")
    }
}

#[derive(Debug)]
pub enum DNSResolver {
    Google,
    CloudFlare,
    Quad9,
}

impl FromStr for DNSResolver {
    type Err = UnknownDNSResolver;

    fn from_str(input: &str) -> Result<DNSResolver, Self::Err> {
        match input {
            "google" => Ok(DNSResolver::Google),
            "cloudflare" => Ok(DNSResolver::CloudFlare),
            "quad9" => Ok(DNSResolver::Quad9),
            _ => return Err(UnknownDNSResolver::new(input.to_string())),
        }
    }
}
