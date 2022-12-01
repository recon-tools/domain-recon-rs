use crate::certificate_provider::{CertificateProvider, UnknownCertificateProvider};
use crate::resolver::{DNSResolver, UnknownDNSResolver};
use anyhow::anyhow;
use std::str::FromStr;

#[derive(Debug)]
pub struct InputArgs {
    pub(crate) domain: String,
    pub(crate) certificate_providers: Vec<CertificateProvider>,
    pub(crate) file: Option<String>,
    pub(crate) use_system_resolver: bool,
    pub(crate) dns_resolvers: Vec<DNSResolver>,
    pub(crate) silent: bool,
    pub(crate) config: Option<String>,
    pub(crate) number_of_parallel_requests: usize,
}

impl InputArgs {
    fn new(
        domain: String,
        certificate_providers: Vec<CertificateProvider>,
        file: Option<String>,
        use_system_resolver: bool,
        dns_resolvers: Vec<DNSResolver>,
        silent: bool,
        config: Option<String>,
        number_of_parallel_requests: usize,
    ) -> anyhow::Result<InputArgs> {
        Ok(InputArgs {
            domain,
            certificate_providers,
            file,
            use_system_resolver,
            dns_resolvers,
            silent,
            config,
            number_of_parallel_requests,
        })
    }
}

#[derive(Debug)]
pub struct InputArgsBuilder {
    pub(crate) domain: String, // required
    pub(crate) certificate_providers: Vec<String>,
    pub(crate) file: Option<String>,
    pub(crate) use_system_resolver: bool,
    pub(crate) dns_resolvers: Vec<String>,
    pub(crate) silent: bool,
    pub(crate) config: Option<String>,
    pub(crate) number_of_parallel_requests: Option<usize>,
}

impl InputArgsBuilder {
    pub fn new(domain: String) -> InputArgsBuilder {
        InputArgsBuilder {
            domain,
            certificate_providers: Vec::new(),
            file: None,
            use_system_resolver: false,
            dns_resolvers: Vec::new(),
            silent: false,
            config: None,
            number_of_parallel_requests: None,
        }
    }

    pub fn certificate_providers(
        mut self,
        certificate_providers: &Vec<String>,
    ) -> InputArgsBuilder {
        self.certificate_providers
            .extend(certificate_providers.to_vec());
        self
    }

    pub fn file(mut self, file: Option<String>) -> InputArgsBuilder {
        self.file = file;
        self
    }

    pub fn use_system_resolver(mut self, use_system_resolver: bool) -> InputArgsBuilder {
        self.use_system_resolver = use_system_resolver;
        self
    }

    pub fn dns_resolvers(mut self, dns_resolvers: &Vec<String>) -> InputArgsBuilder {
        self.dns_resolvers.extend(dns_resolvers.to_vec());
        self
    }

    pub fn silent(mut self, silent: bool) -> InputArgsBuilder {
        self.silent = silent;
        self
    }

    pub fn config(mut self, config: Option<String>) -> InputArgsBuilder {
        self.config = config;
        self
    }

    pub fn number_of_parallel_requests(
        mut self,
        number_of_parallel_requests: usize,
    ) -> InputArgsBuilder {
        self.number_of_parallel_requests = Some(number_of_parallel_requests);
        self
    }

    pub fn build(self) -> anyhow::Result<InputArgs> {
        let certificate_providers: Result<Vec<CertificateProvider>, UnknownCertificateProvider> =
            self.certificate_providers
                .iter()
                .map(|provider| CertificateProvider::from_str(provider))
                .collect();

        let dns_input: Result<Vec<DNSResolver>, UnknownDNSResolver> = if !self.use_system_resolver {
            self.dns_resolvers
                .iter()
                .map(|resolver| DNSResolver::from_str(resolver))
                .collect()
        } else {
            Ok(vec![])
        };
        let n = self.number_of_parallel_requests.unwrap_or_else(|| 20);
        InputArgs::new(
            self.domain,
            certificate_providers.map_err(|e| anyhow!(e))?,
            self.file,
            self.use_system_resolver,
            dns_input.map_err(|e| anyhow!(e))?,
            self.silent,
            self.config,
            n,
        )
    }
}
