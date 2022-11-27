use std::str::FromStr;

#[derive(Debug)]
#[allow(dead_code, unused_variables)]
pub(crate) struct UnknownCertificateProvider {
    pub(crate) provider: String,
}

impl UnknownCertificateProvider {
    fn new(provider: String) -> UnknownCertificateProvider {
        UnknownCertificateProvider { provider }
    }
}

impl std::fmt::Display for UnknownCertificateProvider {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "Unknown Certificate provider!")
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum CertificateProvider {
    CertSh,
    Censys,
}

impl FromStr for CertificateProvider {
    type Err = UnknownCertificateProvider;

    fn from_str(input: &str) -> Result<CertificateProvider, Self::Err> {
        match input {
            "certsh" => Ok(CertificateProvider::CertSh),
            "censys" => Ok(CertificateProvider::Censys),
            _ => return Err(UnknownCertificateProvider::new(input.to_string())),
        }
    }
}
