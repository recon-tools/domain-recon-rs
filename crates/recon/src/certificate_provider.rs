use std::str::FromStr;

#[derive(Debug)]
pub struct UnknownCertificateProvider {
    pub provider: String,
}

impl UnknownCertificateProvider {
    fn new(provider: String) -> UnknownCertificateProvider {
        UnknownCertificateProvider { provider }
    }
}

#[derive(Debug, PartialEq)]
pub enum CertificateProvider {
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
