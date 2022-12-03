use std::str::FromStr;
use crate::config_validator::{CensysConfigValidator, CertSpotterConfigValidator, CertSpotterValidator, ConfigValidator, CrtShConfigValidator, CrtShValidator};

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
    CertSpotter,
}

impl FromStr for CertificateProvider {
    type Err = UnknownCertificateProvider;

    fn from_str(input: &str) -> Result<CertificateProvider, Self::Err> {
        match input {
            "certsh" => Ok(CertificateProvider::CertSh),
            "censys" => Ok(CertificateProvider::Censys),
            "certspotter" => Ok(CertificateProvider::CertSpotter),
            _ => return Err(UnknownCertificateProvider::new(input.to_string())),
        }
    }
}

impl CertificateProvider {
    pub(crate) fn config_validator(&self) -> Box<dyn ConfigValidator> {
        match self {
            CertificateProvider::CertSh => Box::new(CrtShConfigValidator {}),
            CertificateProvider::Censys => Box::new(CensysConfigValidator {}),
            CertificateProvider::CertSpotter => Box::new(CertSpotterConfigValidator {})
        }
    }
}
