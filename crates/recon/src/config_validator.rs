use crate::DomainReconConfig;
use anyhow::{anyhow, Error};

pub(crate) trait ConfigValidator {
    fn validate(&self, config: &DomainReconConfig) -> Result<(), Error>;
}

pub(crate) struct CensysConfigValidator {}

impl ConfigValidator for CensysConfigValidator {
    fn validate(&self, config: &DomainReconConfig) -> Result<(), Error> {
        match &config.censys {
            None => {
                return Err(anyhow!(
                    "Censys requires secrets in the configuration file!"
                ));
            }
            Some(secrets) => {
                if secrets.is_empty() {
                    return Err(anyhow!("Empty array provided for Censys secrets!"));
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct CertSpotterConfigValidator {}

impl ConfigValidator for CertSpotterConfigValidator {
    fn validate(&self, config: &DomainReconConfig) -> Result<(), Error> {
        match &config.certspotter {
            None => {
                return Err(anyhow!(
                    "CertSpotter requires secrets in the configuration file!"
                ));
            }
            Some(secrets) => {
                if secrets.is_empty() {
                    return Err(anyhow!("Empty array provided for CertSpotter secrets!"));
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct CrtShConfigValidator {}

impl ConfigValidator for CrtShConfigValidator {
    fn validate(&self, _: &DomainReconConfig) -> Result<(), Error> {
        // No config required for CrtSh
        Ok(())
    }
}
