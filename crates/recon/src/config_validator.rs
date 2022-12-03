use anyhow::Error;

pub(crate) trait ConfigValidator {
    fn validate() -> Result<(), Error>;
}

pub(crate) struct CensysConfigValidator {
}

impl ConfigValidator for CensysConfigValidator {
    fn validate() -> Result<(), Error> {
        todo!()
    }
}

pub(crate) struct CertSpotterConfigValidator {
}

impl ConfigValidator for CertSpotterConfigValidator {
    fn validate() -> Result<(), Error> {
        todo!()
    }
}

pub(crate) struct CrtShConfigValidator {
}

impl ConfigValidator for CrtShConfigValidator {
    fn validate() -> Result<(), Error> {
        todo!()
    }
}
