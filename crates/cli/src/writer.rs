use recon::DomainInfo;

pub trait Writer {
    fn write(&self, domains: &Vec<DomainInfo>) -> Result<(), anyhow::Error>;
}

pub struct CsvWriter {
    path: String,
}

impl CsvWriter {
    pub fn new(path: String) -> CsvWriter {
        CsvWriter { path }
    }
}

impl Writer for CsvWriter {
    fn write(&self, domains: &Vec<DomainInfo>) -> Result<(), anyhow::Error> {
        let mut writer = csv::Writer::from_path(&self.path)?;
        for domain in domains {
            writer.write_record(&[
                &domain.name,
                &domain.domain_type,
                &domain.ip_addresses.join(", "),
            ])?;
        }
        writer.flush()?;
        Ok(())
    }
}

pub struct StdWriter {}

impl Writer for StdWriter {
    fn write(&self, domains: &Vec<DomainInfo>) -> Result<(), anyhow::Error> {
        for domain in domains {
            println!("{}", domain.name)
        }
        Ok(())
    }
}
