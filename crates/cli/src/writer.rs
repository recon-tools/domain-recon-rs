use recon::DomainInfo;
use std::collections::HashSet;

pub trait Writer {
    fn write(&self, domains: &Vec<DomainInfo>) -> anyhow::Result<(), anyhow::Error>;
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
    fn write(&self, domains: &Vec<DomainInfo>) -> anyhow::Result<(), anyhow::Error> {
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

pub struct PlainStdWriter {}

impl Writer for PlainStdWriter {
    fn write(&self, domains: &Vec<DomainInfo>) -> anyhow::Result<(), anyhow::Error> {
        for domain in domains {
            println!(
                "{} {} {}",
                domain.name,
                domain.domain_type,
                domain.ip_addresses.join(",")
            )
        }
        Ok(())
    }
}

pub struct DomainOnlyStdWriter {}

impl Writer for DomainOnlyStdWriter {
    fn write(&self, domains: &Vec<DomainInfo>) -> anyhow::Result<(), anyhow::Error> {
        for domain in domains {
            println!("{}", domain.name)
        }
        Ok(())
    }
}

pub struct IPOnlyStdWriter {}

impl Writer for IPOnlyStdWriter {
    fn write(&self, domains: &Vec<DomainInfo>) -> anyhow::Result<(), anyhow::Error> {
        let uniq_ips: HashSet<String> = HashSet::from_iter(
            domains
                .into_iter()
                .flat_map(|domain_info| domain_info.ip_addresses.clone()),
        );
        for ip in uniq_ips {
            println!("{}", ip)
        }
        Ok(())
    }
}
