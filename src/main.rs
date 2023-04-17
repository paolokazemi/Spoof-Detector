#![feature(ip)]

use anyhow::{Result, Context};
use clap::Parser;
use etherparse::*;
use pcap_parser::*;
use pcap_parser::data::PacketData;
use serde_derive::{Serialize, Deserialize};
use std::cmp;
use std::collections::HashMap;
use std::fs::File;
use std::net::*;
use std::path::Path;


/// Parse a PCAP file and detect whether source IP addresses are spoofed.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File path of the PCAP file
    #[arg(short, long)]
    file: String,
    /// Whether the IPs are anonymized or not
    #[arg(short, long)]
    anon: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct AnalyzedIp {
    ip: IpAddr,
    ttl_min: u8,
    ttl_max: u8,
    spoofed: bool,
    anonymized: bool,
}

struct SpoofAnalysis {
    ip_ttls: HashMap<IpAddr, AnalyzedIp>,
    ttl_distribution: Vec<u64>,
    anonymized_ips: bool,
}

#[derive(Serialize, Deserialize)]
struct OutputAnalysis {
    total: usize,
    spoofed: usize,
    ttl_distribution: Vec<u64>,
    ips: Vec<AnalyzedIp>,
}

impl AnalyzedIp {

    fn new(ip: IpAddr, ttl: u8, anonymized: bool) -> AnalyzedIp {
        AnalyzedIp {
            ip,
            ttl_min: ttl,
            ttl_max: ttl,
            spoofed: false,
            anonymized,
        }
    }

    fn add_ttl(&mut self, ttl: u8) {
        self.ttl_min = cmp::min(self.ttl_min, ttl);
        self.ttl_max = cmp::max(self.ttl_max, ttl);
        if !self.spoofed {
            self.check_spoofed();
        }
    }

    fn check_spoofed(&mut self) -> bool {
        self.spoofed = !((self.ip.is_global() || self.anonymized) && (self.ttl_max - self.ttl_min) < 5);
        return self.spoofed;
    }
}

impl SpoofAnalysis {

    fn new(anonymized_ips: bool) -> SpoofAnalysis {
        SpoofAnalysis {
            ip_ttls: HashMap::new(),
            ttl_distribution: vec![0; 255],
            anonymized_ips,
        }
    }

    fn add_ip(&mut self, ip: IpAddr, ttl: u8) {
        let ip = self.ip_ttls
            .entry(ip)
            .or_insert(AnalyzedIp::new(ip, ttl, self.anonymized_ips));
        (*ip).add_ttl(ttl);
        self.ttl_distribution[ttl as usize] += 1;
    }

    fn write_to_file(&self, file_path: &str) -> Result<()> {
        let output_stats = self.output_stats();

        std::fs::create_dir_all("out/")?;
        std::fs::write(
            format!("out/{}.json", file_path),
            serde_json::to_string_pretty(&output_stats)?
        )?;

        Ok(())
    }

    fn output_stats(&self) -> OutputAnalysis {
        let ips = self.ip_ttls.values().map(|x| x.clone()).collect::<Vec<_>>();
        let spoofed = self.ip_ttls
            .values()
            .filter(|x| x.spoofed)
            .count();
        let total = self.ip_ttls.values().count();

        return OutputAnalysis {
            ips,
            total,
            spoofed,
            ttl_distribution: self.ttl_distribution.clone(),
        };
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.file)?;
    let mut reader = create_reader(65536, file)?;

    let mut linktype = Linktype::ETHERNET;
    let mut analysis = SpoofAnalysis::new(args.anon);

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                    },
                    PcapBlockOwned::Legacy(b) => {
                        let pkt_data = pcap_parser::data::get_packetdata(
                            b.data,
                            linktype,
                            b.caplen as usize
                        ).context("Invalid packet")?;
                        match pkt_data {
                            PacketData::L2(eth_data) => {
                                let pkt_val = PacketHeaders::from_ethernet_slice(eth_data)?;
                                let (ip, ttl) = match pkt_val.ip.context("Invalid packet")? {
                                    IpHeader::Version4(ip, _) => (IpAddr::from(ip.source), ip.time_to_live),
                                    IpHeader::Version6(ip, _) => (IpAddr::from(ip.source), ip.hop_limit),
                                };
                                analysis.add_ip(ip, ttl);
                            },
                            _ => unreachable!(),
                        }
                    },
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("Error reading file: {:?}", e),
        }
    }

    let output_filename = Path::new(&args.file)
        .file_stem()
        .context("Invalid file name")?
        .to_str()
        .context("Invalid file name")?;
    analysis.write_to_file(output_filename)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::AnalyzedIp;
    use std::net::IpAddr;

    #[test]
    fn normal_ttl() {
        let mut ip = AnalyzedIp::new(IpAddr::from([1, 1, 1, 1]), 50);
        ip.add_ttl(51);
        ip.add_ttl(50);
        ip.add_ttl(52);
        assert_eq!(false, ip.check_spoofed());
    }

    #[test]
    fn spoofed_ttl() {
        let mut ip = AnalyzedIp::new(IpAddr::from([1, 1, 1, 1]), 50);
        ip.add_ttl(50);
        ip.add_ttl(55);
        assert_eq!(true, ip.check_spoofed());
    }

    #[test]
    fn private_ip() {
        let mut ip = AnalyzedIp::new(IpAddr::from([192, 168, 1, 1]), 50);
        assert_eq!(true, ip.check_spoofed());

        let mut ip = AnalyzedIp::new(IpAddr::from([250, 0, 1, 2]), 50);
        assert_eq!(true, ip.check_spoofed());

        let mut ip = AnalyzedIp::new(IpAddr::from([169, 254, 169, 254]), 50);
        assert_eq!(true, ip.check_spoofed());
    }
}
