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
            ttl_distribution: vec![0; 256],
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

fn analyze_packet(pkt_data: pcap_parser::data::PacketData, analysis: &mut SpoofAnalysis) -> Result<()> {
    match pkt_data {
        PacketData::L2(eth_data) => {
            let pkt_val = PacketHeaders::from_ethernet_slice(eth_data)?;
            match pkt_val.ip {
                Some(IpHeader::Version4(ip, _)) => {
                    let (ip, ttl) = (IpAddr::from(ip.source), ip.time_to_live);
                    analysis.add_ip(ip, ttl);
                },
                Some(IpHeader::Version6(ip, _)) => {
                    let (ip, ttl) = (IpAddr::from(ip.source), ip.hop_limit);
                    analysis.add_ip(ip, ttl);
                },
                _ => (),
            }
        },
        _ => unreachable!(),
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.file)?;
    let mut reader = create_reader(65536, file)?;

    let mut linktype = Linktype::ETHERNET;  // Legacy PCAP files
    let mut if_linktypes = Vec::new();      // PCAP-NG files
    let mut analysis = SpoofAnalysis::new(args.anon);
    let mut consecutive_errors = 0;

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
                        ).context("Legacy PCAP Error get_packetdata")?;
                        analyze_packet(pkt_data, &mut analysis)?;
                    },
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        if_linktypes = Vec::new();
                    },
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                    },
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];
                        let pkt_data = pcap_parser::data::get_packetdata(
                            epb.data,
                            linktype,
                            epb.caplen as usize
                        ).context("PCAP-NG EnhancedPacket Error get_packetdata")?;
                        analyze_packet(pkt_data, &mut analysis)?;
                    },
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        let pkt_data = pcap_parser::data::get_packetdata(
                            spb.data,
                            linktype,
                            blen
                        ).context("PCAP-NG SimplePacket Error get_packetdata")?;
                        analyze_packet(pkt_data, &mut analysis)?;
                    },
                    PcapBlockOwned::NG(_) => {
                        eprintln!("unsupported block");
                    },
                }
                reader.consume(offset);
                consecutive_errors = 0;
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                // If the last packet is not complete, the reader might get stuck in a loop.
                // In that case, after too many consecutive errors we stop the execution.
                consecutive_errors += 1;
                if consecutive_errors > 1000 {
                    break;
                }
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
        let mut ip = AnalyzedIp::new(IpAddr::from([1, 1, 1, 1]), 50, false);
        ip.add_ttl(51);
        ip.add_ttl(50);
        ip.add_ttl(52);
        assert_eq!(false, ip.check_spoofed());
    }

    #[test]
    fn spoofed_ttl() {
        let mut ip = AnalyzedIp::new(IpAddr::from([1, 1, 1, 1]), 50, false);
        ip.add_ttl(50);
        ip.add_ttl(55);
        assert_eq!(true, ip.check_spoofed());
    }

    #[test]
    fn private_ip() {
        let mut ip = AnalyzedIp::new(IpAddr::from([192, 168, 1, 1]), 50, false);
        assert_eq!(true, ip.check_spoofed());

        let mut ip = AnalyzedIp::new(IpAddr::from([250, 0, 1, 2]), 50, false);
        assert_eq!(true, ip.check_spoofed());

        let mut ip = AnalyzedIp::new(IpAddr::from([169, 254, 169, 254]), 50, false);
        assert_eq!(true, ip.check_spoofed());
    }

    #[test]
    fn private_anon_ip() {
        let mut ip = AnalyzedIp::new(IpAddr::from([192, 168, 1, 1]), 50, true);
        assert_eq!(false, ip.check_spoofed());

        let mut ip = AnalyzedIp::new(IpAddr::from([250, 0, 1, 2]), 50, true);
        assert_eq!(false, ip.check_spoofed());

        let mut ip = AnalyzedIp::new(IpAddr::from([169, 254, 169, 254]), 50, true);
        assert_eq!(false, ip.check_spoofed());
    }
}
