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
}

#[derive(Serialize, Deserialize)]
struct AnalyzedIp {
    ip: IpAddr,
    ttl_min: u8,
    ttl_max: u8,
    spoofed: bool,
}

struct SpoofAnalysis {
    ip_ttls: HashMap<IpAddr, AnalyzedIp>,
}

impl AnalyzedIp {

    fn new(ip: IpAddr, ttl: u8) -> AnalyzedIp {
        AnalyzedIp {
            ip,
            ttl_min: ttl,
            ttl_max: ttl,
            spoofed: false,
        }
    }

    fn add_ttl(&mut self, ttl: u8) {
        self.ttl_min = cmp::min(self.ttl_min, ttl);
        self.ttl_max = cmp::max(self.ttl_max, ttl);
        self.spoofed = (self.ttl_max - self.ttl_min) > 3;
    }
}

impl SpoofAnalysis {

    fn new() -> SpoofAnalysis {
        SpoofAnalysis { ip_ttls: HashMap::new() }
    }

    fn add_ip(&mut self, ip: IpAddr, ttl: u8) {
        let ip = self.ip_ttls
            .entry(ip)
            .or_insert(AnalyzedIp::new(ip, ttl));
        (*ip).add_ttl(ttl);
    }

    fn write_to_file(&self, file_path: &str) -> Result<()> {
        let ip_vals = &self.ip_ttls.values().collect::<Vec<_>>();

        std::fs::create_dir_all("out/")?;
        std::fs::write(
            format!("out/{}.json", file_path),
            serde_json::to_string_pretty(ip_vals)?
        )?;

        Ok(())
    }

    fn output_stats(&self) {
        let spoofed = self.ip_ttls
            .values()
            .filter(|x| x.spoofed)
            .count();
        let total = self.ip_ttls.values().count();
        println!(
            "Total IPs: {}\nSpoofed IPs: {}\nNon-spoofed IPs: {}",
            total,
            spoofed,
            total - spoofed
        );
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.file)?;
    let mut reader = create_reader(65536, file)?;

    let mut linktype = Linktype::ETHERNET;
    let mut analysis = SpoofAnalysis::new();

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
                                match pkt_val.ip.context("Invalid packet")? {
                                    IpHeader::Version4(ip, _) => {
                                        analysis.add_ip(
                                            IpAddr::from(ip.source),
                                            ip.time_to_live,
                                        );
                                    },
                                    IpHeader::Version6(ip, _) => {
                                        analysis.add_ip(
                                            IpAddr::from(ip.source),
                                            ip.hop_limit,
                                        );
                                    }
                                }
                            },
                            _ => (),
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
    analysis.output_stats();

    Ok(())
}
