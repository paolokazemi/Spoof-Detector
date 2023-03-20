# Spoof Detector

![Build](https://github.com/paolokazemi/spoof_detector/actions/workflows/build.yml/badge.svg)

Detect spoofing of IP packets in a PCAP file using heuristics such as variance in TTL values, global reachability of an IP address, and packet data.

### Build
The project can be built using the following command:

```bash
cargo build
```

### Run
To run the analysis, execute the following command passing as parameter the path to the PCAP file:

```bash
cargo run -- -f data/ddos_attack.pcap
```

### Test
Some basic tests are provided and can be run with the following command:

```bash
cargo test
```
