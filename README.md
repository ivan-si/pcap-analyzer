# PCAP Anomalous Traffic Analyzer

This repository provides a Python-based tool to analyze PCAP files or live network traffic to identify anomalies, suspicious connections, and signs of potential data exfiltration. It uses **Scapy** for packet manipulation and optionally integrates with **Azure services** for logging and blacklist management.

A utility script `traffic_generator.py` is included to create test PCAPs with various traffic scenarios.

---

## Features

### PCAP Analyzer (`pcap_analyzer.py`)

#### Dual Mode Operation:
- **File Mode**: Analyze existing PCAP files.
- **Live Mode**: Capture and analyze real-time network traffic from a specified interface.

#### Anomaly Detection:
- **Malicious IP/Domain Connections**:
  - Checks against a blacklist (default: `malicious_ips.txt`)
  - Optional Azure Table sync for centralized blacklist updates

- **Unusual Port Usage**:
  - Flags traffic on non-standard ports (default threshold: ports > 1024)

- **Long-Lived Connections**:
  - Detects flows active longer than a set duration (default: 3600s)

#### HTTP Protocol Checks:
- Flags HTTP on non-standard ports
- Flags non-HTTP TCP on standard HTTP ports (e.g., port 80)

#### Azure Integration (Optional):
- **Azure Monitor**: Logs anomalies/statistics to Application Insights
- **Azure Table Storage**: Dynamically syncs malicious IP/domain blacklist

#### Additional Features:
- Flow tracking via 5-tuple (IP, port, protocol)
- Configurable thresholds via CLI
- BPF filtering in live mode
- Graceful shutdown and logging
- Simple CLI for modes, paths, and credentials

---

### Traffic Generator (`traffic_generator.py`)
- Generates traffic for testing
- Saves to a PCAP file
- Simulates:
  - Normal TCP/UDP traffic
  - Traffic from malicious IPs
  - Traffic on odd ports
  - Long-lived connections
  - HTTP on non-standard ports
  - Non-HTTP traffic on port 80

---

## Prerequisites

- Python 3.7+
- [Scapy](https://scapy.net/):
  ```
  pip install scapy
  pip install scapy[http]  # optional for better HTTP analysis

* **Azure SDKs** (only for Azure features):

  ```
  pip install azure-monitor-opentelemetry-exporter opentelemetry-api opentelemetry-sdk azure-data-tables
  ```

* **Live Mode**:

  * Root/admin privileges
  * libpcap (Linux/macOS), Npcap/WinPcap (Windows)

---

## Setup

### 1. Clone & Install:

```
git clone <your-repo-url>
cd <your-repo-directory>
pip install -r requirements.txt
```

### 2. (Optional) Local Blacklist File:

Create a file named `malicious_ips.txt`:

```
# Known malicious entities
1.2.3.4
bad-domain.com
198.51.100.10
```

### 3. (Optional) Azure Setup:

#### Azure Monitor:

* Create an Application Insights resource
* Get the "Connection String"

#### Azure Table Storage:

* Create a Storage Account + Table (e.g., `blacklistips`)
* Add entities (malicious IPs/domains) using:

  * `RowKey`: the IP/domain
  * `PartitionKey`: e.g., `GlobalBlacklist`

#### Environment Variables (optional alternative to CLI flags):

```
export AZURE_MONITOR_CONNECTION_STRING="..."
export AZURE_STORAGE_CONNECTION_STRING="..."
export AZURE_BLACKLIST_TABLE="blacklistips"
```

---

## Usage

### 1. Analyze a PCAP File:

```
python pcap_analyzer.py --pcap-file /path/to/file.pcap [OPTIONS]
```

Example:

```
python pcap_analyzer.py --pcap-file test.pcap --long-conn-threshold 1800
```

### 2. Live Traffic Capture:

```
sudo python pcap_analyzer.py --interface eth0 [OPTIONS]
```

Optional:

* `--bpf-filter "tcp port 80"`
* `--monitor-conn-str ...`
* `--storage-conn-str ...`
* `--local-blacklist malicious_ips.txt`

Example:

```
sudo python pcap_analyzer.py --interface eth0 --bpf-filter "tcp"
```

### 3. Generate Test Traffic:

```
python traffic_generator.py --output-pcap test.pcap --malicious-ip 10.0.0.99 --num-malicious 20 --long-conn-duration 120
```

Then analyze:

```
python pcap_analyzer.py --pcap-file test.pcap
```

---

## Logging

* **Console**: Standard logging
* **Azure Monitor** (optional): Sends anomalies & stats as telemetry traces/spans

---

## How it Works

### Initialization

* Loads config, Azure clients, and blacklist(s)

### Packet Processing

* **File Mode**: `scapy.rdpcap()`
* **Live Mode**: `scapy.sniff()`

### Flow Tracking (`_update_flow_stats`)

* Tracks 5-tuple flows
* Maintains packet/byte counts and timestamps

### Anomaly Checks

* `_check_malicious_ip`
* `_check_unusual_port`
* `_analyze_http_traffic`

### Post-Capture Flow Analysis

* Detects long-lived connections
* Live mode uses `_periodic_flow_analysis` thread
* Cleanup and analysis on shutdown

### Azure Logging (`_log_anomaly_to_azure`)

* Sends findings as trace data

---

