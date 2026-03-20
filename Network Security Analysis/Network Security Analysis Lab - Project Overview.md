# Automated Network Forensics Pipeline  
**Author:** Malachi Barratt  
**Date:** October 2025  

---

## Executive Summary  
This project demonstrates the design and deployment of an **automated network forensics pipeline** to accelerate malware investigation and incident response. By integrating **Zeek** for network visibility, **Suricata** for intrusion detection, and custom **Bash automation scripts**, the pipeline reduced analysis overhead and enabled rapid correlation of suspicious activity. The environment was deployed in a **cloud-based Ubuntu 22.04 server** on DigitalOcean.  

The pipeline is capable of:  
- Capturing and parsing live or replayed packet data.  
- Automatically extracting indicators of compromise (IOCs).  
- Correlating logs between Zeek and Suricata to provide context-rich alerts.  
- Reducing manual analyst effort by consolidating evidence into structured reports.  

This report outlines the architecture, scripts, workflow, and impact of the project, highlighting the integration of automation in modern network forensics.

---

## Introduction  
Network forensics is a critical component of modern cybersecurity operations, enabling analysts to reconstruct malicious activity and validate security incidents. Traditional workflows often rely heavily on manual inspection of logs, which can be **time-consuming** and **error-prone**, especially when analyzing high-volume traffic.  

The goal of this project was to address these challenges by creating a **semi-automated pipeline** capable of capturing, parsing, and correlating network traffic efficiently. By combining open-source tools with custom scripts, the pipeline not only accelerates investigation but also improves the **accuracy and repeatability** of forensic analysis.  

Key objectives:  
1. Capture raw network data for analysis.  
2. Parse traffic through multiple engines (Zeek and Suricata).  
3. Automate extraction of indicators of compromise.  
4. Correlate and summarize findings for actionable intelligence.

---

## Infrastructure Overview  
The pipeline was deployed in a **cloud-based environment** to allow scalable processing of large traffic captures. DigitalOcean’s Ubuntu 22.04 droplet (2 vCPU, 4GB RAM, 80GB SSD) provided sufficient resources for running Zeek and Suricata simultaneously.  

Backup planning was necessary after Oracle Cloud ARM instances were unavailable, emphasizing the importance of **flexible cloud deployment strategies**.  

DNS resolution initially failed, preventing package installs. This was fixed by configuring **systemd-resolved** with public DNS servers (8.8.8.8, 1.1.1.1, 67.207.67.2) and adjusting firewall rules for outbound DNS.  

**Core tools included:**  
- **Zeek**: Generates detailed network logs for protocols like HTTP, DNS, and SSL; installed via the official repository with GPG verification.  
- **Suricata**: Real-time intrusion detection using signature-based rules; requires regular signature updates.  
- **Bash scripting**: Automates log parsing, report generation, and IOC correlation.  

This setup supports **rapid triage, detailed forensic analysis, and IOC enrichment** workflows.

---

## Pipeline Architecture  
The workflow consists of four main stages:  

1. **Traffic Ingestion**  
   - Raw packets captured live via `tcpdump` or replayed from stored PCAPs.  
   - Organized in `/pcap/` for batch processing.  

2. **Parallel Analysis**  
   - Zeek parses traffic into protocol-specific logs.  
   - Suricata concurrently detects threats with a tuned ruleset.  

3. **Automated Extraction (Custom Scripts)**  
   - `quick-report.sh`: Fast triage of suspicious activity.  
   - `detailed-report.sh`: Comprehensive forensic reporting.  
   - `ip-look.sh`: Targeted investigation of individual IPs.  
   - `ioc-cor.sh`: Correlates logs to extract actionable IOCs.  

4. **Output & Reporting**  
   - Consolidates alerts, network metadata, and IOCs.  
   - Structured reports include timestamps, IPs, domains, and correlation points.  

This architecture ensures **speed and depth of analysis** while minimizing manual effort.

---

## Automation Scripts  

### 1. `quick-report.sh` — Rapid Triage  
Provides a **high-level overview** of captured traffic:  
- Top 10 destination IPs  
- Top 5 network protocols  
- Top 10 Suricata alerts  
- Suspicious high-entropy domains  
- Recent file transfers with MIME type & filename  

### 2. `detailed-report.sh` — Forensic Report  
Generates a **multi-section analysis** for deeper investigation:  
- Non-standard port and long-lived connections  
- SSH and HTTP authentication failures  
- Executables, scripts, and archive transfers  
- TLS/SSL metadata anomalies  

### 3. `ip-look.sh` — IP Investigation  
Interactive IP-based analysis:  
- MAC address and DHCP associations  
- Kerberos authentication logs  
- Top 10 connections from the IP  
- HTTP requests (URIs & user agents)  
- File transfers and DNS queries  

### 4. `ioc-cor.sh` — IOC Correlation  
Bridges Zeek and Suricata data:  
- Top 20 IPs by connection count  
- High-entropy domains  
- Unusual HTTP user agents  
- Large uploads and suspicious file hashes  
- Correlated Suricata alerts with Zeek connections  

---

## Workflow in Action  
1. **Quick Triage** → `quick-report.sh` highlights IPs, domains, alerts.  
2. **Deep Analysis** → `detailed-report.sh` generates structured forensic report.  
3. **IP Enrichment** → `ip-look.sh` provides IOC-specific insights.  
4. **IOC Correlation** → `ioc-cor.sh` merges alerts with network metadata.  

Seamlessly transitions from **high-level awareness to detailed IOC investigation**.

---

## Benefits and Impact  
- **Time Efficiency**: Multi-step log parsing reduced to single-command execution.  
- **Consistency**: Automated correlation ensures standardized reporting.  
- **IOC Extraction**: Actionable IP/domain/file hash lists.  
- **Scalability**: Cloud-hosted environment can process multiple PCAPs in parallel.  

Automation reduces analyst workload and improves investigative accuracy.

---

## Challenges and Fixes  
- **Noisy Suricata logs** → Filtered with `jq`.  
- **Distributed Zeek logs** → Consolidated with `zeek-cut` pipelines.  
- **High CPU spikes** → Tuned Suricata threads and limited concurrent captures.  
- **DNS/firewall issues** → Configured systemd-resolved and allowed proper DNS IPs.  
- **Empty script outputs** → Corrected typos in input variables.  

These solutions improved **performance, reliability, and accuracy**.

---

## Future Enhancements  
- Integrate **Elasticsearch + Kibana** for visualization.  
- Convert Bash scripts into **modular Python framework**.  
- Integrate with **MISP** for automated threat intelligence.  
- Add **YARA scanning and file carving** for malware payload extraction.  

Aims to improve **scalability, maintainability, and intelligence**.

---

## Conclusion  
This automated network forensics pipeline demonstrates how **open-source tools + scripting** can streamline manual investigations. Analysts can quickly triage, deeply investigate, and correlate network threats with **high accuracy**.  

**Skills demonstrated:**  
- Cloud-based infrastructure design  
- Bash automation for forensics  
- Multi-tool log correlation  
- Threat detection and IOC reporting
