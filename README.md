# Security Operations Portfolio

Real-world defensive security projects demonstrating SOC workflows, threat detection, and security automation. Each project includes architecture diagrams, detailed analysis, and production-ready implementations.

## Featured Projects

### T-Pot Honeypot Deployment & Threat Analysis

49-day honeypot deployment capturing 2M+ attacks across 20+ containerized services. Analyzed geographic attack patterns, credential strategies, and botnet infrastructure abuse.

**Key Findings:**
- 2M+ attacks from 100+ countries
- 36% of traffic concentrated in top 10 IPs
- Confirmed botnet operators using legitimate cloud infrastructure (GCP, DigitalOcean, GoDaddy) for evasion
- Most targeted service: Honeytrap (3,617 network recon attempts)

**Tech Stack:** T-Pot, Wazuh, ELK Stack, Suricata, Kibana, DigitalOcean  
**MITRE ATT&CK:** T1595 (Active Scanning), T1110 (Brute Force)

[View Full Report](./Honeypot%20Report/)

---

### Automated Network Forensics Pipeline

Cloud-deployed pipeline combining Zeek, Suricata, and custom Bash automation to reduce PCAP analysis time from 7+ hours to under 15 minutes. Validated against real malware from malware-traffic-analysis.net.

**Impact:**
- 80%+ time reduction on forensic investigations
- Automated IOC extraction (IPs, domains, file hashes)
- Cross-engine correlation between Zeek protocol analysis and Suricata signatures

**Case Studies:**
- Fake software distribution — Typo-squatted domain delivering 6-stage PowerShell payload with 43-minute C2 session
- Exploit kit compromise — LandUpdate808 drive-by with Cloudflare Tunnel abuse for exfiltration

**Tech Stack:** Zeek, Suricata, Bash, jq, DigitalOcean  
**MITRE ATT&CK:** T1566 (Phishing), T1071 (Application Layer Protocol), T1567 (Exfiltration Over Web Service)

[View Full Report](./Network%20Security%20Analysis/)

---

### SOC Automation — Detection to Case Creation

End-to-end automation pipeline reducing MTTR from 45-90 minutes to under 1 minute. Automatically detects Mimikatz execution, confirms malware via VirusTotal, creates TheHive case, and notifies analyst.

**Impact:**
- 98%+ reduction in manual triage time
- Automated threat intelligence enrichment
- Zero-touch case creation with full context

**Workflow:** Sysmon → Wazuh → Shuffle → VirusTotal → TheHive → Email

**Tech Stack:** Sysmon, Wazuh, Shuffle SOAR, VirusTotal API, TheHive, DigitalOcean  
**MITRE ATT&CK:** T1003 (Credential Dumping)

[View Full Report](./SOC%20Automation%20Report/)

---

## Portfolio Impact Summary

| Metric | Result |
|--------|--------|
| Attacks analyzed | 2M+ (honeypot) + 2 malware campaigns (forensics) |
| Time savings | 80-98% reduction across projects |
| Automated workflows | 3 end-to-end pipelines |
| Tools deployed | 15+ (SIEM, SOAR, IDS, honeypots, forensics) |
| MITRE ATT&CK coverage | 6+ techniques mapped |

## Technical Skills Demonstrated

**Security Operations:** SIEM deployment and tuning, threat hunting, incident response, IOC extraction, malware analysis

**Automation:** SOAR workflow orchestration, custom Bash scripting, log parsing with regex, API integration (VirusTotal, TheHive)

**Infrastructure:** Cloud deployment (DigitalOcean), containerization (Docker), ELK Stack configuration, network segmentation

**Tools:** Wazuh, Splunk, Shuffle, TheHive, T-Pot, Zeek, Suricata, Sysmon, Kibana, Elasticsearch

## Connect

- LinkedIn: [linkedin.com/in/malachi-barratt](https://www.linkedin.com/in/malachi-barratt/)
- Email: malachibarratt@gmail.com

---

### About This Portfolio

These projects were built to simulate real SOC workflows and demonstrate production-ready skills in threat detection, analysis, and automation. Each includes detailed documentation, architecture diagrams, and lessons learned from actual deployment challenges.
