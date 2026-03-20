# T-Pot Honeypot Deployment & Threat Analysis

![T-Pot](https://img.shields.io/badge/T--Pot-Honeypot-red?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat-square&logo=docker)
![Kibana](https://img.shields.io/badge/Kibana-Dashboards-005571?style=flat-square&logo=kibana)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-Log%20Storage-yellow?style=flat-square&logo=elasticsearch)
![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-purple?style=flat-square)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Threat%20Intel-orange?style=flat-square)
![DigitalOcean](https://img.shields.io/badge/DigitalOcean-Cloud-0080FF?style=flat-square&logo=digitalocean)

49-day T-Pot honeypot deployment on DigitalOcean capturing **2M+ attacks** across 20+ containerized services. Integrated with Wazuh SIEM for real-time log forwarding and a Shuffle/VirusTotal automation pipeline for IOC enrichment. Zero successful host breaches confirmed throughout the deployment.

---

## Architecture

### Infrastructure

| Component | Details |
|-----------|---------|
| Cloud Provider | DigitalOcean (VM) |
| Honeypot Platform | T-Pot , 20+ containerized honeypot services |
| SIEM | Wazuh (centralized log aggregation + alerting) |
| Log Storage | Elasticsearch with Kibana dashboards |
| Automation | Shuffle SOAR + VirusTotal API |

### Network Design — Zero-Trust Segmentation

The network was designed to maximize attack surface exposure while maintaining complete host isolation. All honeypot services run inside Docker containers so attacks never reach the host OS.

**Firewall Rules:**

| Direction | Ports | Purpose |
|-----------|-------|---------|
| Inbound | 1–64000 (TCP/UDP) | Expose honeypot services to internet |
| Inbound | 64295 (SSH) | Management, restricted to single trusted IP |
| Outbound | 1514–1515 | Wazuh agent → SIEM |
| Outbound | 53/UDP, 443/TCP | DNS + system updates |

**Host hardening:** SSH key-only authentication, password login disabled, automated security updates.

---

## Key Findings

> Snapshot from a 14-hour analysis window of a broader 49-day dataset.

| Metric | Value |
|--------|-------|
| Total attacks (14hr window) | 7,893 |
| Top 10 IPs share of traffic | 36% |
| Most targeted service | Honeytrap — 3,617 attacks (network recon/port scanning) |
| Most common username | `root` (91 attempts) |
| Most common password | `P@ssw0rd` (17 attempts) |
| Confirmed host breaches | 0 |

**Attack timing** occurred in coordinated bursts rather than steady streams — consistent with managed botnet campaigns using intermittent activity for operational security.

**Attacker reputation breakdown:**

| Type | Count |
|------|-------|
| Known attacker | 3,627 |
| Mass scanner | 330 |
| Bot / crawler | 1 |

---

## Dashboard Visualizations

*Kibana attack map — geographic distribution of inbound traffic*
![Attack Map](images/screenshot1.png)

*Service breakdown and top attacking ASNs*
![Service Breakdown](images/screenshot2.png)

*Temporal attack patterns — burst activity visible across the timeline*
![Timeline](images/screenshot3.png)

---

## Attack Data

<details>
<summary><strong>Geographic Distribution</strong></summary>

| Country | Attack Count |
|---------|-------------|
| United States | 2,734 |
| Bolivia | 1,145 |
| Vietnam | 588 |
| Netherlands | 373 |
| Seychelles | 346 |

</details>

<details>
<summary><strong>Top Attacking IPs & ASNs</strong></summary>

**Top IPs:**

| IP Address | Attacks | Provider |
|-----------|--------|---------|
| 208.109.190.200 | 778 | UCLOUD INFORMATION TECHNOLOGY |
| 200.105.196.189 | 583 | AXS Bolivia S.A. |
| 181.115.190.30 | 396 | Google Cloud Platform |
| 116.99.172.53 | 345 | GoDaddy.com, LLC |
| 196.251.87.127 | 264 | EMPRESA NACIONAL DE TELECOMUNICACIONES |

**Top ASNs:**

| Organization | Attack Count |
|-------------|-------------|
| AXS Bolivia S.A. | 749 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 477 |
| GoDaddy.com, LLC | 404 |
| Google Cloud Platform | 401 |
| EMPRESA NACIONAL DE TELECOMUNICACIONES | 396 |

Notable: attackers heavily leveraged legitimate cloud infrastructure (GCP, DigitalOcean, Scaleway) alongside compromised residential and business networks — a common evasion tactic against IP-reputation-based filtering.

</details>

<details>
<summary><strong>Service Targeting</strong></summary>

| Honeypot Service | Attacks | Description |
|-----------------|--------|-------------|
| Honeytrap | 3,617 | Network recon and port scanning |
| Dionaea | 1,304 | Malware distribution attempts |
| Cowrie | 1,274 | SSH credential brute-forcing |
| Sentrypeer | 815 | VoIP/telecom targeting |
| Tanner | 71 | Web application probing |

</details>

<details>
<summary><strong>Credential Patterns</strong></summary>

**Usernames:**

| Username | Count |
|---------|-------|
| root | 91 |
| admin | 21 |
| monitor | 16 |
| test | 4 |

**Passwords:**

| Password | Count |
|---------|-------|
| P@ssw0rd | 17 |
| admin | 9 |
| 123456 | 6 |
| 1234 | 5 |
| password | 5 |

Credential patterns confirm automated tooling — default and common passwords dominate with no personalization. `P@ssw0rd` leading the list suggests attackers are aware of basic complexity policies and are testing the minimum bar.

</details>

<details>
<summary><strong>IDS Alerts (Suricata)</strong></summary>

| Rule ID | Description | Count |
|---------|-------------|-------|
| 2228000 | SURICATA SSH invalid banner | 551 |
| 2210061 | SURICATA STREAM spurious retransmission | 108 |
| 2001978 | ET INFO SSH session on expected port | 88 |
| 2001984 | ET INFO SSH session on unusual port | 77 |
| 2260002 | SURICATA Applayer protocol one direction | 76 |

</details>

<details>
<summary><strong>OS Fingerprinting (P0f)</strong></summary>

| OS | Count |
|----|-------|
| Linux 2.2.x–3.x | 5,791 |
| Windows NT kernel 5.x | 2,979 |
| Linux 2.2.x–3.x barebone | 1,181 |
| Linux 3.11+ | 78 |
| Windows 7 or 8 | 33 |
| Mac OS X | 18 |

Linux dominance reflects its prevalence in servers and IoT devices. Windows targets skew toward legacy NT kernels, consistent with automated exploitation of unpatched systems.

</details>

---

## Automation Pipeline (Shuffle SOAR + VirusTotal)

# T-Pot Honeypot Deployment & Threat Analysis

![T-Pot](https://img.shields.io/badge/T--Pot-Honeypot-red?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat-square&logo=docker)
![Kibana](https://img.shields.io/badge/Kibana-Dashboards-005571?style=flat-square&logo=kibana)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-Log%20Storage-yellow?style=flat-square&logo=elasticsearch)
![DigitalOcean](https://img.shields.io/badge/DigitalOcean-Cloud-0080FF?style=flat-square&logo=digitalocean)

49-day T-Pot honeypot deployment on DigitalOcean capturing **2M+ attacks** across 20+ containerized services. Integrated with Wazuh SIEM for real-time log forwarding and analyzed via Kibana dashboards. Zero successful host breaches confirmed throughout the deployment.

---

## Architecture

### Infrastructure

| Component | Details |
|-----------|---------|
| Cloud Provider | DigitalOcean (VM) |
| Honeypot Platform | T-Pot — 20+ containerized honeypot services |
| SIEM | Wazuh (centralized log aggregation + alerting) |
| Log Storage | Elasticsearch with Kibana dashboards |

### Network Design — Zero-Trust Segmentation

The network was designed to maximize attack surface exposure while maintaining complete host isolation. All honeypot services run inside Docker containers — attacks never reach the host OS.

**Firewall Rules:**

| Direction | Ports | Purpose |
|-----------|-------|---------|
| Inbound | 1–64000 (TCP/UDP) | Expose honeypot services to internet |
| Inbound | 64295 (SSH) | Management — restricted to single trusted IP |
| Outbound | 1514–1515 | Wazuh agent → SIEM |
| Outbound | 53/UDP, 443/TCP | DNS + system updates |

**Host hardening:** SSH key-only authentication, password login disabled, automated security updates.

---

## Key Findings

> Snapshot from a 14-hour analysis window of the broader 49-day dataset.

| Metric | Value |
|--------|-------|
| Total attacks (14hr window) | 7,893 |
| Top 10 IPs share of traffic | 36% |
| Most targeted service | Honeytrap — 3,617 attacks (network recon/port scanning) |
| Most common username | `root` (91 attempts) |
| Most common password | `P@ssw0rd` (17 attempts) |
| Confirmed host breaches | 0 |

**Attack timing** occurred in coordinated bursts rather than steady streams — consistent with managed botnet campaigns using intermittent activity for operational security.

**Attacker reputation breakdown:**

| Type | Count |
|------|-------|
| Known attacker | 3,627 |
| Mass scanner | 330 |
| Bot / crawler | 1 |

---

## Dashboard Visualizations

*Kibana attack map — geographic distribution of inbound traffic*
![Attack Map](https://github.com/user-attachments/assets/a399382c-ffba-4948-8b83-86001833cb68)

*Service breakdown and top attacking ASNs*
![Service Breakdown](https://github.com/user-attachments/assets/538dc8ee-71eb-4909-a8e8-811f424b58b7)

*Temporal attack patterns — burst activity visible across the timeline*
![Timeline](https://github.com/user-attachments/assets/12ecdaef-9e43-4cd3-8905-5c97b9f5fcbc)

---

## Attack Data

<details>
<summary><strong>Geographic Distribution</strong></summary>

| Country | Attack Count |
|---------|-------------|
| United States | 2,734 |
| Bolivia | 1,145 |
| Vietnam | 588 |
| Netherlands | 373 |
| Seychelles | 346 |

</details>

<details>
<summary><strong>Top Attacking IPs & ASNs</strong></summary>

**Top IPs:**

| IP Address | Attacks | Provider |
|-----------|--------|---------|
| 208.109.190.200 | 778 | UCLOUD INFORMATION TECHNOLOGY |
| 200.105.196.189 | 583 | AXS Bolivia S.A. |
| 181.115.190.30 | 396 | Google Cloud Platform |
| 116.99.172.53 | 345 | GoDaddy.com, LLC |
| 196.251.87.127 | 264 | EMPRESA NACIONAL DE TELECOMUNICACIONES |

**Top ASNs:**

| Organization | Attack Count |
|-------------|-------------|
| AXS Bolivia S.A. | 749 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 477 |
| GoDaddy.com, LLC | 404 |
| Google Cloud Platform | 401 |
| EMPRESA NACIONAL DE TELECOMUNICACIONES | 396 |

Notable: attackers heavily leveraged legitimate cloud infrastructure (GCP, DigitalOcean, Scaleway) alongside compromised residential and business networks — a common evasion tactic against IP-reputation-based filtering.

</details>

<details>
<summary><strong>Service Targeting</strong></summary>

| Honeypot Service | Attacks | Description |
|-----------------|--------|-------------|
| Honeytrap | 3,617 | Network recon and port scanning |
| Dionaea | 1,304 | Malware distribution attempts |
| Cowrie | 1,274 | SSH credential brute-forcing |
| Sentrypeer | 815 | VoIP/telecom targeting |
| Tanner | 71 | Web application probing |

</details>

<details>
<summary><strong>Credential Patterns</strong></summary>

**Usernames:**

| Username | Count |
|---------|-------|
| root | 91 |
| admin | 21 |
| monitor | 16 |
| test | 4 |

**Passwords:**

| Password | Count |
|---------|-------|
| P@ssw0rd | 17 |
| admin | 9 |
| 123456 | 6 |
| 1234 | 5 |
| password | 5 |

Credential patterns confirm automated tooling — default and common passwords dominate with no personalization. `P@ssw0rd` leading suggests attackers are aware of basic complexity policies and are testing the minimum bar.

</details>

<details>
<summary><strong>IDS Alerts (Suricata)</strong></summary>

| Rule ID | Description | Count |
|---------|-------------|-------|
| 2228000 | SURICATA SSH invalid banner | 551 |
| 2210061 | SURICATA STREAM spurious retransmission | 108 |
| 2001978 | ET INFO SSH session on expected port | 88 |
| 2001984 | ET INFO SSH session on unusual port | 77 |
| 2260002 | SURICATA Applayer protocol one direction | 76 |

</details>

<details>
<summary><strong>OS Fingerprinting (P0f)</strong></summary>

| OS | Count |
|----|-------|
| Linux 2.2.x–3.x | 5,791 |
| Windows NT kernel 5.x | 2,979 |
| Linux 2.2.x–3.x barebone | 1,181 |
| Linux 3.11+ | 78 |
| Windows 7 or 8 | 33 |
| Mac OS X | 18 |

Linux dominance reflects its prevalence in servers and IoT devices. Windows targets skew toward legacy NT kernels, consistent with automated exploitation of unpatched systems.

</details>

---

## Troubleshooting

| Issue | Root Cause | Resolution |
|-------|-----------|------------|
| Elasticsearch OOM crash | Container memory limits hit under load | Optimized Docker resource allocation per service |
| Local DNS hijacking | Internal Docker resolver redirecting `ghcr.io` to `192.168.1.1` | Hardcoded `1.1.1.1` in `/etc/resolv.conf` |
| Container update failures | Outbound traffic blocked by default firewall rules | Added explicit outbound rules for 443/TCP and 53/UDP |

---

## Roadmap

The next phase is building an automated threat intelligence pipeline on top of the captured data:

- **Shuffle SOAR** — webhook ingestion of T-Pot log events
- **Python IOC parser** — extract source IPs, JA3 hashes, and payloads from Elasticsearch JSON exports
- **VirusTotal API** — automated reputation scoring and malware validation per IOC
- **Alerting** — summary reports pushed to analyst queue or ticketing system

Current blocker: T-Pot's internal security hardening restricts direct Kibana API access from external services. Next step is extracting Kibana encryption keys to enable API connectivity for real-time processing.

---

## Lessons Learned

- Containerization is an effective containment boundary — 2M+ attacks, zero host-level breaches
- Botnet operators actively use legitimate cloud infrastructure to evade reputation-based blocking — ASN-level monitoring matters more than simple IP blocklists
- Burst-pattern attack timing is a deliberate OPSEC tactic, not noise — behavioral detection catches what signature-based rules miss
- Even a basic deployment generates enough data to surface real attacker patterns around credential choice, service targeting, and infrastructure reuse
