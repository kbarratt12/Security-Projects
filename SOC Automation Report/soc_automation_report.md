# SOC Automation — Detection to Case Creation

![Sysmon](https://img.shields.io/badge/Sysmon-Endpoint%20Monitoring-blue?style=flat-square)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue?style=flat-square)
![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-purple?style=flat-square)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Threat%20Intel-orange?style=flat-square)
![TheHive](https://img.shields.io/badge/TheHive-Case%20Management-yellow?style=flat-square)
![DigitalOcean](https://img.shields.io/badge/DigitalOcean-Cloud-0080FF?style=flat-square&logo=digitalocean)

End-to-end SOC automation pipeline triggered by a Mimikatz execution on a Windows endpoint. Sysmon detects the process, Wazuh fires an alert, Shuffle pulls the SHA-256 hash via regex and sends it to VirusTotal for confirmation, then automatically creates a case in TheHive and emails the analyst — all without manual intervention.

---

## Architecture

**Infrastructure:**

| Component | Platform | Purpose |
|-----------|---------|---------|
| Windows 10 VM + Sysmon | Local (VirtualBox) | Monitored endpoint |
| Wazuh SIEM | DigitalOcean | Log collection and alert generation |
| TheHive | DigitalOcean | Incident case management |
| Shuffle SOAR | Cloud | Workflow orchestration |
| VirusTotal API | External | Automated threat intelligence |

**Workflow:**

```
Sysmon (endpoint)
      │  process execution event
      ▼
Wazuh SIEM
      │  custom rule fires (ID: 100002, severity 15)
      │  MITRE ATT&CK: T1003 — Credential Dumping
      ▼
Shuffle SOAR (webhook trigger)
      │
      ├──► Regex extracts SHA-256 hash from alert payload
      │
      ├──► VirusTotal API — hash lookup and malware confirmation
      │
      ├──► TheHive — case created with enriched threat intel
      │
      └──► Email — analyst notification with case details
```

---

## Workflow Diagrams

*Complete interconnected architecture — endpoint through analyst notification*

<img width="933" height="787" alt="SOC Automation Architecture" src="https://github.com/user-attachments/assets/429e1859-7277-4ce2-b152-aa6c606e30c5" />

*Simplified end-to-end pipeline view*

<img width="1302" height="402" alt="Linear Workflow" src="https://github.com/user-attachments/assets/70603057-2689-4336-b1a2-83e1a61423f7" />

---

## Detection Rule

Custom Wazuh rule written to detect Mimikatz execution:

- **Rule ID:** 100002
- **Severity:** Level 15 (highest priority)
- **MITRE ATT&CK:** T1003 — Credential Dumping
- **Log source:** Sysmon via ossec.conf

Validated by executing Mimikatz on the monitored endpoint and confirming the full pipeline fired end-to-end.

---

## Estimated Performance Impact

Baselines represent estimated manual analyst workflow times accounting for real SOC conditions (alert queue depth, context switching, documentation):

| Metric | Manual Baseline | Automated | Notes |
|--------|----------------|-----------|-------|
| MTTR (credential dumping alert) | 45–90 min | <1 min | Manual baseline assumes alert queue wait time + triage + enrichment + case creation. 30 min is only realistic if the analyst is already watching the queue. |
| Alert enrichment (hash lookup) | 10–15 min | <30 sec | Navigate to VirusTotal, paste hash, read report, document findings — 10 min is realistic for a competent analyst. |
| Case creation | 5–15 min | <10 sec | Manually filling all TheHive fields (title, description, severity, TLP, tags, observables) with proper context takes longer than it looks. |
| Analyst notification | Variable | <1 min | "Variable" is the honest answer — depends entirely on whether the analyst is actively watching the queue or in a meeting. |

---

## Troubleshooting

| Issue | Root Cause | Resolution |
|-------|-----------|------------|
| VM complete rebuild required | Accidental snapshot corruption | Recreated VDI via VirtualBox CLI; rebuilt all components |
| Elasticsearch failing to start | Incorrect JVM options + missing `discovery.type: single-node` | Corrected JVM config and cluster settings |
| TheHive 60-second timeouts | Incorrect API endpoint URLs from outdated documentation | Cross-referenced current TheHive docs; corrected endpoint paths |
| Wazuh-Shuffle webhook failure | XML indentation errors in ossec.conf | Validated and corrected XML formatting |
| Shuffle VirusTotal 404 errors | Wrong field path for hash extraction | Corrected to `$sha256_hash.group_0.#` syntax |
| TheHive 400 errors | Quoted numeric values in JSON payload (TLP/severity fields) | Removed quotes from numeric fields in API call body |
| 30-second timeouts (suspected latency) | UK cloud instance geographic distance | Migrated to US-based DigitalOcean instance |
| No clipboard between host and VM | VM Guest Additions not installed | Installed Guest Additions to enable clipboard sharing |

---

## Roadmap

- Additional Wazuh detection rules for common ATT&CK techniques
- Error handling and retry logic in Shuffle workflows
- XPack authentication for Elasticsearch + Cassandra auth for TheHive
- Automated playbooks for additional incident types
- Expand endpoint coverage beyond single Windows VM
