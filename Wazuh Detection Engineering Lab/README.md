# Wazuh Detection Engineering Lab

> Simulating adversary behavior with Atomic Red Team, detecting it with Wazuh + Sysmon, and mapping coverage to MITRE ATT&CK.

---

## Overview

This project documents a cloud-hosted detection engineering lab built to evaluate real-world SIEM coverage against simulated adversary techniques. The environment was provisioned on AWS using Terraform (Allowing the lab to be spun up, tested, and destroyed repeatably without manual configuration) as well as utilizing my existing homelab environment. 

I used Atomic Red Team to generate attack telemetry and Wazuh as the SIEM, the goal was to identify detection gaps, tune alert severity, and develop custom rules aligned to MITRE ATT&CK.

The lab simulates a realistic blue team workflow: run the attack, observe what fires, identify what doesn't, and fix it.

**Stack:** Wazuh · Sysmon · Atomic Red Team · MITRE ATT&CK · AWS · Terraform

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Detection Status | Rule ID | Notes |
|---|---|---|---|---|---|
| T1033 | System Owner/User Discovery | Discovery | Detected | 100003 | whoami via PowerShell parent — fires reliably |
| T1059.001 | PowerShell | Execution | Detected | 100004 | Mimikatz IEX download string caught |
| T1059.003 | Windows Command Shell | Execution | Detected (generic) | 92052 | Only fires on abnormal parent — not technique-specific |
| T1003.001 | LSASS Memory | Credential Access | Gap → Rule Added | 100110 | procdump + lsass.exe — no default rule existed |
| T1053.005 | Scheduled Task | Persistence | Detected (undertriaged) | 92052 | schtasks /create fired at level 4 — should be 8–10 |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Gap → Rule Added | 100113 | wevtutil cl — no default rule; EID 104 also unmonitored |
| T1082 | System Information Discovery | Discovery | Detected (undertriaged) | 92032 | systeminfo + reg query chain fired at level 3 |
| T1083 | File and Directory Discovery | Discovery | Gap → Rule Added | 100112 | dir /s + tree /F — no default rule existed |
| T1105 | Ingress Tool Transfer | Command and Control | Detected | 92213 | PS script drop to Temp — false positive risk on policy test files |
| T1136.001 | Create Local Account | Persistence | Gap → Rule Added | 100114 | net user /add — only caught by generic parent rule before |
| T1218.011 | Rundll32 | Defense Evasion | Gap → Rule Added | 100111 | JavaScript LOLBIN execution — no default rule existed |
| T1547.001 | Registry Run Keys | Persistence | Detected (undertriaged) | 92302 | reg.exe writing to \CurrentVersion\Run fired at level 6 — should be 10–12 |

---



## Detection Engineering Approach

The lab was structured around three detection layers, built in order of complexity.

**Layer 1 — Atomic detection**
The foundation. Low-level Sysmon event matching on process creation, command-line patterns, and registry writes. These are the rules Wazuh ships with or that fire on raw event IDs. They work, but they're noisy and low-severity — they tell you something happened, not what an attacker was doing.

**Layer 2 — Technique-specific detection**
Instead of "cmd.exe spawned by PowerShell," the goal was rules that fire on specific adversary behavior like procdump targeting lsass, rundll32 executing JavaScript, wevtutil clearing logs. Each rule carries a MITRE technique ID and a severity level that reflects actual risk rather than the default level 3–4 that most generic rules fire at.

**Layer 3 — Correlation**
Every technique tested across this lab originated from the same parent PowerShell session. Discovery, Execution, Persistence, Credential Access were all within seconds of each other. Individually those alerts are noise. Together they're an attack chain. A correlation rule that ties multiple technique-level alerts to the same session would catch that. The design is there; full implementation is constrained by how Wazuh's correlation engine handles Sysmon fields without custom decoder enrichment but it would be the logical next step. 

**Infrastructure**
The environment was provisioned using Terraform on AWS and using my existing homelab. A Wazuh manager that was deployed and destroyed. As well as my windows VM which I had to recreate at the end due to the memory issues from logall (Damn you 256 gb laptop) Reproducible, cost-controlled, and no leftover infrastructure.

---



## Log Analysis & Findings

Each technique tested has a dedicated findings file documenting the raw Wazuh alerts, what fired, what didn't, and why. These are the primary evidence files for this project.

| Technique | Findings |
|---|---|
| T1003.001 — LSASS Memory | [View findings](findings/T1003-lsass-dump.md) |
| T1059.001 — PowerShell | [View findings](findings/T1059-powershell.md) |
| T1059.003 — Windows Command Shell | [View findings](findings/T1059-windows-cmd.md) |
| T1053.005 — Scheduled Task | [View findings](findings/T1053-scheduled-task.md) |
| T1070.001 — Clear Event Logs | [View findings](findings/T1070-log-clearing.md) |
| T1082 — System Information Discovery | [View findings](findings/T1082-sysinfo-discovery.md) |
| T1083 — File and Directory Discovery | [View findings](findings/T1083-directory-discovery.md) |
| T1105 — Ingress Tool Transfer | [View findings](findings/T1105-ingress-tool-transfer.md) |
| T1136.001 — Create Local Account | [View findings](findings/T1136-account-creation.md) |
| T1218.011 — Rundll32 | [View findings](findings/T1218-rundll32.md) |
| T1547.001 — Registry Run Keys | [View findings](findings/T1547-run-keys.md) |

---

## Gaps Identified

Finding gaps was the point of the lab. These are the techniques that either had no coverage at all or were only caught by a generic rule that didn't understand what it was looking at.

**No dedicated rule existed**
- T1003.001 — LSASS memory dumping via procdump only triggered "Windows command prompt started by abnormal process" at level 4. That rule has no idea what procdump is doing.
- T1218.011 — Rundll32 executing JavaScript via `mshtml` is a well-known LOLBIN abuse pattern. Nothing fired for it by default.
- T1083 — Mass recursive directory enumeration (`dir /s`, `tree /F`) with output redirected to a temp file is textbook recon staging. No default rule covers it.
- T1070.001 — Wevtutil clearing the System log only caught the parent process chain, not the log clearing itself. Windows EID 104 was also unmonitored.
- T1136.001 — Local account creation via `net user /add` was only caught because cmd.exe had an unusual parent. The account creation itself wasn't the trigger.

**Detected but undertriaged**
- T1053.005 — Scheduled task creation for persistence fired at level 4. That should be 8–10 at minimum.
- T1547.001 — Registry run key modification fired at level 6. Persistence mechanisms shouldn't sit below level 10.
- T1082 — Chained system discovery commands (systeminfo + reg query) came in at level 3. That's below the threshold most analysts would ever review.

**False positive risk**
- T1105 — Rule 92213 fired at level 15 on a PowerShell script policy test file (`__PSScriptPolicyTest_*.ps1`). That's normal PowerShell behavior and will generate alert fatigue without an exclusion.
- T1059 — `mscorsvw.exe` dropping DLLs to the .NET NativeImages folder is the .NET optimizer running legitimately. Needs an exclusion.

---



## Key Findings

**Generic rules are not detection.** Every technique in this lab initially fired on rule 92052, 'Windows command prompt started by abnormal process' but that alert says nothing about what actually happened. It doesn't know if it's credential dumping or log clearing or account creation. If an attacker changes one part of their chain, a setup that relies only on generic rules will miss it entirely.

**Severity levels were miscalibrated across the board.** Once alerts came in, severity levels were miscalibrated across several techniques. Credential dumping, persistence via run keys, and scheduled task creation all fired at levels lower than what those techniques warrant. In a real environment that means serious alerts getting buried in the noise. Writing a rule is only half the work — it also needs to come in at a level that someone will actually act on.

**Every technique in this lab came from the same PowerShell session.** Same parent process ID, same user, same machine, within a 60-second window across Discovery, Execution, Persistence, Credential Access, and Defense Evasion. Individual alerts told just a part of the story while looking at the entire process tree told a complete one. That's why correlation is so important and its critical to get right at scale. 

**The SIEM infrastructure itself can become a detection gap.** Log archiving with `logall` enabled combined with verbose Sysmon output filled a 30GB volume and caused the Wazuh manager to fail silently (Only noticed when rule saves returned 500 errors), detections stopped updating, and nothing in the UI explained why. Disk exhaustion is a real potential issue for detection pipelines and it isn't always immediately obvious. 

**False positives at level 15 are a problem.** Rule 92213 firing at the highest severity level on a normal PowerShell script policy test file is the kind of thing that trains analysts to ignore high-severity alerts. One noisy rule at the top of the scale does more damage than ten missed detections.

---



## Custom Rules

All custom rules are in [`rules/local_rules.xml`](rules/local_rules.xml). They are structured in two layers, technique-specific detection and severity overrides for undertriaged default rules.

**Technique-specific rules added**

| Rule ID | Technique | Level | Description |
|---|---|---|---|
| 100110 | T1003.001 | 13 | Procdump targeting lsass.exe |
| 100111 | T1218.011 | 14 | Rundll32 JavaScript LOLBIN execution |
| 100112 | T1083 | 10 | Recursive directory enumeration via dir /s or tree /F |
| 100113 | T1070.001 | 15 | Wevtutil clearing System, Security, or Application logs |
| 100114 | T1136.001 | 14 | Local account creation via net user /add |

**Design decisions**
- All rules match on `sysmon_event1` (Process Create) and use `pcre2` regex on command-line fields, specific enough to reduce noise, broad enough to catch variations in path or casing.
- Severity levels were set based on tactic context: credential access and defense evasion sit at 13–15, discovery at 10, execution-adjacent at 12+.
- The correlation rule (multi-technique chain from same session) is documented in [`rules/correlation_notes.md`](rules/correlation_notes.md) , the design is sound but full implementation requires custom decoder enrichment for Sysmon parent process fields.

---



## Lessons Learned

**Detection quality matters more than detection count.** Having twelve techniques "detected" means nothing if eight of them fired at the wrong severity level. The first useful thing this lab produced wasn't a new rule but making sure that alerts fired to the correct level. 

**Sysmon is verbose by design — that's a tradeoff, not a flaw.** Without tuned rules, Sysmon output quickly can become background noise. The same telemetry that caught a Mimikatz download also filled a 30GB disk in a matter of hours. While having verbose alerts can help you find things, without retention policies and log rotation it can easily work against you

**SIEM rule editors are not the right place to engineer detections.** The Wazuh dashboard file editor returns a generic 500 error for any backend failure (bad XML, disk full, permission issue, validation crash) and none of it is distinguishable from the UI. Rule development belongs in SSH with `wazuh-logtest` for validation, not in a browser form that overwrites the whole file on save.

**Infrastructure limits are detection limits.** A full disk doesn't just slow things down but it can totally break the detection pipeline. Rules stop updating, the manager fails to reload, and nothing explicitly tells you why. Monitoring the health of the SIEM itself is part of running a detection program.

**Correlation is where detection becomes investigation.** Individual technique alerts are starting points. What this lab made clear is that the real value is in connecting them. Same session, same user, same machine, multiple tactics in sequence provides true insight into attacker behavior and attacker deterence.

---



## What I'd Do Next

**Build proper correlation.** The groundwork is there but the next step is writing custom Wazuh decoders to extract and normalize parent process fields from Sysmon events, then building correlation rules that group technique-level alerts by session. That would turn this from just a detection lab into something that behaves like a real SOC detection pipeline.

**Tune Sysmon config.** The default Sysmon configuration generates far more noise than signal. A scoped config that captures what matters for ATT&CK coverage without logging every process would reduce disk pressure, improve alert quality, and make the findings easier to act on.

**Add active response.** Wazuh supports automated response actions triggered by rule IDs. For high-confidence detections like LSASS dumping or log clearing, that means automatic process termination or host isolation rather than waiting for an analyst to respond. That's the step that takes detection into prevention.

**Expand log sources.** This lab was Sysmon-only on a single Windows host. A more complete picture would include Windows Security Event logs for logon events and privilege use, PowerShell Script Block Logging for full command visibility, and network-level telemetry to catch C2 and exfiltration techniques that don't show up in process logs.

**Implement log retention policy.** Running `logall` on a 30GB volume with no rotation should only be for short term testing and has to be disabled. A production-grade setup routes archives to cold storage, sets retention windows per data type, and monitors disk usage as part of SIEM health. While it may be easy to overlook it is critical to preventing downtime. 

---
