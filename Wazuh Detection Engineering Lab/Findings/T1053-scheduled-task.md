# T1053.005 — Scheduled Task

## What this technique is

Creating scheduled tasks to establish persistence or execute code at a defined trigger. Attackers use schtasks.exe to run payloads on logon, startup, or at regular intervals — often under SYSTEM context to escalate privilege at the same time.

---

## Test run

```
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

Two scheduled tasks created: one triggering on logon, one on startup, both running `cmd.exe /c calc.exe`.

---

## What fired

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

cmd.exe flagged for abnormal parent. Sysmon's ruleName correctly tagged T1059.003 but the scheduled task creation itself was not the trigger.

---

## Key log fields

```
timestamp:        2026-04-12T22:57:29.142Z
agent:            windowsvm1 (192.168.1.187)
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      "cmd.exe" /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" & schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
rule.id:          92052
rule.level:       4
mitre:            T1059.003 (Sysmon tag) — T1053.005 not mapped

timestamp:        2026-04-12T22:57:29.245Z
image:            C:\Windows\System32\schtasks.exe
commandLine:      schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
parentImage:      C:\Windows\System32\cmd.exe
rule.id:          92052
rule.level:       4
```

---

## Analysis

Two separate process create events fired the same generic rule at the same low level. The schtasks.exe execution itself was visible in the logs but nothing escalated it as a persistence technique. A scheduled task set to run on logon under Administrator context is not a level 4 event.

---

## Rule status

No dedicated rule added in this lab cycle. The detection gap is documented. A rule targeting `schtasks.exe` with `/create` and `/sc onlogon` or `/sc onstart` in the command line would be the appropriate fix, at level 8-10 minimum.
