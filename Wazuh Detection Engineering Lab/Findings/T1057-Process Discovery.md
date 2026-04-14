# T1057 — Process Discovery

## What this technique is

Enumerating running processes to identify security tools, understand the environment, or find targets for injection or credential access. Commonly used in the early stages of post-compromise activity.

---

## Test run

```
Invoke-AtomicTest T1057 -TestNumbers 2
```

---

## What fired

**Rule 100003 — level 5**
"Whoami executed - possible reconnaissance"

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

Process discovery activity generated the same recon chain seen across other techniques — whoami followed by cmd.exe spawned from PowerShell.

---

## Key log fields

```
timestamp:        Apr 12, 2026 @ 18:32:31.056Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\whoami.exe
commandLine:      "C:\Windows\system32\whoami.exe"
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
rule.id:          100003
rule.level:       5
rule.firedtimes:  10
mitre:            T1033

timestamp:        Apr 12, 2026 @ 18:32:31.103Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      "cmd.exe" /c
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
rule.id:          92052
rule.level:       4
rule.firedtimes:  8
mitre:            T1059.003
```

---

## Analysis

The alerts that fired were for the surrounding recon chain rather than the process discovery technique itself. By this point in the test session rule 100003 had fired 10 times — the same whoami detection repeating across multiple technique tests from the same PowerShell session. That repetition is itself useful context: a single process spawning whoami that many times in one session is a stronger signal than any individual firing. Without correlation logic it reads as noise.

---

## Rule status

No dedicated rule added for T1057. Detection relies on the parent process anomaly and whoami recon rules. A rule targeting process enumeration commands (tasklist, Get-Process) would improve coverage.
