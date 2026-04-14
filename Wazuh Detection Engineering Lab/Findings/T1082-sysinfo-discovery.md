# T1082 — System Information Discovery

## What this technique is

Collecting detailed system information to understand the target environment. Attackers use tools like systeminfo and reg query to identify OS version, hardware, installed software, and configuration details that inform next steps.

---

## Test run

```
Invoke-AtomicTest T1082 -TestNumbers 1
```

systeminfo and reg query chained in a single cmd.exe call to enumerate OS details and disk configuration.

---

## What fired

**Rule 100003 — level 5**
"Whoami executed - possible reconnaissance"

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

**Rule 92032 — level 3**
"Suspicious Windows cmd shell execution"

---

## Key log fields

```
timestamp:        2026-04-12T22:28:31.403Z
image:            C:\Windows\System32\whoami.exe
commandLine:      "C:\Windows\system32\whoami.exe"
parentImage:      powershell.exe
rule.id:          100003
rule.level:       5
rule.firedtimes:  6

timestamp:        2026-04-12T22:28:43.681Z
image:            C:\Windows\System32\cmd.exe
commandLine:      "cmd.exe" /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
parentImage:      powershell.exe
rule.id:          92052
rule.level:       4
rule.firedtimes:  6

timestamp:        2026-04-12T22:28:43.725Z
image:            C:\Windows\System32\systeminfo.exe
commandLine:      systeminfo
parentImage:      cmd.exe
parentCommandLine: "cmd.exe" /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
rule.id:          92032
rule.level:       3
rule.firedtimes:  3
mitre:            T1087, T1059.003
```

---

## Analysis

Three rules fired across this technique and the highest level was 5. systeminfo chained with a registry query from a PowerShell-spawned cmd.exe is not a level 3 event. The full command line was visible in the log — the detection just did not treat it with appropriate severity. The T1087 and T1059.003 MITRE tags applied were also not accurate to what was actually happening.

---

## Rule status

No dedicated rule added. Severity tuning is the primary fix — this chain should sit at level 6-8 minimum. A rule specifically matching systeminfo combined with reg query in the same command line would be the more precise detection.
