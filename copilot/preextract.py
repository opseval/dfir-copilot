#!/usr/bin/env python3
"""Pi PRE-EXTRACTION layer: parse raw DFIR tool output -> structured findings using GENERAL
analyst heuristics (not case-specific answers). The small model then narrates these findings
instead of reasoning from raw dumps. Each detector pattern-scans the text independently, so it
is robust to format variation across vol3 / EvtxECmd / Sysmon / MFTECmd output.

Finding = {indicator, severity(malicious|suspicious|benign-signal|info), evidence, why, next}
"""
import re, json, sys

LOLBINS = {
    "certutil": "certificate tool abused to download files (-urlcache/-f over HTTP)",
    "mshta": "executes remote/inline script (HTA) — common malware launcher",
    "regsvr32": "scriptlet execution / AppLocker bypass (scrobj)",
    "rundll32": "arbitrary DLL/JS execution proxy",
    "bitsadmin": "background file transfer abused for download",
    "wscript": "Windows Script Host — runs VBS/JS, classic macro payload",
    "cscript": "Windows Script Host (console) — runs VBS/JS",
}
SCRIPT_HOSTS = ("wscript", "cscript", "powershell", "mshta", "cmd")
OFFICE = ("winword", "excel", "powerpnt", "outlook", "mspub", "msaccess")
MS_GOOD_NETS = ("20.190.", "20.191.", "152.199.", "13.107.", "23.")  # MS service space / CDN (illustrative)

def add(F, **kw): F.append(kw)

def d_process_ancestry(t, F):
    # parent->child from Sysmon EID1 (Image/ParentImage) or pstree, or prose "X spawning Y"
    pairs = []
    for m in re.finditer(r'([A-Za-z0-9_.\\: ()]+\.exe)[^\n]*?(?:ParentImage|parent)[^\n]*?([A-Za-z0-9_.\\: ()]+\.exe)', t, re.I):
        pass
    # robust: pull Image + ParentImage columns if present
    img = re.search(r'(?<![Pa])Image[,:]\s*([^\n,;]+\.exe)', t, re.I)
    par = re.search(r'ParentImage[,:]\s*([^\n,;]+\.exe)', t, re.I)
    if img and par:
        pairs.append((par.group(1).strip(), img.group(1).strip()))
    # CSV header form: TimeCreated,Image,ParentImage,... value rows -> grab child,parent by position handled below
    if not pairs:
        # Office -> scripthost anywhere in text
        for o in OFFICE:
            for s in SCRIPT_HOSTS:
                if re.search(o, t, re.I) and re.search(s, t, re.I):
                    pairs.append((o + ".exe", s + ".exe")); break
    # pstree: services.exe parent of powershell/cmd (col PID PPID Image)
    if re.search(r'services\.exe', t, re.I) and re.search(r'(powershell|cmd)\.exe', t, re.I) and re.search(r'pstree|PPID', t, re.I):
        pairs.append(("services.exe", "powershell.exe"))
    for parent, child in pairs:
        p, c = parent.lower(), child.lower()
        if any(o in p for o in OFFICE) and any(s in c for s in SCRIPT_HOSTS):
            add(F, indicator="Office app spawned a script host", severity="malicious",
                evidence=f"{parent} -> {child}", why="Office apps do not invoke WSH/PowerShell in normal use; this is a VBA macro running a dropped script.",
                next="Recover the script from %TEMP%, hash it, and trace the script host's children (Sysmon EID1) + EID3 callbacks.")
        elif "services.exe" in p and any(s in c for s in ("powershell", "cmd")):
            add(F, indicator="services.exe directly spawned a shell", severity="malicious",
                evidence=f"{parent} -> {child}", why="services.exe launches only svchost/registered service binaries; a direct shell child means a malicious service ran as SYSTEM (persistence).",
                next="windows.svcscan for a recently-created service with a suspicious ImagePath; EvtxECmd System.evtx EID 7045 around the create time.")
        elif ("w3wp" in p or "httpd" in p) and any(s in c for s in ("cmd", "powershell")):
            add(F, indicator="Web worker spawned a shell", severity="malicious",
                evidence=f"{parent} -> {child}", why="A web server process spawning a shell is classic web-shell command execution.",
                next="Pull IIS/access logs for the triggering request; carve the handler from webroot.")

def d_encoded_cmd(t, F):
    if re.search(r'powershell[^\n]*?(-e(nc(odedcommand)?)?\b|-w\s*hidden|-nop|-noni)', t, re.I):
        b64 = re.search(r'-e(?:nc)?\s+([A-Za-z0-9+/=]{16,})', t, re.I)
        add(F, indicator="Obfuscated PowerShell", severity="malicious",
            evidence=(b64.group(0)[:60] if b64 else "powershell -nop -w hidden -enc ..."),
            why="-nop/-w hidden/-enc = non-interactive, hidden, base64-encoded execution: textbook malicious launcher.",
            next="Decode the -enc blob (base64 -> UTF-16LE) to read the payload; identify the parent process.")

def d_lolbin_net(t, F):
    for bin_, desc in LOLBINS.items():
        if re.search(rf'\b{bin_}\.exe\b', t, re.I) or re.search(rf'\b{bin_}\b', t, re.I):
            has_net = re.search(r'(ESTABLISHED|:80\b|:443\b|http://|-urlcache|ForeignAddr|\d+\.\d+\.\d+\.\d+\s+(80|443)\b)', t)
            if bin_ == "certutil" and has_net:
                add(F, indicator="certutil with a network connection (LOLBin download)", severity="malicious",
                    evidence="certutil.exe + outbound socket", why="certutil handles certificates, not HTTP; an outbound socket means `certutil -urlcache -f http://...` payload staging.",
                    next="windows.cmdline --pid <pid> to recover the URL; windows.pstree --pid <pid> for the parent; block the IP.")
            elif bin_ in ("wscript", "cscript") and re.search(r'\.vbs|\.js\b|Temp', t, re.I):
                add(F, indicator=f"{bin_} running a script from a temp path", severity="suspicious",
                    evidence=f"{bin_} ... .vbs/.js", why=desc + "; staged in %TEMP% with a lure name = likely dropper.",
                    next="Recover and read the script; hash it; trace its children.")

def d_malfind(t, F):
    if not re.search(r'PAGE_EXECUTE_READWRITE|VadS', t):
        return
    proc = re.search(r'(\w+\.exe)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+VadS', t, re.I)
    pname = proc.group(1).lower() if proc else (re.search(r'(\w+\.exe)', t).group(1).lower() if re.search(r'(\w+\.exe)', t) else "a process")
    # benign-signal: .NET JIT
    jit = re.search(r'clrjit\.dll|clr\.dll|\.NET', t, re.I)
    clean_prologue = re.search(r'push\s+(rbp|ebp).{0,40}mov\s+(ebp|rbp),\s*(esp|rsp)', t, re.I | re.S)
    mz = re.search(r'\b4d\s*5a\b|^MZ', t, re.I | re.M)
    trampoline = re.search(r'\be9\b(\s+[0-9a-f]{2}){0,4}\s+90\s+90', t, re.I)
    c2 = re.search(r'MSSE-|cobalt|beacon|meterpreter|\\\\\.\\pipe', t, re.I)
    if "lsass" in pname:
        add(F, indicator="RWX executable memory inside lsass.exe", severity="malicious",
            evidence=f"{pname} VadS PAGE_EXECUTE_READWRITE", why="lsass (the credential authority) never legitimately allocates writable+executable memory — strong sign of credential-theft injection.",
            next="windows.malfind --pid <pid> --dump; YARA the dump (REMnux); windows.handles --pid <pid> for named pipes; treat all creds on this host as compromised.")
    if mz:
        add(F, indicator="MZ/PE header in injected region", severity="malicious", evidence="bytes begin 4D 5A",
            why="An MZ header in a private RWX region = a reflectively-loaded PE (injected module).", next="Dump and triage the PE with capa/floss in REMnux.")
    if trampoline and not clean_prologue:
        add(F, indicator="jmp trampoline + NOP padding", severity="malicious", evidence="e9 .. 90 90",
            why="A jump stub followed by NOP sled is shellcode, not a compiled function.", next="Dump the region and disassemble fully.")
    if c2:
        add(F, indicator="C2 artifact string in memory", severity="malicious", evidence=c2.group(0),
            why="Named-pipe/beacon strings (e.g. MSSE-%d-server) match known C2 tradecraft (Cobalt Strike SMB beacon).",
            next="YARA the region against beacon rules; enumerate pipe handles.")
    if (jit or clean_prologue) and not (mz or trampoline or c2 or "lsass" in pname):
        add(F, indicator="RWX region is .NET JIT code (likely benign)", severity="benign-signal",
            evidence=("clrjit.dll loaded" if jit else "valid managed prologue"), why="A clean compiled prologue with the CLR JIT loaded (and no MZ/sled/C2) is normal .NET RWX JIT heap, not injection.",
            next="No action on this region; if PowerShell is in question pivot to its Operational log via EvtxECmd.")

def d_network(t, F):
    for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)\s+(\d{1,5})\s+ESTABLISHED\s+(\d+)\s+(\w+\.exe)', t):
        fip, fport, pid, proc = m.groups()
        if any(fip.startswith(g) for g in MS_GOOD_NETS):
            add(F, indicator="Outbound to Microsoft/CDN space", severity="benign-signal",
                evidence=f"{proc} -> {fip}:{fport}", why="Destination is Microsoft service/CDN range over 443 with a sane host process — consistent with Windows Update / delivery optimization.",
                next="Confirm svchost hosts wuauserv/DoSvc (windows.svcscan) and parent is services.exe.")
        elif proc.lower().split('.')[0] in LOLBINS:
            add(F, indicator=f"{proc} holding a network socket", severity="malicious",
                evidence=f"{proc} -> {fip}:{fport}", why=f"{proc} is a LOLBin; an outbound socket means it is being used to download/stage, not its real purpose.",
                next="Recover the command line; identify parent; block the destination.")

def d_eventids(t, F):
    if re.search(r'\b4648\b', t) and re.search(r'\b4624\b.*Type\s*3', t, re.S) and re.search(r'NTLM|NtLmSsp', t, re.I):
        add(F, indicator="Explicit-cred logon (4648) -> remote NTLM logon (4624 Type 3) + admin (4672)", severity="malicious",
            evidence="4648 + 4624 Type3 NTLM + 4672", why="A user supplying a different privileged account, NTLM (not Kerberos), landing on another host one second later with admin privileges = hands-on-keyboard lateral movement / pass-the-hash.",
            next="Scope every host the privileged account touched (DuckDB over 4624/4648); disable+rotate it; acquire the source workstation for LSASS-access analysis.")
    elif re.search(r'\b4625\b', t) and re.search(r'\b4624\b', t) and re.search(r'Type\s*2', t) and re.search(r'0xC000006A', t, re.I) and len(re.findall(r'\b4625\b', t)) == 1:
        add(F, indicator="Single failed then successful interactive logon (same host)", severity="benign-signal",
            evidence="one 4625 Type2 0xC000006A then 4624 Type2", why="A single wrong-password failure (0xC000006A) followed by success at the user's own workstation is baseline mistyped-password behavior.",
            next="None — reserve attention for repeated failures, multiple accounts, or remote (Type 3/10) sources.")
    elif len(re.findall(r'\b4625\b', t)) >= 3:
        add(F, indicator="Multiple failed logons (possible brute force)", severity="suspicious",
            evidence=f"{len(re.findall(r'4625', t))}x 4625", why="Repeated authentication failures indicate brute force or password spray.",
            next="Aggregate 4625 by source IP and target account in DuckDB; check for a subsequent 4624 success.")
    if re.search(r'\b7045\b', t):
        add(F, indicator="New service installed (7045)", severity="suspicious", evidence="EID 7045",
            why="A newly-installed service is a common SYSTEM-level persistence mechanism.", next="Inspect the service ImagePath; correlate with the process tree.")
    sched = re.search(r'\b(4698|106)\b', t)
    if sched:
        taskname = re.search(r'(?:TaskName|Task)[,:]\s*([^\n,;]+)', t)
        tn = taskname.group(1).strip() if taskname else ""
        if re.search(r'GoogleUpdate|\\Microsoft\\Windows\\', t) and re.search(r'Program Files', t) and re.search(r'SYSTEM', t, re.I):
            add(F, indicator="Scheduled task registration (looks like a vendor auto-updater)", severity="benign-signal",
                evidence=tn or "vendor update task", why="Canonical task name, vendor binary in Program Files, created by SYSTEM, documented args = normal software auto-update.",
                next="Optionally verify the binary signature and that the create time matches a software push; baseline it.")
        else:
            add(F, indicator="Scheduled task registered — action unknown", severity="suspicious",
                evidence=tn or "EID 4698/106", why="EID 106/4698 records registration only, not the Exec command; a non-stock task name or off-hours/non-admin author is worth resolving before clearing.",
                next="Read C:\\Windows\\System32\\Tasks\\<path> for <Command>/<Arguments>; pull paired EID 200/201 for the action.")

def d_webshell_mft(t, F):
    for m in re.finditer(r'([\w.\-]+\.(?:aspx?|ashx|asmx|php|jsp))[^\n]*?(wwwroot|aspnet_client|inetpub)', t, re.I):
        fn, path = m.group(1), m.group(2)
        add(F, indicator="Server-side script written into a web directory", severity="malicious",
            evidence=f"{fn} in {path}", why="Executable web handlers (.aspx/.php) created in static framework dirs like aspnet_client/system_web are web shells (e.g. ProxyShell drops); these paths should never hold handlers.",
            next="Carve and hash the file; grep for eval/Request/Process.Start; pull IIS logs for the first POST to it to fix the attacker IP/time.")

def d_account_group(t, F):
    if re.search(r'\b1102\b', t) and re.search(r'log.{0,20}clear|audit.{0,20}clear', t, re.I):
        add(F, indicator="Security audit log was cleared (1102)", severity="suspicious", evidence="EID 1102",
            why="Clearing the Security log is a common anti-forensic/cleanup step after intrusion (and the act itself is evidence).",
            next="Pull surrounding events from forwarded logs / SIEM; note who/when; treat as tampering until explained.")
    if re.search(r'\b4720\b', t):
        add(F, indicator="New user account created (4720)", severity="suspicious", evidence="EID 4720",
            why="Account creation can be legitimate IT or attacker persistence/backdoor — verify the creator and timing.",
            next="Correlate with 4732/4728 (group adds) and the creating account; confirm against a change ticket.")
    if re.search(r'\b(4732|4728)\b', t) and re.search(r'admin|Domain Admins|Enterprise Admins', t, re.I):
        add(F, indicator="Account added to a privileged group (4732/4728)", severity="malicious", evidence="EID 4732/4728 -> admin group",
            why="Adding a user to Administrators / Domain Admins is high-value privilege escalation / persistence.",
            next="Identify the member + who added it; revert if unsanctioned; hunt that account's recent logons (4624/4648).")

def d_ps_scriptblock(t, F):
    if re.search(r'\b4104\b', t) or re.search(r'ScriptBlock', t, re.I):
        if re.search(r'DownloadString|DownloadFile|IEX|Invoke-Expression|FromBase64String|-enc\b|Net\.WebClient|Reflection\.Assembly|hidden', t, re.I):
            add(F, indicator="Suspicious PowerShell ScriptBlock (4104)", severity="malicious", evidence="4104 w/ download/IEX/base64",
                why="ScriptBlock logging captured download-cradle / in-memory execution primitives (IEX, Net.WebClient, FromBase64String) — fileless execution.",
                next="Reconstruct the full script from the 4104 sequence; extract URLs/IOCs; hunt the parent and any dropped payload.")

def d_kerberos(t, F):
    if re.search(r'\b4769\b', t) and re.search(r'0x17|RC4', t, re.I):
        add(F, indicator="Kerberos service ticket with RC4 (4769 0x17)", severity="suspicious", evidence="4769 EncryptionType 0x17",
            why="RC4-encrypted service tickets are a Kerberoasting / downgrade signal in AES-capable environments.",
            next="Identify the targeted SPN/service account; check for offline-cracking follow-on; rotate the service account.")

def d_registry_persist(t, F):
    if re.search(r'\\Run\b|\\RunOnce\b|CurrentVersion\\Run', t, re.I) and re.search(r'powershell|rundll32|mshta|\\Temp\\|\\AppData\\|-enc|http', t, re.I):
        add(F, indicator="Run-key persistence with a suspicious value", severity="malicious", evidence="...\\CurrentVersion\\Run -> script/temp/encoded",
            why="An autorun (Run/RunOnce) value pointing at a script host, temp path, or encoded command is classic user-logon persistence.",
            next="Read the full value; resolve/recover the target; check creation time vs the intrusion window.")
    if re.search(r'ImagePath', t, re.I) and re.search(r'\\Temp\\|\\AppData\\|powershell|rundll32|cmd /c', t, re.I):
        add(F, indicator="Service ImagePath looks malicious", severity="malicious", evidence="service ImagePath -> temp/script",
            why="A service pointing at a temp path or a shell/script host (not a real binary in Program Files/System32) is malicious service persistence.",
            next="windows.svcscan for the service; correlate EID 7045; recover the target binary.")

def d_exec_path(t, F):
    for m in re.finditer(r'((?:[A-Za-z]:\\|\\)[^\s"\']*\\(?:Temp|AppData|Downloads|Public|ProgramData)\\[^\s"\']*\.(?:exe|dll|scr|ps1|vbs|js))', t, re.I):
        add(F, indicator="Execution from a user-writable / staging path", severity="suspicious", evidence=m.group(1)[:80],
            why="Binaries run from %TEMP%/%AppData%/Downloads/Public/ProgramData are a strong malware-staging signal; trusted software runs from Program Files/System32.",
            next="Hash the file and check reputation; carve it; identify what launched it (parent process / autorun).")

def d_hidden_proc(t, F):
    if re.search(r'psxview|psscan', t, re.I) and re.search(r'\bFalse\b', t) and re.search(r'pslist', t, re.I):
        add(F, indicator="Process hidden from the active process list", severity="malicious", evidence="psxview: pslist=False",
            why="A process visible to pool scanning but absent from the linked process list is being hidden (rootkit / direct unlinking).",
            next="windows.malfind / windows.dlllist on that PID; dump it; check for unlinked modules (ldrmodules).")

def d_capa(t, F):
    caps = re.findall(r'(encrypt(?:ion)? of files|ransom|inject (?:code|process)|keylog|capture screenshot|anti-(?:debug|vm|analysis)|persist|create service|disable (?:security|defender)|spawn (?:a )?shell)', t, re.I)
    if re.search(r'\bcapa\b|ATT&CK|MBC|capability', t, re.I) and caps:
        uniq = sorted({c.lower() for c in caps})
        sev = "malicious" if any(k in " ".join(uniq) for k in ("ransom", "encrypt", "inject", "keylog", "anti-")) else "suspicious"
        add(F, indicator="capa flagged high-risk capabilities", severity=sev, evidence=", ".join(uniq)[:90],
            why="capa matched offensive capabilities in the binary — strong intent signal even before dynamic analysis.",
            next="Prioritize by capability (encryption->ransomware, inject->loader); floss the binary for IOCs; YARA against family rules.")

DETECTORS = [d_process_ancestry, d_encoded_cmd, d_lolbin_net, d_malfind, d_network, d_eventids,
             d_webshell_mft, d_account_group, d_ps_scriptblock, d_kerberos, d_registry_persist,
             d_exec_path, d_hidden_proc, d_capa]

def extract(raw):
    F = []
    for d in DETECTORS:
        try: d(raw, F)
        except Exception as e:
            import sys as _sys
            _sys.stderr.write(f"[preextract] detector {getattr(d, '__name__', d)} failed: {e}\n")
    # dedup by (indicator, evidence)
    seen, out = set(), []
    for f in F:
        k = (f["indicator"], f.get("evidence", ""))
        if k in seen: continue
        seen.add(k); out.append(f)
    sev_rank = {"malicious": 0, "suspicious": 1, "benign-signal": 2, "info": 3}
    out.sort(key=lambda f: sev_rank.get(f["severity"], 9))
    return out

def findings_block(raw):
    F = extract(raw)
    if not F:
        return "PRE-EXTRACTION: no known indicators matched. Reason from the raw output directly."
    lines = ["PRE-EXTRACTED FINDINGS (deterministic indicator scan; highest severity first):"]
    for i, f in enumerate(F, 1):
        lines.append(f"{i}. [{f['severity'].upper()}] {f['indicator']}")
        lines.append(f"   evidence: {f['evidence']}")
        lines.append(f"   why: {f['why']}")
        lines.append(f"   suggested next: {f['next']}")
    return "\n".join(lines)

if __name__ == "__main__":
    raw = sys.stdin.read() if not sys.argv[1:] else open(sys.argv[1]).read()
    print(findings_block(raw))
