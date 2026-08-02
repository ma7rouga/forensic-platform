# Forensic Investigation Report
_Generated 2026-08-03 00:15_

## 1. Network scan
```
{'engine': 'python-socket-scanner', 'target': '127.0.0.1', 'open_ports': [{'port': 135, 'service': 'MSRPC'}, {'port': 445, 'service': 'SMB'}, {'port': 8080, 'service': 'HTTP-alt'}], 'timestamp': '2026-08-03T00:13:51.550459'}
```

## 2. Memory extraction
```
{'engine': 'sample-data', 'source': 'no memory image supplied', 'processes': [{'pid': 612, 'ppid': 500, 'name': 'svchost.exe', 'path': 'C:\\Windows\\System32\\svchost.exe'}, {'pid': 2044, 'ppid': 612, 'name': 'powershell.exe', 'path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'}, {'pid': 3108, 'ppid': 2044, 'name': 'update_svc.exe', 'path': 'C:\\Users\\victim\\AppData\\Local\\Temp\\update_svc.exe'}, {'pid': 4400, 'ppid': 3108, 'name': 'explorer.exe', 'path': 'C:\\Windows\\explorer.exe'}], 'note': 'Live Volatility3 not run — showing representative sample. Wire in a real .raw/.vmem/.dmp file + volatility3 install to go live.'}
```

## 3. Code injection detection
```
{'engine': 'sample-data', 'findings': [{'pid': 3108, 'process': 'update_svc.exe', 'region': '0x00007ff6a1230000', 'protection': 'PAGE_EXECUTE_READWRITE', 'indicator': 'RWX region, no backing file', 'verdict': 'Likely process hollowing / shellcode injection'}, {'pid': 2044, 'process': 'powershell.exe', 'region': '0x000001f3c4410000', 'protection': 'PAGE_EXECUTE_READWRITE', 'indicator': 'Reflective PE load pattern (MZ header in private memory)', 'verdict': 'Likely reflective DLL injection'}], 'note': 'Live malfind not run — showing representative sample findings.'}
```

## 3b. Live results — Volatility3 malfind
1729 suspicious region(s) detected on real memory capture:
- PID 4156 (LenovoVantageS) — protection: PAGE_EXECUTE_READWRITE
- PID 4476 (VoiceAssistant) — protection: PAGE_EXECUTE_READWRITE
- PID 4564 (servicehost.ex) — protection: PAGE_EXECUTE_READWRITE
- PID 4564 (servicehost.ex) — protection: PAGE_EXECUTE_READWRITE
- PID 5500 (rsDNSSvc.exe) — protection: PAGE_EXECUTE_READWRITE
- PID 5684 (rsVPNSvc.exe) — protection: PAGE_EXECUTE_READWRITE
- PID 6196 (MsMpEng.exe) — protection: PAGE_EXECUTE_READWRITE
- PID 6196 (MsMpEng.exe) — protection: PAGE_EXECUTE_READWRITE
- PID 6196 (MsMpEng.exe) — protection: PAGE_EXECUTE_READWRITE
- PID 6196 (MsMpEng.exe) — protection: PAGE_EXECUTE_READWRITE

## 4. Ghidra analysis
```
{'engine': 'sample-data', 'binary': 'update_svc.exe (pulled from extraction stage)', 'decompiled_snippet': 'undefined8 FUN_00401830(void)\n{\n  HMODULE hModule;\n  FARPROC pFVar1;\n\n  hModule = LoadLibraryA("ws2_32.dll");\n  pFVar1 = GetProcAddress(hModule, "WSAStartup");\n  (*pFVar1)(0x202, &local_18);\n  connect_to_c2(&DAT_00404050); // suspicious hardcoded IP\n  return 0;\n}', 'suspicious_api_calls': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibraryA', 'GetProcAddress', 'WSAStartup', 'connect'], 'note': 'Live Ghidra headless not run — set GHIDRA_HOME and pass a real binary_path to go live.'}
```

## 5. MITRE ATT&CK mapping
- **T1036 — Masquerading** (Tactic: Defense Evasion)
- **T1055 — Process Injection** (Tactic: Defense Evasion)
- **T1059.001 — Command and Scripting Interpreter: PowerShell** (Tactic: Execution)
- **T1071.001 — Application Layer Protocol: Web Protocols** (Tactic: Command and Control)

## 6. Registry
```
{'computer_name': 'SAMPLE-PC', 'run_keys': ['C:\\sample\\startup_entry.exe']}
```

## 7. Analysis (AI)
Sample analysis (offline mode): The captured memory image shows a process tree consistent with normal system activity. No high-confidence code injection was found by malfind, and no active network connections were observed at capture time. This is placeholder text shown when no API key is configured.

## 8. Conclusion
See indicators and AI analysis above. Sections still marked 'sample data' indicate a stage where the real tool was not available in this environment — the underlying pipeline is already wired to accept live input for those stages.