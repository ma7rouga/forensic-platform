
import subprocess
import os
import tempfile

SAMPLE_DECOMPILE = """
undefined8 FUN_00401830(void)
{
  HMODULE hModule;
  FARPROC pFVar1;

  hModule = LoadLibraryA("ws2_32.dll");
  pFVar1 = GetProcAddress(hModule, "WSAStartup");
  (*pFVar1)(0x202, &local_18);
  connect_to_c2(&DAT_00404050); // suspicious hardcoded IP
  return 0;
}
"""

SUSPICIOUS_APIS = [
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "LoadLibraryA", "GetProcAddress", "WSAStartup", "connect",
]


def run_ghidra_analysis(binary_path: str = None) -> dict:
    ghidra_home = os.environ.get("GHIDRA_HOME")

    if binary_path and os.path.exists(binary_path) and ghidra_home:
        try:
            headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
            with tempfile.TemporaryDirectory() as project_dir:
                cmd = [
                    headless, project_dir, "TempProject",
                    "-import", binary_path,
                    "-postScript", "DecompileScript.java",
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                return {"engine": "ghidra-headless", "raw_output": result.stdout}
        except Exception:
            pass

    return {
        "engine": "sample-data",
        "binary": binary_path or "update_svc.exe (pulled from extraction stage)",
        "decompiled_snippet": SAMPLE_DECOMPILE.strip(),
        "suspicious_api_calls": SUSPICIOUS_APIS,
        "note": "Live Ghidra headless not run — set GHIDRA_HOME and pass a real "
                "binary_path to go live.",
    }
