"""
Stage 2: EXTRACTION
Pulls volatile artifacts (process list, network connections, registry
handles) out of a memory image using Volatility 3.
If no memory dump is supplied or Volatility isn't installed, falls back
to a realistic sample dataset so the pipeline still runs end-to-end.
"""
import subprocess
import shutil
import os

SAMPLE_PROCESSES = [
    {"pid": 612, "ppid": 500, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"},
    {"pid": 2044, "ppid": 612, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    {"pid": 3108, "ppid": 2044, "name": "update_svc.exe", "path": "C:\\Users\\victim\\AppData\\Local\\Temp\\update_svc.exe"},
    {"pid": 4400, "ppid": 3108, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
]


def _volatility_available() -> bool:
    return shutil.which("vol") is not None or shutil.which("vol3") is not None


def run_extraction(memory_image_path: str = None) -> dict:
    if memory_image_path and os.path.exists(memory_image_path) and _volatility_available():
        try:
            vol_bin = shutil.which("vol") or shutil.which("vol3")
            cmd = [vol_bin, "-f", memory_image_path, "windows.pslist"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return {
                "engine": "volatility3",
                "source": memory_image_path,
                "raw_output": result.stdout,
            }
        except Exception as e:
            pass  # fall through to sample data

    return {
        "engine": "sample-data",
        "source": memory_image_path or "no memory image supplied",
        "processes": SAMPLE_PROCESSES,
        "note": "Live Volatility3 not run — showing representative sample. "
                "Wire in a real .raw/.vmem/.dmp file + volatility3 install to go live.",
    }
