"""
Stage 3: INJECTION DETECTION
Looks for code that malware injected into legitimate processes
(classic DFIR technique — Volatility's `malfind` plugin flags memory
regions with RWX permissions and no backing file, a strong injection
indicator). Falls back to sample flagged findings if Volatility/malfind
isn't available, keeping the pipeline demoable.
"""
import subprocess
import shutil
import os

SAMPLE_FINDINGS = [
    {
        "pid": 3108,
        "process": "update_svc.exe",
        "region": "0x00007ff6a1230000",
        "protection": "PAGE_EXECUTE_READWRITE",
        "indicator": "RWX region, no backing file",
        "verdict": "Likely process hollowing / shellcode injection",
    },
    {
        "pid": 2044,
        "process": "powershell.exe",
        "region": "0x000001f3c4410000",
        "protection": "PAGE_EXECUTE_READWRITE",
        "indicator": "Reflective PE load pattern (MZ header in private memory)",
        "verdict": "Likely reflective DLL injection",
    },
]


def _volatility_available() -> bool:
    return shutil.which("vol") is not None or shutil.which("vol3") is not None


def run_injection_scan(memory_image_path: str = None) -> dict:
    if memory_image_path and os.path.exists(memory_image_path) and _volatility_available():
        try:
            vol_bin = shutil.which("vol") or shutil.which("vol3")
            cmd = [vol_bin, "-f", memory_image_path, "windows.malfind"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return {"engine": "volatility3-malfind", "raw_output": result.stdout}
        except Exception:
            pass

    return {
        "engine": "sample-data",
        "findings": SAMPLE_FINDINGS,
        "note": "Live malfind not run — showing representative sample findings.",
    }
