"""
Stage 1: NETSCAN
Discovers live hosts / open ports on a target.
Tries nmap first (if installed), falls back to a pure-Python
socket scanner so this stage ALWAYS works, even with nothing installed.
"""
import subprocess
import shutil
import socket
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-alt",
}


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _run_nmap(target: str) -> dict:
    cmd = ["nmap", "-sV", "-T4", "--top-ports", "50", target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return {
        "engine": "nmap",
        "target": target,
        "raw_output": result.stdout,
        "timestamp": datetime.now().isoformat(),
    }


def _run_socket_scan(target: str) -> dict:
    open_ports = []
    for port, name in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            if sock.connect_ex((target, port)) == 0:
                open_ports.append({"port": port, "service": name})
        except (socket.gaierror, OSError):
            pass
        finally:
            sock.close()
    return {
        "engine": "python-socket-scanner",
        "target": target,
        "open_ports": open_ports,
        "timestamp": datetime.now().isoformat(),
    }


def run_netscan(target: str = "127.0.0.1") -> dict:
    """Entry point called by the orchestrator."""
    try:
        if _nmap_available():
            return _run_nmap(target)
        return _run_socket_scan(target)
    except Exception as e:
        return {"engine": "error", "target": target, "error": str(e)}
