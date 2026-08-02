

import json
import os


def _load_json_file(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return None
        return json.loads(content)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[volatility_parser] Failed to read {path}: {e}")
        return None


def _flatten_pstree(nodes, flat_list=None):
    """pstree.json is a nested tree (each process has __children). This
    walks it recursively and produces one flat list — easier for the UI
    and for the MemMal-D2024 scorer to work with."""
    if flat_list is None:
        flat_list = []
    for node in nodes:
        children = node.get("__children", [])
        flat_list.append({
            "pid": node.get("PID"),
            "ppid": node.get("PPID"),
            "name": node.get("ImageFileName"),
            "threads": node.get("Threads"),
            "created": node.get("CreateTime"),
            "session_id": node.get("SessionId"),
            "wow64": node.get("Wow64"),
        })
        if children:
            _flatten_pstree(children, flat_list)
    return flat_list


def load_pstree(path="pstree.json"):
    data = _load_json_file(path)
    if data is None:
        return []
    return _flatten_pstree(data)


def load_netscan(path="netscan.json"):
    data = _load_json_file(path)
    if data is None:
        return []
    # netscan.json is already a flat list — field names may vary slightly
    # by Volatility version, so we pull with .get() defensively rather
    # than assuming exact keys.
    connections = []
    for entry in data:
        connections.append({
            "proto": entry.get("Proto"),
            "local_addr": entry.get("LocalAddr"),
            "local_port": entry.get("LocalPort"),
            "foreign_addr": entry.get("ForeignAddr"),
            "foreign_port": entry.get("ForeignPort"),
            "state": entry.get("State"),
            "pid": entry.get("PID"),
            "owner": entry.get("Owner"),
        })
    return connections


def load_malfind(path="malfind.json"):
    data = _load_json_file(path)
    if data is None:
        return []
    findings = []
    for entry in data:
        findings.append({
            "pid": entry.get("PID"),
            "process": entry.get("Process"),
            "start_vpn": entry.get("Start VPN"),
            "protection": entry.get("Protection"),
            "commit_charge": entry.get("CommitCharge"),
            "notes": entry.get("Notes"),
        })
    return findings


def summarize_pstree(procs):
    """Quick derived stats useful for the AI scoring layer and the UI —
    matches the kind of aggregate features MemMal-D2024 was trained on
    (e.g. pslist.nproc, pslist.avg_threads)."""
    if not procs:
        return {}
    thread_counts = [p["threads"] for p in procs if p.get("threads") is not None]
    return {
        "nproc": len(procs),
        "avg_threads": round(sum(thread_counts) / len(thread_counts), 2) if thread_counts else 0,
    }