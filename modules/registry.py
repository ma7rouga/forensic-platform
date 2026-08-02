import os
try:
    from regipy.registry import RegistryHive
    _REGIPY_AVAILABLE = True
except ImportError:
    _REGIPY_AVAILABLE = False

SAMPLE_REGISTRY = {
    "computer_name": "SAMPLE-PC",
    "run_keys": ["C:\\sample\\startup_entry.exe"],
}


def load_registry_summary(hive_path=None):
    if not (_REGIPY_AVAILABLE and hive_path and os.path.exists(hive_path)):
        return SAMPLE_REGISTRY
    try:
        hive = RegistryHive(hive_path)
        run_keys = []
        for entry in hive.recurse_subkeys(as_json=True):
            if entry.path and "Run" in entry.path:
                for value in entry.values:
                    run_keys.append(f"{entry.path}\\{value.name}: {value.value}")
        return {"computer_name": hive.name, "run_keys": run_keys}
    except Exception as e:
        print(f"[registry] Failed to parse hive: {e}")
        return SAMPLE_REGISTRY