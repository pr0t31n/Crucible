"""Adapter registry -- lazy-import and cache adapter instances by tool_id."""

_ADAPTER_MAP = {
    "fracture":  ("adapters.fracture",      "FractureAdapter"),
    "siphon":    ("adapters.siphon",         "SiphonAdapter"),
    "ss3":       ("adapters.scattershot3",   "Scattershot3Adapter"),
    "osift":     ("adapters.osift",          "OSiftAdapter"),
    "aether":    ("adapters.aether",         "AetherAdapter"),
    "aether_b":  ("adapters.aether_b",       "AetherBAdapter"),
    "aether_z":  ("adapters.aether_z",       "AetherZAdapter"),
    "aether_u":  ("adapters.aether_u",       "AetherUAdapter"),
    "authprobe": ("adapters.authprobe",      "AuthProbeAdapter"),
    "auger":     ("adapters.auger",          "AugerAdapter"),
    "nessus":    ("adapters.nessus",         "NessusAdapter"),
    "trawler":   ("adapters.trawler",        "TrawlerAdapter"),
    "bastion":   ("adapters.bastion",        "BastionAdapter"),
    "forge":     ("adapters.forge",          "ForgeAdapter"),
    "quill":     ("adapters.quill",          "QuillAdapter"),
    "isotope":   ("adapters.isotope",        "IsotopeAdapter"),
    "dredge":    ("adapters.dredge",         "DredgeAdapter"),
    # ── External CLI tools ──────────────────────────────────────
    "nuclei":         ("adapters.external", "NucleiAdapter"),
    "testssl":        ("adapters.external", "TestSSLAdapter"),
    "sslscan":        ("adapters.external", "SSLScanAdapter"),
    "droopescan":     ("adapters.external", "DroopeScanAdapter"),
    "dnstwist":       ("adapters.external", "DNSTwistAdapter"),
    "xurlfind3r":     ("adapters.external", "XURLFind3rAdapter"),
    "emailharvester": ("adapters.external", "EmailHarvesterAdapter"),
    "asnmap":         ("adapters.external", "ASNMapAdapter"),
    "webanalyze":     ("adapters.external", "WebAnalyzeAdapter"),
    "amass":          ("adapters.external", "AmassAdapter"),
}

_instances = {}


def get_adapter(tool_id):
    """Get adapter instance by tool_id. Lazily imports and caches."""
    if tool_id in _instances:
        return _instances[tool_id]
    entry = _ADAPTER_MAP.get(tool_id)
    if not entry:
        return None
    module_path, class_name = entry
    import importlib
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    inst = cls()
    _instances[tool_id] = inst
    return inst


def all_adapters():
    """Return all adapter instances (triggers lazy import of all)."""
    for tid in _ADAPTER_MAP:
        get_adapter(tid)
    return dict(_instances)
