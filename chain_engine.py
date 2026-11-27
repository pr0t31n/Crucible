"""Attack Chain Visualization — data model, storage, and auto-detection engine."""

import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path

log = logging.getLogger("crucible.chain_engine")

# ── Constants ────────────────────────────────────────────────────

NODE_TYPES = ("DISCOVERY", "FINDING", "CREDENTIAL", "ACCESS", "IMPACT")

EDGE_RELATIONS = (
    "leads_to", "exposes", "grants", "enables", "escalates",
    "pivots_to", "chains_with", "requires", "mitigated_by", "impacts",
)

CONFIDENCE_LEVELS = ("Certain", "Firm", "Tentative")

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

CHAINS_FILE = "chains.json"

# ── Keywords used by the auto-detection engine ───────────────────

_ACCESS_KEYWORDS = (
    "pwned", "shell", "access obtained", "remote code execution",
    "command execution", "rce", "reverse shell", "bind shell",
    "code execution", "root access", "admin access",
)

_CREDENTIAL_KEYWORDS = (
    "default cred", "weak password", "credential", "password",
    "brute force", "password spray", "clear-text", "plaintext password",
    "hardcoded password", "default password",
)

_PRIVESC_KEYWORDS = (
    "privilege escalation", "sudo", "kernel", "suid", "setuid",
    "root", "local privilege", "uac bypass", "token impersonation",
)

_EXFIL_KEYWORDS = (
    "sensitive data", "pii", "phi", "credit card", "database dump",
    "data exposure", "information disclosure", "patient data",
    "ssn", "hipaa", "data leak",
)

_PIVOT_KEYWORDS = (
    "lateral movement", "pivot", "psexec", "wmi", "pass-the-hash",
    "pass the ticket", "remote service", "ssh from",
)

_WEB_TOOLS = ("fracture", "nuclei", "nikto", "wpscan", "gobuster")
_API_TOOLS = ("siphon",)
_RECON_TOOLS = ("scattershot3", "ss3", "osift")
_WIRELESS_TOOLS = ("aether", "aether_b", "aether_z", "aether_u")

# ACH catalogue IDs → names
ACH_CATALOGUE = {
    "ACH-001": "Multi-Stage Network Penetration",
    "ACH-002": "Credential Harvesting Chain",
    "ACH-003": "Lateral Movement Path",
    "ACH-004": "Privilege Escalation Chain",
    "ACH-005": "Data Exfiltration Path",
    "ACH-006": "Web Application Attack Chain",
    "ACH-007": "API Exploitation Chain",
    "ACH-008": "Wireless to Internal Pivot",
    "ACH-009": "Physical Access Exploitation",
    "ACH-010": "Supply Chain Attack Path",
    "ACH-011": "Social Engineering Chain",
    "ACH-012": "Configuration Weakness Chain",
    "ACH-013": "Cryptographic Weakness Chain",
    "ACH-014": "Medical Device Attack Chain",
    "ACH-015": "Embedded System Attack Chain",
    "ACH-016": "Container/Cloud Escape Chain",
}


# ── Data Model ───────────────────────────────────────────────────

class ChainNode:
    def __init__(self, id=None, node_type="FINDING", label="", finding_id=None,
                 tool="", ip="", port=0, risk="INFO", metadata=None):
        self.id = id or str(uuid.uuid4())
        self.node_type = node_type if node_type in NODE_TYPES else "FINDING"
        self.label = label
        self.finding_id = finding_id
        self.tool = tool
        self.ip = ip
        self.port = int(port) if port else 0
        self.risk = risk.upper() if risk else "INFO"
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "id": self.id,
            "node_type": self.node_type,
            "label": self.label,
            "finding_id": self.finding_id,
            "tool": self.tool,
            "ip": self.ip,
            "port": self.port,
            "risk": self.risk,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            id=d.get("id"),
            node_type=d.get("node_type", "FINDING"),
            label=d.get("label", ""),
            finding_id=d.get("finding_id"),
            tool=d.get("tool", ""),
            ip=d.get("ip", ""),
            port=d.get("port", 0),
            risk=d.get("risk", "INFO"),
            metadata=d.get("metadata") or {},
        )


class ChainEdge:
    def __init__(self, source_id="", target_id="", relation="leads_to",
                 confidence="Firm", description=""):
        self.source_id = source_id
        self.target_id = target_id
        self.relation = relation if relation in EDGE_RELATIONS else "leads_to"
        self.confidence = confidence if confidence in CONFIDENCE_LEVELS else "Firm"
        self.description = description

    def to_dict(self):
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "confidence": self.confidence,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            source_id=d.get("source_id", ""),
            target_id=d.get("target_id", ""),
            relation=d.get("relation", "leads_to"),
            confidence=d.get("confidence", "Firm"),
            description=d.get("description", ""),
        )


class AttackChain:
    def __init__(self, id=None, name="", description="", risk="INFO",
                 nodes=None, edges=None, auto_detected=False,
                 template_id=None, created=None, modified=None):
        self.id = id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.risk = risk.upper() if risk else "INFO"
        self.nodes = nodes or []
        self.edges = edges or []
        self.auto_detected = auto_detected
        self.template_id = template_id
        self.created = created or datetime.now().isoformat()
        self.modified = modified or datetime.now().isoformat()

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "risk": self.risk,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "auto_detected": self.auto_detected,
            "template_id": self.template_id,
            "created": self.created,
            "modified": self.modified,
        }

    @classmethod
    def from_dict(cls, d):
        nodes = [ChainNode.from_dict(n) for n in d.get("nodes", [])]
        edges = [ChainEdge.from_dict(e) for e in d.get("edges", [])]
        return cls(
            id=d.get("id"),
            name=d.get("name", ""),
            description=d.get("description", ""),
            risk=d.get("risk", "INFO"),
            nodes=nodes,
            edges=edges,
            auto_detected=d.get("auto_detected", False),
            template_id=d.get("template_id"),
            created=d.get("created"),
            modified=d.get("modified"),
        )

    def compute_risk(self):
        """Derive chain risk from the highest-risk node."""
        best = "INFO"
        for n in self.nodes:
            if RISK_ORDER.get(n.risk, 99) < RISK_ORDER.get(best, 99):
                best = n.risk
        self.risk = best
        return best


# ── Storage ──────────────────────────────────────────────────────

def _chains_path(project_dir):
    return Path(project_dir) / CHAINS_FILE


def load_chains(project_dir):
    p = _chains_path(project_dir)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [AttackChain.from_dict(d) for d in data]
    except Exception as exc:
        log.warning("Failed to load chains from %s: %s", p, exc)
    return []


def save_chains(project_dir, chains):
    p = _chains_path(project_dir)
    tmp = p.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps([c.to_dict() for c in chains], indent=2),
            encoding="utf-8",
        )
        tmp.replace(p)
    except Exception as exc:
        log.error("Failed to save chains to %s: %s", p, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def get_chain(project_dir, chain_id):
    for c in load_chains(project_dir):
        if c.id == chain_id:
            return c
    return None


def add_chain(project_dir, chain):
    chains = load_chains(project_dir)
    chains.append(chain)
    save_chains(project_dir, chains)
    return chain


def update_chain(project_dir, chain_id, data):
    chains = load_chains(project_dir)
    for i, c in enumerate(chains):
        if c.id == chain_id:
            if "name" in data:
                c.name = data["name"]
            if "description" in data:
                c.description = data["description"]
            if "risk" in data:
                c.risk = data["risk"].upper()
            if "nodes" in data:
                c.nodes = [ChainNode.from_dict(n) for n in data["nodes"]]
            if "edges" in data:
                c.edges = [ChainEdge.from_dict(e) for e in data["edges"]]
            if "template_id" in data:
                c.template_id = data["template_id"]
            c.modified = datetime.now().isoformat()
            chains[i] = c
            save_chains(project_dir, chains)
            return c
    return None


def delete_chain(project_dir, chain_id):
    chains = load_chains(project_dir)
    before = len(chains)
    chains = [c for c in chains if c.id != chain_id]
    if len(chains) < before:
        save_chains(project_dir, chains)
        return True
    return False


# ── Helpers for auto-detection ───────────────────────────────────

def _lower_title(f):
    return (f.get("title") or "").lower()


def _lower_desc(f):
    return (f.get("description") or "").lower()


def _has_keyword(f, keywords):
    t = _lower_title(f) + " " + _lower_desc(f)
    return any(kw in t for kw in keywords)


def _risk_val(f):
    return RISK_ORDER.get((f.get("risk") or "INFO").upper(), 4)


def _finding_ip(f):
    return (f.get("ip") or "").strip()


def _finding_tool(f):
    return (f.get("tool") or f.get("_tool") or "").lower()


def _node_from_finding(f, node_type="FINDING"):
    return ChainNode(
        node_type=node_type,
        label=f.get("title") or "Untitled",
        finding_id=f.get("id"),
        tool=_finding_tool(f),
        ip=_finding_ip(f),
        port=f.get("port", 0),
        risk=(f.get("risk") or "INFO").upper(),
        metadata={"catalogue_id": f.get("catalogue_id", "")},
    )


def _is_recon(f):
    tool = _finding_tool(f)
    cat = (f.get("catalogue_id") or "").upper()
    if tool in _RECON_TOOLS or cat.startswith("SS-") or cat.startswith("OS-"):
        return True
    if _risk_val(f) >= 3 and tool in _RECON_TOOLS:
        return True
    return False


def _is_access(f):
    return _has_keyword(f, _ACCESS_KEYWORDS)


def _is_credential(f):
    return _has_keyword(f, _CREDENTIAL_KEYWORDS)


def _is_privesc(f):
    return _has_keyword(f, _PRIVESC_KEYWORDS)


def _is_exfil_target(f):
    return _has_keyword(f, _EXFIL_KEYWORDS)


def _is_pivot(f):
    return _has_keyword(f, _PIVOT_KEYWORDS)


def _is_web_finding(f):
    tool = _finding_tool(f)
    cat = (f.get("catalogue_id") or "").upper()
    return tool in _WEB_TOOLS or cat.startswith("FR-")


def _is_api_finding(f):
    tool = _finding_tool(f)
    cat = (f.get("catalogue_id") or "").upper()
    return tool in _API_TOOLS or cat.startswith("SI-")


def _is_wireless(f):
    tool = _finding_tool(f)
    cat = (f.get("catalogue_id") or "").upper()
    return tool in _WIRELESS_TOOLS or cat.startswith("AE-")


# ── Auto-detection patterns ──────────────────────────────────────

def _detect_recon_vuln_access(findings):
    """Pattern 1: Recon → Vulnerability → Access."""
    chains = []
    by_ip = {}
    for f in findings:
        ip = _finding_ip(f)
        if ip:
            by_ip.setdefault(ip, []).append(f)

    for ip, group in by_ip.items():
        recon = [f for f in group if _is_recon(f)]
        vulns = [f for f in group if not _is_recon(f) and _risk_val(f) <= 2
                 and not _is_access(f)]
        access = [f for f in group if _is_access(f)]

        if not recon or not vulns:
            continue

        # Pick the best recon, the highest-risk vuln, and best access
        recon_f = recon[0]
        vulns.sort(key=_risk_val)
        vuln_f = vulns[0]

        nodes = [
            _node_from_finding(recon_f, "DISCOVERY"),
            _node_from_finding(vuln_f, "FINDING"),
        ]
        edges = [
            ChainEdge(
                source_id=nodes[0].id, target_id=nodes[1].id,
                relation="exposes", confidence="Firm",
                description="Reconnaissance revealed vulnerability",
            ),
        ]

        if access:
            access.sort(key=_risk_val)
            access_f = access[0]
            access_node = _node_from_finding(access_f, "ACCESS")
            nodes.append(access_node)
            edges.append(ChainEdge(
                source_id=nodes[1].id, target_id=access_node.id,
                relation="leads_to", confidence="Firm",
                description="Exploitation of vulnerability led to access",
            ))

        chain = AttackChain(
            name="Recon to Access: %s" % ip,
            description="Multi-stage attack path on %s: reconnaissance led to "
                        "vulnerability discovery and exploitation." % ip,
            nodes=nodes,
            edges=edges,
            auto_detected=True,
        )
        chain.compute_risk()
        chains.append(chain)

    return chains


def _detect_credential_chain(findings):
    """Pattern 2: Credential discovery → Authenticated access."""
    chains = []
    by_ip = {}
    for f in findings:
        ip = _finding_ip(f)
        if ip:
            by_ip.setdefault(ip, []).append(f)

    for ip, group in by_ip.items():
        cred_findings = [f for f in group if _is_credential(f)]
        access_findings = [f for f in group if _is_access(f) and not _is_credential(f)]

        if not cred_findings:
            continue

        cred_findings.sort(key=_risk_val)
        cred_f = cred_findings[0]

        cred_node = _node_from_finding(cred_f, "CREDENTIAL")
        nodes = [cred_node]
        edges = []

        if access_findings:
            access_findings.sort(key=_risk_val)
            access_f = access_findings[0]
            access_node = _node_from_finding(access_f, "ACCESS")
            nodes.append(access_node)
            edges.append(ChainEdge(
                source_id=cred_node.id, target_id=access_node.id,
                relation="grants", confidence="Firm",
                description="Harvested credentials granted system access",
            ))
        elif len(cred_findings) > 1:
            # Chain of credential discoveries
            second = _node_from_finding(cred_findings[1], "CREDENTIAL")
            nodes.append(second)
            edges.append(ChainEdge(
                source_id=cred_node.id, target_id=second.id,
                relation="chains_with", confidence="Tentative",
                description="Multiple credential weaknesses on same host",
            ))
        else:
            continue  # Single credential finding is not a chain

        chain = AttackChain(
            name="Credential Chain: %s" % ip,
            description="Credential weakness on %s enabling further access." % ip,
            nodes=nodes,
            edges=edges,
            auto_detected=True,
        )
        chain.compute_risk()
        chains.append(chain)

    return chains


def _detect_pivot_chain(findings):
    """Pattern 3: Lateral movement across hosts."""
    chains = []
    access_by_ip = {}
    for f in findings:
        ip = _finding_ip(f)
        if ip and (_is_access(f) or _is_pivot(f)):
            access_by_ip.setdefault(ip, []).append(f)

    ips_with_access = list(access_by_ip.keys())
    if len(ips_with_access) < 2:
        return chains

    # Look for explicit pivot mentions
    pivot_findings = [f for f in findings if _is_pivot(f)]

    if pivot_findings:
        # Build chain from explicit pivot references
        for pf in pivot_findings:
            pivot_ip = _finding_ip(pf)
            other_ips = [ip for ip in ips_with_access if ip != pivot_ip]
            if not other_ips:
                continue

            source_ip = other_ips[0]
            source_f = access_by_ip[source_ip][0]

            source_node = _node_from_finding(source_f, "ACCESS")
            pivot_node = _node_from_finding(pf, "FINDING")

            nodes = [source_node, pivot_node]
            edges = [ChainEdge(
                source_id=source_node.id, target_id=pivot_node.id,
                relation="pivots_to", confidence="Firm",
                description="Access on %s used to pivot to %s" % (source_ip, pivot_ip),
            )]

            # Add target access if present
            if pivot_ip in access_by_ip:
                target_f = access_by_ip[pivot_ip][0]
                target_node = _node_from_finding(target_f, "ACCESS")
                nodes.append(target_node)
                edges.append(ChainEdge(
                    source_id=pivot_node.id, target_id=target_node.id,
                    relation="enables", confidence="Firm",
                    description="Pivot enabled access to %s" % pivot_ip,
                ))

            chain = AttackChain(
                name="Lateral Movement: %s to %s" % (source_ip, pivot_ip),
                description="Lateral movement path from %s to %s." % (source_ip, pivot_ip),
                nodes=nodes,
                edges=edges,
                auto_detected=True,
            )
            chain.compute_risk()
            chains.append(chain)
    else:
        # Heuristic: multiple hosts with access — tentative pivot
        sorted_ips = sorted(ips_with_access)
        for i in range(len(sorted_ips) - 1):
            ip_a = sorted_ips[i]
            ip_b = sorted_ips[i + 1]
            f_a = access_by_ip[ip_a][0]
            f_b = access_by_ip[ip_b][0]

            node_a = _node_from_finding(f_a, "ACCESS")
            node_b = _node_from_finding(f_b, "ACCESS")

            chain = AttackChain(
                name="Potential Pivot: %s to %s" % (ip_a, ip_b),
                description="Multiple hosts compromised — potential lateral "
                            "movement path from %s to %s." % (ip_a, ip_b),
                nodes=[node_a, node_b],
                edges=[ChainEdge(
                    source_id=node_a.id, target_id=node_b.id,
                    relation="pivots_to", confidence="Tentative",
                    description="Both hosts compromised; possible pivot path",
                )],
                auto_detected=True,
            )
            chain.compute_risk()
            chains.append(chain)
            break  # Only one tentative pivot chain

    return chains


def _detect_privesc_chain(findings):
    """Pattern 4: Privilege escalation on same host."""
    chains = []
    by_ip = {}
    for f in findings:
        ip = _finding_ip(f)
        if ip:
            by_ip.setdefault(ip, []).append(f)

    for ip, group in by_ip.items():
        privesc = [f for f in group if _is_privesc(f)]
        low_risk = [f for f in group if _risk_val(f) >= 2 and not _is_privesc(f)
                    and (_is_access(f) or _is_credential(f))]
        high_risk = [f for f in group if _risk_val(f) <= 1 and _is_access(f)]

        if privesc:
            privesc.sort(key=_risk_val)
            pe_f = privesc[0]
            pe_node = _node_from_finding(pe_f, "FINDING")
            nodes = []
            edges = []

            if low_risk:
                low_risk.sort(key=_risk_val)
                initial = _node_from_finding(low_risk[0], "ACCESS")
                nodes.append(initial)
                nodes.append(pe_node)
                edges.append(ChainEdge(
                    source_id=initial.id, target_id=pe_node.id,
                    relation="escalates", confidence="Firm",
                    description="Initial access escalated via privilege escalation",
                ))
            else:
                nodes.append(pe_node)

            if high_risk:
                high_risk.sort(key=_risk_val)
                elevated = _node_from_finding(high_risk[0], "ACCESS")
                nodes.append(elevated)
                edges.append(ChainEdge(
                    source_id=pe_node.id, target_id=elevated.id,
                    relation="leads_to", confidence="Firm",
                    description="Privilege escalation achieved elevated access",
                ))

            if len(nodes) < 2:
                continue

            chain = AttackChain(
                name="Privilege Escalation: %s" % ip,
                description="Privilege escalation path on %s." % ip,
                nodes=nodes,
                edges=edges,
                auto_detected=True,
            )
            chain.compute_risk()
            chains.append(chain)

    return chains


def _detect_exfil_chain(findings):
    """Pattern 5: Access → Data exfiltration / sensitive data exposure."""
    chains = []
    by_ip = {}
    for f in findings:
        ip = _finding_ip(f)
        if ip:
            by_ip.setdefault(ip, []).append(f)

    for ip, group in by_ip.items():
        access = [f for f in group if _is_access(f)]
        exfil = [f for f in group if _is_exfil_target(f) and not _is_access(f)]

        if not access or not exfil:
            continue

        access.sort(key=_risk_val)
        exfil.sort(key=_risk_val)

        access_node = _node_from_finding(access[0], "ACCESS")
        exfil_node = _node_from_finding(exfil[0], "FINDING")
        impact_node = ChainNode(
            node_type="IMPACT",
            label="Data Exposure: %s" % exfil[0].get("title", "Sensitive Data"),
            tool=_finding_tool(exfil[0]),
            ip=ip,
            risk="CRITICAL",
        )

        chain = AttackChain(
            name="Data Exfiltration: %s" % ip,
            description="Access on %s led to exposure of sensitive data." % ip,
            nodes=[access_node, exfil_node, impact_node],
            edges=[
                ChainEdge(
                    source_id=access_node.id, target_id=exfil_node.id,
                    relation="enables", confidence="Firm",
                    description="System access enabled data discovery",
                ),
                ChainEdge(
                    source_id=exfil_node.id, target_id=impact_node.id,
                    relation="impacts", confidence="Firm",
                    description="Sensitive data exposure represents business impact",
                ),
            ],
            auto_detected=True,
        )
        chain.compute_risk()
        chains.append(chain)

    return chains


# ── Main detection entry point ───────────────────────────────────

def detect_chains(findings, targets=None):
    """Run all auto-detection patterns against the findings list.

    Returns a list of AttackChain objects.  Detection is conservative —
    chains are only created when there is reasonable evidence linking
    multiple findings together.
    """
    if not findings:
        return []

    all_chains = []

    try:
        all_chains.extend(_detect_recon_vuln_access(findings))
    except Exception as exc:
        log.warning("Pattern 1 (recon→vuln→access) failed: %s", exc)

    try:
        all_chains.extend(_detect_credential_chain(findings))
    except Exception as exc:
        log.warning("Pattern 2 (credential chain) failed: %s", exc)

    try:
        all_chains.extend(_detect_pivot_chain(findings))
    except Exception as exc:
        log.warning("Pattern 3 (pivot chain) failed: %s", exc)

    try:
        all_chains.extend(_detect_privesc_chain(findings))
    except Exception as exc:
        log.warning("Pattern 4 (privesc chain) failed: %s", exc)

    try:
        all_chains.extend(_detect_exfil_chain(findings))
    except Exception as exc:
        log.warning("Pattern 5 (exfil chain) failed: %s", exc)

    # Deduplicate: if two chains share the same set of finding IDs, keep
    # the one with higher risk.
    seen_keys = {}
    deduped = []
    for chain in all_chains:
        fids = tuple(sorted(
            n.finding_id for n in chain.nodes if n.finding_id
        ))
        if not fids:
            deduped.append(chain)
            continue
        existing = seen_keys.get(fids)
        if existing is None:
            seen_keys[fids] = chain
            deduped.append(chain)
        elif RISK_ORDER.get(chain.risk, 4) < RISK_ORDER.get(existing.risk, 4):
            deduped = [c for c in deduped if c.id != existing.id]
            deduped.append(chain)
            seen_keys[fids] = chain

    return deduped


# ── ACH meta-finding generation ──────────────────────────────────

def _classify_chain(chain):
    """Map a chain to the best-fit ACH catalogue ID."""
    name_lower = chain.name.lower()
    desc_lower = chain.description.lower()
    combined = name_lower + " " + desc_lower
    node_labels = " ".join(n.label.lower() for n in chain.nodes)
    node_tools = {n.tool.lower() for n in chain.nodes if n.tool}
    node_types = {n.node_type for n in chain.nodes}
    edge_rels = {e.relation for e in chain.edges}

    # Specific pattern → catalogue mapping
    if "pivot" in combined or "lateral" in combined or "pivots_to" in edge_rels:
        return "ACH-003"
    if "privilege" in combined or "escalat" in combined or "escalates" in edge_rels:
        return "ACH-004"
    if "exfil" in combined or "data exposure" in combined or "sensitive data" in combined:
        return "ACH-005"
    if any(t in node_tools for t in _WIRELESS_TOOLS):
        return "ACH-008"
    if "physical" in combined or "usb" in combined:
        return "ACH-009"
    if "container" in combined or "docker" in combined or "kubernetes" in combined:
        return "ACH-016"
    if "medical" in combined or "patient" in combined:
        return "ACH-014"
    if "embedded" in combined or "firmware" in combined or "debug port" in combined:
        return "ACH-015"
    if "supply chain" in combined:
        return "ACH-010"
    if "phishing" in combined or "social" in combined:
        return "ACH-011"
    if "certificate" in combined or "cryptograph" in combined or "mitm" in combined:
        return "ACH-013"
    if "config" in combined or "misconfigur" in combined:
        return "ACH-012"
    if any(t in node_tools for t in _API_TOOLS):
        return "ACH-007"
    if any(t in node_tools for t in _WEB_TOOLS):
        return "ACH-006"
    if "CREDENTIAL" in node_types and ("grants" in edge_rels or "credential" in combined):
        return "ACH-002"

    # Default: multi-stage network
    return "ACH-001"


def generate_chain_meta_findings(chains):
    """Generate meta-findings (one per chain) with ACH catalogue IDs.

    Returns a list of finding dicts in the standard finding format.
    """
    meta_findings = []

    for chain in chains:
        ach_id = _classify_chain(chain)
        ach_name = ACH_CATALOGUE.get(ach_id, "Attack Chain")

        component_ids = [n.finding_id for n in chain.nodes if n.finding_id]
        component_titles = [n.label for n in chain.nodes]
        ips = list({n.ip for n in chain.nodes if n.ip})
        ports = list({n.port for n in chain.nodes if n.port and n.port != 0})

        desc_parts = [
            "Attack chain detected: %s" % chain.name,
            "",
            "Chain type: %s (%s)" % (ach_name, ach_id),
            "Nodes: %d | Edges: %d" % (len(chain.nodes), len(chain.edges)),
            "Chain risk: %s" % chain.risk,
            "",
            "Steps:",
        ]
        for i, node in enumerate(chain.nodes):
            desc_parts.append(
                "  %d. [%s] %s (%s)" % (i + 1, node.node_type, node.label, node.risk)
            )
        if component_ids:
            desc_parts.append("")
            desc_parts.append("Component finding IDs: %s" % ", ".join(component_ids))

        finding = {
            "id": str(uuid.uuid4()),
            "tool": "crucible",
            "title": "%s: %s" % (ach_name, chain.name),
            "datetime": datetime.now().isoformat(),
            "ip": ips[0] if len(ips) == 1 else ", ".join(ips[:5]) if ips else "",
            "port": ports[0] if len(ports) == 1 else 0,
            "hostname": "",
            "risk": chain.risk,
            "command": "Auto-detected by Crucible Attack Chain Engine",
            "description": "\n".join(desc_parts),
            "output": "",
            "output_file": "",
            "cves": "",
            "sources": "crucible",
            "service": "",
            "affected": ", ".join(ips[:5]) if ips else "",
            "exploitdb": False,
            "metasploit": False,
            "exploit_details": [],
            "remediation": "Review the full attack chain and address each "
                           "component vulnerability. Prioritize breaking the "
                           "chain at the earliest feasible point.",
            "catalogue_id": ach_id,
            "owasp": "",
            "nist": "",
            "chain_id": chain.id,
            "chain_name": chain.name,
            "component_finding_ids": component_ids,
        }
        meta_findings.append(finding)

    return meta_findings


# ── Template-based chain creation ────────────────────────────────

def load_templates():
    """Load chain templates from chain_templates.json."""
    p = Path(__file__).resolve().parent / "chain_templates.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Failed to load chain templates: %s", exc)
        return []


def create_chain_from_template(template_id, template_data=None,
                               name_override=None):
    """Create an AttackChain pre-populated from a template.

    If *template_data* is ``None``, the template is looked up by
    *template_id* from ``chain_templates.json``.  *name_override*
    replaces the template's default name when provided.
    """
    if template_data is None:
        for t in load_templates():
            if t.get("id") == template_id:
                template_data = t
                break
    if template_data is None:
        return None

    nodes = []
    for tn in template_data.get("nodes", []):
        nodes.append(ChainNode(
            node_type=tn.get("node_type", "FINDING"),
            label=tn.get("label", ""),
            risk=template_data.get("risk", "INFO"),
            metadata={"placeholder": True, "template_node": True},
        ))

    edges = []
    for te in template_data.get("edges", []):
        src_idx = te.get("source_idx", 0)
        tgt_idx = te.get("target_idx", 1)
        if src_idx < len(nodes) and tgt_idx < len(nodes):
            edges.append(ChainEdge(
                source_id=nodes[src_idx].id,
                target_id=nodes[tgt_idx].id,
                relation=te.get("relation", "leads_to"),
                confidence="Tentative",
                description=te.get("description", ""),
            ))

    chain = AttackChain(
        name=name_override or template_data.get("name", "Chain from Template"),
        description=template_data.get("description", ""),
        risk=template_data.get("risk", "INFO"),
        nodes=nodes,
        edges=edges,
        auto_detected=False,
        template_id=template_id,
    )
    return chain
