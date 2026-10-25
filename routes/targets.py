"""Targets API routes — network hosts + OSINT assets."""

import logging

from flask import Blueprint, jsonify
from routes._helpers import require_project
from models.targets import load_all_targets, get_target_summary

log = logging.getLogger("crucible.routes.targets")

targets_bp = Blueprint("targets", __name__)


@targets_bp.route("/api/targets/<project_id>")
def api_targets(project_id):
    project = require_project(project_id)
    targets = load_all_targets(project)
    # Overlay live targets from ProcessManager cache
    try:
        from flask import current_app
        pm = current_app.extensions.get("process_manager")
        if pm:
            live = pm.get_live_targets(project_id)
            if live:
                disk_hosts = targets.get("network", [])
                by_ip = {h.get("ip"): h for h in disk_hosts if h.get("ip")}
                for lh in live:
                    if lh["ip"] not in by_ip:
                        disk_hosts.append(lh)
                        by_ip[lh["ip"]] = lh
                    else:
                        dh = by_ip[lh["ip"]]
                        if lh.get("hostname") and not dh.get("hostname"):
                            dh["hostname"] = lh["hostname"]
                        disk_ports = {p.get("port") for p in dh.get("ports", [])
                                      if isinstance(p, dict)}
                        for lp in lh.get("ports", []):
                            if isinstance(lp, dict) and lp.get("port") not in disk_ports:
                                dh.setdefault("ports", []).append(lp)
                targets["network"] = disk_hosts
    except Exception as exc:
        log.warning("targets live overlay: %s", exc)
    summary = get_target_summary(project)
    return jsonify({"targets": targets, "summary": summary})


@targets_bp.route("/api/topology/<project_id>")
def api_topology(project_id):
    """Generate Mermaid topology diagram from targets."""
    project = require_project(project_id)
    targets = load_all_targets(project)
    try:
        from flask import current_app
        pm = current_app.extensions.get("process_manager")
        if pm:
            live = pm.get_live_targets(project_id)
            if live:
                disk_hosts = targets.get("network", [])
                by_ip = {h.get("ip"): h for h in disk_hosts if h.get("ip")}
                for lh in live:
                    if lh["ip"] not in by_ip:
                        disk_hosts.append(lh)
                targets["network"] = disk_hosts
    except Exception as exc:
        log.warning("topology live overlay: %s", exc)

    def _esc_mermaid(s):
        return str(s).replace('"', '#quot;').replace('[', '#91;').replace(']', '#93;').replace('-->', '— >')

    lines = ["graph TD"]
    for i, host in enumerate(targets.get("network", [])[:50]):
        ip = _esc_mermaid(host.get("ip", f"host_{i}"))
        hostname = _esc_mermaid(host.get("hostname", ""))
        label = f"{hostname}\\n{ip}" if hostname else ip
        node_id = f"h{i}"
        lines.append(f'    {node_id}["{label}"]')
        for port_info in host.get("ports", [])[:10]:
            port = port_info.get("port", "")
            svc = _esc_mermaid(port_info.get("service", ""))
            port_label = f"{port}/{svc}" if svc else str(port)
            port_id = f"{node_id}_p{port}"
            lines.append(f'    {node_id} --> {port_id}["{port_label}"]')

    mermaid = "\n".join(lines)
    return jsonify({"mermaid": mermaid})
