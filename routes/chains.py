"""Attack Chain Visualization API routes."""

import json
import logging
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify, current_app
from routes._helpers import require_project, get_ext

chains_bp = Blueprint("chains", __name__)
log = logging.getLogger("crucible.routes.chains")


def _project_dir(project):
    return Path(project.get("project_dir") or project.get("engagement_dir", ""))


def _engine():
    return get_ext("findings_engine")


@chains_bp.route("/api/chains/<project_id>")
def api_list_chains(project_id):
    """List all attack chains for a project."""
    project = require_project(project_id)
    try:
        from chain_engine import load_chains
        chains = load_chains(_project_dir(project))
        return jsonify({"chains": [c.to_dict() for c in chains]})
    except Exception as exc:
        log.exception("Error listing chains for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/<chain_id>")
def api_get_chain(project_id, chain_id):
    """Get a single attack chain."""
    project = require_project(project_id)
    try:
        from chain_engine import get_chain
        chain = get_chain(_project_dir(project), chain_id)
        if not chain:
            return jsonify({"error": "Chain not found"}), 404
        return jsonify(chain.to_dict())
    except Exception as exc:
        log.exception("Error getting chain %s", chain_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/detect", methods=["POST"])
def api_detect_chains(project_id):
    """Run auto-detection engine on project findings."""
    project = require_project(project_id)
    try:
        fe = _engine()
        if not fe:
            return jsonify({"error": "Findings engine not available"}), 503

        findings = fe.get_findings(project_id, project)

        targets = None
        try:
            from models.targets import load_all_targets
            tdata = load_all_targets(project)
            targets = tdata.get("network", [])
        except Exception:
            pass

        from chain_engine import detect_chains, save_chains, load_chains, generate_chain_meta_findings

        detected = detect_chains(findings, targets=targets)
        if not detected:
            return jsonify({"chains": [], "meta_findings": [],
                            "message": "No attack chains detected"})

        pdir = _project_dir(project)
        existing = load_chains(pdir)
        existing_names = {c.name for c in existing}

        added = []
        for chain in detected:
            if chain.name not in existing_names:
                existing.append(chain)
                added.append(chain)

        save_chains(pdir, existing)

        meta_findings = generate_chain_meta_findings(added)

        return jsonify({
            "chains": [c.to_dict() for c in added],
            "meta_findings": meta_findings,
            "message": f"Detected {len(added)} new attack chain(s)"
        })
    except Exception as exc:
        log.exception("Error detecting chains for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>", methods=["POST"])
def api_create_chain(project_id):
    """Create a manual attack chain."""
    project = require_project(project_id)
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No data provided"}), 400

        from chain_engine import AttackChain, ChainNode, ChainEdge, add_chain
        import uuid

        nodes = []
        for nd in data.get("nodes", []):
            nodes.append(ChainNode(
                id=nd.get("id") or str(uuid.uuid4()),
                node_type=nd.get("node_type", "FINDING"),
                label=nd.get("label", ""),
                finding_id=nd.get("finding_id"),
                tool=nd.get("tool", "manual"),
                ip=nd.get("ip", ""),
                port=int(nd.get("port", 0)),
                risk=nd.get("risk", "INFO"),
                metadata=nd.get("metadata", {}),
            ))

        edges = []
        for ed in data.get("edges", []):
            edges.append(ChainEdge(
                source_id=ed.get("source_id", ""),
                target_id=ed.get("target_id", ""),
                relation=ed.get("relation", "leads_to"),
                confidence=ed.get("confidence", "Firm"),
                description=ed.get("description", ""),
            ))

        now = datetime.now().isoformat()
        chain = AttackChain(
            id=str(uuid.uuid4()),
            name=data.get("name", "Unnamed Chain"),
            description=data.get("description", ""),
            risk=data.get("risk", "INFO"),
            nodes=nodes,
            edges=edges,
            auto_detected=False,
            template_id=data.get("template_id"),
            created=now,
            modified=now,
        )

        pdir = _project_dir(project)
        add_chain(pdir, chain)

        return jsonify(chain.to_dict()), 201
    except Exception as exc:
        log.exception("Error creating chain for %s", project_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/<chain_id>", methods=["PUT"])
def api_update_chain(project_id, chain_id):
    """Update an existing attack chain."""
    project = require_project(project_id)
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No data provided"}), 400

        from chain_engine import update_chain
        updated = update_chain(_project_dir(project), chain_id, data)
        if not updated:
            return jsonify({"error": "Chain not found"}), 404

        return jsonify(updated.to_dict())
    except Exception as exc:
        log.exception("Error updating chain %s", chain_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/<chain_id>", methods=["DELETE"])
def api_delete_chain(project_id, chain_id):
    """Delete an attack chain."""
    project = require_project(project_id)
    try:
        from chain_engine import delete_chain
        ok = delete_chain(_project_dir(project), chain_id)
        if not ok:
            return jsonify({"error": "Chain not found"}), 404
        return jsonify({"ok": True})
    except Exception as exc:
        log.exception("Error deleting chain %s", chain_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/<chain_id>/export", methods=["POST"])
def api_export_chain(project_id, chain_id):
    """Export a single chain as JSON."""
    project = require_project(project_id)
    try:
        from chain_engine import get_chain
        chain = get_chain(_project_dir(project), chain_id)
        if not chain:
            return jsonify({"error": "Chain not found"}), 404

        return jsonify({
            "chain": chain.to_dict(),
            "exported_at": datetime.now().isoformat(),
            "project_id": project_id,
            "project_name": project.get("name", ""),
        })
    except Exception as exc:
        log.exception("Error exporting chain %s", chain_id)
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/templates")
def api_list_templates(project_id):
    """List available chain templates."""
    require_project(project_id)
    try:
        tmpl_path = Path(__file__).resolve().parent.parent / "chain_templates.json"
        if tmpl_path.exists():
            with open(tmpl_path, "r") as f:
                templates = json.load(f)
        else:
            templates = []
        return jsonify({"templates": templates})
    except Exception as exc:
        log.exception("Error listing templates")
        return jsonify({"error": str(exc)}), 500


@chains_bp.route("/api/chains/<project_id>/from-template", methods=["POST"])
def api_create_from_template(project_id):
    """Create a chain from a template."""
    project = require_project(project_id)
    try:
        data = request.get_json(force=True)
        template_id = data.get("template_id")
        chain_name = data.get("name", "")
        if not template_id:
            return jsonify({"error": "template_id required"}), 400

        tmpl_path = Path(__file__).resolve().parent.parent / "chain_templates.json"
        if not tmpl_path.exists():
            return jsonify({"error": "Templates file not found"}), 404

        with open(tmpl_path, "r") as f:
            templates = json.load(f)

        tmpl = None
        for t in templates:
            if t.get("id") == template_id:
                tmpl = t
                break
        if not tmpl:
            return jsonify({"error": "Template not found"}), 404

        from chain_engine import create_chain_from_template, add_chain
        chain = create_chain_from_template(template_id, tmpl,
                                           name_override=chain_name or None)

        pdir = _project_dir(project)
        add_chain(pdir, chain)

        return jsonify(chain.to_dict()), 201
    except Exception as exc:
        log.exception("Error creating chain from template for %s", project_id)
        return jsonify({"error": str(exc)}), 500
