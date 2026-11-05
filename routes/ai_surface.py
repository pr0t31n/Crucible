"""AI Surface aggregation API — /api/ai_surface/<project_id>."""

import re
import logging
from flask import Blueprint, jsonify
from routes._helpers import require_project, get_ext

ai_surface_bp = Blueprint("ai_surface", __name__)
log = logging.getLogger("crucible.routes.ai_surface")

_AI_SVC_RE = re.compile(
    r"ollama|gradio|streamlit|mlflow|vllm|triton|bentoml|litellm|"
    r"torchserve|huggingface|langflow|comfyui|stable.diffusion|"
    r"jupyter|sglang|llamacpp|nextchat|dify|chromadb|milvus|"
    r"qdrant|weaviate|pgvector|whisper|text.generation",
    re.IGNORECASE,
)

_AI_KEY_RE = re.compile(
    r"openai.*(key|token)|anthropic.*(key|token)|hugging\s*face.*(key|token)|"
    r"cohere.*(key|token)|replicate.*(key|token)|google\s*ai.*(key|token)|"
    r"azure\s*openai.*(key|token)|ai\s*api\s*key|llm\s*key|"
    r"sk-ant-|hf_[A-Za-z]|r8_[A-Za-z]|sk-proj-",
    re.IGNORECASE,
)

AI_PORTS = {
    11434: "Ollama", 7860: "Gradio", 8501: "Streamlit",
    5000: "MLflow", 8000: "vLLM/ChromaDB", 3000: "Dify",
    8080: "Weaviate/BentoML", 8001: "Triton HTTP",
    8002: "Triton gRPC", 6333: "Qdrant HTTP", 6334: "Qdrant gRPC",
    19530: "Milvus", 8888: "Jupyter", 8188: "ComfyUI",
    7869: "Gradio Alt",
}


def _is_ai_finding(f):
    title = (f.get("title") or "").lower()
    service = (f.get("service") or "").lower()
    port = int(f.get("port") or 0)
    if _AI_SVC_RE.search(title) or _AI_SVC_RE.search(service):
        return True
    if port in AI_PORTS and _AI_SVC_RE.search(f.get("description") or ""):
        return True
    if "prompt injection" in title or "ai model" in title or "ai service" in title:
        return True
    if f.get("tool") == "pain":
        return True
    if (f.get("owasp") or "").startswith("LLM"):
        return True
    cat_id = (f.get("catalogue_id") or "").upper()
    if cat_id.startswith("PI-") or cat_id.startswith("SS-AI-"):
        return True
    return False


def _is_ai_key_finding(f):
    title = (f.get("title") or "")
    desc = (f.get("description") or "")
    return bool(_AI_KEY_RE.search(title) or _AI_KEY_RE.search(desc))


def _classify_service(f):
    title = (f.get("title") or "").lower()
    service = (f.get("service") or "").lower()
    port = int(f.get("port") or 0)
    for name in ["ollama", "gradio", "streamlit", "mlflow", "vllm",
                  "triton", "bentoml", "litellm", "torchserve",
                  "huggingface", "langflow", "comfyui", "jupyter",
                  "dify", "chromadb", "milvus", "qdrant", "weaviate",
                  "whisper"]:
        if name in title or name in service:
            return name.title()
    if port in AI_PORTS:
        return AI_PORTS[port]
    return "AI Service"


def _extract_models(output):
    if not output:
        return []
    matches = re.findall(r'"(?:name|model)":\s*"([^"]+)"', output)
    seen = set()
    result = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def _auth_status(f):
    title_l = (f.get("title") or "").lower()
    if "unauthenticated" in title_l or "no auth" in title_l or "unauth" in title_l:
        return "no"
    if "authenticated" in title_l or "auth required" in title_l:
        return "yes"
    return "unknown"


@ai_surface_bp.route("/api/ai_surface/<project_id>")
def api_ai_surface(project_id):
    project = require_project(project_id)
    fe = get_ext("findings_engine")
    if not fe:
        return jsonify({"error": "Findings engine not available"}), 503

    all_findings = fe.get_findings(project_id, project)

    ai_findings = [f for f in all_findings if _is_ai_finding(f)]
    ai_key_findings = [f for f in all_findings if _is_ai_key_finding(f)]

    services = {}
    for f in ai_findings:
        ip = f.get("ip", "")
        port = int(f.get("port") or 0)
        key = f"{ip}:{port}"
        if key not in services:
            services[key] = {
                "ip": ip, "port": port,
                "service_type": _classify_service(f),
                "auth_status": _auth_status(f),
                "models": [],
                "source": f.get("tool", "unknown"),
                "hostname": f.get("hostname", ""),
            }
        svc = services[key]
        for m in _extract_models(f.get("output", "")):
            if m not in svc["models"]:
                svc["models"].append(m)
        auth = _auth_status(f)
        if auth != "unknown" and svc["auth_status"] == "unknown":
            svc["auth_status"] = auth

    all_models = []
    for svc in services.values():
        for m in svc["models"]:
            all_models.append({
                "name": m,
                "endpoint": f"{svc['ip']}:{svc['port']}",
                "service_type": svc["service_type"],
            })

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_tool = {}
    unauth_count = 0
    for f in ai_findings:
        risk = (f.get("risk") or "INFO").upper()
        if risk in risk_counts:
            risk_counts[risk] += 1
        tool = f.get("tool", "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1
        if _auth_status(f) == "no":
            unauth_count += 1

    pain_findings = [f for f in ai_findings if f.get("tool") == "pain"]
    pain_status = None
    if pain_findings:
        pr = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in pain_findings:
            r = (f.get("risk") or "INFO").upper()
            if r in pr:
                pr[r] += 1
        pain_status = {
            "total_findings": len(pain_findings),
            "risk_counts": pr,
            "targets_tested": len(set(f.get("ip", "") for f in pain_findings)),
        }

    key_exposure = []
    for f in ai_key_findings:
        key_exposure.append({
            "title": f.get("title", ""),
            "location": f.get("output_file", "") or f.get("affected", ""),
            "tool": f.get("tool", "unknown"),
            "risk": (f.get("risk") or "HIGH").upper(),
        })

    return jsonify({
        "services": list(services.values()),
        "model_inventory": all_models,
        "findings": [{
            "title": f.get("title", ""),
            "ip": f.get("ip", ""),
            "port": f.get("port", 0),
            "risk": (f.get("risk") or "INFO").upper(),
            "tool": f.get("tool", ""),
            "catalogue_id": f.get("catalogue_id", ""),
        } for f in ai_findings],
        "summary": {
            "total_services": len(services),
            "unauth_services": unauth_count,
            "total_models": len(all_models),
            "total_findings": len(ai_findings),
            "findings_by_severity": risk_counts,
            "findings_by_tool": by_tool,
        },
        "pain_status": pain_status,
        "key_exposure": key_exposure,
    })
