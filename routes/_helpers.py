"""Shared route helpers — project lookup, file resolution, extension access."""

from pathlib import Path

from flask import abort, current_app, jsonify, make_response, request

from models.project import get_project


def require_project(project_id):
    """Return the project dict or abort 404 with JSON error."""
    project = get_project(project_id)
    if not project:
        abort(make_response(jsonify({"error": "Not found"}), 404))
    return project


def get_ext(name):
    """Shorthand for current_app.extensions.get(name)."""
    return current_app.extensions.get(name)


def _collect_allowed_dirs(project):
    proj_dir = Path(project.get("project_dir", ""))
    dirs = {str(proj_dir.resolve())}
    for td in project.get("tool_dirs", {}).values():
        dirs.add(str(Path(td).resolve()))
    for scope_dirs in project.get("scope_tool_dirs", {}).values():
        for td in scope_dirs.values():
            dirs.add(str(Path(td).resolve()))
    eng = project.get("engagement_dir", "")
    if eng:
        dirs.add(str(Path(eng).resolve()))
    return proj_dir, sorted(dirs)


def resolve_project_file(project, rel_path):
    """Resolve a relative or absolute path against project dir and tool dirs.
    Returns the full Path if valid, or aborts with the appropriate error."""
    if not rel_path or ".." in rel_path:
        abort(make_response(jsonify({"error": "Invalid path"}), 400))

    proj_dir, allowed = _collect_allowed_dirs(project)

    if rel_path.startswith("/"):
        full_path = Path(rel_path)
        if full_path.exists() and full_path.is_file():
            resolved = str(full_path.resolve())
            if any(resolved.startswith(d) for d in allowed):
                return full_path
        # Absolute path failed — try deriving relative from project dir.
        # The finding may have been written with a different CLIENTS_BASE
        # (e.g. /clients/ vs /root/clients/). Try stripping known prefixes
        # and resolving against the current project_dir.
        for d in allowed:
            if rel_path.startswith(d):
                rel_part = rel_path[len(d):].lstrip("/")
                candidate = Path(d) / rel_part
                if candidate.exists() and candidate.is_file():
                    return candidate
        # Try walking from the end of the path against all tool dirs
        parts = Path(rel_path).parts
        for start in range(1, len(parts)):
            suffix = str(Path(*parts[start:]))
            candidate = proj_dir / suffix
            if candidate.exists() and candidate.is_file():
                resolved = str(candidate.resolve())
                if any(resolved.startswith(d) for d in allowed):
                    return candidate
            for td in project.get("tool_dirs", {}).values():
                candidate = Path(td) / suffix
                if candidate.exists() and candidate.is_file():
                    resolved = str(candidate.resolve())
                    if any(resolved.startswith(d) for d in allowed):
                        return candidate
            for scope_dirs in project.get("scope_tool_dirs", {}).values():
                for td in scope_dirs.values():
                    candidate = Path(td) / suffix
                    if candidate.exists() and candidate.is_file():
                        resolved = str(candidate.resolve())
                        if any(resolved.startswith(d) for d in allowed):
                            return candidate
        abort(make_response(jsonify({"error": "File not found"}), 404))

    # Relative path handling
    full_path = proj_dir / rel_path

    if not full_path.exists():
        for td in project.get("tool_dirs", {}).values():
            candidate = Path(td) / rel_path
            if candidate.exists():
                full_path = candidate
                break

    if not full_path.exists():
        for scope_dirs in project.get("scope_tool_dirs", {}).values():
            for td in scope_dirs.values():
                candidate = Path(td) / rel_path
                if candidate.exists():
                    full_path = candidate
                    break
            if full_path.exists():
                break

    if not full_path.exists():
        _all_tdirs = list(project.get("tool_dirs", {}).values())
        for scope_dirs in project.get("scope_tool_dirs", {}).values():
            _all_tdirs.extend(scope_dirs.values())
        for td in _all_tdirs:
            td_path = Path(td)
            if not td_path.is_dir():
                continue
            for sub in td_path.iterdir():
                if not sub.is_dir():
                    continue
                candidate = sub / rel_path
                if candidate.exists() and candidate.is_file():
                    full_path = candidate
                    break
            if full_path.exists():
                break

    if not full_path.exists():
        fname = Path(rel_path).name
        if fname:
            _all_tdirs2 = [proj_dir] + list(project.get("tool_dirs", {}).values())
            for scope_dirs in project.get("scope_tool_dirs", {}).values():
                _all_tdirs2.extend(scope_dirs.values())
            for td in _all_tdirs2:
                td_path = Path(td)
                if not td_path.is_dir():
                    continue
                for match in td_path.rglob(fname):
                    if match.is_file():
                        full_path = match
                        break
                if full_path.exists():
                    break

    if not full_path.exists() or not full_path.is_file():
        abort(make_response(jsonify({"error": "File not found"}), 404))

    resolved = str(full_path.resolve())
    if not any(resolved.startswith(d) for d in allowed):
        abort(make_response(jsonify({"error": "Access denied"}), 403))

    return full_path
