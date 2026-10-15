"""SocketIO events for worker delegation."""

from services.utils import project_room as _room


def register_worker_events(socketio, worker_delegate):
    @socketio.on("join_delegation")
    def on_join_delegation(data):
        from flask_socketio import join_room
        delegation_id = data.get("delegation_id", "")
        if delegation_id:
            join_room(f"delegation:{delegation_id}")

    @socketio.on("delegate_tool")
    def on_delegate_tool(data):
        project_id = data.get("project_id", "")
        tool_id = data.get("tool_id", "")
        worker_name = data.get("worker_name", "")
        settings = data.get("settings", {})

        if not all([project_id, tool_id, worker_name]):
            socketio.emit("delegation_error", {
                "error": "project_id, tool_id, and worker_name required",
            })
            return

        try:
            delegation_id = worker_delegate.delegate_tool(
                project_id, tool_id, worker_name, settings,
            )
            socketio.emit("delegation_started", {
                "delegation_id": delegation_id,
                "tool_id": tool_id,
                "worker": worker_name,
            }, room=_room(project_id))
        except Exception as e:
            socketio.emit("delegation_error", {
                "error": str(e),
                "tool_id": tool_id,
            }, room=_room(project_id))

    @socketio.on("recall_delegation")
    def on_recall_delegation(data):
        delegation_id = data.get("delegation_id", "")
        if delegation_id and worker_delegate:
            worker_delegate.recall_delegation(delegation_id)
