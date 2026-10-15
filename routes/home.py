"""Home routes — index, project list, wizard entry."""

from flask import Blueprint, render_template, redirect, url_for, jsonify
from models.project import list_projects, get_project

home_bp = Blueprint("home", __name__)


@home_bp.route("/")
def index():
    projects = list_projects()
    return render_template("index.html", projects=projects)


@home_bp.route("/new_project")
def new_project_wizard():
    return render_template("wizard.html", project=None, edit_mode=False)


@home_bp.route("/edit_project/<project_id>")
def edit_project(project_id):
    project = get_project(project_id)
    if not project:
        return redirect(url_for("home.index"))
    return render_template("wizard.html", project=project, edit_mode=True)
