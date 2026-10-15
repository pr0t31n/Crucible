"""Web shell route — interactive terminal in the browser."""

from flask import Blueprint, render_template

shell_bp = Blueprint("shell", __name__)


@shell_bp.route("/shell")
def shell_page():
    return render_template("shell.html")
