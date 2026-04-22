from flask import Flask

from .routes import register_routes


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
    register_routes(app)
    return app
