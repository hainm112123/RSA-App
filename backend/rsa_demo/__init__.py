from flask import Flask
from flask_cors import CORS

from .routes import register_routes
from .crypto.key_pool import key_pool


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
    
    # Start the background key generation pool
    key_pool.start()
    
    register_routes(app)
    return app
