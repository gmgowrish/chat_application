# Entry point for gunicorn: gunicorn -w 1 --threads 100 wsgi:app
from app import app, socketio  # noqa: F401
