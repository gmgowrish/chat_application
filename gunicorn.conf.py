# Used automatically by `gunicorn wsgi:app` (Render start command).
# One worker: online users live in memory. Threads handle the WebSocket connections.
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}" if os.environ.get("PORT") else "127.0.0.1:8000"
workers = 1
threads = 100
timeout = 120
