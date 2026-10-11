# Loaded automatically by gunicorn (any of: `gunicorn wsgi:app`, `gunicorn app:app`).
# One worker: online users live in memory. Threads handle the WebSocket connections.
import os

# Render (and most hosts) give the port in $PORT; locally we bind to loopback only.
bind = f"0.0.0.0:{os.environ['PORT']}" if os.environ.get("PORT") else "127.0.0.1:5000"
workers = 1
threads = 100
timeout = 120
# gunicorn's admin control socket isn't needed and fails on read-only home directories.
control_socket_disable = True
# Open WebSockets would otherwise hold up restarts and deploys for 30 s; clients reconnect anyway.
graceful_timeout = 5
