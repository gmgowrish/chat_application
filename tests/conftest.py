import os
import tempfile

from werkzeug.security import generate_password_hash

# Configure before app/analytics are imported: throwaway SQLite DB + known admin secrets.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="chat-test-")
os.environ["ADMIN_PATH"] = "test-secret-panel-path-0123456789"
os.environ["ADMIN_PASSWORD_HASH"] = generate_password_hash("correct horse battery staple")
os.environ.pop("RENDER", None)
# Analytics run on SQLite by default; set TEST_DATABASE_URL to run them against PostgreSQL.
if os.environ.get("TEST_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
else:
    os.environ.pop("DATABASE_URL", None)
