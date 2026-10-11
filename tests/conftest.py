import os
import tempfile

from werkzeug.security import generate_password_hash

# Configure before app/analytics are imported: throwaway SQLite DB + known admin secrets.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="chat-test-")
os.environ["ADMIN_PATH"] = "test-secret-panel-path-0123456789"
os.environ["ADMIN_PASSWORD_HASH"] = generate_password_hash("correct horse battery staple")
os.environ.pop("RENDER", None)
os.environ.pop("DATABASE_URL", None)
