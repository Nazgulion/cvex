"""Provision only the disposable browser-test database, never a deployment."""
import os
from cvex.config import load_config
from cvex.db.session import make_session_factory
from cvex.workspace import query,password_hash

url=os.environ["CVEX_TEST_DATABASE_URL"]
assert "127.0.0.1:55439/" in url, "Browser setup requires the isolated disposable test database"
os.environ["CVEX_DATABASE_URL"]=url
with make_session_factory(load_config())() as db:
    query(db,"INSERT INTO cvex.web_user(username,password_hash,role) VALUES('browser-admin',:p,'admin') ON CONFLICT(username) DO NOTHING",p=password_hash("browser-test-password"))
    db.commit()
