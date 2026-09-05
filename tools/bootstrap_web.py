"""Create private deployment settings and the initial admin without printing secrets.

Run once inside the deployment directory, with the application's database environment.
Existing settings and existing admin credentials are never overwritten.
"""
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet
from cvex.config import load_config
from cvex.db.session import make_session_factory
from cvex.workspace import password_hash, query


def private_file(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(value)


def main():
    settings = Path(".web.env")
    if not settings.exists():
        private_file(settings, "CVEX_ENCRYPTION_KEY="+Fernet.generate_key().decode()+"\nCVEX_HTTPS_PORT=8443\n")
        print("Created private .web.env; include this file in encrypted backups.")
    factory = make_session_factory(load_config())
    with factory() as db:
        if not query(db,"SELECT 1 FROM cvex.web_user WHERE role='admin' LIMIT 1").scalar():
            password=secrets.token_urlsafe(24)
            credential_path=Path("data/workspace/initial-admin.txt")
            credential_path.parent.mkdir(parents=True,exist_ok=True)
            private_file(credential_path,"Username: admin\nPassword: "+password+"\n")
            query(db,"INSERT INTO cvex.web_user(username,password_hash,role) VALUES('admin',:p,'admin')",p=password_hash(password))
            db.commit()
            print("Created admin. Retrieve credentials from data/workspace/initial-admin.txt and change the password after signing in.")
        else:
            print("An administrator already exists; no account changed.")


if __name__ == "__main__":
    main()
