import os
import shutil

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BACKEND_DIR)

# Persistent data is deliberately kept outside the extracted application folder.
# This means replacing/updating the ASLISIEM ZIP does not delete the user's history.
# Override with ASLISIEM_DATA_DIR if desired.
DATA_DIR = os.path.abspath(os.path.expanduser(
    os.environ.get("ASLISIEM_DATA_DIR", "~/.aslisiem_data")
))
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
TMP_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "tmp")
INSTANCE_DIR = DATA_DIR
DB_PATH = os.path.join(INSTANCE_DIR, "aslisiem.db")

# One-time migration: this project was previously named MiniSIEM. If the new
# data directory doesn't exist yet but the old MiniSIEM one does, copy the
# ENTIRE directory over (not just the .db file) -- WAL-mode sidecar files
# (-wal/-shm) and the uploads/ folder must move too, or in-flight
# uncommitted data / uploaded source files would be silently lost. This must
# run before any os.makedirs() below, otherwise DATA_DIR would already exist
# (empty) and the check would never trigger.
PRE_RENAME_DATA_DIR = os.path.abspath(os.path.expanduser(
    os.environ.get("MINISIEM_DATA_DIR", "~/.minisiemfinal_data")
))
PRE_RENAME_DB_PATH = os.path.join(PRE_RENAME_DATA_DIR, "minisiem.db")

if not os.path.exists(DATA_DIR) and os.path.exists(PRE_RENAME_DB_PATH):
    shutil.copytree(PRE_RENAME_DATA_DIR, DATA_DIR)
    for suffix in ("", "-wal", "-shm"):
        old_sidecar = os.path.join(DATA_DIR, "minisiem.db" + suffix)
        if os.path.exists(old_sidecar):
            os.rename(old_sidecar, DB_PATH + suffix)

# One-time migration: if an even older build stored data inside the project
# folder, move/copy that database into the new stable data location.
LEGACY_INSTANCE_DIR = os.path.join(ROOT_DIR, "instance")
LEGACY_DB_PATH = os.path.join(LEGACY_INSTANCE_DIR, "minisiem.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TMP_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(INSTANCE_DIR, exist_ok=True)

if not os.path.exists(DB_PATH) and os.path.exists(LEGACY_DB_PATH):
    shutil.copy2(LEGACY_DB_PATH, DB_PATH)

# MITRE ATT&CK catalog is fetched at runtime from the official STIX data
# repository, pinned to a specific release tag. This is a deliberate online
# dependency -- unlike the rest of this app, it requires internet access.
# Filenames/paths and kill_chain_name values below were verified directly
# against the real v19.1 tag before implementation.
MITRE_ATTACK_VERSION = "v19.1"
MITRE_STIX_REPO_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
MITRE_DOMAINS = ["enterprise", "mobile", "ics"]
MITRE_DOMAIN_FOLDERS = {
    "enterprise": "enterprise-attack",
    "mobile": "mobile-attack",
    "ics": "ics-attack",
}
MITRE_DOMAIN_URLS = {
    domain: f"{MITRE_STIX_REPO_BASE}/{MITRE_ATTACK_VERSION}/{folder}/{folder}-19.1.json"
    for domain, folder in MITRE_DOMAIN_FOLDERS.items()
}
MITRE_KILL_CHAIN_NAME_BY_DOMAIN = {
    "enterprise": "mitre-attack",
    "mobile": "mitre-mobile-attack",
    "ics": "mitre-ics-attack",
}
MITRE_FETCH_TIMEOUT_SECONDS = 60

# Signs the Flask session cookie (login state). Generated fresh per process
# start rather than hardcoded -- this project is now in git, so a fixed
# secret would be committed and effectively public. The accepted cost: every
# server restart invalidates existing sessions, logging everyone out. Fine
# for this app's demo-grade, single-hardcoded-user auth (see auth_routes.py).
SECRET_KEY = os.urandom(24)


class Config:
    SECRET_KEY = SECRET_KEY
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = UPLOAD_FOLDER
    TMP_UPLOAD_FOLDER = TMP_UPLOAD_FOLDER
    DATA_DIR = DATA_DIR
    DB_PATH = DB_PATH
    ALLOWED_EXTENSIONS = {"csv", "json"}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024

    MITRE_ATTACK_VERSION = MITRE_ATTACK_VERSION
    MITRE_DOMAINS = MITRE_DOMAINS
    MITRE_DOMAIN_URLS = MITRE_DOMAIN_URLS
    MITRE_KILL_CHAIN_NAME_BY_DOMAIN = MITRE_KILL_CHAIN_NAME_BY_DOMAIN
    MITRE_FETCH_TIMEOUT_SECONDS = MITRE_FETCH_TIMEOUT_SECONDS
