PACKAGES = [
    {"name": "lodash", "ecosystem": "npm"},
    {"name": "log4j-core", "ecosystem": "maven"},
    {"name": "openssl", "ecosystem": "generic"},
    {"name": "django", "ecosystem": "PyPI"},
    {"name": "express", "ecosystem": "npm"},
    {"name": "flask", "ecosystem": "PyPI"},
    {"name": "axios", "ecosystem": "npm"},
]

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1"

RAW_NVD_DIR = "data/raw/nvd"
RAW_OSV_DIR = "data/raw/osv"
NORMALIZED_DIR = "data/normalized"

