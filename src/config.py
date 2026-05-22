"""
src/config.py
-------------
Central constants cho toàn bộ project — gom các magic number/path lặp lại
nhiều nơi. Mục tiêu: 1 chỗ đổi, không phải grep + sửa rải rác.

Nguyên tắc:
  • Path: project-relative (`certs/...`), KHÔNG absolute — cho phép chạy
    nhiều instance/thư mục khác nhau.
  • Hằng số validity (365/3650 ngày) là default UI khi `system_config` DB
    chưa có / chưa đọc được — runtime ưu tiên đọc từ DB.
  • Port + URL thực tế ở `services/infra_manager.py` (env-overridable).
"""

# ── Filesystem paths ─────────────────────────────────────────────────────────

# Production data
CERTS_DIR             = "certs"
PROD_CRL_PATH         = "certs/crl.pem"
PROD_OCSP_DB_PATH     = "certs/ocsp_db.json"
TRUST_STORE_DIR       = "certs/trust_store"
TRUST_STORE_CERT      = "certs/trust_store/root_ca.crt"

# Lab data (Verification Lab demo — tách hoàn toàn khỏi Prod)
LAB_DIR               = "lab"
LAB_CRL_PATH          = "lab/crl.pem"
LAB_OCSP_DB_PATH      = "lab/ocsp_db.json"
LAB_TRUST_STORE_DIR   = "lab/trust_store"

# Runtime app data (root project)
DB_FILE               = "ca_app.db"
MASTER_KEY_FILE       = "master.key"


# ── Cert lifecycle defaults (UI fallback) ────────────────────────────────────

DEFAULT_VALIDITY_DAYS         = 365
DEFAULT_ROOT_CA_VALIDITY_DAYS = 3650
DEFAULT_KEY_SIZE              = 2048


# ── HTTP fetch limits ────────────────────────────────────────────────────────

MAX_CRL_BYTES   = 10 * 1024 * 1024
MAX_OCSP_BYTES  = 64 * 1024
HTTP_FETCH_TIMEOUT_SEC = 5
