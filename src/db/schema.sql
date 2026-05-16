-- ─────────────────────────────────────────────────────────────────────────────
-- X.509 CA Management — SQLite schema
--
-- Quy ước:
--   • Mọi cột thời gian là TEXT chứa ISO-8601 UTC (datetime.isoformat()).
--   • password_hash là chuỗi tự-mô-tả ("scrypt$N$r$p$salt$hash"), KHÔNG mã hóa.
--   • encrypted_private_key + gcm_nonce: AES-256-GCM (xem core/encryption.py).
--     ciphertext đã bao gồm auth tag ở cuối. AAD (nếu dùng) là `f"{table}:{row_id}"`.
--   • CHECK / FOREIGN KEY được bật runtime bằng PRAGMA foreign_keys = ON
--     trong connection.py (mặc định SQLite tắt).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK(role IN ('admin', 'customer')),
    created_at      TEXT    NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE IF NOT EXISTS system_config (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    updated_by      INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Root CA: lý thuyết là singleton (1 hệ thống = 1 Root CA active), nhưng
-- giữ id+is_active để cho phép "rotate Root CA" về sau (giữ history).
CREATE TABLE IF NOT EXISTS root_ca (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    common_name              TEXT    NOT NULL,
    serial_hex               TEXT    NOT NULL,
    cert_pem                 BLOB    NOT NULL,
    encrypted_private_key    BLOB    NOT NULL,
    gcm_nonce                BLOB    NOT NULL,
    not_valid_before         TEXT    NOT NULL,
    not_valid_after          TEXT    NOT NULL,
    created_at               TEXT    NOT NULL,
    created_by               INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_active                INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1))
);

-- Customer keypairs — public/private key của khách hàng để ký CSR.
CREATE TABLE IF NOT EXISTS customer_keys (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                     TEXT    NOT NULL,
    algorithm                TEXT    NOT NULL,
    key_size                 INTEGER NOT NULL,
    public_key_pem           BLOB    NOT NULL,
    encrypted_private_key    BLOB    NOT NULL,
    gcm_nonce                BLOB    NOT NULL,
    created_at               TEXT    NOT NULL,
    UNIQUE(owner_id, name)
);

-- CSR (Certificate Signing Request) — khách hàng submit, admin duyệt.
CREATE TABLE IF NOT EXISTS csr_requests (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    customer_key_id          INTEGER NOT NULL REFERENCES customer_keys(id) ON DELETE RESTRICT,
    common_name              TEXT    NOT NULL,
    san_list_json            TEXT,
    csr_pem                  BLOB    NOT NULL,
    status                   TEXT    NOT NULL DEFAULT 'pending'
                                     CHECK(status IN ('pending', 'approved', 'rejected')),
    reject_reason            TEXT,
    submitted_at             TEXT    NOT NULL,
    reviewed_at              TEXT,
    reviewed_by              INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Certificates đã phát hành. csr_request_id forward-references csr_requests.id;
-- back-reference (csr → cert) tra qua JOIN khi cần.
CREATE TABLE IF NOT EXISTS issued_certs (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    csr_request_id           INTEGER REFERENCES csr_requests(id) ON DELETE SET NULL,
    owner_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    serial_hex               TEXT    NOT NULL UNIQUE,
    common_name              TEXT    NOT NULL,
    cert_pem                 BLOB    NOT NULL,
    not_valid_before         TEXT    NOT NULL,
    not_valid_after          TEXT    NOT NULL,
    issued_at                TEXT    NOT NULL,
    issued_by                INTEGER REFERENCES users(id) ON DELETE SET NULL,
    -- Chain renew: cert mới sinh từ renew trỏ về cert cũ.
    renewed_from_id          INTEGER REFERENCES issued_certs(id) ON DELETE SET NULL,
    -- Revocation: nếu revoked_at != NULL thì cert đã bị thu hồi.
    revoked_at               TEXT,
    revocation_reason        TEXT
);

CREATE TABLE IF NOT EXISTS revocation_requests (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    issued_cert_id           INTEGER NOT NULL REFERENCES issued_certs(id) ON DELETE CASCADE,
    requester_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason                   TEXT,
    status                   TEXT    NOT NULL DEFAULT 'pending'
                                     CHECK(status IN ('pending', 'approved', 'rejected')),
    submitted_at             TEXT    NOT NULL,
    reviewed_at              TEXT,
    reviewed_by              INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id                 INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action                   TEXT    NOT NULL,
    target_type              TEXT,
    target_id                TEXT,
    details_json             TEXT,
    timestamp                TEXT    NOT NULL
);

-- Customer feature B.9: upload cert ngoài để theo dõi + verify thông tin.
CREATE TABLE IF NOT EXISTS external_certs (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    uploader_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cert_pem                 BLOB    NOT NULL,
    fingerprint_sha256       TEXT    NOT NULL,
    notes                    TEXT,
    uploaded_at              TEXT    NOT NULL
);

-- Index cho các truy vấn thường xuyên.
CREATE INDEX IF NOT EXISTS idx_audit_timestamp        ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor            ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_issued_certs_owner     ON issued_certs(owner_id);
CREATE INDEX IF NOT EXISTS idx_issued_certs_revoked   ON issued_certs(revoked_at)
                                                       WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_csr_status             ON csr_requests(status);
CREATE INDEX IF NOT EXISTS idx_csr_requester          ON csr_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_revoke_status          ON revocation_requests(status);
CREATE INDEX IF NOT EXISTS idx_external_uploader      ON external_certs(uploader_id);
