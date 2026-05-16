"""
test_m1_foundation.py
---------------------
Smoke test cho M1 (foundation): DB schema, encryption, auth, audit, system_config.

Chạy (từ project root):
    python tests/test_m1_foundation.py

Mỗi test dùng DB file tạm + master.key file tạm để không đụng state thật.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from db.connection import init_db, get_conn
from core import encryption
from core.encryption import (
    encrypt_blob, decrypt_blob,
    hash_password, verify_password,
    reset_master_key_cache,
)
from services.auth import (
    register_user, login, change_password, seed_admin_if_empty,
    count_users, get_user_by_id, AuthError,
)
from services.audit import write_audit, list_recent, Action
from services.system_config import (
    seed_defaults, get_config, set_config, get_all_config, DEFAULTS,
)


# ── Test scaffold ────────────────────────────────────────────────────────────

class TestEnv:
    """Tạo thư mục tạm chứa DB + master.key cho mỗi test."""
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="m1test_")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.master_key_path = os.path.join(self.tmpdir, "master.key")
        # Trỏ encryption module dùng master.key trong tmpdir
        reset_master_key_cache()
        encryption.DEFAULT_MASTER_KEY_PATH = self.master_key_path
        init_db(self.db_path)

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_db_init_creates_tables():
    env = TestEnv()
    try:
        conn = get_conn(env.db_path)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            tables = [r["name"] for r in rows]
            expected = {
                "users", "system_config", "root_ca", "customer_keys",
                "csr_requests", "issued_certs", "revocation_requests",
                "audit_log", "external_certs",
            }
            missing = expected - set(tables)
            assert not missing, f"Thiếu bảng: {missing}; có: {tables}"
            print("  [db] PASS ✓ — schema tạo đủ 9 bảng:", ", ".join(sorted(expected)))
        finally:
            conn.close()
    finally:
        env.cleanup()


def test_password_hash_roundtrip():
    pw = "SuperSecret#123"
    h = hash_password(pw)
    assert h.startswith("scrypt$"), f"Format hash sai: {h[:20]}"
    assert verify_password(pw, h), "Verify mật khẩu đúng phải trả True"
    assert not verify_password(pw + "x", h), "Verify mật khẩu sai phải trả False"
    assert not verify_password("", h), "Verify mật khẩu rỗng phải trả False"
    # Hash 2 lần cùng 1 password phải khác (salt random)
    assert hash_password(pw) != hash_password(pw), "Hash phải có salt random"
    print("  [hash] PASS ✓ — scrypt hash + verify + salt random")


def test_aes_gcm_roundtrip():
    env = TestEnv()
    try:
        plaintext = b"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----"
        nonce, ct = encrypt_blob(plaintext, aad=b"customer_keys:42")
        assert len(nonce) == 12, f"Nonce phải 12 bytes, được {len(nonce)}"
        assert ct != plaintext, "Ciphertext phải khác plaintext"

        # Decrypt OK
        recovered = decrypt_blob(nonce, ct, aad=b"customer_keys:42")
        assert recovered == plaintext, "Decrypt sai content"

        # AAD sai → InvalidTag
        from cryptography.exceptions import InvalidTag
        try:
            decrypt_blob(nonce, ct, aad=b"customer_keys:43")
            assert False, "AAD sai phải raise InvalidTag"
        except InvalidTag:
            pass

        # Ciphertext bị sửa → InvalidTag
        tampered = bytearray(ct); tampered[5] ^= 0x01
        try:
            decrypt_blob(nonce, bytes(tampered), aad=b"customer_keys:42")
            assert False, "Ciphertext bị sửa phải raise InvalidTag"
        except InvalidTag:
            pass

        print("  [aes-gcm] PASS ✓ — encrypt/decrypt + AAD check + tamper detection")
    finally:
        env.cleanup()


def test_register_login_flow():
    env = TestEnv()
    try:
        # Register admin
        admin = register_user("admin01", "AdminPass123", "admin", env.db_path)
        assert admin["role"] == "admin"
        assert admin["id"] > 0

        # Trùng username → AuthError
        try:
            register_user("admin01", "Other", "admin", env.db_path)
            assert False, "Phải raise AuthError khi trùng username"
        except AuthError:
            pass

        # Register customer
        cust = register_user("alice", "AlicePw#42", "customer", env.db_path)
        assert cust["role"] == "customer"

        # Login OK
        session = login("alice", "AlicePw#42", env.db_path)
        assert session["id"] == cust["id"]
        assert session["role"] == "customer"

        # Login sai password → AuthError
        try:
            login("alice", "WrongPw", env.db_path)
            assert False, "Sai pw phải raise AuthError"
        except AuthError:
            pass

        # Login username không tồn tại → AuthError (cùng message generic)
        try:
            login("nobody", "whatever", env.db_path)
            assert False, "User không tồn tại phải raise AuthError"
        except AuthError:
            pass

        # last_login_at được set sau login thành công
        u = get_user_by_id(cust["id"], env.db_path)
        assert u["last_login_at"] is not None, "last_login_at phải được cập nhật"

        print("  [auth] PASS ✓ — register + login + last_login_at + duplicate detect")
    finally:
        env.cleanup()


def test_change_password():
    env = TestEnv()
    try:
        u = register_user("bob", "OldPw123", "customer", env.db_path)
        # Sai old pw
        try:
            change_password(u["id"], "WrongOld", "NewPw456", env.db_path)
            assert False, "Sai old pw phải raise AuthError"
        except AuthError:
            pass
        # New == old → AuthError
        try:
            change_password(u["id"], "OldPw123", "OldPw123", env.db_path)
            assert False, "New == Old phải raise AuthError"
        except AuthError:
            pass
        # OK
        change_password(u["id"], "OldPw123", "NewPw456", env.db_path)
        # Login với pw cũ → fail
        try:
            login("bob", "OldPw123", env.db_path)
            assert False, "Login với pw cũ phải fail"
        except AuthError:
            pass
        # Login với pw mới → OK
        session = login("bob", "NewPw456", env.db_path)
        assert session["username"] == "bob"
        print("  [change-pw] PASS ✓ — old/new validation + re-login")
    finally:
        env.cleanup()


def test_seed_admin_if_empty():
    env = TestEnv()
    try:
        # Lần đầu: tạo
        admin = seed_admin_if_empty("root", "RootPass", env.db_path)
        assert admin is not None and admin["role"] == "admin"
        assert count_users(env.db_path, role="admin") == 1

        # Lần sau: idempotent (đã có admin → trả None)
        again = seed_admin_if_empty("root2", "OtherPass", env.db_path)
        assert again is None
        assert count_users(env.db_path, role="admin") == 1

        print("  [seed] PASS ✓ — seed_admin chỉ chạy khi chưa có admin")
    finally:
        env.cleanup()


def test_audit_log():
    env = TestEnv()
    try:
        u = register_user("logger", "LogPw1234", "admin", env.db_path)
        uid = u["id"]
        write_audit(env.db_path, uid, Action.LOGIN,
                    target_type="user", target_id=str(uid))
        write_audit(env.db_path, uid, Action.CONFIG_UPDATED,
                    target_type="config", target_id="default_key_size",
                    details={"old": "2048", "new": "4096"})
        write_audit(env.db_path, None, "system_started")  # actor=None OK

        events = list_recent(env.db_path)
        assert len(events) == 3, f"Phải có 3 event, có {len(events)}"
        # Newest first
        actions = [e["action"] for e in events]
        assert actions == ["system_started",
                           Action.CONFIG_UPDATED, Action.LOGIN], \
            f"Thứ tự sai: {actions}"
        # details_json là string JSON
        import json as _json
        config_event = next(e for e in events if e["action"] == Action.CONFIG_UPDATED)
        d = _json.loads(config_event["details_json"])
        assert d == {"old": "2048", "new": "4096"}

        # Filter theo action
        login_events = list_recent(env.db_path, action=Action.LOGIN)
        assert len(login_events) == 1
        print("  [audit] PASS ✓ — write + list + filter + JSON details")
    finally:
        env.cleanup()


def test_system_config():
    env = TestEnv()
    try:
        n = seed_defaults(env.db_path)
        assert n == len(DEFAULTS), f"Seed phải insert {len(DEFAULTS)}, được {n}"
        # Seed lần 2 idempotent
        assert seed_defaults(env.db_path) == 0

        # Default values
        all_cfg = get_all_config(env.db_path)
        for k, v in DEFAULTS.items():
            assert all_cfg.get(k) == v, f"Default {k}: {all_cfg.get(k)} != {v}"

        # Update
        u = register_user("cfg_admin", "Pw123456", "admin", env.db_path)
        set_config("default_key_size", "4096", updated_by=u["id"],
                   db_path=env.db_path)
        assert get_config("default_key_size", env.db_path) == "4096"

        # Whitelist enforcement
        try:
            set_config("hacker_field", "evil", updated_by=u["id"],
                       db_path=env.db_path)
            assert False, "Key ngoài whitelist phải raise ValueError"
        except ValueError:
            pass

        print("  [config] PASS ✓ — seed + get/set + whitelist guard")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_db_init_creates_tables,
    test_password_hash_roundtrip,
    test_aes_gcm_roundtrip,
    test_register_login_flow,
    test_change_password,
    test_seed_admin_if_empty,
    test_audit_log,
    test_system_config,
]


def main():
    print("=" * 60)
    print("  M1 Foundation — Smoke Test Suite")
    print("=" * 60)

    passed = 0
    failed = 0
    errors = []

    for test_fn in TESTS:
        label = (test_fn.__doc__.strip().splitlines()[0]
                 if test_fn.__doc__ else test_fn.__name__)
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL ✗ — {test_fn.__name__}: {e}")
            errors.append((test_fn.__name__, str(e)))
            failed += 1
        except Exception as e:
            print(f"  ERROR ✗ — {test_fn.__name__}: {type(e).__name__}: {e}")
            errors.append((test_fn.__name__, f"{type(e).__name__}: {e}"))
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Kết quả: {passed} PASS / {failed} FAIL  (tổng {len(TESTS)})")
    print("=" * 60)

    if failed > 0:
        for name, msg in errors:
            print(f"  - {name}: {msg}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
