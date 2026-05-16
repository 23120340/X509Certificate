"""
test_m4_ca_admin.py
-------------------
Test cho M4: services/ca_admin.py — create/load/publish Root CA + verify
private key được encrypt-at-rest (không lưu raw vào DB).

Chạy:  python tests/test_m4_ca_admin.py
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from db.connection import init_db, get_conn
from core import encryption
from core.encryption import reset_master_key_cache
from services.auth import register_user
from services.ca_admin import (
    create_root_ca, get_active_root_ca, list_root_ca_history,
    load_active_root_ca_with_key, publish_active_to_trust_store, CAError,
)


class TestEnv:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="m4test_")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.master_key_path = os.path.join(self.tmpdir, "master.key")
        reset_master_key_cache()
        encryption.DEFAULT_MASTER_KEY_PATH = self.master_key_path
        init_db(self.db_path)
        admin = register_user("admin01", "AdminPass123", "admin", self.db_path)
        self.admin_id = admin["id"]

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_create_root_ca_first_time():
    env = TestEnv()
    try:
        ca = create_root_ca(
            common_name="Test Root CA", key_size=2048,
            validity_days=365, created_by=env.admin_id,
            db_path=env.db_path,
        )
        assert ca["is_active"] == 1
        assert ca["common_name"] == "Test Root CA"
        assert len(ca["serial_hex"]) > 0

        active = get_active_root_ca(env.db_path)
        assert active is not None
        assert active["id"] == ca["id"]
        # cert_pem là blob PEM hợp lệ
        cert = x509.load_pem_x509_certificate(active["cert_pem"])
        assert "Test Root CA" in cert.subject.rfc4514_string()
        print("  [create] PASS ✓ — Root CA tạo + active = 1 + cert PEM parse được")
    finally:
        env.cleanup()


def test_private_key_encrypted_at_rest():
    """Verify private key trong DB là ciphertext, không phải PEM raw."""
    env = TestEnv()
    try:
        create_root_ca(
            common_name="Test", key_size=2048, validity_days=365,
            created_by=env.admin_id, db_path=env.db_path,
        )
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT encrypted_private_key, gcm_nonce FROM root_ca "
                "WHERE is_active = 1"
            ).fetchone()
        finally:
            conn.close()

        # Ciphertext KHÔNG được chứa marker PEM
        ct = bytes(row["encrypted_private_key"])
        assert b"-----BEGIN" not in ct, \
            "encrypted_private_key chứa BEGIN marker — chưa encrypt!"
        assert b"PRIVATE KEY" not in ct, \
            "encrypted_private_key chứa 'PRIVATE KEY' — chưa encrypt!"
        # Nonce 12 bytes (GCM)
        assert len(bytes(row["gcm_nonce"])) == 12

        # Decrypt qua API + parse PEM thành công
        cert_obj, key_obj = load_active_root_ca_with_key(env.db_path)
        assert isinstance(key_obj, rsa.RSAPrivateKey)
        # Key trong DB phải match cert public key
        cert_pub = cert_obj.public_key().public_numbers()
        key_pub  = key_obj.public_key().public_numbers()
        assert cert_pub == key_pub, "Private key không match cert public key"
        print("  [encrypt-at-rest] PASS ✓ — DB chứa ciphertext, decrypt → match cert")
    finally:
        env.cleanup()


def test_rotate_root_ca():
    """Tạo 2 Root CA liên tiếp → chỉ 1 active, cái cũ bị deactivate."""
    env = TestEnv()
    try:
        ca1 = create_root_ca(
            common_name="CA-v1", key_size=2048, validity_days=365,
            created_by=env.admin_id, db_path=env.db_path,
        )
        ca2 = create_root_ca(
            common_name="CA-v2", key_size=2048, validity_days=365,
            created_by=env.admin_id, db_path=env.db_path,
        )
        assert ca1["id"] != ca2["id"]

        history = list_root_ca_history(env.db_path)
        assert len(history) == 2, f"Phải có 2 row, có {len(history)}"
        actives = [h for h in history if h["is_active"]]
        assert len(actives) == 1, f"Phải đúng 1 active, có {len(actives)}"
        assert actives[0]["id"] == ca2["id"], "Active phải là CA-v2"

        active = get_active_root_ca(env.db_path)
        assert active["common_name"] == "CA-v2"
        print("  [rotate] PASS ✓ — 2 row, 1 active (newest), 1 retired")
    finally:
        env.cleanup()


def test_input_validation():
    env = TestEnv()
    try:
        # key_size sai
        try:
            create_root_ca("X", key_size=1024, validity_days=30,
                           created_by=env.admin_id, db_path=env.db_path)
            assert False, "key_size=1024 phải raise CAError"
        except CAError:
            pass
        # CN rỗng
        try:
            create_root_ca("  ", key_size=2048, validity_days=30,
                           created_by=env.admin_id, db_path=env.db_path)
            assert False, "CN rỗng phải raise CAError"
        except CAError:
            pass
        # validity < 1
        try:
            create_root_ca("X", key_size=2048, validity_days=0,
                           created_by=env.admin_id, db_path=env.db_path)
            assert False, "validity=0 phải raise CAError"
        except CAError:
            pass
        print("  [validation] PASS ✓ — key_size/CN/validity được validate")
    finally:
        env.cleanup()


def test_load_when_no_active():
    """load_active_root_ca_with_key phải raise khi chưa có Root CA."""
    env = TestEnv()
    try:
        try:
            load_active_root_ca_with_key(env.db_path)
            assert False, "Chưa có Root CA mà load được"
        except CAError:
            pass
        print("  [load-empty] PASS ✓ — load khi chưa có Root CA raise CAError")
    finally:
        env.cleanup()


def test_publish_to_trust_store():
    env = TestEnv()
    try:
        # Chưa có Root CA → None
        out = publish_active_to_trust_store(
            env.db_path, os.path.join(env.tmpdir, "ts"),
        )
        assert out is None

        create_root_ca(
            common_name="PubCA", key_size=2048, validity_days=365,
            created_by=env.admin_id, db_path=env.db_path,
        )
        ts_dir = os.path.join(env.tmpdir, "ts")
        out = publish_active_to_trust_store(env.db_path, ts_dir)
        assert out is not None and os.path.exists(out)
        # File ra phải parse được làm cert
        with open(out, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        assert "PubCA" in cert.subject.rfc4514_string()
        print("  [publish] PASS ✓ — ghi cert ra Trust Store, parse OK")
    finally:
        env.cleanup()


def test_aad_binding():
    """
    Verify AAD=b'root_ca' binding: nếu decrypt với AAD khác phải fail.
    Đây là sanity check cho design encryption.
    """
    env = TestEnv()
    try:
        create_root_ca(
            common_name="AAD test", key_size=2048, validity_days=30,
            created_by=env.admin_id, db_path=env.db_path,
        )
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT encrypted_private_key, gcm_nonce FROM root_ca "
                "WHERE is_active = 1"
            ).fetchone()
        finally:
            conn.close()

        from core.encryption import decrypt_blob
        # AAD đúng → OK
        plain = decrypt_blob(
            bytes(row["gcm_nonce"]),
            bytes(row["encrypted_private_key"]),
            aad=b"root_ca",
        )
        assert b"PRIVATE KEY" in plain

        # AAD sai → InvalidTag
        from cryptography.exceptions import InvalidTag
        try:
            decrypt_blob(
                bytes(row["gcm_nonce"]),
                bytes(row["encrypted_private_key"]),
                aad=b"customer_keys",
            )
            assert False, "AAD sai phải raise InvalidTag"
        except InvalidTag:
            pass
        print("  [aad-binding] PASS ✓ — AAD=root_ca bắt buộc đúng để decrypt")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_create_root_ca_first_time,
    test_private_key_encrypted_at_rest,
    test_rotate_root_ca,
    test_input_validation,
    test_load_when_no_active,
    test_publish_to_trust_store,
    test_aad_binding,
]


def main():
    print("=" * 60)
    print("  M4 CA Admin — Test Suite")
    print("=" * 60)

    passed = 0
    failed = 0
    errors = []

    for test_fn in TESTS:
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
