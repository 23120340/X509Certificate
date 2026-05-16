"""
test_m5_customer.py
-------------------
Test cho M5: customer_keys + csr_workflow + core/csr.

Bao trùm:
  • Sinh keypair, encrypt-at-rest, AAD binding theo id
  • BOLA guard: user A không decrypt được key của user B
  • Build CSR + verify chữ ký (proof of possession)
  • Submit CSR, list/cancel CSR của mình
  • CSR persist đúng common_name + SAN
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric import rsa

from db.connection import init_db, get_conn
from core import encryption
from core.encryption import reset_master_key_cache, decrypt_blob
from core.csr import (
    build_csr, parse_csr, verify_csr_signature,
    get_csr_common_name, get_csr_san_dns,
)
from services.auth import register_user
from services.customer_keys import (
    generate_keypair, list_keys, get_key_meta, load_private_key,
    delete_key, CustomerKeyError,
)
from services.csr_workflow import (
    submit_csr, list_my_csr, get_my_csr_by_id, cancel_csr, CSRError,
)


class TestEnv:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="m5test_")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.master_key_path = os.path.join(self.tmpdir, "master.key")
        reset_master_key_cache()
        encryption.DEFAULT_MASTER_KEY_PATH = self.master_key_path
        init_db(self.db_path)

        alice = register_user("alice", "AlicePw123", "customer", self.db_path)
        bob   = register_user("bob",   "BobPw123",   "customer", self.db_path)
        self.alice_id = alice["id"]
        self.bob_id   = bob["id"]

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_generate_and_load_keypair():
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "main-key", 2048, env.db_path)
        assert kp["key_size"] == 2048
        assert kp["algorithm"] == "RSA"

        # Load private key qua API
        key = load_private_key(kp["id"], env.alice_id, env.db_path)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

        # Public key trong meta phải match
        meta = get_key_meta(kp["id"], env.alice_id, env.db_path)
        assert meta is not None
        assert b"PUBLIC KEY" in bytes(meta["public_key_pem"])
        print("  [generate-load] PASS ✓ — sinh + decrypt key qua API")
    finally:
        env.cleanup()


def test_private_key_encrypted_in_db():
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "k", 2048, env.db_path)
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT encrypted_private_key, gcm_nonce "
                "FROM customer_keys WHERE id = ?", (kp["id"],),
            ).fetchone()
        finally:
            conn.close()
        ct = bytes(row["encrypted_private_key"])
        assert b"BEGIN" not in ct, "Ciphertext không được chứa BEGIN marker"
        assert b"PRIVATE KEY" not in ct, "Chưa encrypt"
        assert len(bytes(row["gcm_nonce"])) == 12
        print("  [encrypt-at-rest] PASS ✓ — customer_keys.encrypted_private_key là ciphertext")
    finally:
        env.cleanup()


def test_aad_bound_to_key_id():
    """AAD = f'customer_keys:{id}' → decrypt với id khác phải fail."""
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "k", 2048, env.db_path)
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT encrypted_private_key, gcm_nonce "
                "FROM customer_keys WHERE id = ?", (kp["id"],),
            ).fetchone()
        finally:
            conn.close()

        from cryptography.exceptions import InvalidTag
        # AAD đúng → OK
        decrypt_blob(
            bytes(row["gcm_nonce"]),
            bytes(row["encrypted_private_key"]),
            aad=f"customer_keys:{kp['id']}".encode(),
        )
        # AAD sai (id khác) → InvalidTag
        try:
            decrypt_blob(
                bytes(row["gcm_nonce"]),
                bytes(row["encrypted_private_key"]),
                aad=f"customer_keys:{kp['id'] + 9999}".encode(),
            )
            assert False, "AAD id khác phải raise InvalidTag"
        except InvalidTag:
            pass
        print("  [aad-id-bound] PASS ✓ — AAD bind theo key id, không copy-paste được")
    finally:
        env.cleanup()


def test_bola_guard():
    """User B không được phép load/get/delete key của user A."""
    env = TestEnv()
    try:
        kp_a = generate_keypair(env.alice_id, "alice-key", 2048, env.db_path)

        # Bob get meta → None
        meta = get_key_meta(kp_a["id"], env.bob_id, env.db_path)
        assert meta is None, "Bob get_key_meta của Alice phải trả None"

        # Bob load → CustomerKeyError
        try:
            load_private_key(kp_a["id"], env.bob_id, env.db_path)
            assert False, "Bob load_private_key của Alice phải raise"
        except CustomerKeyError:
            pass

        # Bob delete → CustomerKeyError
        try:
            delete_key(kp_a["id"], env.bob_id, env.db_path)
            assert False, "Bob delete_key của Alice phải raise"
        except CustomerKeyError:
            pass

        # list_keys(bob) không có key của Alice
        bob_keys = list_keys(env.bob_id, env.db_path)
        assert all(k["id"] != kp_a["id"] for k in bob_keys)
        print("  [bola-guard] PASS ✓ — get/load/delete đều check owner_id")
    finally:
        env.cleanup()


def test_duplicate_key_name():
    env = TestEnv()
    try:
        generate_keypair(env.alice_id, "main", 2048, env.db_path)
        try:
            generate_keypair(env.alice_id, "main", 2048, env.db_path)
            assert False, "Trùng name trong owner phải raise"
        except CustomerKeyError:
            pass
        # User khác có thể dùng cùng name
        generate_keypair(env.bob_id, "main", 2048, env.db_path)
        print("  [unique-name] PASS ✓ — name unique trong owner, không cross-user")
    finally:
        env.cleanup()


def test_build_and_parse_csr():
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "csr-key", 2048, env.db_path)
        key = load_private_key(kp["id"], env.alice_id, env.db_path)

        csr = build_csr(
            key, common_name="example.com",
            san_list=["www.example.com", "api.example.com"],
        )
        assert verify_csr_signature(csr), "CSR signature phải verify được"
        assert get_csr_common_name(csr) == "example.com"
        sans = get_csr_san_dns(csr)
        assert "example.com" in sans
        assert "www.example.com" in sans
        assert "api.example.com" in sans

        # Round-trip PEM
        from core.csr import csr_to_pem
        pem = csr_to_pem(csr)
        csr2 = parse_csr(pem)
        assert get_csr_common_name(csr2) == "example.com"
        print("  [csr-build] PASS ✓ — build + verify chữ ký + SAN + PEM roundtrip")
    finally:
        env.cleanup()


def test_submit_csr_persists_correctly():
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "submit-key", 2048, env.db_path)
        csr = submit_csr(
            requester_id=env.alice_id,
            customer_key_id=kp["id"],
            common_name="my-shop.com",
            san_list=["my-shop.com", "www.my-shop.com"],
            db_path=env.db_path,
        )
        assert csr["status"] == "pending"
        assert csr["common_name"] == "my-shop.com"

        # Load back
        rec = get_my_csr_by_id(csr["id"], env.alice_id, env.db_path)
        assert rec is not None
        assert rec["common_name"] == "my-shop.com"
        assert "www.my-shop.com" in rec["san_list"]

        # CSR PEM trong DB parse được + verify được
        parsed = parse_csr(bytes(rec["csr_pem"]))
        assert verify_csr_signature(parsed)
        assert get_csr_common_name(parsed) == "my-shop.com"

        # list_my_csr
        mine = list_my_csr(env.alice_id, env.db_path)
        assert len(mine) == 1
        assert mine[0]["id"] == csr["id"]
        print("  [submit-csr] PASS ✓ — persist + parse PEM + verify signature + list")
    finally:
        env.cleanup()


def test_submit_csr_ownership_check():
    """Alice submit CSR dùng key của Bob → reject."""
    env = TestEnv()
    try:
        kp_bob = generate_keypair(env.bob_id, "bob-key", 2048, env.db_path)
        try:
            submit_csr(
                requester_id=env.alice_id,
                customer_key_id=kp_bob["id"],
                common_name="alice.com",
                san_list=[],
                db_path=env.db_path,
            )
            assert False, "Submit CSR với key của người khác phải raise"
        except CSRError:
            pass
        print("  [csr-ownership] PASS ✓ — submit reject khi customer_key không thuộc requester")
    finally:
        env.cleanup()


def test_invalid_common_name():
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "k", 2048, env.db_path)
        for bad_cn in ("", "  ", "has space.com", "javascript:alert"):
            try:
                submit_csr(
                    env.alice_id, kp["id"], bad_cn, [], env.db_path,
                )
                assert False, f"CN={bad_cn!r} phải bị reject"
            except CSRError:
                pass
        # Wildcard hợp lệ
        ok = submit_csr(env.alice_id, kp["id"], "*.example.com", [], env.db_path)
        assert ok["common_name"] == "*.example.com"
        print("  [cn-validation] PASS ✓ — CN rỗng/space/lạ bị reject, wildcard OK")
    finally:
        env.cleanup()


def test_cancel_csr():
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "k", 2048, env.db_path)
        c = submit_csr(env.alice_id, kp["id"], "to-cancel.com", [], env.db_path)
        cancel_csr(c["id"], env.alice_id, env.db_path)
        rec = get_my_csr_by_id(c["id"], env.alice_id, env.db_path)
        assert rec["status"] == "rejected"
        assert "cancel" in (rec["reject_reason"] or "").lower()

        # Cancel cái đã rejected → fail
        try:
            cancel_csr(c["id"], env.alice_id, env.db_path)
            assert False, "Cancel CSR không pending phải raise"
        except CSRError:
            pass
        print("  [cancel-csr] PASS ✓ — cancel pending OK, cancel non-pending raise")
    finally:
        env.cleanup()


def test_delete_key_blocked_when_used():
    """Không cho phép xóa keypair đang được CSR tham chiếu."""
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "k", 2048, env.db_path)
        submit_csr(env.alice_id, kp["id"], "still-here.com", [], env.db_path)
        try:
            delete_key(kp["id"], env.alice_id, env.db_path)
            assert False, "Delete key đang được CSR ref phải raise"
        except CustomerKeyError:
            pass
        # Sau khi xóa hết CSR thì xóa được. Cancel xong key vẫn ref → vẫn không xóa
        # được (cancel chỉ đổi status, row vẫn tồn tại). Đó là intentional cho audit.
        print("  [delete-key-guard] PASS ✓ — không xóa được key đang được CSR ref")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_generate_and_load_keypair,
    test_private_key_encrypted_in_db,
    test_aad_bound_to_key_id,
    test_bola_guard,
    test_duplicate_key_name,
    test_build_and_parse_csr,
    test_submit_csr_persists_correctly,
    test_submit_csr_ownership_check,
    test_invalid_common_name,
    test_cancel_csr,
    test_delete_key_blocked_when_used,
]


def main():
    print("=" * 60)
    print("  M5 Customer (keypair + CSR) — Test Suite")
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
