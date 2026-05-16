"""
test_m7_cert_lifecycle.py
-------------------------
Test cho M7: services/cert_lifecycle (list/detail/revoke/renew).

Bao trùm:
  • list_all / list_for_owner (BOLA guard)
  • _compute_status: active / expired / revoked
  • revoke_cert happy + reason required + double-revoke blocked
  • renew_cert happy: cert mới có cùng public key + subject + renewed_from_id
  • renew_cert khi cert đã revoked → error
  • renew_cert khi chưa có Root CA → error
  • get_cert_detail ownership: customer chỉ xem được cert của mình
"""

import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from db.connection import init_db, get_conn
from core import encryption
from core.encryption import reset_master_key_cache
from services.auth import register_user
from services.ca_admin import create_root_ca, load_active_root_ca_with_key
from services.customer_keys import generate_keypair
from services.csr_workflow import submit_csr
from services.csr_admin import approve_csr
from services.cert_lifecycle import (
    list_all_certs, list_certs_for_owner, get_cert_detail,
    revoke_cert, renew_cert, CertLifecycleError,
)


class TestEnv:
    def __init__(self, with_root_ca: bool = True):
        self.tmpdir = tempfile.mkdtemp(prefix="m7test_")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.master_key_path = os.path.join(self.tmpdir, "master.key")
        reset_master_key_cache()
        encryption.DEFAULT_MASTER_KEY_PATH = self.master_key_path
        init_db(self.db_path)

        admin = register_user("admin1", "AdminPw1234", "admin", self.db_path)
        alice = register_user("alice",  "AlicePw123",  "customer", self.db_path)
        bob   = register_user("bob",    "BobPw123",    "customer", self.db_path)
        self.admin_id = admin["id"]
        self.alice_id = alice["id"]
        self.bob_id   = bob["id"]

        if with_root_ca:
            create_root_ca(
                "Test Root CA", 2048, 3650,
                created_by=self.admin_id, db_path=self.db_path,
            )

    def issue_cert(self, owner_id: int, common_name: str,
                   san: "list[str] | None" = None) -> int:
        """Helper: tạo keypair + CSR + approve → return issued_cert_id."""
        kp = generate_keypair(owner_id, f"k-{common_name}", 2048, self.db_path)
        csr = submit_csr(
            owner_id, kp["id"], common_name, san or [], self.db_path,
        )
        issued = approve_csr(csr["id"], self.admin_id, 365, self.db_path)
        return issued["id"]

    def expire_cert(self, cert_id: int) -> None:
        """Force not_valid_after vào quá khứ để test status='expired'."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        conn = get_conn(self.db_path)
        try:
            conn.execute("BEGIN")
            conn.execute(
                "UPDATE issued_certs SET not_valid_after = ? WHERE id = ?",
                (past, cert_id),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_list_for_owner_isolation():
    """Alice không thấy cert của Bob qua list_certs_for_owner."""
    env = TestEnv()
    try:
        a_id = env.issue_cert(env.alice_id, "alice.com")
        b_id = env.issue_cert(env.bob_id,   "bob.com")

        a_list = list_certs_for_owner(env.alice_id, env.db_path)
        b_list = list_certs_for_owner(env.bob_id,   env.db_path)
        all_list = list_all_certs(env.db_path)

        assert {c["id"] for c in a_list} == {a_id}
        assert {c["id"] for c in b_list} == {b_id}
        assert {c["id"] for c in all_list} == {a_id, b_id}
        print("  [list-isolation] PASS ✓ — customer list chỉ thấy cert của mình; admin thấy tất cả")
    finally:
        env.cleanup()


def test_compute_status_three_branches():
    env = TestEnv()
    try:
        active_id  = env.issue_cert(env.alice_id, "active.com")
        expired_id = env.issue_cert(env.alice_id, "expired.com")
        revoked_id = env.issue_cert(env.alice_id, "revoked.com")

        env.expire_cert(expired_id)
        revoke_cert(revoked_id, env.admin_id, "test", env.db_path)

        by_id = {c["id"]: c["status"] for c in list_all_certs(env.db_path)}
        assert by_id[active_id]  == "active",  by_id
        assert by_id[expired_id] == "expired", by_id
        assert by_id[revoked_id] == "revoked", by_id

        # Filter
        actives = list_all_certs(env.db_path, status="active")
        assert {c["id"] for c in actives} == {active_id}
        expireds = list_all_certs(env.db_path, status="expired")
        assert {c["id"] for c in expireds} == {expired_id}
        revoked_only = list_all_certs(env.db_path, status="revoked")
        assert {c["id"] for c in revoked_only} == {revoked_id}
        print("  [compute-status] PASS ✓ — 3 nhánh active/expired/revoked + filter đúng")
    finally:
        env.cleanup()


def test_revoke_cert_happy():
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "to-revoke.com")
        rec = revoke_cert(cert_id, env.admin_id, "Key compromised", env.db_path)
        assert rec["status"] == "revoked"
        assert rec["revoked_at"] is not None
        assert "compromised" in (rec["revocation_reason"] or "").lower()

        # Double revoke → error
        try:
            revoke_cert(cert_id, env.admin_id, "again", env.db_path)
            assert False, "Double revoke phải raise"
        except CertLifecycleError:
            pass

        # Reason rỗng → error
        cert_id2 = env.issue_cert(env.alice_id, "to-revoke2.com")
        try:
            revoke_cert(cert_id2, env.admin_id, "  ", env.db_path)
            assert False, "Reason rỗng phải raise"
        except CertLifecycleError:
            pass
        print("  [revoke] PASS ✓ — revoke OK + reason required + double-revoke blocked")
    finally:
        env.cleanup()


def test_renew_cert_happy():
    env = TestEnv()
    try:
        old_id = env.issue_cert(env.alice_id, "renew.com",
                                san=["www.renew.com"])
        old = get_cert_detail(old_id, env.db_path)

        new = renew_cert(old_id, env.admin_id, 730, env.db_path)
        assert new["id"] != old_id
        assert new["renewed_from_id"] == old_id
        assert new["common_name"] == old["common_name"]
        assert new["owner_id"] == old["owner_id"]
        assert new["serial_hex"] != old["serial_hex"]

        # Cert cũ KHÔNG bị revoke tự động
        old_after = get_cert_detail(old_id, env.db_path)
        assert old_after["revoked_at"] is None
        assert old_after["status"] == "active"

        # Cert mới có cùng public key + subject + SAN
        new_full = get_cert_detail(new["id"], env.db_path)
        old_cert = x509.load_pem_x509_certificate(bytes(old["cert_pem"]))
        new_cert = x509.load_pem_x509_certificate(bytes(new_full["cert_pem"]))
        assert (
            old_cert.public_key().public_numbers()
            == new_cert.public_key().public_numbers()
        ), "Public key phải giống nhau (admin không có private key của customer)"
        assert old_cert.subject == new_cert.subject

        old_san = old_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        new_san = new_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        assert set(old_san) == set(new_san), "SAN phải giống"

        # Cert mới ký bởi Root CA — verify
        ca_cert, _ = load_active_root_ca_with_key(env.db_path)
        ca_cert.public_key().verify(
            new_cert.signature, new_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), new_cert.signature_hash_algorithm,
        )
        print("  [renew-happy] PASS ✓ — cert mới giữ public key + subject + SAN, ký Root CA verify OK")
    finally:
        env.cleanup()


def test_renew_revoked_cert_blocked():
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "rev-then-renew.com")
        revoke_cert(cert_id, env.admin_id, "compromised", env.db_path)
        try:
            renew_cert(cert_id, env.admin_id, 365, env.db_path)
            assert False, "Renew cert đã revoked phải raise"
        except CertLifecycleError:
            pass
        print("  [renew-blocked] PASS ✓ — renew cert đã revoked → error")
    finally:
        env.cleanup()


def test_renew_without_root_ca():
    """Admin xóa Root CA (set inactive) thì renew phải fail."""
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "x.com")
        # Deactivate Root CA → load_active sẽ raise
        conn = get_conn(env.db_path)
        try:
            conn.execute("BEGIN")
            conn.execute("UPDATE root_ca SET is_active = 0")
            conn.execute("COMMIT")
        finally:
            conn.close()
        try:
            renew_cert(cert_id, env.admin_id, 365, env.db_path)
            assert False, "Renew khi không có Root CA active phải raise"
        except CertLifecycleError as e:
            assert "Root CA" in str(e)
        print("  [renew-no-root-ca] PASS ✓ — renew raise khi không có Root CA active")
    finally:
        env.cleanup()


def test_get_cert_detail_ownership():
    env = TestEnv()
    try:
        a_id = env.issue_cert(env.alice_id, "alice.com")

        # Alice xem được
        rec = get_cert_detail(a_id, env.db_path, owner_id=env.alice_id)
        assert rec is not None

        # Bob xem được? — phải None vì owner_id check
        rec_b = get_cert_detail(a_id, env.db_path, owner_id=env.bob_id)
        assert rec_b is None, "Bob không được xem cert Alice"

        # Admin xem (owner_id=None) → OK
        rec_admin = get_cert_detail(a_id, env.db_path)
        assert rec_admin is not None
        print("  [ownership] PASS ✓ — get_cert_detail enforce owner_id khi truyền")
    finally:
        env.cleanup()


def test_renew_then_renew_chain():
    """Renew nhiều lần → chain renewed_from_id chính xác."""
    env = TestEnv()
    try:
        c1 = env.issue_cert(env.alice_id, "chain.com")
        c2 = renew_cert(c1, env.admin_id, 365, env.db_path)["id"]
        c3 = renew_cert(c2, env.admin_id, 365, env.db_path)["id"]

        r3 = get_cert_detail(c3, env.db_path)
        r2 = get_cert_detail(c2, env.db_path)
        r1 = get_cert_detail(c1, env.db_path)
        assert r3["renewed_from_id"] == c2
        assert r2["renewed_from_id"] == c1
        assert r1["renewed_from_id"] is None
        print("  [renew-chain] PASS ✓ — chain renewed_from_id chính xác qua 3 lần renew")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_list_for_owner_isolation,
    test_compute_status_three_branches,
    test_revoke_cert_happy,
    test_renew_cert_happy,
    test_renew_revoked_cert_blocked,
    test_renew_without_root_ca,
    test_get_cert_detail_ownership,
    test_renew_then_renew_chain,
]


def main():
    print("=" * 60)
    print("  M7 Cert Lifecycle — Test Suite")
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
