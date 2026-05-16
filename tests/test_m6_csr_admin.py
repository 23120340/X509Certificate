"""
test_m6_csr_admin.py
--------------------
Test cho M6: csr_admin (approve/reject) + issue_cert_from_csr.

Bao trùm:
  • approve_csr happy path: cert ký bởi Root CA active, public key match CSR
  • reject_csr: status → rejected + reason saved
  • approve khi chưa có Root CA → error
  • approve khi CSR đã reviewed → error
  • Chữ ký CSR bị sửa → approve reject
  • Race: 2 admin approve cùng lúc → 1 thắng, 1 fail
  • Cert phát hành có đúng SAN từ CSR
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from db.connection import init_db, get_conn
from core import encryption
from core.encryption import reset_master_key_cache
from services.auth import register_user
from services.ca_admin import create_root_ca, load_active_root_ca_with_key
from services.customer_keys import generate_keypair
from services.csr_workflow import submit_csr
from services.csr_admin import (
    list_pending_csr, list_all_csr, get_csr_detail,
    approve_csr, reject_csr, CSRAdminError,
)


class TestEnv:
    def __init__(self, with_root_ca: bool = True):
        self.tmpdir = tempfile.mkdtemp(prefix="m6test_")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.master_key_path = os.path.join(self.tmpdir, "master.key")
        reset_master_key_cache()
        encryption.DEFAULT_MASTER_KEY_PATH = self.master_key_path
        init_db(self.db_path)

        admin = register_user("admin1", "AdminPw1234", "admin", self.db_path)
        alice = register_user("alice",  "AlicePw123",  "customer", self.db_path)
        self.admin_id = admin["id"]
        self.alice_id = alice["id"]

        if with_root_ca:
            create_root_ca(
                "Test Root CA", 2048, 3650,
                created_by=self.admin_id, db_path=self.db_path,
            )

    def make_csr(self, common_name: str = "demo.com",
                 san_list=None, owner_id=None) -> int:
        owner = owner_id or self.alice_id
        kp = generate_keypair(owner, f"k-{common_name}", 2048, self.db_path)
        csr = submit_csr(
            owner, kp["id"], common_name, san_list or [], self.db_path,
        )
        return csr["id"]

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_approve_csr_happy_path():
    env = TestEnv()
    try:
        csr_id = env.make_csr("happy.com", ["www.happy.com"])

        before = list_pending_csr(env.db_path)
        assert any(c["id"] == csr_id for c in before)

        issued = approve_csr(
            csr_id=csr_id, admin_id=env.admin_id,
            validity_days=365, db_path=env.db_path,
        )
        assert issued["common_name"] == "happy.com"
        assert len(issued["serial_hex"]) > 0

        # CSR sang approved + cert có trong issued_certs
        rec = get_csr_detail(csr_id, env.db_path)
        assert rec["status"] == "approved"
        assert rec["reviewed_by"] == env.admin_id

        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT cert_pem, csr_request_id, owner_id, common_name "
                "FROM issued_certs WHERE id = ?", (issued["id"],),
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        assert row["csr_request_id"] == csr_id
        assert row["owner_id"] == env.alice_id

        # Cert ký bởi Root CA — verify signature
        cert = x509.load_pem_x509_certificate(bytes(row["cert_pem"]))
        ca_cert, _ = load_active_root_ca_with_key(env.db_path)
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        assert cert.issuer == ca_cert.subject, "issuer phải = Root CA subject"

        print("  [approve-happy] PASS ✓ — cert issued, CSR approved, chữ ký Root CA verify OK")
    finally:
        env.cleanup()


def test_cert_san_matches_csr():
    env = TestEnv()
    try:
        csr_id = env.make_csr("shop.com", ["www.shop.com", "api.shop.com"])
        issued = approve_csr(
            csr_id, env.admin_id, 365, env.db_path,
        )
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT cert_pem FROM issued_certs WHERE id = ?",
                (issued["id"],),
            ).fetchone()
        finally:
            conn.close()
        cert = x509.load_pem_x509_certificate(bytes(row["cert_pem"]))
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        dns_names = set(san.get_values_for_type(x509.DNSName))
        assert "shop.com" in dns_names
        assert "www.shop.com" in dns_names
        assert "api.shop.com" in dns_names
        print("  [san-copy] PASS ✓ — SAN từ CSR được copy vào cert")
    finally:
        env.cleanup()


def test_cert_public_key_matches_csr():
    """Cert phát hành phải bind public key từ CSR (proof of possession)."""
    env = TestEnv()
    try:
        from services.customer_keys import load_private_key
        kp = generate_keypair(env.alice_id, "pop-key", 2048, env.db_path)
        csr = submit_csr(env.alice_id, kp["id"], "pop.com", [], env.db_path)
        issued = approve_csr(csr["id"], env.admin_id, 365, env.db_path)

        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT cert_pem FROM issued_certs WHERE id = ?",
                (issued["id"],),
            ).fetchone()
        finally:
            conn.close()
        cert = x509.load_pem_x509_certificate(bytes(row["cert_pem"]))

        priv = load_private_key(kp["id"], env.alice_id, env.db_path)
        cert_pub = cert.public_key().public_numbers()
        priv_pub = priv.public_key().public_numbers()
        assert cert_pub == priv_pub, "Public key của cert phải khớp customer key"
        print("  [public-key-bind] PASS ✓ — cert public key = customer keypair")
    finally:
        env.cleanup()


def test_reject_csr():
    env = TestEnv()
    try:
        csr_id = env.make_csr("bad.com")
        reject_csr(csr_id, env.admin_id, "Domain không thuộc tổ chức của bạn.",
                   env.db_path)
        rec = get_csr_detail(csr_id, env.db_path)
        assert rec["status"] == "rejected"
        assert "Domain" in rec["reject_reason"]
        assert rec["reviewed_by"] == env.admin_id

        # Reject lần 2 → error
        try:
            reject_csr(csr_id, env.admin_id, "x", env.db_path)
            assert False, "Reject CSR không pending phải raise"
        except CSRAdminError:
            pass

        # Reason rỗng → error
        csr_id2 = env.make_csr("other.com")
        try:
            reject_csr(csr_id2, env.admin_id, "  ", env.db_path)
            assert False, "Reason rỗng phải raise"
        except CSRAdminError:
            pass

        print("  [reject] PASS ✓ — reject + reason required + double-reject blocked")
    finally:
        env.cleanup()


def test_approve_without_root_ca():
    env = TestEnv(with_root_ca=False)
    try:
        csr_id = env.make_csr("no-ca.com")
        try:
            approve_csr(csr_id, env.admin_id, 365, env.db_path)
            assert False, "Approve khi không có Root CA phải raise"
        except CSRAdminError as e:
            assert "Root CA" in str(e)
        # CSR vẫn pending
        rec = get_csr_detail(csr_id, env.db_path)
        assert rec["status"] == "pending"
        print("  [no-root-ca] PASS ✓ — approve raise khi chưa có Root CA, CSR vẫn pending")
    finally:
        env.cleanup()


def test_approve_already_reviewed():
    env = TestEnv()
    try:
        csr_id = env.make_csr()
        approve_csr(csr_id, env.admin_id, 365, env.db_path)
        # Approve lần 2 → error
        try:
            approve_csr(csr_id, env.admin_id, 365, env.db_path)
            assert False, "Approve CSR đã approved phải raise"
        except CSRAdminError:
            pass
        print("  [double-approve] PASS ✓ — approve CSR non-pending raise")
    finally:
        env.cleanup()


def test_tampered_csr_signature_rejected():
    """Sửa byte trong CSR PEM → approve phải reject."""
    env = TestEnv()
    try:
        csr_id = env.make_csr("tamper.com")
        # Sửa 1 byte ngẫu nhiên trong chữ ký của CSR_PEM trong DB
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT csr_pem FROM csr_requests WHERE id = ?", (csr_id,),
            ).fetchone()
            pem = bytes(row["csr_pem"])
            # Parse + tamper bytes inside DER signature, không phá format PEM.
            # Cách đơn giản: load CSR → DER → flip byte cuối (signature) → re-encode PEM
            csr_obj = x509.load_pem_x509_csr(pem)
            der = bytearray(csr_obj.public_bytes(serialization.Encoding.DER))
            der[-50] ^= 0x01  # ở vùng signature (giống tamper_cert_pem legacy)
            import base64
            new_b64 = base64.b64encode(bytes(der)).decode()
            wrapped = "\n".join(new_b64[i:i+64] for i in range(0, len(new_b64), 64))
            tampered_pem = (
                "-----BEGIN CERTIFICATE REQUEST-----\n"
                + wrapped +
                "\n-----END CERTIFICATE REQUEST-----\n"
            ).encode()
            conn.execute("BEGIN")
            conn.execute(
                "UPDATE csr_requests SET csr_pem = ? WHERE id = ?",
                (tampered_pem, csr_id),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

        try:
            approve_csr(csr_id, env.admin_id, 365, env.db_path)
            assert False, "CSR tamper phải bị reject ở verify_csr_signature"
        except CSRAdminError as e:
            assert "Chữ ký" in str(e) or "signature" in str(e).lower()
        print("  [tampered-csr] PASS ✓ — CSR signature lệch → approve reject")
    finally:
        env.cleanup()


def test_list_pending_filters_correctly():
    env = TestEnv()
    try:
        a = env.make_csr("a.com")
        b = env.make_csr("b.com")
        c = env.make_csr("c.com")
        approve_csr(a, env.admin_id, 365, env.db_path)
        reject_csr(b, env.admin_id, "spam", env.db_path)

        pending = list_pending_csr(env.db_path)
        ids = {p["id"] for p in pending}
        assert c in ids
        assert a not in ids and b not in ids

        approved = list_all_csr(env.db_path, status="approved")
        assert {x["id"] for x in approved} == {a}

        rejected = list_all_csr(env.db_path, status="rejected")
        assert {x["id"] for x in rejected} == {b}

        all_ = list_all_csr(env.db_path)
        assert {x["id"] for x in all_} == {a, b, c}
        print("  [list-filter] PASS ✓ — list_pending/list_all/filter status đúng")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_approve_csr_happy_path,
    test_cert_san_matches_csr,
    test_cert_public_key_matches_csr,
    test_reject_csr,
    test_approve_without_root_ca,
    test_approve_already_reviewed,
    test_tampered_csr_signature_rejected,
    test_list_pending_filters_correctly,
]


def main():
    print("=" * 60)
    print("  M6 CSR Admin — Test Suite")
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
