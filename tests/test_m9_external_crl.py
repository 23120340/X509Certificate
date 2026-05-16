"""
test_m9_external_crl.py
-----------------------
Test cho M9: external_certs + list_crl_entries.

Bao trùm:
  • parse_cert_summary: parse PEM/DER, fingerprint chính xác
  • save_external_cert: PEM/DER input đều OK, fingerprint UNIQUE per uploader
  • BOLA guard: Bob không xem/xóa được cert của Alice
  • delete_external_cert
  • list_crl_entries: parse CRL file đã publish, enrich với DB
"""

import os
import shutil
import sys
import tempfile
import hashlib
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from db.connection import init_db
from core import encryption
from core.encryption import reset_master_key_cache
from services.auth import register_user
from services.ca_admin import (
    create_root_ca, load_active_root_ca_with_key,
)
from services.customer_keys import generate_keypair
from services.csr_workflow import submit_csr
from services.csr_admin import approve_csr
from services.cert_lifecycle import revoke_cert, get_cert_detail
from services.crl_publish import publish_crl, list_crl_entries
from services.external_certs import (
    save_external_cert, list_external_certs, get_external_cert,
    delete_external_cert, parse_cert_summary, ExternalCertError,
)


class TestEnv:
    def __init__(self, with_root_ca: bool = True):
        self.tmpdir = tempfile.mkdtemp(prefix="m9test_")
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

    def issue_cert(self, owner_id: int, cn: str) -> dict:
        kp = generate_keypair(owner_id, f"k-{cn}", 2048, self.db_path)
        csr = submit_csr(owner_id, kp["id"], cn, [], self.db_path)
        issued = approve_csr(csr["id"], self.admin_id, 365, self.db_path)
        return get_cert_detail(issued["id"], self.db_path)

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_parse_cert_summary_pem_and_der():
    env = TestEnv()
    try:
        cert_rec = env.issue_cert(env.alice_id, "preview.com")
        pem_bytes = bytes(cert_rec["cert_pem"])
        s = parse_cert_summary(pem_bytes)
        assert "preview.com" in s["subject"]
        assert "Root" in s["issuer"]
        assert len(s["fingerprint_sha256"]) == 64  # SHA-256 hex

        # Verify fingerprint match manual
        cert = x509.load_pem_x509_certificate(pem_bytes)
        der = cert.public_bytes(Encoding.DER)
        manual_fp = hashlib.sha256(der).hexdigest()
        assert s["fingerprint_sha256"] == manual_fp

        # DER cũng parse được
        der_bytes = cert.public_bytes(Encoding.DER)
        s2 = parse_cert_summary(der_bytes)
        assert s2["fingerprint_sha256"] == manual_fp
        print("  [parse-summary] PASS ✓ — PEM/DER đều parse, fingerprint khớp")
    finally:
        env.cleanup()


def test_parse_invalid_cert():
    env = TestEnv()
    try:
        try:
            parse_cert_summary(b"this is not a certificate")
            assert False, "Garbage input phải raise ExternalCertError"
        except ExternalCertError:
            pass
        print("  [parse-invalid] PASS ✓ — input không hợp lệ raise ExternalCertError")
    finally:
        env.cleanup()


def test_save_external_cert_happy():
    env = TestEnv()
    try:
        cert_rec = env.issue_cert(env.bob_id, "third-party.com")
        pem = bytes(cert_rec["cert_pem"])
        rec = save_external_cert(
            env.alice_id, pem, "cert của Bob để theo dõi", env.db_path,
        )
        assert rec["uploader_id"] == env.alice_id
        assert rec["id"] > 0

        # list
        items = list_external_certs(env.alice_id, env.db_path)
        assert any(r["id"] == rec["id"] for r in items)
        # subject + issuer được enrich
        item = next(r for r in items if r["id"] == rec["id"])
        assert "third-party.com" in item["subject"]
        print("  [save-happy] PASS ✓ — save + list + enrich subject/issuer")
    finally:
        env.cleanup()


def test_duplicate_upload_blocked():
    env = TestEnv()
    try:
        cert_rec = env.issue_cert(env.bob_id, "dup.com")
        pem = bytes(cert_rec["cert_pem"])
        save_external_cert(env.alice_id, pem, "first", env.db_path)
        try:
            save_external_cert(env.alice_id, pem, "second", env.db_path)
            assert False, "Cùng uploader + cùng fingerprint phải raise"
        except ExternalCertError as e:
            assert "fingerprint" in str(e).lower()
        # Bob CÓ THỂ upload cùng cert (vì uploader khác)
        save_external_cert(env.bob_id, pem, "from-bob", env.db_path)
        print("  [dup] PASS ✓ — duplicate per-uploader blocked, cross-uploader OK")
    finally:
        env.cleanup()


def test_bola_guard():
    env = TestEnv()
    try:
        cert_rec = env.issue_cert(env.alice_id, "x.com")
        pem = bytes(cert_rec["cert_pem"])
        rec = save_external_cert(env.alice_id, pem, "alice", env.db_path)

        # Bob không xem/xóa được
        assert get_external_cert(rec["id"], env.bob_id, env.db_path) is None
        try:
            delete_external_cert(rec["id"], env.bob_id, env.db_path)
            assert False, "Bob xóa cert Alice phải raise"
        except ExternalCertError:
            pass

        # Alice xem/xóa được
        assert get_external_cert(rec["id"], env.alice_id, env.db_path) is not None
        delete_external_cert(rec["id"], env.alice_id, env.db_path)
        assert get_external_cert(rec["id"], env.alice_id, env.db_path) is None
        print("  [bola] PASS ✓ — uploader-only access cho get/delete")
    finally:
        env.cleanup()


def test_list_crl_entries():
    env = TestEnv()
    try:
        c1 = env.issue_cert(env.alice_id, "crl1.com")
        c2 = env.issue_cert(env.alice_id, "crl2.com")
        c3 = env.issue_cert(env.bob_id,   "crl3.com")
        revoke_cert(c1["id"], env.admin_id, "r1", env.db_path)
        revoke_cert(c3["id"], env.admin_id, "r3", env.db_path)

        crl_path = os.path.join(env.tmpdir, "crl.pem")
        publish_crl(env.admin_id, env.db_path, crl_path, ocsp_db_path=None)

        # Không có db_path → enrich rỗng
        bare = list_crl_entries(crl_path)
        assert len(bare) == 2
        assert all(e["common_name"] == "" for e in bare)

        # Với db_path → enrich
        rich = list_crl_entries(crl_path, db_path=env.db_path)
        assert len(rich) == 2
        cns = {e["common_name"] for e in rich}
        assert "crl1.com" in cns and "crl3.com" in cns
        # owner_username enrich
        owners = {e["owner_username"] for e in rich}
        assert "alice" in owners and "bob" in owners
        print("  [crl-entries] PASS ✓ — parse CRL + enrich CN/owner từ DB")
    finally:
        env.cleanup()


def test_list_crl_entries_no_file():
    env = TestEnv()
    try:
        entries = list_crl_entries("/nonexistent/path/crl.pem")
        assert entries == []
        print("  [crl-entries-no-file] PASS ✓ — file không tồn tại → trả []")
    finally:
        env.cleanup()


def test_external_cert_pem_roundtrip():
    """Upload DER → DB lưu PEM → re-read parse OK."""
    env = TestEnv()
    try:
        cert_rec = env.issue_cert(env.bob_id, "roundtrip.com")
        pem_orig = bytes(cert_rec["cert_pem"])
        cert = x509.load_pem_x509_certificate(pem_orig)
        der = cert.public_bytes(Encoding.DER)

        # Upload bằng DER
        rec = save_external_cert(env.alice_id, der, "der-input", env.db_path)
        stored = get_external_cert(rec["id"], env.alice_id, env.db_path)
        # Lưu trong DB là PEM
        stored_pem = bytes(stored["cert_pem"])
        assert b"BEGIN CERTIFICATE" in stored_pem
        # Parse được + đúng cert
        parsed = x509.load_pem_x509_certificate(stored_pem)
        assert parsed.serial_number == cert.serial_number
        print("  [der-input] PASS ✓ — DER input lưu thành PEM, roundtrip OK")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_parse_cert_summary_pem_and_der,
    test_parse_invalid_cert,
    test_save_external_cert_happy,
    test_duplicate_upload_blocked,
    test_bola_guard,
    test_list_crl_entries,
    test_list_crl_entries_no_file,
    test_external_cert_pem_roundtrip,
]


def main():
    print("=" * 60)
    print("  M9 External certs + CRL Lookup — Test Suite")
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
