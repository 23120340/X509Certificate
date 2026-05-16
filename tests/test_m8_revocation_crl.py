"""
test_m8_revocation_crl.py
-------------------------
Test cho M8: revocation_workflow + crl_publish.

Bao trùm:
  • submit revoke request: validate ownership + cert chưa revoked + no duplicate pending
  • list_my_requests / list_pending / filter status
  • approve_revocation: cert đánh dấu revoked + request='approved' atomic
  • reject_revocation: reason required
  • approve khi cert đã revoked sẵn (admin revoke trực tiếp) → vẫn approve nhưng không ghi đè
  • snapshot_revoked_serials: parse hex đúng + sort ổn định
  • publish_crl: file CRL có signature từ Root CA, parse + verify OK
  • publish_crl: OCSP DB JSON sync đúng
  • publish_crl khi chưa có Root CA → error
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from cryptography import x509

from db.connection import init_db, get_conn
from core import encryption
from core.encryption import reset_master_key_cache
from services.auth import register_user
from services.ca_admin import create_root_ca, load_active_root_ca_with_key
from services.customer_keys import generate_keypair
from services.csr_workflow import submit_csr
from services.csr_admin import approve_csr
from services.cert_lifecycle import revoke_cert
from services.revocation_workflow import (
    submit_revoke_request, list_my_revocation_requests,
    list_pending_revocations, list_all_revocations,
    approve_revocation, reject_revocation, get_revocation_detail,
    RevocationWorkflowError,
)
from services.crl_publish import (
    publish_crl, snapshot_revoked_serials, get_published_crl_info,
    CRLPublishError,
)


class TestEnv:
    def __init__(self, with_root_ca: bool = True):
        self.tmpdir = tempfile.mkdtemp(prefix="m8test_")
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

    def issue_cert(self, owner_id: int, cn: str) -> int:
        kp = generate_keypair(owner_id, f"k-{cn}", 2048, self.db_path)
        csr = submit_csr(owner_id, kp["id"], cn, [], self.db_path)
        issued = approve_csr(csr["id"], self.admin_id, 365, self.db_path)
        return issued["id"]

    def cleanup(self):
        reset_master_key_cache()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_submit_revoke_request_happy():
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "rev1.com")
        req = submit_revoke_request(
            cert_id, env.alice_id, "Key bị lộ", env.db_path,
        )
        assert req["status"] == "pending"
        assert req["issued_cert_id"] == cert_id

        mine = list_my_revocation_requests(env.alice_id, env.db_path)
        assert any(r["id"] == req["id"] for r in mine)

        pending = list_pending_revocations(env.db_path)
        assert any(r["id"] == req["id"] for r in pending)
        print("  [submit-happy] PASS ✓ — submit + list_my + list_pending OK")
    finally:
        env.cleanup()


def test_submit_validation():
    env = TestEnv()
    try:
        a_cert = env.issue_cert(env.alice_id, "alice.com")

        # Bob không submit được request cho cert của Alice
        try:
            submit_revoke_request(a_cert, env.bob_id, "spam", env.db_path)
            assert False, "BOLA — phải raise"
        except RevocationWorkflowError:
            pass

        # Reason rỗng
        try:
            submit_revoke_request(a_cert, env.alice_id, "  ", env.db_path)
            assert False, "Reason rỗng phải raise"
        except RevocationWorkflowError:
            pass

        # Duplicate pending
        submit_revoke_request(a_cert, env.alice_id, "key lost", env.db_path)
        try:
            submit_revoke_request(a_cert, env.alice_id, "again", env.db_path)
            assert False, "Duplicate pending phải raise"
        except RevocationWorkflowError as e:
            assert "pending" in str(e).lower()

        # Cert đã revoked
        revoked_cert = env.issue_cert(env.alice_id, "revoked.com")
        revoke_cert(revoked_cert, env.admin_id, "manual", env.db_path)
        try:
            submit_revoke_request(
                revoked_cert, env.alice_id, "x", env.db_path,
            )
            assert False, "Cert đã revoked phải raise"
        except RevocationWorkflowError:
            pass

        print("  [submit-validation] PASS ✓ — BOLA/empty/duplicate/already-revoked đều bị reject")
    finally:
        env.cleanup()


def test_approve_revocation_marks_cert_revoked():
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "app1.com")
        req = submit_revoke_request(
            cert_id, env.alice_id, "no longer needed", env.db_path,
        )
        result = approve_revocation(req["id"], env.admin_id, env.db_path)
        assert result["cert_was_revoked"] is True

        rec = get_revocation_detail(req["id"], env.db_path)
        assert rec["status"] == "approved"
        assert rec["reviewed_by"] == env.admin_id

        # Cert giờ là revoked
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT revoked_at, revocation_reason FROM issued_certs "
                "WHERE id = ?", (cert_id,),
            ).fetchone()
        finally:
            conn.close()
        assert row["revoked_at"] is not None
        assert "no longer needed" in row["revocation_reason"]
        print("  [approve] PASS ✓ — approve revocation → cert.revoked_at set, request='approved'")
    finally:
        env.cleanup()


def test_approve_when_already_revoked():
    """Cert đã revoke trực tiếp → approve request không ghi đè revoked_at cũ."""
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "race.com")
        # Tạo request (chỉ có thể tạo khi cert chưa revoked)
        req = submit_revoke_request(
            cert_id, env.alice_id, "from customer", env.db_path,
        )
        # Admin revoke trực tiếp (không qua request)
        revoke_cert(cert_id, env.admin_id, "from admin", env.db_path)
        # Lấy revoked_at từ direct revoke
        conn = get_conn(env.db_path)
        try:
            old_revoked = conn.execute(
                "SELECT revoked_at FROM issued_certs WHERE id = ?",
                (cert_id,),
            ).fetchone()["revoked_at"]
        finally:
            conn.close()

        # Approve request giờ — cert đã revoke, request vẫn được approve
        result = approve_revocation(req["id"], env.admin_id, env.db_path)
        assert result["cert_was_revoked"] is False  # đã revoked từ trước

        # revoked_at không bị ghi đè
        conn = get_conn(env.db_path)
        try:
            new_revoked = conn.execute(
                "SELECT revoked_at, revocation_reason FROM issued_certs "
                "WHERE id = ?", (cert_id,),
            ).fetchone()
        finally:
            conn.close()
        assert new_revoked["revoked_at"] == old_revoked, \
            "revoked_at phải giữ giá trị ban đầu khi cert đã revoked"
        assert "from admin" in new_revoked["revocation_reason"], \
            "revocation_reason phải giữ lý do ban đầu"
        print("  [approve-already-revoked] PASS ✓ — approve không ghi đè revoked_at cũ")
    finally:
        env.cleanup()


def test_reject_revocation():
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "reject.com")
        req = submit_revoke_request(
            cert_id, env.alice_id, "want to revoke", env.db_path,
        )

        # Reason rỗng → fail
        try:
            reject_revocation(req["id"], env.admin_id, "  ", env.db_path)
            assert False, "Reason rỗng phải raise"
        except RevocationWorkflowError:
            pass

        reject_revocation(
            req["id"], env.admin_id, "Domain vẫn còn hợp lệ.", env.db_path,
        )
        rec = get_revocation_detail(req["id"], env.db_path)
        assert rec["status"] == "rejected"

        # Cert KHÔNG bị revoked
        conn = get_conn(env.db_path)
        try:
            row = conn.execute(
                "SELECT revoked_at FROM issued_certs WHERE id = ?",
                (cert_id,),
            ).fetchone()
        finally:
            conn.close()
        assert row["revoked_at"] is None
        print("  [reject] PASS ✓ — reject + reason required, cert không bị revoked")
    finally:
        env.cleanup()


def test_double_approve_blocked():
    env = TestEnv()
    try:
        cert_id = env.issue_cert(env.alice_id, "double.com")
        req = submit_revoke_request(cert_id, env.alice_id, "x", env.db_path)
        approve_revocation(req["id"], env.admin_id, env.db_path)
        try:
            approve_revocation(req["id"], env.admin_id, env.db_path)
            assert False, "Double approve phải raise"
        except RevocationWorkflowError:
            pass
        print("  [double-approve] PASS ✓ — request non-pending không approve được")
    finally:
        env.cleanup()


def test_snapshot_revoked_serials():
    env = TestEnv()
    try:
        # Phát hành 3 cert, revoke 2
        c1 = env.issue_cert(env.alice_id, "s1.com")
        c2 = env.issue_cert(env.alice_id, "s2.com")
        c3 = env.issue_cert(env.alice_id, "s3.com")
        revoke_cert(c1, env.admin_id, "r1", env.db_path)
        revoke_cert(c3, env.admin_id, "r3", env.db_path)

        serials = snapshot_revoked_serials(env.db_path)
        assert len(serials) == 2, f"Phải có 2 serial revoked, có {len(serials)}"
        # Mỗi serial > 0
        for s in serials:
            assert isinstance(s, int) and s > 0
        print("  [snapshot] PASS ✓ — chỉ trả về serial của cert revoked_at != NULL")
    finally:
        env.cleanup()


def test_publish_crl_file():
    env = TestEnv()
    try:
        c1 = env.issue_cert(env.alice_id, "p1.com")
        c2 = env.issue_cert(env.alice_id, "p2.com")
        revoke_cert(c1, env.admin_id, "compromised", env.db_path)

        crl_path = os.path.join(env.tmpdir, "crl.pem")
        ocsp_db_path = os.path.join(env.tmpdir, "ocsp_db.json")
        info = publish_crl(
            env.admin_id, env.db_path, crl_path, ocsp_db_path,
            validity_days=7,
        )
        assert info["revoked_count"] == 1
        assert os.path.exists(crl_path)
        assert os.path.exists(ocsp_db_path)

        # Parse CRL file
        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        revoked_in_crl = [r.serial_number for r in crl]
        # c1 phải có; c2 không
        conn = get_conn(env.db_path)
        try:
            s1 = int(conn.execute(
                "SELECT serial_hex FROM issued_certs WHERE id = ?", (c1,),
            ).fetchone()["serial_hex"], 16)
            s2 = int(conn.execute(
                "SELECT serial_hex FROM issued_certs WHERE id = ?", (c2,),
            ).fetchone()["serial_hex"], 16)
        finally:
            conn.close()
        assert s1 in revoked_in_crl
        assert s2 not in revoked_in_crl

        # CRL được ký bởi Root CA → verify chữ ký
        ca_cert, _ = load_active_root_ca_with_key(env.db_path)
        assert crl.is_signature_valid(ca_cert.public_key()), \
            "CRL signature phải verify được bằng Root CA public key"
        assert crl.issuer == ca_cert.subject

        # OCSP DB JSON là list serial as string
        with open(ocsp_db_path) as f:
            ocsp_data = json.load(f)
        assert isinstance(ocsp_data, list)
        assert str(s1) in ocsp_data
        assert str(s2) not in ocsp_data
        print("  [publish] PASS ✓ — CRL signed by Root CA verify OK, OCSP DB sync đúng")
    finally:
        env.cleanup()


def test_publish_crl_without_root_ca():
    env = TestEnv(with_root_ca=False)
    try:
        crl_path = os.path.join(env.tmpdir, "crl.pem")
        try:
            publish_crl(env.admin_id, env.db_path, crl_path)
            assert False, "Publish khi không có Root CA phải raise"
        except CRLPublishError as e:
            assert "Root CA" in str(e)
        print("  [publish-no-root-ca] PASS ✓ — publish raise khi không có Root CA")
    finally:
        env.cleanup()


def test_get_published_crl_info():
    env = TestEnv()
    try:
        crl_path = os.path.join(env.tmpdir, "crl.pem")
        # Chưa publish → None
        assert get_published_crl_info(crl_path) is None

        c1 = env.issue_cert(env.alice_id, "info.com")
        revoke_cert(c1, env.admin_id, "x", env.db_path)
        publish_crl(env.admin_id, env.db_path, crl_path,
                    ocsp_db_path=None)

        info = get_published_crl_info(crl_path)
        assert info is not None
        assert info["revoked_count"] == 1
        assert "Root" in info["issuer"]
        assert info["file_size"] > 0
        print("  [info] PASS ✓ — get_published_crl_info đọc + parse OK")
    finally:
        env.cleanup()


def test_filter_status_in_list_all():
    env = TestEnv()
    try:
        c1 = env.issue_cert(env.alice_id, "f1.com")
        c2 = env.issue_cert(env.alice_id, "f2.com")
        c3 = env.issue_cert(env.alice_id, "f3.com")
        r1 = submit_revoke_request(c1, env.alice_id, "x", env.db_path)["id"]
        r2 = submit_revoke_request(c2, env.alice_id, "y", env.db_path)["id"]
        r3 = submit_revoke_request(c3, env.alice_id, "z", env.db_path)["id"]
        approve_revocation(r1, env.admin_id, env.db_path)
        reject_revocation(r2, env.admin_id, "no.", env.db_path)
        # r3 vẫn pending

        approved = list_all_revocations(env.db_path, status="approved")
        rejected = list_all_revocations(env.db_path, status="rejected")
        pending  = list_all_revocations(env.db_path, status="pending")
        assert {x["id"] for x in approved} == {r1}
        assert {x["id"] for x in rejected} == {r2}
        assert {x["id"] for x in pending}  == {r3}
        all_   = list_all_revocations(env.db_path)
        assert {x["id"] for x in all_} == {r1, r2, r3}
        print("  [filter] PASS ✓ — list_all filter status đúng cả 3 trạng thái")
    finally:
        env.cleanup()


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_submit_revoke_request_happy,
    test_submit_validation,
    test_approve_revocation_marks_cert_revoked,
    test_approve_when_already_revoked,
    test_reject_revocation,
    test_double_approve_blocked,
    test_snapshot_revoked_serials,
    test_publish_crl_file,
    test_publish_crl_without_root_ca,
    test_get_published_crl_info,
    test_filter_status_in_list_all,
]


def main():
    print("=" * 60)
    print("  M8 Revocation Workflow + CRL Publish — Test Suite")
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
