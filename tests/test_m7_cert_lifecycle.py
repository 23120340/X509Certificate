"""
test_m7_cert_lifecycle.py
-------------------------
Test cho M7: services/cert_lifecycle (list/detail/revoke/renew).

Bao trùm:
  • list_all / list_for_owner (BOLA guard)
  • _compute_status: active / expired / revoked
  • revoke_cert happy + reason required + double-revoke blocked
  • renew_cert happy: cert kế nhiệm (id mới) renewed_from_id = cert cũ, giữ
    public key + subject + SAN; cert cũ tự thu hồi 'superseded'
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
from services.customer_keys import generate_keypair, get_key_meta
from services.csr_workflow import submit_csr, domains_for_key, CSRError
from services.csr_admin import approve_csr, list_all_csr, CSRAdminError
from services.cert_lifecycle import (
    list_all_certs, list_certs_for_owner, get_cert_detail,
    revoke_cert, renew_cert,
    certs_sharing_public_key, revoke_certs_by_key,
    CertLifecycleError,
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

    def issue_cert_with_key(self, owner_id: int, key_id: int,
                            common_name: str,
                            san: "list[str] | None" = None) -> int:
        """Helper: dùng LẠI keypair `key_id` → CSR + approve → cert_id.
        Cho phép nhiều cert chia sẻ chung 1 public key (test revoke-by-key)."""
        csr = submit_csr(owner_id, key_id, common_name, san or [], self.db_path)
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
    """Renew = cert KẾ NHIỆM: cert mới (id mới) renewed_from_id = cert cũ, giữ
    public key + subject + SAN; cert cũ tự thu hồi 'superseded'."""
    env = TestEnv()
    try:
        old_id = env.issue_cert(env.alice_id, "renew.com",
                                san=["www.renew.com"])
        old = get_cert_detail(old_id, env.db_path)

        new = renew_cert(old_id, env.admin_id, 730, env.db_path)
        # Cert kế nhiệm: row MỚI, trỏ về cert cũ
        assert new["id"] != old_id
        assert new["renewed_from_id"] == old_id
        assert new["common_name"] == old["common_name"]
        assert new["owner_id"] == old["owner_id"]
        assert new["serial_hex"] != old["serial_hex"]
        assert new["not_valid_after"] > old["not_valid_after"]
        assert new["status"] == "active"
        assert new["revoked_at"] is None

        # Cert cũ tự thu hồi 'superseded'
        old_after = get_cert_detail(old_id, env.db_path)
        assert old_after["revoked_at"] is not None
        assert "superseded" in (old_after["revocation_reason"] or "").lower()
        assert old_after["status"] == "revoked"

        # Có đúng 2 cert (cũ + kế nhiệm)
        assert len(list_all_certs(env.db_path)) == 2

        # Cùng public key + subject + SAN
        old_cert = x509.load_pem_x509_certificate(bytes(old["cert_pem"]))
        new_cert = x509.load_pem_x509_certificate(bytes(new["cert_pem"]))
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

        # Cert mới verify bởi Root CA
        ca_cert, _ = load_active_root_ca_with_key(env.db_path)
        ca_cert.public_key().verify(
            new_cert.signature, new_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), new_cert.signature_hash_algorithm,
        )
        print("  [renew-happy] PASS ✓ — cert kế nhiệm renewed_from_id trỏ cert cũ; cert cũ superseded; giữ public key + subject + SAN")
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
    """Renew nhiều lần → chain renewed_from_id chính xác; cert cũ superseded."""
    env = TestEnv()
    try:
        c1 = env.issue_cert(env.alice_id, "chain.com")
        c2 = renew_cert(c1, env.admin_id, 365, env.db_path)["id"]
        c3 = renew_cert(c2, env.admin_id, 365, env.db_path)["id"]

        r3 = get_cert_detail(c3, env.db_path)
        r2 = get_cert_detail(c2, env.db_path)
        r1 = get_cert_detail(c1, env.db_path)
        # Chain renewed_from_id
        assert r3["renewed_from_id"] == c2
        assert r2["renewed_from_id"] == c1
        assert r1["renewed_from_id"] is None
        # Các cert tiền nhiệm đã superseded; chỉ cert mới nhất còn active
        assert r1["status"] == "revoked" and r2["status"] == "revoked"
        assert r3["status"] == "active"
        print("  [renew-chain] PASS ✓ — chain renewed_from_id đúng qua 3 đời; tiền nhiệm superseded")
    finally:
        env.cleanup()


# ── Revoke-by-key (containment khi lộ private key) ─────────────────────────────

def test_certs_sharing_public_key():
    """certs_sharing_public_key gom đúng các cert chung 1 keypair, loại cert key khác."""
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "shared-key", 2048, env.db_path)
        c1 = env.issue_cert_with_key(env.alice_id, kp["id"], "one.com")
        c2 = env.issue_cert_with_key(env.alice_id, kp["id"], "two.com")
        other = env.issue_cert(env.alice_id, "other.com")  # key KHÁC

        ids = {s["id"] for s in certs_sharing_public_key(c1, env.db_path)}
        assert ids == {c1, c2}, ids
        assert other not in ids
        # Đối xứng: từ c2 cũng ra cùng tập
        assert {s["id"] for s in certs_sharing_public_key(c2, env.db_path)} == {c1, c2}
        print("  [share-key] PASS ✓ — gom đúng cert chung public key, loại key khác")
    finally:
        env.cleanup()


def test_revoke_by_key_cascade():
    """revoke_certs_by_key thu hồi mọi cert chung khóa; cert key khác giữ nguyên; idempotent."""
    env = TestEnv()
    try:
        ocsp = os.path.join(env.tmpdir, "ocsp.json")
        kp = generate_keypair(env.alice_id, "leak-key", 2048, env.db_path)
        c1 = env.issue_cert_with_key(env.alice_id, kp["id"], "a.com")
        c2 = env.issue_cert_with_key(env.alice_id, kp["id"], "b.com")
        safe = env.issue_cert(env.alice_id, "safe.com")  # key KHÁC

        res = revoke_certs_by_key(c1, env.admin_id, "Private key leaked",
                                  env.db_path, ocsp_db_path=ocsp)
        assert res["revoked_count"] == 2, res
        assert set(res["revoked_ids"]) == {c1, c2}, res

        by_id = {c["id"]: c["status"] for c in list_all_certs(env.db_path)}
        assert by_id[c1] == "revoked" and by_id[c2] == "revoked"
        assert by_id[safe] == "active", "cert dùng key khác KHÔNG được đụng"
        assert "leaked" in (
            get_cert_detail(c2, env.db_path)["revocation_reason"] or ""
        ).lower()

        # Idempotent: gọi lại không revoke thêm
        res2 = revoke_certs_by_key(c1, env.admin_id, "again",
                                   env.db_path, ocsp_db_path=ocsp)
        assert res2["revoked_count"] == 0, res2
        assert set(res2["already_revoked_ids"]) == {c1, c2}, res2

        # Reason rỗng → raise (validate trước khi đụng DB)
        try:
            revoke_certs_by_key(safe, env.admin_id, "  ",
                                env.db_path, ocsp_db_path=ocsp)
            assert False, "reason rỗng phải raise"
        except CertLifecycleError:
            pass
        print("  [revoke-by-key] PASS ✓ — cascade theo khóa, chừa key khác, idempotent, reason required")
    finally:
        env.cleanup()


def test_revoke_by_key_catches_renewed():
    """Cert sau renew giữ nguyên key → revoke-by-key gom cả dòng renew, không double-revoke."""
    env = TestEnv()
    try:
        ocsp = os.path.join(env.tmpdir, "ocsp.json")
        kp = generate_keypair(env.alice_id, "renew-key", 2048, env.db_path)
        c1 = env.issue_cert_with_key(env.alice_id, kp["id"], "renewme.com")
        new_id = renew_cert(c1, env.admin_id, 365, env.db_path)["id"]  # c1→superseded

        # new dùng chung key với c1 (renew giữ nguyên public key)
        assert {s["id"] for s in certs_sharing_public_key(new_id, env.db_path)} == {c1, new_id}

        res = revoke_certs_by_key(new_id, env.admin_id, "key leaked",
                                  env.db_path, ocsp_db_path=ocsp)
        assert new_id in res["revoked_ids"]
        assert c1 in res["already_revoked_ids"]  # đã superseded từ trước
        assert get_cert_detail(new_id, env.db_path)["status"] == "revoked"
        print("  [revoke-by-key-renew] PASS ✓ — gom cả cert đã renew (cùng key), bỏ qua cert superseded")
    finally:
        env.cleanup()


def test_domains_for_key_warning_data():
    """domains_for_key trả domain (pending/approved) đã dùng keypair — dữ liệu cho cảnh báo reuse."""
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "multi-domain", 2048, env.db_path)
        env.issue_cert_with_key(env.alice_id, kp["id"], "first.com")   # approved
        submit_csr(env.alice_id, kp["id"], "second.com", [], env.db_path)  # pending

        assert set(domains_for_key(kp["id"], env.alice_id, env.db_path)) == {
            "first.com", "second.com",
        }
        # BOLA: Bob hỏi key của Alice → rỗng
        assert domains_for_key(kp["id"], env.bob_id, env.db_path) == []
        # Key chưa dùng → rỗng
        kp2 = generate_keypair(env.alice_id, "fresh", 2048, env.db_path)
        assert domains_for_key(kp2["id"], env.alice_id, env.db_path) == []
        print("  [domains-for-key] PASS ✓ — liệt kê domain pending/approved của key; BOLA-safe")
    finally:
        env.cleanup()


def test_revoke_by_key_marks_and_wipes_keypair():
    """revoke-by-key (Admin) đánh dấu key lộ + WIPE private key → key thành
    public-only; submit_csr bằng key đó bị chặn."""
    env = TestEnv()
    try:
        ocsp = os.path.join(env.tmpdir, "ocsp.json")
        kp = generate_keypair(env.alice_id, "leak-kp", 2048, env.db_path)
        c1 = env.issue_cert_with_key(env.alice_id, kp["id"], "lk-a.com")

        before = get_key_meta(kp["id"], env.alice_id, env.db_path)
        assert before["compromised_at"] is None and before["is_public_only"] == 0

        res = revoke_certs_by_key(
            c1, env.admin_id, "key leaked", env.db_path, ocsp_db_path=ocsp,
        )
        assert kp["id"] in res["compromised_key_ids"], res

        after = get_key_meta(kp["id"], env.alice_id, env.db_path)
        assert after["compromised_at"] is not None
        assert after["is_public_only"] == 1, "private key phải bị wipe"

        # submit_csr bằng key đã lộ → chặn
        try:
            submit_csr(env.alice_id, kp["id"], "new-domain.com", [], env.db_path)
            assert False, "submit_csr bằng key lộ phải raise"
        except CSRError as e:
            assert "lộ" in str(e).lower()
        print("  [revoke-by-key-marks-key] PASS ✓ — key lộ bị đánh dấu + wipe + chặn CSR mới")
    finally:
        env.cleanup()


def test_revoke_by_key_cancels_pending_csrs():
    """⭐ revoke-by-key phải HỦY luôn các CSR đang pending dùng chung khóa lộ;
    CSR dùng key KHÁC không bị đụng; CSR đã hủy không approve được nữa."""
    env = TestEnv()
    try:
        ocsp = os.path.join(env.tmpdir, "ocsp.json")
        kp = generate_keypair(env.alice_id, "reuse-key", 2048, env.db_path)
        # 4 CSR chung 1 key: duyệt 2 (ra cert), để 2 pending.
        c1 = env.issue_cert_with_key(env.alice_id, kp["id"], "d1.com")
        env.issue_cert_with_key(env.alice_id, kp["id"], "d2.com")
        p3 = submit_csr(env.alice_id, kp["id"], "d3.com", [], env.db_path)
        p4 = submit_csr(env.alice_id, kp["id"], "d4.com", [], env.db_path)
        # CSR pending dùng key KHÁC — phải giữ nguyên.
        kp_other = generate_keypair(env.alice_id, "other-key", 2048, env.db_path)
        p_keep = submit_csr(env.alice_id, kp_other["id"], "keep.com", [], env.db_path)

        res = revoke_certs_by_key(c1, env.admin_id, "Private key leaked",
                                  env.db_path, ocsp_db_path=ocsp)
        assert set(res["cancelled_csr_ids"]) == {p3["id"], p4["id"]}, res

        status = {c["id"]: c["status"] for c in list_all_csr(env.db_path)}
        assert status[p3["id"]] == "rejected", status
        assert status[p4["id"]] == "rejected", status
        assert status[p_keep["id"]] == "pending", "CSR key khác không được đụng"

        # CSR đã hủy → approve phải bị chặn (status không còn pending).
        try:
            approve_csr(p3["id"], env.admin_id, 365, env.db_path)
            assert False, "approve CSR đã hủy phải raise"
        except CSRAdminError:
            pass
        print("  [revoke-by-key-cancels-csr] PASS ✓ — hủy CSR pending chung khóa; key khác giữ nguyên")
    finally:
        env.cleanup()


def test_approve_csr_blocked_on_compromised_key():
    """Phòng tuyến 2: approve_csr TỪ CHỐI nếu keypair của CSR đã bị đánh dấu LỘ
    KHÓA — kể cả khi CSR còn lọt 'pending' (mô phỏng trường hợp lọt cascade)."""
    env = TestEnv()
    try:
        kp = generate_keypair(env.alice_id, "comp-key", 2048, env.db_path)
        csr = submit_csr(env.alice_id, kp["id"], "late.com", [], env.db_path)

        # Mô phỏng: keypair bị đánh dấu lộ NHƯNG CSR vẫn pending (chưa qua cascade).
        conn = get_conn(env.db_path)
        try:
            conn.execute("BEGIN")
            conn.execute(
                "UPDATE customer_keys SET compromised_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), kp["id"]),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

        try:
            approve_csr(csr["id"], env.admin_id, 365, env.db_path)
            assert False, "approve trên key đã lộ phải raise"
        except CSRAdminError as e:
            assert "lộ" in str(e).lower(), str(e)
        print("  [approve-blocked-compromised] PASS ✓ — approve_csr chặn CSR dùng key đã lộ")
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
    test_certs_sharing_public_key,
    test_revoke_by_key_cascade,
    test_revoke_by_key_catches_renewed,
    test_revoke_by_key_marks_and_wipes_keypair,
    test_revoke_by_key_cancels_pending_csrs,
    test_approve_csr_blocked_on_compromised_key,
    test_domains_for_key_warning_data,
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
