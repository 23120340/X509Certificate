"""
services/cert_lifecycle.py
--------------------------
Quản lý vòng đời của cert đã phát hành — đáp ứng:
  • A.8  Admin quản lý các cert đã cấp phát (revoke, renew).
  • B.6  Customer xem danh sách + tải các cert đã được cấp.

API:
  • list_certs_for_owner(owner_id, db_path, status?)  — customer xem cert mình
  • list_all_certs(db_path, status?)                  — admin xem tất cả
  • get_cert_detail(cert_id, db_path, owner_id?)      — kèm cert_pem; nếu
                                                          owner_id != None
                                                          → enforce ownership
  • revoke_cert(cert_id, admin_id, reason, db_path)   — set revoked_at + reason
  • renew_cert(cert_id, admin_id, validity_days, db_path) → cert mới

Cert status được suy ra động (không lưu trong DB):
  revoked   → nếu revoked_at IS NOT NULL
  expired   → nếu now > not_valid_after
  active    → ngược lại
"""

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from core import keyalg
from core.cert_builder import reissue_cert_for_renewal
from db.connection import conn_scope, transaction
from services.ca_admin import load_active_root_ca_with_key, CAError
from services.customer_keys import compromise_keys_for_fingerprint
from services.crl_publish import DEFAULT_OCSP_DB_PATH, sync_ocsp_db, publish_crl
from services.system_config import get_config, get_hash_algorithm


VALID_STATUS_FILTERS = ("active", "expired", "revoked", "all")
MAX_REVOKE_REASON_LEN = 500


class CertLifecycleError(Exception):
    """Lỗi nghiệp vụ trong cert lifecycle."""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _compute_status(row, now: datetime) -> str:
    """Suy ra status hiện tại của cert. Row phải có revoked_at + not_valid_after."""
    if row["revoked_at"]:
        return "revoked"
    na = _parse_iso(row["not_valid_after"])
    if na is None:
        return "active"
    # `not_valid_after` đã lưu dạng tz-aware; nếu không, gán UTC.
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)
    if na < now:
        return "expired"
    return "active"


def _row_to_dict(row, now: datetime) -> dict:
    d = dict(row)
    d["status"] = _compute_status(row, now)
    return d


# ── Queries ──────────────────────────────────────────────────────────────────

def _list_certs(db_path: str, where: str, params: tuple,
                status: Optional[str]) -> "list[dict]":
    """Helper chung: chạy query rồi filter status post-hoc (status là computed)."""
    if status is not None and status not in VALID_STATUS_FILTERS:
        raise CertLifecycleError(f"Status filter không hợp lệ: {status}")

    sql = (
        "SELECT c.id, c.csr_request_id, c.owner_id, u.username AS owner_username, "
        "       c.serial_hex, c.common_name, c.not_valid_before, "
        "       c.not_valid_after, c.issued_at, c.issued_by, "
        "       c.renewed_from_id, c.revoked_at, c.revocation_reason "
        "FROM issued_certs c LEFT JOIN users u ON u.id = c.owner_id"
    )
    if where:
        sql += " WHERE " + where
    sql += " ORDER BY c.id DESC"

    now = datetime.now(timezone.utc)
    with conn_scope(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        out: "list[dict]" = []
        for r in rows:
            d = _row_to_dict(r, now)
            if status in (None, "all") or d["status"] == status:
                out.append(d)
        return out


def list_certs_for_owner(
    owner_id: int, db_path: str, status: Optional[str] = None,
) -> "list[dict]":
    """Customer xem cert của mình (newest first)."""
    return _list_certs(db_path, "c.owner_id = ?", (owner_id,), status)


def list_all_certs(
    db_path: str, status: Optional[str] = None,
) -> "list[dict]":
    """Admin xem tất cả cert (newest first)."""
    return _list_certs(db_path, "", (), status)


def get_cert_detail(
    cert_id: int, db_path: str, owner_id: Optional[int] = None,
) -> Optional[dict]:
    """
    Trả về cert metadata + cert_pem. Nếu `owner_id != None`, enforce
    ownership (customer view). Trả về None nếu không tồn tại hoặc không
    thuộc owner_id.
    """
    sql = (
        "SELECT c.id, c.csr_request_id, c.owner_id, u.username AS owner_username, "
        "       c.serial_hex, c.common_name, c.cert_pem, "
        "       c.not_valid_before, c.not_valid_after, c.issued_at, "
        "       c.issued_by, c.renewed_from_id, "
        "       c.revoked_at, c.revocation_reason "
        "FROM issued_certs c LEFT JOIN users u ON u.id = c.owner_id "
        "WHERE c.id = ?"
    )
    params: tuple = (cert_id,)
    if owner_id is not None:
        sql += " AND c.owner_id = ?"
        params = (cert_id, owner_id)

    with conn_scope(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    return _row_to_dict(row, now)


# ── Revoke ───────────────────────────────────────────────────────────────────

def revoke_cert(
    cert_id: int, admin_id: int, reason: str, db_path: str,
    ocsp_db_path: "str | None" = DEFAULT_OCSP_DB_PATH,
) -> dict:
    """
    Đánh dấu cert đã thu hồi. CRL chưa publish ngay; sẽ snapshot qua
    services/crl_publish.py ở M8.

    Refuse nếu cert đã revoked rồi (giữ history chỉ 1 revocation event).
    Trả về dict cert sau khi revoke.
    """
    reason = (reason or "").strip()
    if not reason:
        raise CertLifecycleError("Lý do thu hồi không được rỗng.")
    if len(reason) > MAX_REVOKE_REASON_LEN:
        raise CertLifecycleError(
            f"Lý do dài quá {MAX_REVOKE_REASON_LEN} ký tự."
        )

    now = datetime.now(timezone.utc).isoformat()
    with transaction(db_path) as conn:
        row = conn.execute(
            "SELECT revoked_at FROM issued_certs WHERE id = ?", (cert_id,),
        ).fetchone()
        if row is None:
            raise CertLifecycleError("Không tìm thấy cert.")
        if row["revoked_at"]:
            raise CertLifecycleError(
                f"Cert đã bị revoked lúc {row['revoked_at']}."
            )
        conn.execute(
            "UPDATE issued_certs SET revoked_at = ?, revocation_reason = ? "
            "WHERE id = ?",
            (now, reason, cert_id),
        )

    sync_ocsp_db(db_path, ocsp_db_path)
    detail = get_cert_detail(cert_id, db_path)
    return detail


# ── Revoke-by-key (containment khi nghi ngờ lộ private key) ───────────────────
#
# Revocation chuẩn là THEO SERIAL: revoke_cert chỉ thu hồi đúng 1 cert. Nhưng một
# private key có thể đứng sau NHIỀU cert — khách hàng dùng lại key cho nhiều domain,
# hoặc cert đã renew/re-issue (giữ nguyên public key). Khi key bị lộ, thu hồi 1 serial
# KHÔNG vô hiệu hóa các cert anh em → key vẫn còn đường sống. Nhóm hàm dưới gom mọi
# cert chia sẻ public key rồi thu hồi đồng loạt.
#
# Định danh khóa = SHA-256(SubjectPublicKeyInfo DER) trích trực tiếp từ cert_pem.
# Ổn định tuyệt đối: cùng keypair → cùng fingerprint, bất kể subject/serial/extension;
# bắt được cả cert renew/re-issue lẫn cert không gắn CSR nào (vd cert external/đổi CA).

def _spki_fingerprint(cert) -> str:
    """SHA-256 (hex) SPKI của public key trong cert (keyalg.public_key_fingerprint)."""
    return keyalg.public_key_fingerprint(cert.public_key())


def _fingerprint_of_pem(cert_pem) -> "str | None":
    """Fingerprint khóa từ cert PEM (bytes/str). None nếu PEM hỏng (skip phòng thủ)."""
    try:
        cert = x509.load_pem_x509_certificate(bytes(cert_pem))
    except Exception:
        return None
    return _spki_fingerprint(cert)


def _anchor_fingerprint(cert_id: int, db_path: str) -> "tuple[dict, str]":
    """(anchor_detail, key_fingerprint). Raise CertLifecycleError nếu cert không
    tồn tại hoặc PEM hỏng — fingerprint được tính MỘT lần, không bao giờ None."""
    anchor = get_cert_detail(cert_id, db_path)
    if anchor is None:
        raise CertLifecycleError("Không tìm thấy cert.")
    fp = _fingerprint_of_pem(anchor["cert_pem"])
    if fp is None:
        raise CertLifecycleError(
            "Cert này có PEM không hợp lệ, không trích được public key."
        )
    return anchor, fp


def _scan_certs_with_fingerprint(
    target_fp: str, db_path: str, only_unrevoked: bool,
    owner_id: Optional[int] = None,
) -> "list[dict]":
    """Quét issued_certs, trả các row có cùng key-fingerprint (status computed,
    bỏ cert_pem). Dùng chung cho certs_sharing_public_key + revoke_certs_by_key
    nên cả hai luôn nhìn CÙNG một tập khóa.

    owner_id != None → chỉ xét cert của owner đó (giới hạn cascade trong phạm vi
    1 chủ sở hữu, dùng cho yêu cầu thu hồi do chính customer gửi)."""
    now = datetime.now(timezone.utc)
    out: "list[dict]" = []
    with conn_scope(db_path) as conn:
        rows = conn.execute(
            "SELECT c.id, c.owner_id, u.username AS owner_username, "
            "       c.serial_hex, c.common_name, c.cert_pem, "
            "       c.not_valid_after, c.revoked_at, c.revocation_reason "
            "FROM issued_certs c LEFT JOIN users u ON u.id = c.owner_id "
            "ORDER BY c.id DESC"
        ).fetchall()
    for r in rows:
        if owner_id is not None and r["owner_id"] != owner_id:
            continue   # giới hạn phạm vi chủ sở hữu (rẻ hơn parse PEM → check trước)
        if _fingerprint_of_pem(r["cert_pem"]) != target_fp:
            continue
        status = _compute_status(r, now)
        if only_unrevoked and status == "revoked":
            continue
        d = dict(r)
        d.pop("cert_pem", None)
        d["status"] = status
        out.append(d)
    return out


def key_fingerprint_for_cert(cert_id: int, db_path: str) -> str:
    """Fingerprint public key của cert (SHA-256 SPKI). Raise CertLifecycleError
    nếu cert không tồn tại / PEM hỏng."""
    _anchor, fp = _anchor_fingerprint(cert_id, db_path)
    return fp


def certs_sharing_public_key(
    cert_id: int, db_path: str, only_unrevoked: bool = False,
    owner_id: Optional[int] = None,
) -> "list[dict]":
    """
    Danh sách cert dùng CHUNG public key với `cert_id` (GỒM cả chính nó),
    newest-first. Mỗi phần tử có `status` computed, KHÔNG kèm cert_pem.

    only_unrevoked=True → bỏ cert đã thu hồi (dùng để xem trước khi cascade).
    owner_id != None    → chỉ gom cert của owner đó (yêu cầu của customer chỉ
                          được tác động lên cert của chính họ — giữ kỷ luật BOLA).
    Lưu ý: cert đã hết hạn (status 'expired') vẫn được tính — chúng chưa thu
    hồi nên revoke-by-key vẫn nên gom để đánh dấu thu hồi rõ ràng khi lộ khóa.

    Raise CertLifecycleError nếu cert_id không tồn tại / PEM hỏng.
    """
    _anchor, target_fp = _anchor_fingerprint(cert_id, db_path)
    return _scan_certs_with_fingerprint(
        target_fp, db_path, only_unrevoked, owner_id=owner_id,
    )


def revoke_certs_by_key(
    cert_id: int,
    admin_id: int,
    reason: str,
    db_path: str,
    ocsp_db_path: "str | None" = DEFAULT_OCSP_DB_PATH,
) -> dict:
    """
    Thu hồi TẤT CẢ cert chưa-thu-hồi dùng CHUNG public key với `cert_id`
    (containment khi nghi ngờ lộ khóa). Idempotent: cert đã revoked được bỏ qua.

    Thứ tự FAIL-SAFE: (1) thu hồi cert — mọi UPDATE trong 1 transaction;
    (2) sync OCSP; (3) đánh dấu + wipe keypair lộ. Bước (3) chạy SAU vì việc
    thu hồi cert là containment quan trọng nhất; nếu lỗi giữa (1) và (3), cert
    đã revoked (an toàn) và bước wipe key là idempotent, chạy lại được.

    Sau khi thu hồi cert + wipe key, còn HỦY mọi CSR đang pending dùng chung
    khóa này (containment — khóa đã lộ không được sinh thêm cert).

    Trả về dict {anchor_id, key_fingerprint, matched, revoked_ids,
                 already_revoked_ids, revoked_count, compromised_key_ids,
                 cancelled_csr_ids}.
    Raise CertLifecycleError nếu reason rỗng/quá dài hoặc cert_id không hợp lệ.
    """
    reason = (reason or "").strip()
    if not reason:
        raise CertLifecycleError("Lý do thu hồi không được rỗng.")
    if len(reason) > MAX_REVOKE_REASON_LEN:
        raise CertLifecycleError(f"Lý do dài quá {MAX_REVOKE_REASON_LEN} ký tự.")

    # Fingerprint tính 1 lần (đã None-checked) và dùng cho cả scan lẫn audit →
    # không còn double-read, key_fingerprint trả về luôn hợp lệ.
    _anchor, key_fp = _anchor_fingerprint(cert_id, db_path)
    siblings = _scan_certs_with_fingerprint(key_fp, db_path, only_unrevoked=False)

    pending = [s for s in siblings if s["status"] != "revoked"]
    already = [s["id"] for s in siblings if s["status"] == "revoked"]

    now = datetime.now(timezone.utc).isoformat()
    revoked_ids: "list[int]" = []
    if pending:
        with transaction(db_path) as conn:
            for s in pending:
                cur = conn.execute(
                    "UPDATE issued_certs SET revoked_at = ?, revocation_reason = ? "
                    "WHERE id = ? AND revoked_at IS NULL",
                    (now, reason, s["id"]),
                )
                if cur.rowcount > 0:
                    revoked_ids.append(s["id"])
        # Đồng bộ OCSP 1 lần sau cả batch (giống reissue_all_under_active_ca).
        sync_ocsp_db(db_path, ocsp_db_path)

    # Lộ khóa → đánh dấu + wipe private key của MỌI keypair dùng khóa này
    # (cross-owner: đây là công cụ của Admin, có thẩm quyền containment).
    compromised_key_ids = compromise_keys_for_fingerprint(key_fp, db_path)

    # Khóa đã vô hiệu hóa → hủy luôn các CSR đang pending dùng chính khóa đó,
    # tránh admin lỡ duyệt rồi phát hành cert mới từ một khóa đã lộ. Import cục bộ
    # để tránh phụ thuộc vòng giữa hai service ở thời điểm nạp module.
    from services.csr_workflow import cancel_pending_csrs_for_fingerprint
    cancelled_csr_ids = cancel_pending_csrs_for_fingerprint(
        key_fp, db_path, admin_id=admin_id,
        reason=f"Tự hủy do revoke-by-key (lộ khóa) — fingerprint {key_fp[:16]}…",
    )

    return {
        "anchor_id":            cert_id,
        "key_fingerprint":      key_fp,
        "matched":              len(siblings),
        "revoked_ids":          revoked_ids,
        "already_revoked_ids":  already,
        "revoked_count":        len(revoked_ids),
        "compromised_key_ids":  compromised_key_ids,
        "cancelled_csr_ids":    cancelled_csr_ids,
    }


# ── Renew ────────────────────────────────────────────────────────────────────

def renew_cert(
    cert_id: int,
    admin_id: int,
    validity_days: int,
    db_path: str,
    ocsp_url: "str | None" = None,
    crl_url:  "str | None" = None,
    ocsp_db_path: "str | None" = DEFAULT_OCSP_DB_PATH,
) -> dict:
    """
    GIA HẠN bằng cách phát hành cert KẾ NHIỆM:

      1. Ký lại (giữ subject + public key + extensions của cert cũ) thành cert
         MỚI với thời hạn validity mới + serial mới + chữ ký Root CA active;
         `renewed_from_id` trỏ về cert cũ → cột "Renew từ" hiển thị chain.
      2. THU HỒI cert cũ với lý do 'superseded' + sync OCSP (tránh hai cert hợp
         lệ song song cho cùng domain).

    Hàm băm chữ ký lấy theo system_config. ocsp_url/crl_url mặc định None →
    giữ nguyên CRLDP/AIA của cert cũ (chỉ ghi đè nếu caller truyền URL mới).

    Trả về dict cert MỚI. Raise CertLifecycleError nếu:
      • cert_id không tồn tại
      • cert đã revoked (gia hạn cert đã thu hồi vô nghĩa)
      • chưa có Root CA active
    """
    if validity_days < 1:
        raise CertLifecycleError("validity_days phải >= 1.")

    old = get_cert_detail(cert_id, db_path)
    if old is None:
        raise CertLifecycleError("Không tìm thấy cert.")
    if old["revoked_at"]:
        raise CertLifecycleError(
            "Cert đã bị thu hồi — không thể renew. Phát hành cert mới qua CSR."
        )

    try:
        ca_cert, ca_key = load_active_root_ca_with_key(db_path)
    except CAError as e:
        raise CertLifecycleError(
            f"Không renew được: {e} Tạo Root CA trước."
        ) from e

    old_cert_obj = x509.load_pem_x509_certificate(bytes(old["cert_pem"]))
    new_cert, new_serial = reissue_cert_for_renewal(
        old_cert_obj, ca_cert, ca_key,
        validity_days=validity_days,
        ocsp_url=ocsp_url, crl_url=crl_url,
        hash_algorithm=get_hash_algorithm(db_path),
    )
    cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)

    try:
        nb = new_cert.not_valid_before_utc.isoformat()
        na = new_cert.not_valid_after_utc.isoformat()
    except AttributeError:
        nb = new_cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
        na = new_cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

    now = datetime.now(timezone.utc).isoformat()
    serial_hex = f"{new_serial:x}"

    # INSERT cert kế nhiệm (renewed_from_id = cert cũ) + thu hồi cert cũ.
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO issued_certs "
            "(csr_request_id, owner_id, serial_hex, common_name, cert_pem, "
            " not_valid_before, not_valid_after, issued_at, issued_by, "
            " renewed_from_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (old["csr_request_id"], old["owner_id"], serial_hex,
             old["common_name"], cert_pem, nb, na, now, admin_id, cert_id),
        )
        new_id = cur.lastrowid
        conn.execute(
            "UPDATE issued_certs SET revoked_at = ?, revocation_reason = ? "
            "WHERE id = ? AND revoked_at IS NULL",
            (now, "superseded — renewed", cert_id),
        )

    # Đồng bộ OCSP để cert cũ (đã superseded) hiển thị revoked ngay.
    sync_ocsp_db(db_path, ocsp_db_path)
    return get_cert_detail(new_id, db_path)


# ── Re-issue toàn bộ dưới Root CA active (A.x — đổi/active CA) ────────────────

def _signed_by(cert, ca_public_key, ca_subject) -> bool:
    """True nếu `cert` được CA (subject + public key) này ký hợp lệ."""
    if cert.issuer != ca_subject:
        return False
    try:
        keyalg.verify_with_public_key(
            ca_public_key, cert.signature,
            cert.tbs_certificate_bytes, cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def reissue_all_under_active_ca(
    admin_id: int, db_path: str,
    ocsp_db_path: "str | None" = DEFAULT_OCSP_DB_PATH,
) -> dict:
    """
    Cấp lại TOÀN BỘ chứng chỉ đang còn hiệu lực dưới Root CA ĐANG ACTIVE.

    Dùng sau khi tạo / đổi (rotate) Root CA: các cert cũ vẫn mang chữ ký của
    CA cũ nên client FAIL verify. Hàm này, với mỗi cert active (chưa revoked,
    chưa hết hạn) mà CHƯA do CA active ký:
      1. Ký lại bằng CA active — giữ subject + public key + extensions, GIỮ
         nguyên hạn hết hạn ban đầu → INSERT cert mới. KHÔNG set renewed_from_id
         (đây là RE-ISSUE do đổi CA, KHÔNG phải renew — cột "Renew từ" để '—').
      2. Thu hồi cert cũ với lý do 'superseded' (truy vết qua revocation_reason).
    Sau cùng: publish CRL mới (ký bởi CA active) + đồng bộ OCSP, để cert cũ
    hiển thị đã thu hồi.

    Idempotent: bỏ qua cert đã do CA active ký (chạy lại không nhân đôi),
    cert đã revoked, cert đã hết hạn.

    Trả về dict {total, reissued, revoked, skipped, crl}.
    """
    try:
        ca_cert, ca_key = load_active_root_ca_with_key(db_path)
    except CAError as e:
        raise CertLifecycleError(
            f"Không cấp lại được: {e} Tạo Root CA trước."
        ) from e

    hash_algo = get_hash_algorithm(db_path)
    from services.infra_manager import prod_crl_url, prod_ocsp_url
    ocsp_url = get_config("prod_ocsp_url", db_path) or prod_ocsp_url()
    crl_url  = get_config("prod_crl_url", db_path) or prod_crl_url()

    active_pub = ca_cert.public_key()
    active_subject = ca_cert.subject

    actives = list_all_certs(db_path, status="active")
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    to_write = []   # (old_id, owner_id, csr_req, cn, cert_pem, nb, na, serial_hex)
    skipped = 0
    for r in actives:
        detail = get_cert_detail(r["id"], db_path)
        if detail is None:
            continue
        old_cert = x509.load_pem_x509_certificate(bytes(detail["cert_pem"]))
        if _signed_by(old_cert, active_pub, active_subject):
            skipped += 1   # đã do CA active ký — bỏ qua (idempotent)
            continue
        try:
            na_old = old_cert.not_valid_after_utc
        except AttributeError:
            na_old = old_cert.not_valid_after.replace(tzinfo=timezone.utc)
        remaining_days = max(1, (na_old - now_dt).days)  # giữ nguyên hạn cũ
        new_cert, new_serial = reissue_cert_for_renewal(
            old_cert, ca_cert, ca_key,
            validity_days=remaining_days,
            ocsp_url=ocsp_url, crl_url=crl_url,
            hash_algorithm=hash_algo,
        )
        cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)
        try:
            nb = new_cert.not_valid_before_utc.isoformat()
            na = new_cert.not_valid_after_utc.isoformat()
        except AttributeError:
            nb = new_cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
            na = new_cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()
        to_write.append((
            detail["id"], detail["owner_id"], detail["csr_request_id"],
            detail["common_name"], cert_pem, nb, na, f"{new_serial:x}",
        ))

    with transaction(db_path) as conn:
        for (old_id, owner_id, csr_req, cn, cert_pem, nb, na, serial_hex) in to_write:
            # KHÔNG set renewed_from_id: re-issue do đổi Root CA, không phải
            # renew → "Renew từ" hiển thị '—'. Lineage truy vết qua việc cert
            # cũ bị thu hồi với lý do 'superseded' (cập nhật ngay bên dưới).
            conn.execute(
                "INSERT INTO issued_certs "
                "(csr_request_id, owner_id, serial_hex, common_name, cert_pem, "
                " not_valid_before, not_valid_after, issued_at, issued_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (csr_req, owner_id, serial_hex, cn, cert_pem,
                 nb, na, now_iso, admin_id),
            )
            conn.execute(
                "UPDATE issued_certs SET revoked_at = ?, revocation_reason = ? "
                "WHERE id = ? AND revoked_at IS NULL",
                (now_iso, "superseded — re-issued under active Root CA", old_id),
            )

    reissued = len(to_write)
    crl_info = None
    if reissued > 0:
        # CRL mới ký bởi CA active, snapshot toàn bộ revoked (gồm cert vừa thu hồi).
        crl_info = publish_crl(admin_id, db_path, ocsp_db_path=ocsp_db_path)

    return {
        "total":    len(actives),
        "reissued": reissued,
        "revoked":  reissued,
        "skipped":  skipped,
        "crl":      crl_info,
    }
