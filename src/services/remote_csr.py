"""
services/remote_csr.py
----------------------
Receive a CSR from a remote LAN client and insert it into the normal CSR queue.

This is intentionally narrow: it supports the project demo where machine A runs
the Admin/CA app, while machine B generates a keypair + CSR and submits it over
LAN. Admin approval still uses the existing CSR Queue UI and csr_admin service.
"""

import json
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from core.csr import parse_csr, verify_csr_signature
from db.connection import conn_scope, transaction
from services.audit import write_audit, Action
from services.auth import login, register_user, AuthError
from services.cert_lifecycle import list_certs_for_owner, get_cert_detail
from services.csr_workflow import list_my_csr, get_my_csr_by_id
from services.revocation_workflow import (
    submit_revoke_request,
    list_my_revocation_requests,
    RevocationWorkflowError,
)


class RemoteCSRError(Exception):
    """Business error while accepting a remote CSR."""


def _clean_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise RemoteCSRError("username is required")
    return username


def _clean_password(password: str) -> str:
    if not password:
        raise RemoteCSRError("password is required")
    return password


def _csr_common_name(csr) -> str:
    attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs or not attrs[0].value.strip():
        raise RemoteCSRError("CSR subject must contain Common Name")
    return attrs[0].value.strip()


def _csr_san_list(csr) -> list[str]:
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    dns = san.get_values_for_type(x509.DNSName)
    ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    out = []
    for item in dns + ips:
        if item not in out:
            out.append(item)
    return out


def _login_or_register_customer(username: str, password: str, db_path: str) -> dict:
    try:
        user = login(username, password, db_path)
    except AuthError:
        try:
            user = register_user(username, password, "customer", db_path)
            write_audit(
                db_path, user["id"], Action.REGISTER,
                target_type="user", target_id=str(user["id"]),
                details={"role": "customer", "source": "remote_csr_api"},
            )
        except AuthError as e:
            raise RemoteCSRError(str(e)) from e

    if user["role"] != "customer":
        raise RemoteCSRError("remote CSR submitter must be a customer account")
    return user


def _login_customer(username: str, password: str, db_path: str) -> dict:
    username = _clean_username(username)
    password = _clean_password(password)
    try:
        user = login(username, password, db_path)
    except AuthError as e:
        raise RemoteCSRError(str(e)) from e
    if user["role"] != "customer":
        raise RemoteCSRError("remote customer endpoint requires a customer account")
    return user


def _unique_key_name(owner_id: int, requested_name: str, db_path: str) -> str:
    base = (requested_name or "remote-key").strip()[:48] or "remote-key"
    with conn_scope(db_path) as conn:
        exists = conn.execute(
            "SELECT 1 FROM customer_keys WHERE owner_id = ? AND name = ?",
            (owner_id, base),
        ).fetchone()
    if not exists:
        return base
    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{base}-{suffix}"[:64]


def submit_remote_csr(
    *,
    username: str,
    password: str,
    csr_pem: "str | bytes",
    key_name: str,
    db_path: str,
) -> dict:
    """
    Accept a CSR generated on another machine and create a pending csr_requests
    row in the Admin machine database.

    The private key never leaves the client machine. Because the existing schema
    requires a customer_keys row, we store only the CSR public key and leave the
    encrypted private key fields empty for this remote/demo key.
    """
    username = _clean_username(username)
    password = _clean_password(password)
    csr_bytes = csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem

    try:
        csr = parse_csr(csr_bytes)
    except ValueError as e:
        raise RemoteCSRError(f"invalid CSR: {e}") from e
    if not verify_csr_signature(csr):
        raise RemoteCSRError("CSR signature is invalid")

    common_name = _csr_common_name(csr)
    san_list = _csr_san_list(csr)
    public_key = csr.public_key()
    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_size = getattr(public_key, "key_size", 2048)

    user = _login_or_register_customer(username, password, db_path)
    final_key_name = _unique_key_name(user["id"], key_name, db_path)
    now = datetime.now(timezone.utc).isoformat()
    san_json = json.dumps(san_list, ensure_ascii=False) if san_list else None

    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO customer_keys "
            "(owner_id, name, algorithm, key_size, public_key_pem, "
            " encrypted_private_key, gcm_nonce, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user["id"], final_key_name, "RSA", key_size,
                public_key_pem, b"", b"", now,
            ),
        )
        key_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO csr_requests "
            "(requester_id, customer_key_id, common_name, san_list_json, "
            " csr_pem, status, submitted_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (user["id"], key_id, common_name, san_json, csr_bytes, now),
        )
        csr_id = cur.lastrowid

    write_audit(
        db_path, user["id"], Action.CSR_SUBMITTED,
        target_type="csr", target_id=str(csr_id),
        details={
            "source": "remote_csr_api",
            "common_name": common_name,
            "san_list": san_list,
            "customer_key_id": key_id,
        },
    )
    return {
        "id": csr_id,
        "requester_id": user["id"],
        "username": user["username"],
        "customer_key_id": key_id,
        "key_name": final_key_name,
        "common_name": common_name,
        "san_list": san_list,
        "status": "pending",
        "submitted_at": now,
    }


def list_remote_csrs(
    *,
    username: str,
    password: str,
    db_path: str,
    status: "str | None" = None,
) -> list[dict]:
    user = _login_customer(username, password, db_path)
    return list_my_csr(user["id"], db_path, status=status)


def get_remote_csr_detail(
    *,
    username: str,
    password: str,
    csr_id: int,
    db_path: str,
) -> "dict | None":
    user = _login_customer(username, password, db_path)
    rec = get_my_csr_by_id(csr_id, user["id"], db_path)
    if rec is not None and isinstance(rec.get("csr_pem"), (bytes, bytearray)):
        rec["csr_pem"] = bytes(rec["csr_pem"]).decode("ascii", errors="replace")
    return rec


def list_remote_certs(
    *,
    username: str,
    password: str,
    db_path: str,
    status: "str | None" = None,
) -> list[dict]:
    user = _login_customer(username, password, db_path)
    return list_certs_for_owner(user["id"], db_path, status=status)


def get_remote_cert_detail(
    *,
    username: str,
    password: str,
    cert_id: int,
    db_path: str,
) -> "dict | None":
    user = _login_customer(username, password, db_path)
    rec = get_cert_detail(cert_id, db_path, owner_id=user["id"])
    if rec is not None and isinstance(rec.get("cert_pem"), (bytes, bytearray)):
        rec["cert_pem"] = bytes(rec["cert_pem"]).decode("ascii", errors="replace")
    return rec


def submit_remote_revocation_request(
    *,
    username: str,
    password: str,
    cert_id: int,
    reason: str,
    db_path: str,
) -> dict:
    user = _login_customer(username, password, db_path)
    try:
        rec = submit_revoke_request(cert_id, user["id"], reason, db_path)
    except RevocationWorkflowError as e:
        raise RemoteCSRError(str(e)) from e
    write_audit(
        db_path, user["id"], Action.REVOKE_REQUESTED,
        target_type="revocation_request", target_id=str(rec["id"]),
        details={"cert_id": cert_id, "source": "remote_csr_api"},
    )
    return rec


def list_remote_revocation_requests(
    *,
    username: str,
    password: str,
    db_path: str,
) -> list[dict]:
    user = _login_customer(username, password, db_path)
    return list_my_revocation_requests(user["id"], db_path)
