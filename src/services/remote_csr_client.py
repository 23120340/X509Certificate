"""
services/remote_csr_client.py
-----------------------------
Client-side helper for submitting a CSR to the Admin machine over LAN.
"""

import json
import urllib.error
import urllib.request


class RemoteCSRClientError(Exception):
    """Network/API error while submitting a CSR to the Admin machine."""


def check_admin_api_health(*, api_url: str, timeout: float = 5.0) -> dict:
    api_url = (api_url or "").strip().rstrip("/")
    if not api_url:
        raise RemoteCSRClientError("Admin API URL is required")
    try:
        with urllib.request.urlopen(api_url + "/health", timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RemoteCSRClientError(f"HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RemoteCSRClientError(f"Cannot connect to Admin API: {e}") from e
    except TimeoutError as e:
        raise RemoteCSRClientError("Cannot connect to Admin API: timed out") from e
    except json.JSONDecodeError as e:
        raise RemoteCSRClientError(f"Invalid JSON response: {e}") from e
    if not data.get("ok"):
        raise RemoteCSRClientError(str(data.get("error", "health check failed")))
    return data


def _post_json(
    *,
    api_url: str,
    path: str,
    payload: dict,
    token: str = "",
    timeout: float = 10.0,
) -> dict:
    api_url = (api_url or "").strip().rstrip("/")
    if not api_url:
        raise RemoteCSRClientError("Admin API URL is required")
    req = urllib.request.Request(
        api_url + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        req.add_header("X-CSR-API-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RemoteCSRClientError(f"HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RemoteCSRClientError(f"Cannot connect to Admin API: {e}") from e
    except TimeoutError as e:
        raise RemoteCSRClientError("Cannot connect to Admin API: timed out") from e
    except json.JSONDecodeError as e:
        raise RemoteCSRClientError(f"Invalid JSON response: {e}") from e
    if not data.get("ok"):
        raise RemoteCSRClientError(str(data.get("error", "remote API failed")))
    return data


def submit_csr_to_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    key_name: str,
    csr_pem: bytes,
    token: str = "",
) -> dict:
    payload = {
        "username": username,
        "password": password,
        "key_name": key_name,
        "csr_pem": csr_pem.decode("ascii"),
    }
    data = _post_json(
        api_url=api_url, path="/api/csr/submit", payload=payload, token=token,
    )
    return data["csr"]


def list_customer_csrs_from_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    status: "str | None" = None,
    token: str = "",
) -> list[dict]:
    data = _post_json(
        api_url=api_url,
        path="/api/customer/csrs",
        payload={"username": username, "password": password, "status": status},
        token=token,
    )
    return data["csrs"]


def get_customer_csr_detail_from_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    csr_id: int,
    token: str = "",
) -> dict:
    data = _post_json(
        api_url=api_url,
        path="/api/customer/csr/detail",
        payload={"username": username, "password": password, "csr_id": csr_id},
        token=token,
    )
    return data["csr"]


def list_customer_certs_from_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    status: "str | None" = None,
    token: str = "",
) -> list[dict]:
    data = _post_json(
        api_url=api_url,
        path="/api/customer/certs",
        payload={"username": username, "password": password, "status": status},
        token=token,
    )
    return data["certs"]


def get_customer_cert_detail_from_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    cert_id: int,
    token: str = "",
) -> dict:
    data = _post_json(
        api_url=api_url,
        path="/api/customer/cert/detail",
        payload={"username": username, "password": password, "cert_id": cert_id},
        token=token,
    )
    return data["cert"]


def submit_revocation_to_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    cert_id: int,
    reason: str,
    token: str = "",
) -> dict:
    data = _post_json(
        api_url=api_url,
        path="/api/customer/revoke/submit",
        payload={
            "username": username,
            "password": password,
            "cert_id": cert_id,
            "reason": reason,
        },
        token=token,
    )
    return data["revocation_request"]


def list_revocation_requests_from_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    token: str = "",
) -> list[dict]:
    data = _post_json(
        api_url=api_url,
        path="/api/customer/revoke/requests",
        payload={"username": username, "password": password},
        token=token,
    )
    return data["revocation_requests"]


def get_crl_from_admin_api(
    *,
    api_url: str,
    token: str = "",
) -> tuple["dict | None", list[dict]]:
    data = _post_json(
        api_url=api_url,
        path="/api/crl/current",
        payload={},
        token=token,
    )
    return data.get("crl_info"), data.get("crl_entries", [])
