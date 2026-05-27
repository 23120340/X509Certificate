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


def submit_csr_to_admin_api(
    *,
    api_url: str,
    username: str,
    password: str,
    key_name: str,
    csr_pem: bytes,
    token: str = "",
) -> dict:
    api_url = (api_url or "").strip().rstrip("/")
    if not api_url:
        raise RemoteCSRClientError("Admin API URL is required")
    payload = {
        "username": username,
        "password": password,
        "key_name": key_name,
        "csr_pem": csr_pem.decode("ascii"),
    }
    req = urllib.request.Request(
        api_url + "/api/csr/submit",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        req.add_header("X-CSR-API-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
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
        raise RemoteCSRClientError(str(data.get("error", "remote submit failed")))
    return data["csr"]
