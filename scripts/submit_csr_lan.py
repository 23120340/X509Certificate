"""
Generate a local keypair + CSR and submit it to the Admin machine over LAN.

Example:
    python scripts/submit_csr_lan.py --server http://192.168.1.10:8787 ^
      --username alice --password AlicePw123 --domain myshop.com ^
      --san myshop.com,www.myshop.com
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cryptography.hazmat.primitives import serialization

from core.cert_builder import generate_rsa_keypair
from core.csr import build_csr, csr_to_pem


def _parse_args():
    p = argparse.ArgumentParser(description="Submit CSR to X.509 Admin over LAN")
    p.add_argument("--server", required=True, help="Admin API base URL, e.g. http://192.168.1.10:8787")
    p.add_argument("--username", required=True, help="Customer username on Admin machine")
    p.add_argument("--password", required=True, help="Customer password")
    p.add_argument("--domain", required=True, help="Common Name for the CSR")
    p.add_argument("--san", default="", help="Comma-separated SAN values")
    p.add_argument("--key-name", default="lan-client-key", help="Key display name in Admin DB")
    p.add_argument("--key-size", type=int, default=2048, choices=(2048, 3072, 4096))
    p.add_argument("--out-dir", default="client_artifacts", help="Where to save private key + CSR locally")
    p.add_argument("--token", default="", help="Optional X-CSR-API-Token")
    return p.parse_args()


def main():
    args = _parse_args()
    san_list = [s.strip() for s in args.san.split(",") if s.strip()]

    key = generate_rsa_keypair(args.key_size)
    csr = build_csr(key, common_name=args.domain, san_list=san_list)
    csr_pem = csr_to_pem(csr)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_domain = "".join(c if c.isalnum() or c in ".-_" else "_" for c in args.domain)
    key_path = out_dir / f"{safe_domain}.key"
    csr_path = out_dir / f"{safe_domain}.csr"
    key_path.write_bytes(key_pem)
    csr_path.write_bytes(csr_pem)

    payload = {
        "username": args.username,
        "password": args.password,
        "key_name": args.key_name,
        "csr_pem": csr_pem.decode("ascii"),
    }
    body = json.dumps(payload).encode("utf-8")
    url = args.server.rstrip("/") + "/api/csr/submit"
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if args.token:
        req.add_header("X-CSR-API-Token", args.token)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Submit failed HTTP {e.code}: {msg}")
    except urllib.error.URLError as e:
        raise SystemExit(f"Cannot connect to Admin API: {e}")

    print(json.dumps(response, ensure_ascii=False, indent=2))
    print(f"Saved private key: {key_path}")
    print(f"Saved CSR:         {csr_path}")
    print("Admin can now refresh CSR Queue and approve/reject this request.")


if __name__ == "__main__":
    main()
