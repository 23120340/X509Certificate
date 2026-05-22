"""
test_infra_manager.py
---------------------
Smoke test cho services.infra_manager — module mới quản lý Prod + Lab CRL/OCSP.

6 P0 test:
  • singleton identity
  • start_prod_servers idempotent
  • start_lab_servers idempotent
  • prod + lab cùng chạy, mỗi cái phục vụ data riêng (isolation)
  • lab OCSP toggle enabled/503 runtime
  • stop_all idempotent + reset state

Chạy:
    python tests/test_infra_manager.py
"""

import os
import socket
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

import services.infra_manager as infra_module
from services.infra_manager import (
    InfraManager, get_infra,
    PROD_CRL_PORT, PROD_OCSP_PORT, LAB_CRL_PORT, LAB_OCSP_PORT,
    prod_crl_url, prod_ocsp_url, lab_crl_url, lab_ocsp_url,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _reset_singleton():
    """Reset module-level singleton giữa các test."""
    if infra_module._instance is not None:
        try:
            infra_module._instance.stop_all()
        except Exception:
            pass
    infra_module._instance = None


def _seed_data():
    """Ghi CRL + OCSP DB stub vào cả 2 thư mục để server có file phục vụ."""
    os.makedirs("certs", exist_ok=True)
    os.makedirs("lab", exist_ok=True)
    Path("certs/crl.pem").write_bytes(b"PROD-CRL-DATA")
    Path("certs/ocsp_db.json").write_text("{}")
    Path("lab/crl.pem").write_bytes(b"LAB-CRL-DATA")
    Path("lab/ocsp_db.json").write_text("[]")


def _http_get(url: str, timeout: float = 2.0) -> tuple:
    """GET → (status, body bytes). 127.0.0.1 thay localhost tránh IPv6 delay
    trên Windows."""
    url_ip = url.replace("localhost", "127.0.0.1")
    try:
        with urllib.request.urlopen(url_ip, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ── Tests ────────────────────────────────────────────────────────────────────

def test_singleton_identity():
    """get_infra() lần nào gọi cũng trả cùng instance."""
    _reset_singleton()
    a = get_infra()
    b = get_infra()
    c = get_infra()
    assert a is b is c, "get_infra() phải trả cùng instance"
    assert isinstance(a, InfraManager), "Phải là InfraManager"
    print("  [singleton] PASS — identity giữ nguyên qua N lần gọi")


def test_start_prod_idempotent():
    """start_prod_servers() gọi 2 lần không raise, chỉ bind port 1 lần."""
    _reset_singleton()
    _seed_data()
    infra = get_infra()
    infra.start_prod_servers()
    crl_ref_1 = infra._prod_crl
    ocsp_ref_1 = infra._prod_ocsp
    assert crl_ref_1 is not None, "Prod CRL phải start"
    assert ocsp_ref_1 is not None, "Prod OCSP phải start"

    # Gọi lại — KHÔNG được start lại (sẽ OSError nếu thử bind port lần 2)
    infra.start_prod_servers()
    assert infra._prod_crl is crl_ref_1, "Prod CRL không được start lại"
    assert infra._prod_ocsp is ocsp_ref_1, "Prod OCSP không được start lại"
    assert infra.is_prod_running(), "is_prod_running phải True"

    infra.stop_all()
    print("  [prod_idempotent] PASS — start 2 lần OK, không bind lại port")


def test_start_lab_idempotent():
    """start_lab_servers() idempotent + is_lab_running query đúng."""
    _reset_singleton()
    _seed_data()
    infra = get_infra()
    assert not infra.is_lab_running(), "Trước khi start: is_lab_running = False"

    infra.start_lab_servers()
    crl_ref_1 = infra._lab_crl
    assert infra.is_lab_running(), "Sau start: is_lab_running = True"

    # Gọi lại
    infra.start_lab_servers()
    assert infra._lab_crl is crl_ref_1, "Lab CRL không được start lại"

    # get_lab_ocsp_state trả dict mutable
    state = infra.get_lab_ocsp_state()
    assert state is not None, "Sau start phải có ocsp state"
    assert state.get("enabled") is True, "Default enabled phải True"

    infra.stop_all()
    print("  [lab_idempotent] PASS — start 2 lần OK + is_lab_running + state dict")


def test_prod_lab_coexist_isolated():
    """Prod (8889/8888) + Lab (9889/9888) chạy cùng lúc, phục vụ data riêng."""
    _reset_singleton()
    _seed_data()
    infra = get_infra()
    infra.start_prod_servers()
    infra.start_lab_servers()
    time.sleep(0.2)  # Cho HTTP server bind socket xong

    status = infra.status()
    assert all(status.values()), f"Cả 4 server phải up: {status}"

    # Lấy CRL từ 2 port khác nhau → 2 content khác nhau
    code_p, body_p = _http_get(prod_crl_url())
    code_l, body_l = _http_get(lab_crl_url())
    assert code_p == 200, f"Prod CRL HTTP code: {code_p}"
    assert code_l == 200, f"Lab CRL HTTP code: {code_l}"
    assert body_p == b"PROD-CRL-DATA", f"Prod CRL content sai: {body_p!r}"
    assert body_l == b"LAB-CRL-DATA", f"Lab CRL content sai: {body_l!r}"

    # Port phải khác nhau
    assert PROD_CRL_PORT != LAB_CRL_PORT, "Prod + Lab CRL port phải khác"
    assert PROD_OCSP_PORT != LAB_OCSP_PORT, "Prod + Lab OCSP port phải khác"

    infra.stop_all()
    print(f"  [coexist] PASS — Prod :{PROD_CRL_PORT} ≠ Lab :{LAB_CRL_PORT}, data isolated")


def test_lab_ocsp_toggle_enabled():
    """set_lab_ocsp_enabled(False) → GET trả 503; True → trả 200."""
    _reset_singleton()
    _seed_data()
    infra = get_infra()
    infra.start_lab_servers()
    time.sleep(0.2)

    # Default enabled
    code, _ = _http_get(lab_ocsp_url() + "?serial=1")
    assert code == 200, f"Lab OCSP default phải 200, got {code}"

    # Disable → 503
    infra.set_lab_ocsp_enabled(False)
    code, body = _http_get(lab_ocsp_url() + "?serial=1")
    assert code == 503, f"Sau disable phải 503, got {code} body={body!r}"

    # Re-enable → 200
    infra.set_lab_ocsp_enabled(True)
    code, _ = _http_get(lab_ocsp_url() + "?serial=1")
    assert code == 200, f"Sau re-enable phải 200, got {code}"

    infra.stop_all()
    print("  [ocsp_toggle] PASS — enabled=False trả 503, =True trả 200")


def test_stop_all_idempotent():
    """stop_all() gọi nhiều lần không raise; gọi khi chưa start cũng OK."""
    _reset_singleton()
    infra = get_infra()

    # Chưa start gì → stop_all không raise
    infra.stop_all()
    assert not infra.is_prod_running()
    assert not infra.is_lab_running()

    # Start rồi stop 2 lần
    _seed_data()
    infra.start_prod_servers()
    infra.start_lab_servers()
    assert infra.is_prod_running()
    assert infra.is_lab_running()

    infra.stop_all()
    assert not infra.is_prod_running(), "Sau stop: prod = False"
    assert not infra.is_lab_running(), "Sau stop: lab = False"

    # Stop lần 2 — không raise
    infra.stop_all()
    assert not infra.is_prod_running()

    # State dict đã clear
    assert infra.get_lab_ocsp_state() is None

    print("  [stop_idempotent] PASS — double-stop OK, state reset")


# ── Test runner ──────────────────────────────────────────────────────────────

TESTS = [
    test_singleton_identity,
    test_start_prod_idempotent,
    test_start_lab_idempotent,
    test_prod_lab_coexist_isolated,
    test_lab_ocsp_toggle_enabled,
    test_stop_all_idempotent,
]


def main():
    print("=" * 60)
    print("  InfraManager — Smoke Test Suite")
    print("=" * 60)

    # Cleanup state ở start
    _reset_singleton()

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
        finally:
            _reset_singleton()

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
