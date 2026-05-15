"""
test_scenarios.py
-----------------
End-to-end automated tests cho 7 hành vi demo (a-i).

Chạy (từ project root):
    python tests/test_scenarios.py

Tất cả tests phải PASS trước khi demo cho thầy.

Dùng port riêng (19xxx / 18xxx) để không đụng bản demo đang chạy.
"""

import os
import shutil
import sys
import time
from pathlib import Path

# Cho phép import từ src/ dù chạy từ project root hay từ tests/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

# ── Cấu hình test (port riêng biệt) ──────────────────────────────────────────
TEST_DIR      = str(_PROJECT_ROOT / "certs_test")
TEST_CRL_PORT = 18889
TEST_OCSP_PORT = 18888
TEST_CRL_URL  = f"http://localhost:{TEST_CRL_PORT}/crl.pem"
TEST_OCSP_URL = f"http://localhost:{TEST_OCSP_PORT}/ocsp"
TEST_CRL_PATH = os.path.join(TEST_DIR, "crl.pem")
TEST_OCSP_DB  = os.path.join(TEST_DIR, "ocsp_db.json")
TEST_ISSUER_CERT = os.path.join(TEST_DIR, "issuer.crt")
TEST_ISSUER_KEY  = os.path.join(TEST_DIR, "issuer.key")
TEST_TRUST_STORE = os.path.join(TEST_DIR, "trust_store")

BASE_PORT = 19001  # server test dùng port 19001, 19002, ...

# ── Imports sau khi định nghĩa hằng để không side-effect ─────────────────────
from issuer import load_or_create_issuer, publish_root_ca_to_trust_store
from server_manager import ServerManager
from crl_manager import build_and_publish_crl
from ocsp_server import OCSPHandler, start_ocsp_server
from crl_server import start_crl_server
from client import fetch_certificate, verify_certificate_full


# ── Hạ tầng test ─────────────────────────────────────────────────────────────

_mgr: ServerManager = None
_port_counter = [BASE_PORT]


def _next_port() -> int:
    p = _port_counter[0]
    _port_counter[0] += 1
    return p


def setup():
    """Khởi tạo thư mục, issuer, CRL/OCSP server cho test."""
    global _mgr
    os.makedirs(TEST_DIR, exist_ok=True)

    issuer_cert, issuer_key = load_or_create_issuer(TEST_ISSUER_CERT, TEST_ISSUER_KEY)

    # Publish Root CA cert vào Trust Store của test client
    publish_root_ca_to_trust_store(issuer_cert, TEST_TRUST_STORE)

    # Khởi động CRL server
    start_crl_server(
        host="localhost", port=TEST_CRL_PORT,
        crl_path=TEST_CRL_PATH, log_callback=None,
    )
    # Khởi động OCSP server
    OCSPHandler.enabled = True
    start_ocsp_server(
        host="localhost", port=TEST_OCSP_PORT,
        revoked_list_path=TEST_OCSP_DB, log_callback=None,
    )
    # Tạo CRL rỗng để CRL server có file phục vụ
    build_and_publish_crl(issuer_cert, issuer_key, TEST_OCSP_DB, TEST_CRL_PATH)

    _mgr = ServerManager(
        cert_dir=TEST_DIR,
        ocsp_db_path=TEST_OCSP_DB,
        crl_path=TEST_CRL_PATH,
        issuer_cert=issuer_cert,
        issuer_key=issuer_key,
        ocsp_url=TEST_OCSP_URL,
        crl_url=TEST_CRL_URL,
    )
    time.sleep(0.4)   # Chờ HTTP servers sẵn sàng


def teardown():
    """Dọn dẹp sau khi chạy test."""
    if _mgr:
        _mgr.remove_all()
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR, ignore_errors=True)


def _verify(port) -> tuple:
    """Lấy cert từ port và chạy 5 bước. Trả về (overall, results)."""
    cert_bytes, peer_address = fetch_certificate("localhost", port)
    overall, results, _ = verify_certificate_full(
        cert_bytes, "localhost",
        trust_store_dir=TEST_TRUST_STORE,
        peer_address=peer_address,
    )
    return overall, results


def _step_ok(results, step_index: int) -> bool:
    return results[step_index][1]


# ── Test cases ────────────────────────────────────────────────────────────────

def test_b_valid():
    """(b) Server-A flavor=valid → PASS tất cả 5 bước."""
    port = _next_port()
    _mgr.add_server("test-valid", port, "valid")
    time.sleep(0.1)
    overall, results = _verify(port)
    assert overall, f"[b] Kỳ vọng PASS nhưng FAIL: {[r[2] for r in results if not r[1]]}"
    print("  [b] PASS ✓ — valid cert: all 5 steps OK")


def test_c_expired():
    """(c) Server-B flavor=expired → FAIL ở Bước 2 (thời hạn)."""
    port = _next_port()
    _mgr.add_server("test-expired", port, "expired")
    time.sleep(0.1)
    overall, results = _verify(port)
    assert not overall, "[c] Kỳ vọng FAIL nhưng lại PASS"
    assert _step_ok(results, 0), "[c] Bước 1 (signature) phải PASS"
    assert not _step_ok(results, 1), "[c] Bước 2 (validity) phải FAIL"
    print("  [c] PASS ✓ — expired cert: FAIL ở Bước 2")


def test_d_revoked_both():
    """(d) Server-C flavor=revoked_both → FAIL ở Bước 4 (CRL) VÀ Bước 5 (OCSP)."""
    port = _next_port()
    _mgr.add_server("test-revoked-both", port, "revoked_both")
    time.sleep(0.1)
    overall, results = _verify(port)
    assert not overall, "[d] Kỳ vọng FAIL nhưng lại PASS"
    assert not _step_ok(results, 3), "[d] Bước 4 (CRL) phải FAIL"
    assert not _step_ok(results, 4), "[d] Bước 5 (OCSP) phải FAIL"
    print("  [d] PASS ✓ — revoked_both: FAIL ở cả Bước 4 và Bước 5")


def test_e_revoked_ocsp_only():
    """
    (e) ⭐ Server-D flavor=revoked_ocsp_only:
        Bước 4 (CRL) PASS — CRL chưa biết
        Bước 5 (OCSP) FAIL — OCSP đã biết
    """
    port = _next_port()
    _mgr.add_server("test-ocsp-only", port, "revoked_ocsp_only")
    time.sleep(0.1)
    overall, results = _verify(port)
    assert not overall, "[e] Kỳ vọng FAIL nhưng lại PASS"
    assert _step_ok(results, 3), \
        f"[e] Bước 4 (CRL) phải PASS — CRL chưa publish: {results[3][2]}"
    assert not _step_ok(results, 4), \
        f"[e] Bước 5 (OCSP) phải FAIL: {results[4][2]}"
    print("  [e] PASS ✓ ⭐ revoked_ocsp_only: Bước 4 PASS, Bước 5 FAIL")
    print("          → Đây là điểm nhấn: lý do cần OCSP dù đã có CRL")


def test_f_publish_crl():
    """
    (f) Sau khi Publish CRL Now → Verify lại Server-D:
        Bước 4 (CRL) giờ cũng FAIL.
    """
    issuer_cert, issuer_key = load_or_create_issuer(TEST_ISSUER_CERT, TEST_ISSUER_KEY)
    build_and_publish_crl(issuer_cert, issuer_key, TEST_OCSP_DB, TEST_CRL_PATH)
    time.sleep(0.2)  # Chờ CRL server phục vụ file mới

    # Tìm port của test-ocsp-only từ bước (e)
    entry = _mgr.servers.get("test-ocsp-only")
    assert entry, "[f] Không tìm thấy server 'test-ocsp-only'"

    overall, results = _verify(entry.port)
    assert not _step_ok(results, 3), \
        "[f] Sau khi publish CRL, Bước 4 phải FAIL"
    assert not _step_ok(results, 4), "[f] Bước 5 vẫn phải FAIL"
    print("  [f] PASS ✓ — sau Publish CRL Now: Bước 4 cũng FAIL")


def test_g_ocsp_down():
    """
    (g) Tắt OCSP → Verify Server-C (revoked_both):
        Bước 4 (CRL) vẫn FAIL — CRL làm fallback
        Bước 5 (OCSP) FAIL vì lỗi mạng (503)
    """
    OCSPHandler.enabled = False
    try:
        entry = _mgr.servers.get("test-revoked-both")
        assert entry, "[g] Không tìm thấy server 'test-revoked-both'"
        overall, results = _verify(entry.port)
        assert not _step_ok(results, 3), "[g] Bước 4 (CRL) phải FAIL dù OCSP down"
        assert not _step_ok(results, 4), "[g] Bước 5 phải FAIL (OCSP down = lỗi)"
        step5_msg = results[4][2]
        assert "503" in step5_msg or "Lỗi" in step5_msg or "error" in step5_msg.lower(), \
            f"[g] Bước 5 phải báo lỗi OCSP down: {step5_msg}"
        print("  [g] PASS ✓ — OCSP down: Bước 4 vẫn bắt được (CRL fallback), Bước 5 lỗi mạng")
    finally:
        OCSPHandler.enabled = True


def test_h_tampered():
    """(h) Server-E flavor=tampered → FAIL ở Bước 1 (chữ ký không khớp)."""
    port = _next_port()
    _mgr.add_server("test-tampered", port, "tampered")
    time.sleep(0.1)
    overall, results = _verify(port)
    assert not overall, "[h] Kỳ vọng FAIL nhưng lại PASS"
    assert not _step_ok(results, 0), \
        f"[h] Bước 1 (signature) phải FAIL: {results[0][2]}"
    print("  [h] PASS ✓ — tampered cert: FAIL ở Bước 1 (chữ ký không khớp)")


def test_i_delete_server():
    """(i) Xóa Server-B → port đóng, bảng cập nhật."""
    entry = _mgr.servers.get("test-expired")
    assert entry, "[i] Không tìm thấy server 'test-expired'"
    port = entry.port

    _mgr.remove_server("test-expired")
    assert "test-expired" not in _mgr.servers, "[i] Server vẫn còn trong dict"
    assert not os.path.exists(entry.cert_path), "[i] Cert file chưa được xóa"

    # Thử kết nối lại port — phải bị từ chối
    import socket as _socket
    time.sleep(0.2)
    try:
        with _socket.create_connection(("localhost", port), timeout=1):
            assert False, "[i] Port vẫn còn mở sau khi xóa"
    except (ConnectionRefusedError, OSError):
        pass  # Đúng rồi

    print("  [i] PASS ✓ — server đã xóa: port đóng, cert file xóa")


# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    test_b_valid,
    test_c_expired,
    test_d_revoked_both,
    test_e_revoked_ocsp_only,
    test_f_publish_crl,
    test_g_ocsp_down,
    test_h_tampered,
    test_i_delete_server,
]


def main():
    print("=" * 60)
    print("  X.509 Dynamic Multi-Server — End-to-End Test Suite")
    print("=" * 60)

    print("\n[Setup] Khởi động infrastructure servers...")
    setup()
    print("[Setup] Sẵn sàng.\n")

    passed = 0
    failed = 0
    errors = []

    for test_fn in TESTS:
        label = test_fn.__doc__.strip().splitlines()[0] if test_fn.__doc__ else test_fn.__name__
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL ✗ — {label}")
            print(f"         {e}")
            errors.append((test_fn.__name__, str(e)))
            failed += 1
        except Exception as e:
            print(f"  ERROR ✗ — {label}")
            print(f"         {type(e).__name__}: {e}")
            errors.append((test_fn.__name__, f"{type(e).__name__}: {e}"))
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Kết quả: {passed} PASS / {failed} FAIL  (tổng {len(TESTS)})")
    print("=" * 60)

    teardown()

    if failed > 0:
        print("\nCác test FAIL:")
        for name, msg in errors:
            print(f"  - {name}: {msg}")
        sys.exit(1)
    else:
        print("\nTất cả tests PASS ✓ — Sẵn sàng demo!")
        sys.exit(0)


if __name__ == "__main__":
    main()
