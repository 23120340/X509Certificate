"""
server.py
---------
Socket Server — giả lập HTTPS server trong PKI hierarchy.

Giao thức (mỗi kết nối xử lý 1 request):
  "GET_CERT"        → gửi [4B len][CA cert PEM] rồi [4B len][Server cert PEM]
  "MSG_ENC:<hex>"   → giải mã bằng server private key (OAEP), log, phản hồi
"""

import socket
import threading

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cert_generator import load_private_key


def start_cert_server(
    ca_cert_path: str,
    cert_path: str,
    key_path: str,
    host: str = "localhost",
    port: int = 9999,
    log_callback=None,
):
    """
    Khởi động socket server ở background thread.
    Trả về (server_socket, stop_flag).
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    server_socket.settimeout(1.0)

    stop_flag = {"stop": False}

    def _log(msg):
        if log_callback:
            log_callback(msg)

    _log(f"[Server] Socket server khởi động tại {host}:{port}")

    def _handle(conn, addr):
        try:
            conn.settimeout(5.0)
            _log(f"[Server] Kết nối từ {addr}")

            # Đọc toàn bộ request (tối đa 4 KB — đủ cho hex RSA-2048)
            chunks = []
            while True:
                part = conn.recv(4096)
                if not part:
                    break
                chunks.append(part)
                if b"\n" in part or len(part) < 4096:
                    break
            data = b"".join(chunks).decode(errors="ignore").strip()

            if data == "GET_CERT":
                with open(ca_cert_path, "rb") as f:
                    ca_pem = f.read()
                with open(cert_path, "rb") as f:
                    cert_pem = f.read()
                conn.sendall(len(ca_pem).to_bytes(4, "big"))
                conn.sendall(ca_pem)
                conn.sendall(len(cert_pem).to_bytes(4, "big"))
                conn.sendall(cert_pem)
                _log(
                    f"[Server] Đã gửi CA cert ({len(ca_pem)} B) "
                    f"+ Server cert ({len(cert_pem)} B) → {addr}"
                )

            elif data.startswith("MSG_ENC:"):
                hex_data = data[len("MSG_ENC:"):]
                try:
                    encrypted_bytes = bytes.fromhex(hex_data)
                    private_key = load_private_key(key_path)
                    decrypted = private_key.decrypt(
                        encrypted_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    msg = decrypted.decode("utf-8")
                    _log(f"[Server] Giải mã tin nhắn từ client: '{msg}'")
                    response = f"SERVER_ACK:{msg}"
                    resp_bytes = response.encode("utf-8")
                    conn.sendall(len(resp_bytes).to_bytes(4, "big"))
                    conn.sendall(resp_bytes)
                except Exception as e:
                    _log(f"[Server] Lỗi giải mã: {e}")
                    error_bytes = b"SERVER_ERROR:decrypt_failed"
                    conn.sendall(len(error_bytes).to_bytes(4, "big"))
                    conn.sendall(error_bytes)

            else:
                _log(f"[Server] Request không hợp lệ: {data!r}")

        except Exception as e:
            _log(f"[Server] Lỗi xử lý client: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _serve():
        while not stop_flag["stop"]:
            try:
                conn, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    return server_socket, stop_flag
