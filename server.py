"""
server.py
---------
Phần 2 của đề bài: Socket Server (giả lập HTTPS).
Khi Client kết nối và gửi "GET_CERT", server đáp lại bằng chứng chỉ PEM:

    [4 bytes big-endian length][PEM bytes]
"""

import socket
import threading


def start_cert_server(
    cert_path: str,
    host: str = "localhost",
    port: int = 9999,
    log_callback=None,
):
    """
    Mở Socket server ở background. Trả về (server_socket, stop_flag).
    Gọi stop_flag['stop'] = True và server_socket.close() để dừng.
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

    _log(f"[Server] Socket server started at {host}:{port}")

    def _serve():
        while not stop_flag["stop"]:
            try:
                conn, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                conn.settimeout(5.0)
                _log(f"[Server] Kết nối từ {addr}")
                data = conn.recv(1024).decode(errors="ignore").strip()
                if data == "GET_CERT":
                    with open(cert_path, "rb") as f:
                        cert_pem = f.read()
                    conn.sendall(len(cert_pem).to_bytes(4, "big"))
                    conn.sendall(cert_pem)
                    _log(f"[Server] Đã gửi certificate ({len(cert_pem)} bytes) cho {addr}")
                else:
                    _log(f"[Server] Request không hợp lệ: {data!r}")
            except Exception as e:
                _log(f"[Server] Lỗi xử lý client: {e}")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    return server_socket, stop_flag
