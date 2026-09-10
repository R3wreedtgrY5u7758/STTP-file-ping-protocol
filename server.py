# server.py — STTP (Servertest File Ping Protocol) v1
# UDP control + TCP data: download and upload.
import socket, secrets, time, os, hashlib, threading
from protocol import *


HOST = "0.0.0.0"
UDP_PORT = DEFAULT_PORT          # 36373
TCP_PORT = TCP_PORT_DEFAULT      # 36374
SHARED_DIR = "./shared"          # files served for download
UPLOAD_DIR = "./uploads"         # files received from clients
ALLOWED_CLIENTS = None           # None = allow all; or set({"1.2.3.4", ...})
MAX_FILES_IN_INDEX = 4096
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024    # 1 GB
ALLOW_OVERWRITE = False

tokens = {}                      # token(bytes) -> dict(...)
tokens_lock = threading.Lock()


# ==================== Helpers ====================
def list_shared_files():
    files = []
    try:
        entries = sorted(os.listdir(SHARED_DIR))
    except FileNotFoundError:
        return files
    for name in entries[:MAX_FILES_IN_INDEX]:
        if name.startswith("."):
            continue
        path = os.path.join(SHARED_DIR, name)
        if os.path.isfile(path):
            files.append((name, os.path.getsize(path)))
    return files


def safe_name(name: str) -> bool:
    return not ("/" in name or "\\" in name or name.startswith(".")
                or name in ("", ".", ".."))


# ==================== UDP handlers ====================
def handle_download_req(addr, payload, nonce):
    ip = addr[0]
    try:
        filename = unpack_download_req(payload)
    except ValueError:
        return pack(TYPE_DOWNLOAD_DENY,
                    pack_download_deny(DENY_BAD_REQUEST, "bad request"), nonce)

    if ALLOWED_CLIENTS is not None and ip not in ALLOWED_CLIENTS:
        return pack(TYPE_DOWNLOAD_DENY,
                    pack_download_deny(DENY_FORBIDDEN, "not allowed"), nonce)

    if not safe_name(filename):
        return pack(TYPE_DOWNLOAD_DENY,
                    pack_download_deny(DENY_BAD_REQUEST, "bad name"), nonce)

    path = os.path.join(SHARED_DIR, filename)
    if not os.path.isfile(path):
        return pack(TYPE_DOWNLOAD_DENY,
                    pack_download_deny(DENY_NOT_FOUND, "no such file"), nonce)

    size = os.path.getsize(path)
    token = secrets.token_bytes(TOKEN_SIZE)
    with tokens_lock:
        tokens[token] = {
            "mode": "download",
            "path": path,
            "size": size,
            "expires": time.time() + TOKEN_TTL,
            "ip": ip,
            "used": False,
        }
    print(f"[+] DOWNLOAD ALLOW {ip} {filename!r} size={size} "
          f"token={token.hex()}")
    return pack(TYPE_DOWNLOAD_ALLOW,
                pack_download_allow(token, size, TCP_PORT), nonce)


def handle_upload_req(addr, payload, nonce):
    ip = addr[0]
    try:
        filename, size = unpack_upload_req(payload)
    except ValueError:
        return pack(TYPE_UPLOAD_DENY,
                    pack_upload_deny(DENY_BAD_REQUEST, "bad request"), nonce)

    if ALLOWED_CLIENTS is not None and ip not in ALLOWED_CLIENTS:
        return pack(TYPE_UPLOAD_DENY,
                    pack_upload_deny(DENY_FORBIDDEN, "not allowed"), nonce)

    if not safe_name(filename):
        return pack(TYPE_UPLOAD_DENY,
                    pack_upload_deny(DENY_BAD_REQUEST, "bad name"), nonce)

    if size <= 0:
        return pack(TYPE_UPLOAD_DENY,
                    pack_upload_deny(DENY_BAD_REQUEST, "empty file"), nonce)

    if size > MAX_UPLOAD_SIZE:
        return pack(TYPE_UPLOAD_DENY,
                    pack_upload_deny(DENY_TOO_BIG,
                                     f"limit {MAX_UPLOAD_SIZE}"), nonce)

    path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(path) and not ALLOW_OVERWRITE:
        return pack(TYPE_UPLOAD_DENY,
                    pack_upload_deny(DENY_EXISTS, "file exists"), nonce)

    # free space check (POSIX only)
    try:
        st = os.statvfs(UPLOAD_DIR)
        free = st.f_bavail * st.f_frsize
        if free < size:
            return pack(TYPE_UPLOAD_DENY,
                        pack_upload_deny(DENY_NO_SPACE, "no space"), nonce)
    except (AttributeError, OSError):
        pass

    token = secrets.token_bytes(TOKEN_SIZE)
    with tokens_lock:
        tokens[token] = {
            "mode": "upload",
            "path": path,
            "size": size,
            "expires": time.time() + TOKEN_TTL,
            "ip": ip,
            "used": False,
        }
    print(f"[+] UPLOAD ALLOW {ip} {filename!r} size={size} "
          f"token={token.hex()}")
    return pack(TYPE_UPLOAD_ALLOW,
                pack_upload_allow(token, size, TCP_PORT), nonce)


def udp_loop(sock):
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:
            continue
        try:
            msg_type, nonce, payload = unpack(data)
        except ValueError as e:
            print(f"[udp] drop from {addr}: {e}")
            continue

        if msg_type == TYPE_HI:
            resp = pack(TYPE_HELLO, b"hello!", nonce)
        elif msg_type == TYPE_AUTUINDEX:
            resp = pack(TYPE_INDEX, pack_index(list_shared_files()), nonce)
        elif msg_type == TYPE_DOWNLOAD_REQ:
            resp = handle_download_req(addr, payload, nonce)
        elif msg_type == TYPE_UPLOAD_REQ:
            resp = handle_upload_req(addr, payload, nonce)
        else:
            resp = pack(TYPE_ERROR, b"unknown type", nonce)

        try:
            sock.sendto(resp, addr)
        except OSError as e:
            print(f"[udp] send error to {addr}: {e}")


# ==================== TCP: download ====================
def handle_tcp_download(conn, addr, info):
    ip = addr[0]
    path = info["path"]
    size = info["size"]

    try:
        # Confirmation
        _send_msg(conn, TYPE_TCP_CONFIRM_Q, b"are you sure?")
        mtype, _, _ = _recv_msg(conn)
        if mtype == TYPE_TCP_CONFIRM_N:
            _send_msg(conn, TYPE_TCP_BYE)
            print(f"[tcp] {ip} cancelled"); return
        if mtype != TYPE_TCP_CONFIRM_Y:
            _send_msg(conn, TYPE_TCP_ERROR, b"expected CONFIRM_Y"); return

        # Mandatory TESTSERVER
        _send_msg(conn, TYPE_TCP_TESTSERVER, b"testserver")
        mtype, _, _ = _recv_msg(conn)
        if mtype != TYPE_TCP_OK:
            _send_msg(conn, TYPE_TCP_ERROR, b"expected OK after TESTSERVER")
            return
        print(f"[tcp] {ip} alive, sending {size} bytes")

        sha = hashlib.sha256()
        offset = 0
        t0 = time.time()
        last_seen = time.time()
        conn.settimeout(SESSION_TIMEOUT)

        with open(path, "rb") as f:
            while offset < size:
                if time.time() - last_seen > SESSION_TIMEOUT:
                    print(f"[tcp] {ip} heartbeat timeout"); return

                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)
                _send_msg(conn, TYPE_TCP_DATA, pack_tcp_data(offset, chunk))
                offset += len(chunk)

                # non-blocking check for OK / BYE from client
                conn.settimeout(0.001)
                try:
                    while True:
                        mtype, _, _ = _recv_msg(conn)
                        if mtype == TYPE_TCP_OK:
                            last_seen = time.time()
                        elif mtype == TYPE_TCP_BYE:
                            print(f"[tcp] {ip} client closed"); return
                except (socket.timeout, BlockingIOError):
                    pass
                finally:
                    conn.settimeout(SESSION_TIMEOUT)

        _send_msg(conn, TYPE_TCP_DONE, pack_tcp_done(sha.digest(), size))
        dt = time.time() - t0
        avg = size / dt if dt > 0 else 0
        print(f"[tcp] {ip} sent {size} bytes in {dt:.2f}s "
              f"({avg/1024/1024:.2f} MB/s), sha256={sha.hexdigest()[:16]}…")

        conn.settimeout(5.0)
        try:
            mtype, _, _ = _recv_msg(conn)
            if mtype == TYPE_TCP_BYE:
                print(f"[tcp] {ip} done cleanly")
        except Exception:
            pass

    except ConnectionError as e:
        print(f"[tcp] {ip} disconnected: {e}")
    except Exception as e:
        print(f"[tcp] {ip} error: {e}")
    finally:
        try: conn.close()
        except Exception: pass


# ==================== TCP: upload ====================
def handle_tcp_upload(conn, addr, info):
    ip = addr[0]
    path = info["path"]
    size = info["size"]
    tmp_path = path + ".part"

    try:
        # Confirmation
        _send_msg(conn, TYPE_TCP_CONFIRM_Q, b"are you sure?")
        mtype, _, _ = _recv_msg(conn)
        if mtype == TYPE_TCP_CONFIRM_N:
            _send_msg(conn, TYPE_TCP_BYE)
            print(f"[tcp-up] {ip} cancelled"); return
        if mtype != TYPE_TCP_CONFIRM_Y:
            _send_msg(conn, TYPE_TCP_ERROR, b"expected CONFIRM_Y"); return

        # Mandatory TESTSERVER
        _send_msg(conn, TYPE_TCP_TESTSERVER, b"testserver")
        mtype, _, _ = _recv_msg(conn)
        if mtype != TYPE_TCP_OK:
            _send_msg(conn, TYPE_TCP_ERROR, b"expected OK after TESTSERVER")
            return
        print(f"[tcp-up] {ip} alive, receiving {size} bytes")

        sha = hashlib.sha256()
        received = 0
        t0 = time.time()
        last_seen = time.time()
        conn.settimeout(SESSION_TIMEOUT)

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(tmp_path, "wb") as f:
            while received < size:
                if time.time() - last_seen > SESSION_TIMEOUT:
                    print(f"[tcp-up] {ip} heartbeat timeout")
                    try: os.remove(tmp_path)
                    except Exception: pass
                    return

                try:
                    mtype, _, payload = _recv_msg(conn)
                except (socket.timeout, ConnectionError) as e:
                    print(f"[tcp-up] {ip} recv error: {e}")
                    try: os.remove(tmp_path)
                    except Exception: pass
                    return

                if mtype == TYPE_TCP_UPLOAD_DATA:
                    off, chunk = unpack_tcp_data(payload)
                    if off != received:
                        print(f"[tcp-up] {ip} offset mismatch "
                              f"{off} != {received}")
                        try: os.remove(tmp_path)
                        except Exception: pass
                        return
                    f.write(chunk)
                    sha.update(chunk)
                    received += len(chunk)
                    last_seen = time.time()
                elif mtype == TYPE_TCP_OK:
                    last_seen = time.time()
                elif mtype == TYPE_TCP_BYE:
                    print(f"[tcp-up] {ip} client closed early")
                    try: os.remove(tmp_path)
                    except Exception: pass
                    return
                else:
                    print(f"[tcp-up] {ip} unexpected: {mtype:#x}")
                    try: os.remove(tmp_path)
                    except Exception: pass
                    return

        # UPLOAD_DONE
        mtype, _, payload = _recv_msg(conn)
        if mtype != TYPE_TCP_UPLOAD_DONE:
            print(f"[tcp-up] {ip} expected UPLOAD_DONE, got {mtype:#x}")
            try: os.remove(tmp_path)
            except Exception: pass
            return

        srv_sha, srv_size = unpack_tcp_done(payload)
        if srv_size != received or srv_sha != sha.digest():
            print(f"[tcp-up] {ip} integrity mismatch")
            _send_msg(conn, TYPE_TCP_UPLOAD_ERR, b"integrity mismatch")
            try: os.remove(tmp_path)
            except Exception: pass
            return

        os.replace(tmp_path, path)

        dt = time.time() - t0
        avg = received / dt if dt > 0 else 0
        print(f"[tcp-up] {ip} received {received} bytes in {dt:.2f}s "
              f"({avg/1024/1024:.2f} MB/s), sha256={sha.hexdigest()[:16]}…")

        _send_msg(conn, TYPE_TCP_UPLOAD_OK,
                  pack_tcp_done(sha.digest(), received))

        conn.settimeout(5.0)
        try:
            mtype, _, _ = _recv_msg(conn)
            if mtype == TYPE_TCP_BYE:
                print(f"[tcp-up] {ip} done cleanly")
        except Exception:
            pass

    except Exception as e:
        print(f"[tcp-up] {ip} error: {e}")
        try: os.remove(tmp_path)
        except Exception: pass
    finally:
        try: conn.close()
        except Exception: pass


# ==================== TCP: accept loop ====================
def handle_tcp_client(conn, addr):
    ip = addr[0]
    try:
        conn.settimeout(10.0)
        mtype, _, payload = _recv_msg(conn)
        if mtype != TYPE_TCP_HELLO or len(payload) < TOKEN_SIZE:
            _send_msg(conn, TYPE_TCP_ERROR, b"expected TCP_HELLO+token")
            return
        token = payload[:TOKEN_SIZE]

        with tokens_lock:
            info = tokens.get(token)
            if not info:
                _send_msg(conn, TYPE_TCP_ERROR, b"bad token"); return
            if info["used"]:
                _send_msg(conn, TYPE_TCP_ERROR, b"token already used"); return
            if info["expires"] < time.time():
                _send_msg(conn, TYPE_TCP_ERROR, b"token expired"); return
            if info["ip"] != ip:
                _send_msg(conn, TYPE_TCP_ERROR, b"ip mismatch"); return
            info["used"] = True
            mode = info.get("mode", "download")
            info_copy = dict(info)

        print(f"[tcp] {ip} token OK, mode={mode}, "
              f"file={info_copy['path']} size={info_copy['size']}")

        if mode == "upload":
            handle_tcp_upload(conn, addr, info_copy)
        else:
            handle_tcp_download(conn, addr, info_copy)

    except ConnectionError as e:
        print(f"[tcp] {ip} disconnected: {e}")
    except Exception as e:
        print(f"[tcp] {ip} error: {e}")
    finally:
        try: conn.close()
        except Exception: pass


def tcp_accept_loop(srv):
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            continue
        threading.Thread(target=handle_tcp_client,
                         args=(conn, addr), daemon=True).start()


# ==================== main ====================
def main():
    os.makedirs(SHARED_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((HOST, UDP_PORT))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((HOST, TCP_PORT))
    tcp.listen(64)

    print(f"[STTP] UDP {HOST}:{UDP_PORT}, TCP {HOST}:{TCP_PORT}, "
          f"shared={SHARED_DIR}, uploads={UPLOAD_DIR}")

    threading.Thread(target=udp_loop, args=(udp,), daemon=True).start()
    tcp_accept_loop(tcp)


if __name__ == "__main__":
    main()
