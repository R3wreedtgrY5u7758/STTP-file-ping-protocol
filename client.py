# client.py — STTP (Servertest File Ping Protocol) v1
# CLI client: check / index / get / put
import socket, os, sys, time, hashlib
from protocol import *


HOST = "127.0.0.1"
UDP_PORT = DEFAULT_PORT
TIMEOUT = 2.0
DOWNLOAD_DIR = "."
DRAW_EVERY = 0.1


# ==================== Helpers ====================
def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.2f}PB"


def human_speed(bps):
    return human_size(bps) + "/s"


def human_time(sec):
    if sec < 1:
        return f"{sec*1000:.0f}ms"
    if sec < 60:
        return f"{sec:.1f}s"
    m, s = divmod(int(sec), 60)
    return f"{m}m{s:02d}s"


def draw_progress(prefix, done, total, elapsed):
    if total <= 0:
        line = f"{prefix} {human_size(done)}  ???"
    else:
        pct = done * 100 / total
        bar_w = 30
        fill = int(pct * bar_w / 100)
        bar = "█" * fill + "░" * (bar_w - fill)
        speed = done / elapsed if elapsed > 0 else 0
        eta = (total - done) / speed if speed > 0 else 0
        line = (f"{prefix} [{bar}] {pct:5.1f}%  "
                f"{human_size(done)}/{human_size(total)}  "
                f"{human_speed(speed)}  ETA {human_time(eta)}")
    sys.stdout.write("\r" + line + " " * 4)
    sys.stdout.flush()


# ==================== UDP RPC ====================
def rpc(sock, msg_type, payload=b""):
    nonce = int.from_bytes(os.urandom(4), "little")
    sock.sendto(pack(msg_type, payload, nonce), (HOST, UDP_PORT))
    while True:
        data, _ = sock.recvfrom(65535)
        mtype, rnonce, rpayload = unpack(data)
        if rnonce != nonce:
            continue
        return mtype, rpayload


# ==================== TCP wrappers ====================
def tcp_send(sock, mtype, payload=b"", nonce=0):
    _send_msg(sock, mtype, payload, nonce)


def tcp_recv(sock):
    return _recv_msg(sock)


# ==================== Commands ====================
def cmd_check():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(TIMEOUT)
    try:
        mtype, payload = rpc(udp, TYPE_HI, b"hi!")
    except socket.timeout:
        print("[1] server NOT available (timeout)")
        return False
    finally:
        udp.close()
    if mtype == TYPE_HELLO and payload == b"hello!":
        print("[1] server up")
        return True
    print("[1] server NOT available")
    return False


def cmd_index():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(TIMEOUT)
    try:
        mtype, payload = rpc(udp, TYPE_AUTUINDEX)
    finally:
        udp.close()
    if mtype != TYPE_INDEX:
        print(f"[2] unexpected: {mtype:#x}")
        return
    files = unpack_index(payload)
    print(f"[2] INDEX ({len(files)} files):")
    for name, size in files:
        print(f"    {name:<40} {human_size(size):>10}")


REASON_NAMES = {
    DENY_NOT_FOUND: "not found",
    DENY_FORBIDDEN: "forbidden",
    DENY_LIMIT: "limit",
    DENY_BUSY: "busy",
    DENY_BAD_REQUEST: "bad request",
    DENY_EXISTS: "already exists",
    DENY_NO_SPACE: "no space",
    DENY_TOO_BIG: "too big",
}


def cmd_get(filename):
    # --- UDP: permission + token ---
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(TIMEOUT)
    try:
        mtype, payload = rpc(udp, TYPE_DOWNLOAD_REQ,
                             pack_download_req(filename))
    finally:
        udp.close()

    if mtype == TYPE_DOWNLOAD_DENY:
        reason, text = unpack_download_deny(payload)
        print(f"[2] DENY ({REASON_NAMES.get(reason, reason)}): {text}")
        return 2
    if mtype != TYPE_DOWNLOAD_ALLOW:
        print(f"[2] unexpected: {mtype:#x}")
        return 3

    token, size, tcp_port = unpack_download_allow(payload)
    print(f"[2] ALLOW size={human_size(size)} token={token.hex()} "
          f"tcp={HOST}:{tcp_port}")

    # --- TCP ---
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(10.0)
    conn.connect((HOST, tcp_port))
    print("[3] TCP connected")

    try:
        tcp_send(conn, TYPE_TCP_HELLO, token)

        mtype, _, payload = tcp_recv(conn)
        if mtype != TYPE_TCP_CONFIRM_Q:
            print(f"\n[3] unexpected: {mtype:#x} {payload!r}")
            return 3
        print(f"[3] server asks: {payload.decode(errors='replace')}")
        ans = input("[3] start download? [y/N] ").strip().lower()
        if ans != "y":
            tcp_send(conn, TYPE_TCP_CONFIRM_N)
            try: tcp_recv(conn)
            except Exception: pass
            return 0
        tcp_send(conn, TYPE_TCP_CONFIRM_Y)

        mtype, _, payload = tcp_recv(conn)
        if mtype != TYPE_TCP_TESTSERVER or payload != b"testserver":
            print(f"\n[3] expected TESTSERVER, got {mtype:#x} {payload!r}")
            return 3
        print("[3] TESTSERVER received")
        tcp_send(conn, TYPE_TCP_OK)

        out_path = os.path.join(DOWNLOAD_DIR, os.path.basename(filename))
        sha = hashlib.sha256()
        received = 0
        t0 = time.time()
        last_ok = time.time()
        last_draw = 0.0

        conn.settimeout(SESSION_TIMEOUT)

        with open(out_path, "wb") as f:
            while True:
                if time.time() - last_ok >= HEARTBEAT_INTERVAL:
                    tcp_send(conn, TYPE_TCP_OK)
                    last_ok = time.time()

                try:
                    mtype, _, payload = tcp_recv(conn)
                except socket.timeout:
                    print(f"\n[3] server silent > {SESSION_TIMEOUT}s, abort")
                    return 4
                except ConnectionError:
                    print("\n[3] connection closed by server")
                    return 4

                if mtype == TYPE_TCP_DATA:
                    off, chunk = unpack_tcp_data(payload)
                    if off != received:
                        print(f"\n[3] offset mismatch: got {off}, "
                              f"expected {received}")
                        return 4
                    f.write(chunk); sha.update(chunk); received += len(chunk)

                    now = time.time()
                    if now - last_draw >= DRAW_EVERY:
                        draw_progress("[3]", received, size, now - t0)
                        last_draw = now

                elif mtype == TYPE_TCP_DONE:
                    srv_sha, srv_size = unpack_tcp_done(payload)
                    draw_progress("[3]", received, size, time.time() - t0)
                    print()

                    if srv_size != received:
                        print(f"[3] size mismatch: {srv_size} != {received}")
                        return 4
                    if srv_sha != sha.digest():
                        print("[3] sha256 MISMATCH")
                        return 4

                    elapsed = time.time() - t0
                    avg = received / elapsed if elapsed > 0 else 0
                    print(f"[3] DONE verified sha256 OK  "
                          f"size={human_size(received)}  "
                          f"time={human_time(elapsed)}  "
                          f"avg={human_speed(avg)}")
                    tcp_send(conn, TYPE_TCP_BYE)
                    return 0

                elif mtype == TYPE_TCP_ERROR:
                    print(f"\n[3] server error: "
                          f"{payload.decode(errors='replace')}")
                    return 3
                else:
                    print(f"\n[3] unexpected: {mtype:#x}")
                    return 3
    finally:
        conn.close()


def cmd_put(local_path, remote_name=None):
    if not os.path.isfile(local_path):
        print(f"[!] local file not found: {local_path}")
        return 1
    filename = remote_name or os.path.basename(local_path)
    size = os.path.getsize(local_path)

    # --- UDP: permission + token ---
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(TIMEOUT)
    try:
        mtype, payload = rpc(udp, TYPE_UPLOAD_REQ,
                             pack_upload_req(filename, size))
    finally:
        udp.close()

    if mtype == TYPE_UPLOAD_DENY:
        reason, text = unpack_upload_deny(payload)
        print(f"[2] DENY ({REASON_NAMES.get(reason, reason)}): {text}")
        return 2
    if mtype != TYPE_UPLOAD_ALLOW:
        print(f"[2] unexpected: {mtype:#x}")
        return 3

    token, srv_size, tcp_port = unpack_upload_allow(payload)
    print(f"[2] ALLOW size={human_size(size)} token={token.hex()} "
          f"tcp={HOST}:{tcp_port}")

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(10.0)
    conn.connect((HOST, tcp_port))
    print("[3] TCP connected")

    try:
        tcp_send(conn, TYPE_TCP_HELLO, token)

        mtype, _, payload = tcp_recv(conn)
        if mtype != TYPE_TCP_CONFIRM_Q:
            print(f"\n[3] unexpected: {mtype:#x} {payload!r}")
            return 3
        print(f"[3] server asks: {payload.decode(errors='replace')}")
        ans = input("[3] start upload? [y/N] ").strip().lower()
        if ans != "y":
            tcp_send(conn, TYPE_TCP_CONFIRM_N)
            try: tcp_recv(conn)
            except Exception: pass
            return 0
        tcp_send(conn, TYPE_TCP_CONFIRM_Y)

        mtype, _, payload = tcp_recv(conn)
        if mtype != TYPE_TCP_TESTSERVER or payload != b"testserver":
            print(f"\n[3] expected TESTSERVER, got {mtype:#x} {payload!r}")
            return 3
        print("[3] TESTSERVER received")
        tcp_send(conn, TYPE_TCP_OK)

        sha = hashlib.sha256()
        sent = 0
        t0 = time.time()
        last_ok = time.time()
        last_draw = 0.0

        conn.settimeout(30.0)

        with open(local_path, "rb") as f:
            while sent < size:
                if time.time() - last_ok >= HEARTBEAT_INTERVAL:
                    tcp_send(conn, TYPE_TCP_OK)
                    last_ok = time.time()

                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)
                tcp_send(conn, TYPE_TCP_UPLOAD_DATA,
                         pack_tcp_data(sent, chunk))
                sent += len(chunk)

                # non-blocking check: did the server send anything (e.g. error)?
                conn.settimeout(0.001)
                try:
                    while True:
                        mt, _, pl = tcp_recv(conn)
                        if mt == TYPE_TCP_ERROR:
                            print(f"\n[3] server error: "
                                  f"{pl.decode(errors='replace')}")
                            return 3
                except (socket.timeout, BlockingIOError):
                    pass
                finally:
                    conn.settimeout(30.0)

                now = time.time()
                if now - last_draw >= DRAW_EVERY:
                    draw_progress("[3]", sent, size, now - t0)
                    last_draw = now

        tcp_send(conn, TYPE_TCP_UPLOAD_DONE,
                 pack_tcp_done(sha.digest(), sent))

        mtype, _, payload = tcp_recv(conn)
        draw_progress("[3]", sent, size, time.time() - t0)
        print()

        if mtype == TYPE_TCP_UPLOAD_OK:
            srv_sha, srv_size = unpack_tcp_done(payload)
            if srv_size != sent or srv_sha != sha.digest():
                print("[3] server reported mismatch")
                return 4
            elapsed = time.time() - t0
            avg = sent / elapsed if elapsed > 0 else 0
            print(f"[3] DONE verified sha256 OK  "
                  f"size={human_size(sent)}  "
                  f"time={human_time(elapsed)}  "
                  f"avg={human_speed(avg)}")
            tcp_send(conn, TYPE_TCP_BYE)
            return 0
        elif mtype == TYPE_TCP_UPLOAD_ERR:
            print(f"[3] server error: {payload.decode(errors='replace')}")
            return 3
        else:
            print(f"\n[3] unexpected: {mtype:#x}")
            return 3
    finally:
        conn.close()


# ==================== main ====================
def main():
    global HOST
    args = sys.argv[1:]
    if args and (("." in args[0] and not args[0].startswith("-"))
                 or args[0][0].isdigit()):
        HOST = args.pop(0)

    if not cmd_check():
        return 1
    if not args:
        return 0

    cmd = args[0]
    if cmd == "index":
        cmd_index(); return 0
    if cmd == "get" and len(args) >= 2:
        return cmd_get(args[1])
    if cmd == "put" and len(args) >= 2:
        return cmd_put(args[1], args[2] if len(args) >= 3 else None)
    print("usage: client.py [host] [index | get <filename> | put <local> [remote]]")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
