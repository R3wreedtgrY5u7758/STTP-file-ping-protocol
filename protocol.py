# protocol.py — STTP (Servertest File Ping Protocol) v1
# Hybrid UDP + TCP file transfer protocol with token authorization,
# session liveness checks, and sha256 verification.
import struct, os, time, secrets, hashlib, socket as _socket

# ==================== Common ====================
MAGIC = 0x53545450          # "STTP"
VERSION = 1
HEADER_FORMAT = "<IBBHI"    # magic, version, type, reserved, nonce
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)   # 12

MAX_MSG = 16 * 1024 * 1024  # 16 MB — maximum size of a single message

DEFAULT_PORT = 36373        # UDP
TCP_PORT_DEFAULT = 36374    # TCP
TOKEN_SIZE = 16
TOKEN_TTL = 30

# ==================== UDP types ====================
TYPE_HI             = 0x01
TYPE_HELLO          = 0x02
TYPE_ERROR          = 0x03
TYPE_AUTUINDEX      = 0x04
TYPE_INDEX          = 0x05

TYPE_DOWNLOAD_REQ   = 0x10
TYPE_DOWNLOAD_ALLOW = 0x11
TYPE_DOWNLOAD_DENY  = 0x12

TYPE_UPLOAD_REQ     = 0x13
TYPE_UPLOAD_ALLOW   = 0x14
TYPE_UPLOAD_DENY    = 0x15

# Denial reasons
DENY_NOT_FOUND   = 0x01
DENY_FORBIDDEN   = 0x02
DENY_LIMIT       = 0x03
DENY_BUSY        = 0x04
DENY_BAD_REQUEST = 0x05
DENY_EXISTS      = 0x06
DENY_NO_SPACE    = 0x07
DENY_TOO_BIG     = 0x08

# ==================== TCP types ====================
TYPE_TCP_HELLO       = 0x20
TYPE_TCP_CONFIRM_Q   = 0x21
TYPE_TCP_CONFIRM_Y   = 0x22
TYPE_TCP_CONFIRM_N   = 0x23
TYPE_TCP_TESTSERVER  = 0x24
TYPE_TCP_OK          = 0x25
TYPE_TCP_DATA        = 0x26
TYPE_TCP_DONE        = 0x27
TYPE_TCP_BYE         = 0x28
TYPE_TCP_ERROR       = 0x29

TYPE_TCP_UPLOAD_DATA = 0x2A
TYPE_TCP_UPLOAD_DONE = 0x2B
TYPE_TCP_UPLOAD_OK   = 0x2C
TYPE_TCP_UPLOAD_ERR  = 0x2D

CHUNK_SIZE         = 256 * 1024   # 256 KB
HEARTBEAT_INTERVAL = 12.0
SESSION_TIMEOUT    = 12.0

# ==================== Header ====================
def pack(msg_type, payload=b"", nonce=0):
    total = HEADER_SIZE + len(payload)
    if total > MAX_MSG:
        raise ValueError(f"packet too big: {total} > {MAX_MSG}")
    return struct.pack(HEADER_FORMAT, MAGIC, VERSION, msg_type, 0, nonce) + payload

def unpack(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("packet too short")
    magic, version, msg_type, reserved, nonce = struct.unpack(
        HEADER_FORMAT, data[:HEADER_SIZE])
    if magic != MAGIC:     raise ValueError("bad magic")
    if version != VERSION: raise ValueError("bad version")
    return msg_type, nonce, data[HEADER_SIZE:]

# ==================== DOWNLOAD_REQ ====================
def pack_download_req(filename: str) -> bytes:
    b = filename.encode("utf-8")
    if len(b) > 0xFFFF:
        raise ValueError("filename too long")
    return struct.pack("<H", len(b)) + b

def unpack_download_req(payload: bytes) -> str:
    if len(payload) < 2:
        raise ValueError("short req")
    n = struct.unpack("<H", payload[:2])[0]
    if len(payload) < 2 + n:
        raise ValueError("truncated req")
    return payload[2:2+n].decode("utf-8")

# ==================== DOWNLOAD_ALLOW ====================
# token(16) + size(8) + port(4) = 28 bytes
ALLOW_FORMAT = "<16sIQ"
ALLOW_SIZE   = struct.calcsize(ALLOW_FORMAT)   # 28

def pack_download_allow(token: bytes, size: int, port: int) -> bytes:
    if len(token) != TOKEN_SIZE:
        raise ValueError(f"token must be {TOKEN_SIZE} bytes")
    return struct.pack(ALLOW_FORMAT, token, size, port)

def unpack_download_allow(payload: bytes):
    if len(payload) < ALLOW_SIZE:
        raise ValueError("short allow")
    return struct.unpack(ALLOW_FORMAT, payload[:ALLOW_SIZE])

# ==================== DOWNLOAD_DENY ====================
def pack_download_deny(reason: int, text: str = "") -> bytes:
    return struct.pack("<B", reason) + text.encode("utf-8")

def unpack_download_deny(payload: bytes):
    if not payload:
        raise ValueError("short deny")
    return payload[0], payload[1:].decode("utf-8", "replace")

# ==================== UPLOAD_REQ ====================
# namelen(2) + name + size(8)
def pack_upload_req(filename: str, size: int) -> bytes:
    b = filename.encode("utf-8")
    if len(b) > 0xFFFF:
        raise ValueError("filename too long")
    return struct.pack("<H", len(b)) + b + struct.pack("<Q", size)

def unpack_upload_req(payload: bytes):
    if len(payload) < 2:
        raise ValueError("short upload req")
    n = struct.unpack("<H", payload[:2])[0]
    if len(payload) < 2 + n + 8:
        raise ValueError("truncated upload req")
    name = payload[2:2+n].decode("utf-8")
    size = struct.unpack("<Q", payload[2+n:2+n+8])[0]
    return name, size

# UPLOAD_ALLOW / UPLOAD_DENY — same layout as download
pack_upload_allow   = pack_download_allow
unpack_upload_allow = unpack_download_allow
pack_upload_deny    = pack_download_deny
unpack_upload_deny  = unpack_download_deny

# ==================== INDEX ====================
# count(2) + [ namelen(2) + name + size(8) ] * count
def pack_index(files):
    out = struct.pack("<H", len(files))
    for name, size in files:
        b = name.encode("utf-8")
        if len(b) > 0xFFFF:
            raise ValueError(f"filename too long: {name!r}")
        out += struct.pack("<H", len(b)) + b + struct.pack("<Q", size)
    return out

def unpack_index(payload: bytes):
    if len(payload) < 2:
        raise ValueError("short index")
    count = struct.unpack("<H", payload[:2])[0]
    off = 2
    files = []
    for _ in range(count):
        if off + 2 > len(payload):
            raise ValueError("truncated index (namelen)")
        n = struct.unpack("<H", payload[off:off+2])[0]; off += 2
        if off + n > len(payload):
            raise ValueError("truncated index (name)")
        name = payload[off:off+n].decode("utf-8"); off += n
        if off + 8 > len(payload):
            raise ValueError("truncated index (size)")
        size = struct.unpack("<Q", payload[off:off+8])[0]; off += 8
        files.append((name, size))
    return files

# ==================== TCP framing (4-byte length) ====================
TCP_FRAME_LEN = "<I"
TCP_FRAME_HDR = 4

def _send_msg(sock, msg_type, payload=b"", nonce=0):
    pkt = pack(msg_type, payload, nonce)
    sock.sendall(struct.pack(TCP_FRAME_LEN, len(pkt)) + pkt)

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf

def _recv_msg(sock, max_len=MAX_MSG):
    hdr = _recv_exact(sock, TCP_FRAME_HDR)
    (n,) = struct.unpack(TCP_FRAME_LEN, hdr)
    if n > max_len:
        raise ConnectionError(f"msg too big: {n} > {max_len}")
    body = _recv_exact(sock, n)
    return unpack(body)

# ==================== TCP payload helpers ====================
def pack_tcp_data(offset: int, chunk: bytes) -> bytes:
    return struct.pack("<Q", offset) + chunk

def unpack_tcp_data(payload: bytes):
    if len(payload) < 8:
        raise ValueError("short data")
    return struct.unpack("<Q", payload[:8])[0], payload[8:]

def pack_tcp_done(sha256: bytes, size: int) -> bytes:
    if len(sha256) != 32:
        raise ValueError("sha256 must be 32 bytes")
    return struct.pack("<32sQ", sha256, size)

def unpack_tcp_done(payload: bytes):
    if len(payload) < 40:
        raise ValueError("short done")
    return struct.unpack("<32sQ", payload[:40])

# ==================== __all__ ====================
__all__ = [
    "MAGIC", "VERSION", "HEADER_FORMAT", "HEADER_SIZE", "MAX_MSG",
    "DEFAULT_PORT", "TCP_PORT_DEFAULT", "TOKEN_SIZE", "TOKEN_TTL",
    "TYPE_HI", "TYPE_HELLO", "TYPE_ERROR", "TYPE_AUTUINDEX", "TYPE_INDEX",
    "TYPE_DOWNLOAD_REQ", "TYPE_DOWNLOAD_ALLOW", "TYPE_DOWNLOAD_DENY",
    "TYPE_UPLOAD_REQ", "TYPE_UPLOAD_ALLOW", "TYPE_UPLOAD_DENY",
    "DENY_NOT_FOUND", "DENY_FORBIDDEN", "DENY_LIMIT", "DENY_BUSY",
    "DENY_BAD_REQUEST", "DENY_EXISTS", "DENY_NO_SPACE", "DENY_TOO_BIG",
    "TYPE_TCP_HELLO", "TYPE_TCP_CONFIRM_Q", "TYPE_TCP_CONFIRM_Y",
    "TYPE_TCP_CONFIRM_N", "TYPE_TCP_TESTSERVER", "TYPE_TCP_OK",
    "TYPE_TCP_DATA", "TYPE_TCP_DONE", "TYPE_TCP_BYE", "TYPE_TCP_ERROR",
    "TYPE_TCP_UPLOAD_DATA", "TYPE_TCP_UPLOAD_DONE",
    "TYPE_TCP_UPLOAD_OK", "TYPE_TCP_UPLOAD_ERR",
    "CHUNK_SIZE", "HEARTBEAT_INTERVAL", "SESSION_TIMEOUT",
    "pack", "unpack",
    "pack_download_req", "unpack_download_req",
    "pack_download_allow", "unpack_download_allow",
    "pack_download_deny", "unpack_download_deny",
    "pack_upload_req", "unpack_upload_req",
    "pack_upload_allow", "unpack_upload_allow",
    "pack_upload_deny", "unpack_upload_deny",
    "pack_index", "unpack_index",
    "_send_msg", "_recv_msg", "_recv_exact",
    "pack_tcp_data", "unpack_tcp_data",
    "pack_tcp_done", "unpack_tcp_done",
]
