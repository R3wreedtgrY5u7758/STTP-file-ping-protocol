# STTP — Servertest File Ping Protocol

> **STTP/1** — a hybrid UDP+TCP file transfer protocol with a fast "file ping" check, token authorization, session liveness checks, and sha256 verification.

[![Protocol](https://img.shields.io/badge/protocol-STTP%2F1-blue)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

---

## Table of contents

- [Overview](#overview)
- [Key features](#key-features)
- [Architecture](#architecture)
- [Protocol specification](#protocol-specification)
  - [Header format](#header-format)
  - [Packet types](#packet-types)
  - [Denial reasons](#denial-reasons)
  - [Defaults](#defaults)
- [Installation](#installation)
- [Usage](#usage)
  - [Start the server](#start-the-server)
  - [Check availability](#check-availability)
  - [List files](#list-files)
  - [Download a file](#download-a-file)
  - [Upload a file](#upload-a-file)
- [Project layout](#project-layout)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

**STTP (Servertest File Ping Protocol)** is a lightweight hybrid protocol for exchanging files between a client and a server. It uses **UDP** for a fast "file ping" — checking whether the server is alive, listing available files, and requesting a transfer permit — and **TCP** for the actual data.

Every transfer session is protected by a single-use token with a TTL, bound to the client's IP, starts with a mandatory `CONFIRM → TESTSERVER → OK` handshake, and ends with a `sha256` verification. STTP supports both **download** and **upload** of files of arbitrary size, a 12-second heartbeat, and atomic writes via a `.part` file.

It fits embedded systems, game backends, and internal services where HTTP/TLS overhead is unwanted but control and integrity still matter.

---

## Key features

- **File ping first.** A single UDP round-trip confirms the server is up, returns the file index, and issues a permission token. No TCP connection is opened until the ping succeeds.
- **Hybrid transport.** UDP `36373` for control, TCP `36374` for data. Light control messages are never blocked by heavy transfers.
- **Token authorization.** Each transfer requires a single-use token (16 bytes, 30s TTL) bound to the client's IP and mode (`download` / `upload`).
- **Explicit confirmation.** The server asks `are you sure?` before starting a transfer; the client may decline.
- **Mandatory TESTSERVER.** After confirmation, the server sends `TESTSERVER`; the client replies `OK`. Guarantees bidirectional liveness before the first byte of data.
- **Heartbeat.** Client sends `OK` every 12 seconds; the server drops the session if the client is silent longer than `SESSION_TIMEOUT`.
- **Integrity.** sha256 computed on both sides and compared in `TCP_DONE` / `TCP_UPLOAD_OK`.
- **Atomic writes.** Uploads go to `*.part`; on completion, `os.replace()` swaps it in. A broken session never leaves a corrupted file.
- **Extensible header.** `MAGIC`, `VERSION`, `TYPE`, `RESERVED`, `NONCE`. New packet types can be added without breaking older clients.

---

## Architecture
Client Server
│ │
│──── UDP: HI ────────────────────────────►│ file ping: availability
│◄─── UDP: HELLO ──────────────────────────│
│ │
│──── UDP: AUTUINDEX ─────────────────────►│ file ping: listing
│◄─── UDP: INDEX ──────────────────────────│
│ │
│──── UDP: DOWNLOAD_REQ / UPLOAD_REQ ─────►│ file ping: permission
│◄─── UDP: ALLOW (token, size, port) ──────│
│ │
│──── TCP: HELLO (token) ─────────────────►│ session
│◄─── TCP: CONFIRM_Q ("are you sure?") ────│
│──── TCP: CONFIRM_Y ─────────────────────►│
│◄─── TCP: TESTSERVER ─────────────────────│
│──── TCP: OK ────────────────────────────►│
│◄─── TCP: DATA × N ───────────────────────│ transfer
│──── TCP: OK (heartbeat, 12s) ───────────►│
│◄─── TCP: DONE (sha256, size) ────────────│
│──── TCP: BYE ───────────────────────────►│


---

## Protocol specification

### Header format

12 bytes, little-endian.

0 1 2 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| MAGIC (0x53545450) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| VERSION (1) | TYPE | RESERVED |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| NONCE (uint32) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| PAYLOAD ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


- `MAGIC` = `0x53545450` (ASCII `"STTP"`)
- `VERSION` = `1`
- `TYPE` — see below
- `RESERVED` — future use, zero
- `NONCE` — per-request random ID, echoed in the response
- `PAYLOAD` — depends on `TYPE`

### Packet types

#### UDP — control (the "file ping")

| Code | Name           | Direction | Payload |
|------|----------------|-----------|---------|
| 0x01 | `HI`             | C→S       | `"hi!"` |
| 0x02 | `HELLO`          | S→C       | `"hello!"` |
| 0x03 | `ERROR`          | S→C       | text |
| 0x04 | `AUTUINDEX`      | C→S       | — |
| 0x05 | `INDEX`          | S→C       | `count(2) + [namelen(2)+name+size(8)]×count` |
| 0x10 | `DOWNLOAD_REQ`   | C→S       | `namelen(2) + name` |
| 0x11 | `DOWNLOAD_ALLOW` | S→C       | `token(16) + size(8) + port(4)` |
| 0x12 | `DOWNLOAD_DENY`  | S→C       | `reason(1) + text` |
| 0x13 | `UPLOAD_REQ`     | C→S       | `namelen(2) + name + size(8)` |
| 0x14 | `UPLOAD_ALLOW`   | S→C       | `token(16) + size(8) + port(4)` |
| 0x15 | `UPLOAD_DENY`    | S→C       | `reason(1) + text` |

#### TCP — session

| Code | Name              | Direction | Payload |
|------|-------------------|-----------|---------|
| 0x20 | `TCP_HELLO`       | C→S       | `token(16)` |
| 0x21 | `TCP_CONFIRM_Q`   | S→C       | `"are you sure?"` |
| 0x22 | `TCP_CONFIRM_Y`   | C→S       | — |
| 0x23 | `TCP_CONFIRM_N`   | C→S       | — |
| 0x24 | `TCP_TESTSERVER`  | S→C       | `"testserver"` |
| 0x25 | `TCP_OK`          | C→S       | — |
| 0x26 | `TCP_DATA`        | S→C       | `offset(8) + chunk` |
| 0x27 | `TCP_DONE`        | S→C       | `sha256(32) + size(8)` |
| 0x28 | `TCP_BYE`         | C→S       | — |
| 0x29 | `TCP_ERROR`       | both      | text |
| 0x2A | `TCP_UPLOAD_DATA` | C→S       | `offset(8) + chunk` |
| 0x2B | `TCP_UPLOAD_DONE` | C→S       | `sha256(32) + size(8)` |
| 0x2C | `TCP_UPLOAD_OK`   | S→C       | `sha256(32) + size(8)` |
| 0x2D | `TCP_UPLOAD_ERR`  | S→C       | text |

TCP framing: each message is prefixed with a 4-byte little-endian length (`<I`), followed by the STTP packet (header + payload).

### Denial reasons

| Code | Name          | Description |
|------|---------------|-------------|
| 0x01 | `NOT_FOUND`   | file not found |
| 0x02 | `FORBIDDEN`   | client not in whitelist |
| 0x03 | `LIMIT`       | quota exceeded |
| 0x04 | `BUSY`        | server busy |
| 0x05 | `BAD_REQUEST` | malformed request |
| 0x06 | `EXISTS`      | file already exists |
| 0x07 | `NO_SPACE`    | not enough disk space |
| 0x08 | `TOO_BIG`     | size limit exceeded |

### Defaults

| Parameter | Value |
|-----------|-------|
| UDP port | `36373` |
| TCP port | `36374` |
| Chunk size | 256 KB |
| Token TTL | 30 s |
| Heartbeat | 12 s |
| Session timeout | 12 s |
| Max message | 16 MB |
| Protocol version | 1 |

---

## Installation

Requires **Python 3.8+**. No external dependencies.
