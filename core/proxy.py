"""SOCKS5 proxy + معالجة الباكتات في thread منفصل.

التصميم (مهم للـ GUI في المرحلة 2):
    threads الـ relay  →  raw_queue  →  PacketProcessor (thread)  →  events queue  →  GUI/CLI
الـ GUI/CLI بيقرأ من ``events`` بس (QTimer كل 100ms)، ومحدش يلمس الواجهة من threads هنا.

⚠️ للأغراض التعليمية فقط، على ترافيك حسابك. الـ proxy بيسمع على 127.0.0.1 فقط.
"""
from __future__ import annotations

import itertools
import queue
import select
import socket
import struct
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import config
from core import crypto
from core.packet_store import (STATUS_DECRYPTED, STATUS_PARTIAL, STATUS_PLAIN, STATUS_RAW,
                               Packet, PacketStore, PacketTypeInfo, load_packet_types)
from core.protobuf_parser import parse_message


# PARTIAL بس لو الـ parse غطّى نصف الباكت على الأقل (بيقلل النتائج الوهمية من بيانات عشوائية)
MIN_PARTIAL_COVERAGE = 0.5


def looks_like_tls(data: bytes) -> bool:
    """أول record في TLS: type 0x14-0x17 + version 03 0x (مثلاً 16 03 01 أو 17 03 03)."""
    return len(data) >= 5 and 0x14 <= data[0] <= 0x17 and data[1] == 3 and data[2] <= 4


@dataclass
class Event:
    """رسالة من الـ proxy للواجهة. kind: packet | log | error | keys | state."""
    kind: str
    payload: Any = None


# ---------------------------------------------------------------- تجميع الباكتات
class StreamAssembler:
    """يحوّل chunks الـ TCP لباكتات.

    معطّل (الافتراضي): كل chunk = باكت.
    مفعّل: بيجمّع الـ buffer حسب حقل الطول (الطول الكلي = header + length).
    """

    def __init__(self, cfg: config.ReassemblyConfig) -> None:
        self.cfg = cfg
        self._buf = bytearray()
        self._first = True

    def feed(self, data: bytes) -> List[bytes]:
        c = self.cfg
        if not c.enabled:
            return [data] if data else []
        if self._first:
            self._first = False
            if c.skip_first:  # handshake: يتعرض كما هو (شكله مختلف عن باقي الباكتات)
                return [data] if data else []
        self._buf += data
        out: List[bytes] = []
        need = c.length_offset + c.length_size
        while len(self._buf) >= max(need, c.header_size):
            length = int.from_bytes(self._buf[c.length_offset:need], c.length_endian)
            total = c.header_size + length
            if total > config.MAX_FRAME_BYTES:
                # افتراض الـ framing غلط: نفرّغ الـ buffer كباكت خام بدل ما نتجمّد
                out.append(bytes(self._buf))
                self._buf.clear()
                break
            if len(self._buf) < total:
                break
            out.append(bytes(self._buf[:total]))
            del self._buf[:total]
        return out


# ---------------------------------------------------------------- معالجة الباكتات
class PacketProcessor(threading.Thread):
    """فك تشفير + parse + تخزين، بعيد عن مسار الـ relay عشان مايتأخرش."""

    def __init__(self, keys: crypto.KeyManager, store: PacketStore,
                 events: "queue.Queue[Event]", header_sizes: Dict[str, int],
                 types: Optional[Dict[str, PacketTypeInfo]] = None) -> None:
        super().__init__(daemon=True, name="packet-processor")
        self.keys = keys
        self.store = store
        self.events = events
        self.header_sizes = header_sizes
        self.types = types if types is not None else load_packet_types()
        self.raw_queue: "queue.Queue[Optional[tuple]]" = queue.Queue(maxsize=20000)
        self.dropped = 0

    def submit(self, raw: bytes, direction: str, conn: int, peer: str = "") -> None:
        if len(raw) < 2:
            return
        try:
            self.raw_queue.put_nowait((raw, direction, conn, datetime.now(), peer))
        except queue.Full:
            self.dropped += 1

    def stop(self) -> None:
        self.raw_queue.put(None)

    def run(self) -> None:
        while True:
            item = self.raw_queue.get()
            if item is None:
                return
            try:
                self._process(*item)
            except Exception as exc:  # لا نسيب خطأ يوقّف الـ worker
                self._emit("error", f"processor error: {exc!r}")

    def _process(self, raw: bytes, direction: str, conn: int, ts: datetime, peer: str = "") -> None:
        prefix = raw[:2].hex().upper()
        body = raw[self.header_sizes.get(direction, config.DEFAULT_HEADER_SIZE):]

        key, iv = self.keys.current()
        decrypted = crypto.aes_cbc_decrypt(body, key, iv) if body else None

        if prefix == config.KEY_PACKET_PREFIX:
            before = self.keys.fingerprint()
            self.keys.ingest_key_packet(body, decrypted)
            after = self.keys.fingerprint()
            if after != before:
                self._emit("keys", after)

        pkt = self._build_packet(raw, body, decrypted, prefix, direction, conn, ts, peer)
        self.store.add(pkt)
        self._emit("packet", pkt)

    def _build_packet(self, raw: bytes, body: bytes, decrypted: Optional[bytes], prefix: str,
                      direction: str, conn: int, ts: datetime, peer: str = "") -> Packet:
        dec_res = parse_message(decrypted) if decrypted else None
        plain_res = parse_message(body) if body else None

        # الأفضلية: parse كامل من المفكوك، ثم parse كامل من الخام، ثم أي parse جزئي
        if dec_res and dec_res.complete:
            parsed, status = dec_res.fields, STATUS_DECRYPTED
        elif plain_res and plain_res.complete:
            parsed, status = plain_res.fields, STATUS_PLAIN
        elif dec_res and dec_res.fields and dec_res.coverage >= MIN_PARTIAL_COVERAGE:
            parsed, status = dec_res.fields, STATUS_PARTIAL
        elif plain_res and plain_res.fields and plain_res.coverage >= MIN_PARTIAL_COVERAGE:
            parsed, status = plain_res.fields, STATUS_PARTIAL
        else:
            parsed, status = None, STATUS_RAW

        info = self.types.get(prefix)
        return Packet(
            ts=ts.isoformat(timespec="milliseconds"), direction=direction, prefix=prefix,
            name=info.name if info else "UNKNOWN",
            confidence=info.confidence if info else "unknown",
            size=len(raw), raw_hex=raw.hex(),
            decrypted_hex=decrypted.hex() if decrypted else None,
            parsed=parsed, status=status, conn=conn, peer=peer)

    def _emit(self, kind: str, payload: Any) -> None:
        try:
            self.events.put_nowait(Event(kind, payload))
        except queue.Full:
            self.dropped += 1


# ---------------------------------------------------------------- SOCKS5
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def _reply(code: int, bind: Optional[Tuple] = None) -> bytes:
    """رد SOCKS5 بعنوان IPv4 أو IPv6 حسب ``bind``."""
    if bind and ":" in str(bind[0]):
        addr = socket.inet_pton(socket.AF_INET6, str(bind[0]).split("%")[0])
        return b"\x05" + bytes([code]) + b"\x00\x04" + addr + struct.pack(">H", bind[1])
    host, port = (bind[0], bind[1]) if bind else ("0.0.0.0", 0)
    return b"\x05" + bytes([code]) + b"\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port)


def _socks5_handshake(client: socket.socket) -> Tuple[str, int]:
    """مصافحة بدون auth (CONNECT فقط) ← (host, port). بيدعم IPv4/IPv6/domain."""
    ver, nmethods = _recv_exact(client, 2)
    if ver != 5:
        raise ConnectionError("not SOCKS5")
    _recv_exact(client, nmethods)
    client.sendall(b"\x05\x00")

    ver, cmd, _, atyp = _recv_exact(client, 4)
    if cmd != 1:
        client.sendall(_reply(7))
        raise ConnectionError("only CONNECT is supported")
    if atyp == 1:
        host = socket.inet_ntoa(_recv_exact(client, 4))
    elif atyp == 3:
        host = _recv_exact(client, _recv_exact(client, 1)[0]).decode()
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
    else:
        client.sendall(_reply(8))
        raise ConnectionError("unsupported address type")
    return host, struct.unpack(">H", _recv_exact(client, 2))[0]


class Socks5Proxy:
    """الـ proxy كامل: start()/stop() + ``events`` queue للواجهة."""

    def __init__(self, cfg: Optional[config.ProxyConfig] = None,
                 keys: Optional[crypto.KeyManager] = None,
                 store: Optional[PacketStore] = None) -> None:
        self.cfg = cfg if cfg is not None else config.ProxyConfig()
        self.cfg.reassembly.validate()
        if self.cfg.server_reassembly:
            self.cfg.server_reassembly.validate()
        self.keys = keys if keys is not None else crypto.KeyManager()
        # مهم: `store or ...` غلط لأن PacketStore الفاضي (len == 0) بيتعامل كـ False فيتتجاهل
        self.store = store if store is not None else PacketStore(self.cfg.max_packets)
        self.events: "queue.Queue[Event]" = queue.Queue(maxsize=50000)
        self.processor = PacketProcessor(self.keys, self.store, self.events, self.cfg.header_sizes())

        self._server: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._conns: Set[socket.socket] = set()
        self._conns_lock = threading.Lock()
        self._conn_ids = itertools.count(1)
        self.bound_port: int = 0

    @property
    def running(self) -> bool:
        return self._accept_thread is not None and self._accept_thread.is_alive()

    def start(self) -> None:
        """بيربط الـ socket فورًا (أخطاء الـ bind بتتفع هنا) ثم يشغّل الـ threads."""
        if self.running:
            return
        crypto.setup_key_logger()
        self._stop.clear()
        # 127.0.0.1 فقط — ثابت من config.LISTEN_HOST
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((config.LISTEN_HOST, self.cfg.port))
        srv.listen(50)
        srv.settimeout(0.5)
        self._server = srv
        self.bound_port = srv.getsockname()[1]
        assert srv.getsockname()[0] == "127.0.0.1"

        if not self.processor.is_alive():
            self.processor = PacketProcessor(self.keys, self.store, self.events, self.cfg.header_sizes())
        self.processor.start()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True,
                                               name="socks5-accept")
        self._accept_thread.start()
        self._emit("state", "running")
        self._emit("log", f"listening on {config.LISTEN_HOST}:{self.bound_port}")

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        with self._conns_lock:
            for s in list(self._conns):
                try:
                    s.close()
                except OSError:
                    pass
            self._conns.clear()
        if self._accept_thread:
            self._accept_thread.join(timeout=2)
        self.processor.stop()
        self.processor.join(timeout=2)
        self._emit("state", "stopped")

    # ------------------------------------------------------------ الداخلي
    def _emit(self, kind: str, payload: Any = None) -> None:
        try:
            self.events.put_nowait(Event(kind, payload))
        except queue.Full:
            pass

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _track(self, sock: socket.socket, add: bool) -> None:
        with self._conns_lock:
            (self._conns.add if add else self._conns.discard)(sock)

    def _handle_client(self, client: socket.socket) -> None:
        conn = next(self._conn_ids)
        remote: Optional[socket.socket] = None
        self._track(client, True)
        try:
            client.settimeout(30)
            host, port = _socks5_handshake(client)
            try:
                remote = socket.create_connection((host, port), timeout=10)  # IPv4 + IPv6
            except OSError as exc:
                client.sendall(_reply(5))
                self._emit("error", f"c{conn} connect {host}:{port} failed: {exc}")
                return
            self._track(remote, True)
            client.sendall(_reply(0, remote.getsockname()[:2]))
            client.settimeout(None)
            remote.settimeout(None)
            peer = f"{host}:{port}"
            analyze = (not self.cfg.only_ports or port in self.cfg.only_ports) and port not in self.cfg.skip_ports
            self._emit("log", f"c{conn} SOCKS5 → {peer}" + ("" if analyze else "  (skipped: port filter)"))
            self._relay(client, remote, conn, peer, analyze)
        except (OSError, ConnectionError):
            pass
        finally:
            for s in (client, remote):
                if s:
                    self._track(s, False)
                    try:
                        s.close()
                    except OSError:
                        pass

    def _relay(self, client: socket.socket, remote: socket.socket, conn: int,
               peer: str, analyze: bool) -> None:
        peers = {client: remote, remote: client}
        dirs: Dict[socket.socket, Tuple[str, StreamAssembler]] = {
            client: ("CLIENT", StreamAssembler(self.cfg.reassembly_for("CLIENT"))),
            remote: ("SERVER", StreamAssembler(self.cfg.reassembly_for("SERVER"))),
        }
        idle = 0.0
        checked: Set[socket.socket] = set()  # أول chunk من كل اتجاه بيتفحص
        while not self._stop.is_set():
            readable, _, _ = select.select([client, remote], [], [], 1.0)
            if not readable:
                idle += 1.0
                if idle >= self.cfg.idle_timeout:
                    return
                continue
            idle = 0.0
            for sock in readable:
                data = sock.recv(65536)
                if not data:
                    return
                peers[sock].sendall(data)  # الأول نوصّل الداتا، التحليل بعدين
                if sock not in checked:
                    checked.add(sock)
                    if analyze and not self.cfg.show_tls and looks_like_tls(data):
                        analyze = False  # اتصال TLS: محتواه مشفّر ومش هيتفك هنا
                        self._emit("log", f"c{conn} {peer} is TLS → skipped (use --show-tls to keep)")
                if not analyze:
                    continue
                direction, assembler = dirs[sock]
                for packet in assembler.feed(data):
                    self.processor.submit(packet, direction, conn, peer)
