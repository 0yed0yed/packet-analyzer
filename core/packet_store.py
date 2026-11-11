"""نموذج الباكت + تخزين thread-safe + حفظ/تحميل session (JSONL) + قاموس الأسماء."""
from __future__ import annotations

import json
import logging
import threading
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional

import config
from core.protobuf_parser import parse_message

log = logging.getLogger(__name__)

# حالات الباكت
STATUS_DECRYPTED = "DECRYPTED"   # فك التشفير + parse كامل
STATUS_PLAIN = "PLAIN"           # parse كامل من غير تشفير
STATUS_PARTIAL = "PARTIAL"       # parse جزئي
STATUS_RAW = "RAW"               # مفيش حاجة اتفسّرت


# ---------------------------------------------------------------- أسماء الباكتات
@dataclass(frozen=True)
class PacketTypeInfo:
    name: str
    confidence: str = "guess"   # "guess" | "confirmed"
    notes: str = ""


def default_packet_types() -> Dict[str, PacketTypeInfo]:
    """الـ 12 الأصليين، كلهم guess."""
    return {p: PacketTypeInfo(n, "guess", "inherited from original script; unverified")
            for p, n in config.DEFAULT_PACKET_TYPES.items()}


def load_packet_types(path: Path = config.PACKET_TYPES_FILE) -> Dict[str, PacketTypeInfo]:
    """يقرأ {"prefix": {"name","confidence","notes"}}؛ لو الملف مش موجود/بايظ يستخدم الافتراضي."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default_packet_types()
    except (OSError, ValueError) as exc:
        log.warning("packet_types.json unreadable (%s); using defaults", exc)
        return default_packet_types()
    types: Dict[str, PacketTypeInfo] = {}
    for prefix, info in raw.items():
        if prefix.startswith("_") or not isinstance(info, dict) or not info.get("name"):
            continue
        conf = info.get("confidence", "guess")
        types[prefix.upper()] = PacketTypeInfo(
            str(info["name"]), conf if conf in ("guess", "confirmed") else "guess",
            str(info.get("notes", "")))
    return types or default_packet_types()


# ---------------------------------------------------------------- الباكت
@dataclass
class Packet:
    """باكت واحد بعد التحليل."""
    ts: str
    direction: str          # "CLIENT" | "SERVER"
    prefix: str
    name: str
    confidence: str         # guess | confirmed | unknown
    size: int
    raw_hex: str
    decrypted_hex: Optional[str]
    parsed: Optional[Dict[int, Any]]
    status: str
    conn: int = 0
    peer: str = ""          # host:port بتاع الاتصال
    num: int = 0            # بيتعيّن من الـ store

    def to_record(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, max_hex: Optional[int] = None) -> str:
        """JSON منسّق للباكت. ``max_hex`` بيقصّ حقول الـ hex الطويلة (للعرض فقط)."""
        rec = self.to_record()
        if max_hex is not None:
            for key in ("raw_hex", "decrypted_hex"):
                val = rec.get(key)
                if val and len(val) > max_hex:
                    rec[key] = val[:max_hex] + f"… (+{(len(val) - max_hex) // 2} bytes)"
        return json.dumps(rec, ensure_ascii=False, indent=2)

    @classmethod
    def from_record(cls, rec: Dict[str, Any]) -> "Packet":
        return cls(
            ts=rec.get("ts", ""), direction=rec.get("direction", ""),
            prefix=str(rec.get("prefix", "")).upper(), name=rec.get("name", "UNKNOWN"),
            confidence=rec.get("confidence", "unknown"), size=int(rec.get("size", 0)),
            raw_hex=rec.get("raw_hex", ""), decrypted_hex=rec.get("decrypted_hex"),
            parsed=_int_keys(rec.get("parsed")), status=rec.get("status", STATUS_RAW),
            conn=int(rec.get("conn", 0)), peer=rec.get("peer", ""), num=int(rec.get("num", 0)),
        )


def hex_dump(hex_str: str, max_bytes: int = 65536) -> str:
    """عرض hex بشكل offset + bytes + ASCII (للـ GUI). بيقصّ بعد ``max_bytes``."""
    try:
        data = bytes.fromhex(hex_str[: max_bytes * 2])
    except ValueError:
        return "(invalid hex)"
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hx:<47}  {asc}")
    total = len(hex_str) // 2
    if total > max_bytes:
        lines.append(f"… truncated: showing {max_bytes:,} of {total:,} bytes (use Copy Hex for all)")
    return "\n".join(lines)


def _int_keys(obj: Any) -> Any:
    """JSON بيحوّل مفاتيح الـ dict لنصوص؛ بنرجعها أرقام."""
    if isinstance(obj, dict):
        return {(int(k) if str(k).isdigit() else k): _int_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_int_keys(v) for v in obj]
    return obj


# ---------------------------------------------------------------- الـ store
class PacketStore:
    """تخزين thread-safe بحد أقصى (الأقدم بيتشال لو اتعدّى الحد)."""

    def __init__(self, max_packets: int = config.DEFAULT_MAX_PACKETS) -> None:
        self._lock = threading.Lock()
        self._packets: Deque[Packet] = deque(maxlen=max_packets)
        self._total = 0

    @property
    def total(self) -> int:
        """إجمالي اللي اتضاف (مش بس اللي في الذاكرة)."""
        with self._lock:
            return self._total

    def __len__(self) -> int:
        with self._lock:
            return len(self._packets)

    def add(self, pkt: Packet) -> Packet:
        with self._lock:
            self._total += 1
            pkt.num = self._total
            self._packets.append(pkt)
        return pkt

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._total = 0

    def set_max_packets(self, max_packets: int) -> None:
        """تغيير الحد الأقصى للباكتات في الذاكرة (الأقدم بيتشال لو الحد قلّ)."""
        with self._lock:
            self._packets = deque(self._packets, maxlen=max_packets)

    def snapshot(self) -> List[Packet]:
        with self._lock:
            return list(self._packets)

    def filter(self, direction: Optional[str] = None, prefix: Optional[str] = None,
               text: str = "", decrypted_only: bool = False) -> List[Packet]:
        """فلترة (الـ text بيدوّر في الرقم والـ prefix والاسم والاتجاه)."""
        return filter_packets(self.snapshot(), direction, prefix, text, decrypted_only)

    # ------------------------------------------------------ حفظ / تحميل
    def save_jsonl(self, path: Path, packets: Optional[Iterable[Packet]] = None) -> int:
        """يحفظ سطر JSON لكل باكت. بيرجع العدد."""
        items = list(packets) if packets is not None else self.snapshot()
        with open(path, "w", encoding="utf-8") as fh:
            for p in items:
                fh.write(json.dumps(p.to_record(), ensure_ascii=False) + "\n")
        return len(items)

    @staticmethod
    def export_packet(pkt: Packet, path: Path) -> None:
        """تصدير باكت واحد كـ JSON منسّق."""
        Path(path).write_text(json.dumps(pkt.to_record(), ensure_ascii=False, indent=2),
                              encoding="utf-8")

    @staticmethod
    def export_json(path: Path, packets: Iterable["Packet"]) -> int:
        """تصدير مجموعة باكتات كـ JSON array منسّق. بيرجع العدد."""
        items = [p.to_record() for p in packets]
        Path(path).write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
        return len(items)

    def load_jsonl(self, path: Path, replace: bool = True,
                   types: Optional[Dict[str, "PacketTypeInfo"]] = None) -> int:
        """يحمّل session محفوظة (Replay). أي سطر بايظ بيتتخطى.

        لو ``types`` اتمرّر، الأسماء الحالية والـ parser الحالي بيتطبقوا بأثر رجعي.
        """
        if replace:
            self.clear()
        n = 0
        for rec in iter_jsonl(path):
            pkt = Packet.from_record(rec)
            if types is not None:
                refresh_packet(pkt, types)
            self.add(pkt)
            n += 1
        return n


def refresh_packet(pkt: Packet, types: Dict[str, PacketTypeInfo]) -> Packet:
    """يطبّق قاموس الأسماء الحالي ويعيد الـ parse من ``decrypted_hex`` (للـ replay)."""
    info = types.get(pkt.prefix)
    pkt.name, pkt.confidence = (info.name, info.confidence) if info else ("UNKNOWN", "unknown")
    if pkt.decrypted_hex:
        try:
            res = parse_message(bytes.fromhex(pkt.decrypted_hex))
        except ValueError:
            return pkt
        pkt.parsed = res.fields or pkt.parsed
    return pkt


def iter_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                log.warning("skipping malformed line in %s", path)


def filter_packets(packets: Iterable[Packet], direction: Optional[str] = None,
                   prefix: Optional[str] = None, text: str = "",
                   decrypted_only: bool = False) -> List[Packet]:
    text = text.strip().lower()
    prefix = prefix.upper() if prefix else None
    out: List[Packet] = []
    for p in packets:
        if direction and p.direction != direction:
            continue
        if prefix and p.prefix != prefix:
            continue
        if decrypted_only and p.status != STATUS_DECRYPTED:
            continue
        if text and text not in f"{p.num} {p.prefix} {p.name} {p.direction}".lower():
            continue
        out.append(p)
    return out
