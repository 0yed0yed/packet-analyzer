"""الإعدادات المركزية للتطبيق (ثوابت + dataclasses).

⚠️ للأغراض التعليمية وتحليل ترافيك حسابك على جهازك فقط.
"""
from __future__ import annotations

import os
import re

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

APP_NAME = "Packet Analyzer"
APP_VERSION = "0.2.0-gui"

# ---------------------------------------------------------------- المسارات
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
# على أندرويد (p4a) بنكتب اللوجات في المجلد الخاص بالتطبيق
_PRIVATE_DIR = os.environ.get("ANDROID_PRIVATE")
LOGS_DIR = (Path(_PRIVATE_DIR) / "logs") if _PRIVATE_DIR else (BASE_DIR / "logs")
PACKET_TYPES_FILE = DATA_DIR / "packet_types.json"
FIELD_NAMES_FILE = DATA_DIR / "field_names.json"
KEY_LOG_FILE = LOGS_DIR / "key_extraction.log"

# ---------------------------------------------------------------- الشبكة
# الـ proxy يسمع على loopback فقط، وده ثابت عمدًا (مفيش خيار لتغييره).
LISTEN_HOST = "127.0.0.1"
DEFAULT_PORT = 1081
DEFAULT_IDLE_TIMEOUT = 120  # ثواني بدون ترافيك قبل قفل الاتصال
MAX_FRAME_BYTES = 1 << 20   # حد أمان للـ reassembly buffer (1 MiB)

# ---------------------------------------------------------------- التشفير
# Placeholder: استبدلهم بالقيم بتاعتك. بيتستخدموا فقط لحد ما يتستخرج KEY/IV من 2F33.
FALLBACK_KEY = b"0" * 16
FALLBACK_IV = b"0" * 16

KEY_PACKET_PREFIX = "2F33"
KEY_FIELD_NUMBER = 22   # 0xB2 >> 3  (assumption مأخوذ من --hex في الكود الأصلي)
IV_FIELD_NUMBER = 23    # 0xBA >> 3
KEY_LENGTH = 16

# ---------------------------------------------------------------- الباكتات
DEFAULT_HEADER_SIZE = 6
DEFAULT_MAX_PACKETS = 100_000  # الحد الأقصى للباكتات في الذاكرة

# الـ 12 الأصليين — كلهم تخمين غير موثّق.
DEFAULT_PACKET_TYPES: Dict[str, str] = {
    "0515": "SQUAD", "1215": "GUILD", "0E00": "BASIC", "1200": "MESSAGE",
    "1600": "FRIEND", "0500": "GHOST", "0300": "AUTH", "1D00": "UPDATE",
    "2F33": "ENCRYPT", "0F00": "CONNECT", "0F15": "ADVANCED", "0E15": "SYSTEM",
}

LEGAL_WARNING = (
    "⚠️  للأغراض التعليمية فقط: استخدم الأداة لتحليل ترافيك حسابك على جهازك أنت.\n"
    "    ممنوع استخدامها في الغش أو مخالفة شروط اللعبة أو إساءة استخدام الحسابات."
)


@dataclass
class ReassemblyConfig:
    """إعدادات تجميع الباكتات (معطّلة افتراضيًا: كل recv = باكت مستقل).

    الطول الكلي للباكت = header_size + قيمة حقل الطول.
    شكل الـ header الفعلي غير معروف، لازم تظبطه بنفسك.
    """
    enabled: bool = False
    header_size: int = DEFAULT_HEADER_SIZE
    length_offset: int = 2
    length_size: int = 2
    length_endian: str = "big"  # "big" | "little"
    skip_first: bool = False     # أول chunk في الاتصال (handshake) يتعرض كما هو من غير تجميع

    def validate(self) -> None:
        if self.length_endian not in ("big", "little"):
            raise ValueError("length_endian must be 'big' or 'little'")
        if self.header_size < 2:
            raise ValueError("header_size must be >= 2 (prefix is 2 bytes)")
        if self.enabled:
            if self.length_size not in (1, 2, 3, 4):
                raise ValueError("length_size must be 1..4")
            if self.length_offset < 0 or self.length_offset + self.length_size > self.header_size:
                raise ValueError("length field must fit inside the header")


@dataclass
class ProxyConfig:
    """إعدادات الـ proxy. العنوان ثابت 127.0.0.1 (انظر LISTEN_HOST)."""
    port: int = DEFAULT_PORT
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT
    max_packets: int = DEFAULT_MAX_PACKETS
    skip_ports: tuple = ()      # منافذ وجهة بتتخطى (مثلاً 443)
    only_ports: tuple = ()      # فاضي = كل المنافذ؛ غير كده بيحلّل المنافذ دي بس
    show_tls: bool = False      # الاتصالات المكتشفة كـ TLS بتتخطى افتراضيًا
    reassembly: ReassemblyConfig = field(default_factory=ReassemblyConfig)
    server_reassembly: Optional[ReassemblyConfig] = None  # لو None بيستخدم نفس إعداد العميل

    def reassembly_for(self, direction: str) -> ReassemblyConfig:
        if direction == "SERVER" and self.server_reassembly is not None:
            return self.server_reassembly
        return self.reassembly

    def header_sizes(self) -> Dict[str, int]:
        return {d: self.reassembly_for(d).header_size for d in ("CLIENT", "SERVER")}

    @property
    def host(self) -> str:
        return LISTEN_HOST

    @property
    def header_size(self) -> int:
        return self.reassembly.header_size


def observed_preset() -> tuple:
    """الشكل الملاحظ في الـ capture (يحتاج تأكيد منك):

    CLIENT → SERVER: prefix(2) + length(4, big-endian) + body         → header 6، طول عند offset 2
    SERVER → CLIENT: type(1)   + length(4, big-endian) + body         → header 5، طول عند offset 1
    وأول chunk من العميل (handshake) بيتعرض كما هو.
    """
    client = ReassemblyConfig(enabled=True, header_size=6, length_offset=2, length_size=4,
                              length_endian="big", skip_first=True)
    server = ReassemblyConfig(enabled=True, header_size=5, length_offset=1, length_size=4,
                              length_endian="big", skip_first=False)
    return client, server


def parse_ports(text: str) -> tuple:
    """'443, 8080' → (443, 8080). بيرفع ValueError برسالة واضحة لو فيه رقم غلط."""
    ports = []
    for token in re.split(r"[,\s]+", text.strip()):
        if not token:
            continue
        if not token.isdigit() or not 1 <= int(token) <= 65535:
            raise ValueError(f"Invalid port: {token!r} (must be 1..65535)")
        ports.append(int(token))
    return tuple(ports)


def default_gui_config() -> ProxyConfig:
    """إعدادات الـ GUI الافتراضية: الـ observed preset شغّال (بعد ما اتأكد من الـ capture).

    الـ CLI لسه بيبدأ بالتجميع معطّل (--preset observed لتفعيله).
    """
    cfg = ProxyConfig()
    cfg.reassembly, cfg.server_reassembly = observed_preset()
    return cfg


def proxy_config_to_dict(cfg: ProxyConfig) -> Dict[str, Any]:
    """تحويل الإعدادات لـ dict قابل للحفظ كـ JSON (في QSettings)."""
    return asdict(cfg)


def _reassembly_from_dict(d: Any, fallback: ReassemblyConfig) -> ReassemblyConfig:
    if not isinstance(d, dict):
        return fallback
    base = asdict(fallback)
    for k in base:
        if k in d and isinstance(d[k], type(base[k])):
            base[k] = d[k]
    return ReassemblyConfig(**base)


def proxy_config_from_dict(d: Any) -> ProxyConfig:
    """عكس ``proxy_config_to_dict``. أي حقل ناقص أو غلط بياخد القيمة الافتراضية للـ GUI."""
    cfg = default_gui_config()
    if not isinstance(d, dict):
        return cfg
    for key in ("port", "idle_timeout", "max_packets"):
        if isinstance(d.get(key), int) and not isinstance(d.get(key), bool):
            setattr(cfg, key, d[key])
    for key in ("skip_ports", "only_ports"):
        if isinstance(d.get(key), (list, tuple)):
            setattr(cfg, key, tuple(int(p) for p in d[key] if isinstance(p, int)))
    if isinstance(d.get("show_tls"), bool):
        cfg.show_tls = d["show_tls"]
    cfg.reassembly = _reassembly_from_dict(d.get("reassembly"), cfg.reassembly)
    srv = d.get("server_reassembly")
    if srv is None and "server_reassembly" in d:
        cfg.server_reassembly = None
    else:
        cfg.server_reassembly = _reassembly_from_dict(srv, cfg.server_reassembly or cfg.reassembly)
    return cfg


def ensure_dirs() -> None:
    """إنشاء logs/ و data/ تلقائيًا."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
