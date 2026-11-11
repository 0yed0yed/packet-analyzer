"""AES-128-CBC + استخراج KEY/IV من باكت 2F33 + إدارة المفاتيح.

الـ KEY/IV مبيتطبعوش ولا بيتسجلوا في أي log (بس fingerprint قصير).
"""
from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Tuple

import config

from core import aes_pure

try:  # pycryptodome أسرع؛ لو مش موجود بنستخدم تنفيذ بايثون صافي (aes_pure)
    from Crypto.Cipher import AES
    CRYPTO_BACKEND = "pycryptodome"
except ImportError:
    AES = None
    CRYPTO_BACKEND = "pure-python"
CRYPTO_OK = True  # فك التشفير متاح دايمًا (بأي من الـ backend دول)

key_logger = logging.getLogger("key_extraction")


def setup_key_logger() -> None:
    """تهيئة logs/key_extraction.log (آمن لو اتنده أكتر من مرة)."""
    if key_logger.handlers:
        return
    config.ensure_dirs()
    handler = RotatingFileHandler(config.KEY_LOG_FILE, maxBytes=1_000_000,
                                  backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    key_logger.addHandler(handler)
    key_logger.setLevel(logging.INFO)
    key_logger.propagate = False


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        out.append(b | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field_marker(field_number: int) -> bytes:
    """tag (length-delimited) + طول 16 → للـ field 22 بتطلع B2 01 10 وللـ 23 BA 01 10."""
    return _encode_varint((field_number << 3) | 2) + bytes([config.KEY_LENGTH])


KEY_MARKER = _field_marker(config.KEY_FIELD_NUMBER)
IV_MARKER = _field_marker(config.IV_FIELD_NUMBER)


def aes_cbc_decrypt(body: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
    """فك AES-128-CBC. البايتات الزيادة عن مضاعف 16 بتتتجاهل.

    لو الـ padding غلط بيرجع الـ plaintext الخام بدل ما يفشل.
    """
    if len(key) != 16 or len(iv) != 16:
        return None
    n = len(body) - (len(body) % 16)
    if n == 0:
        return None
    if AES is not None:
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(body[:n])
    else:
        plain = aes_pure.cbc_decrypt(body[:n], key, iv)
    return _strip_padding(plain)


def _strip_padding(plain: bytes) -> bytes:
    """PKCS#7: لو الـ padding سليم يتشال، وإلا بنرجع الـ plaintext الخام."""
    pad = plain[-1] if plain else 0
    if 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad):
        return plain[:-pad]
    return plain


@dataclass
class ExtractionResult:
    """نتيجة محاولة استخراج KEY/IV من باكت."""
    key: Optional[bytes]
    iv: Optional[bytes]
    success: bool
    reason: str
    source: str  # "decrypted" | "raw"

    def describe(self) -> str:
        """وصف آمن (من غير قيم المفاتيح)."""
        return (f"{'SUCCESS' if self.success else 'FAIL'} source={self.source} "
                f"key={'found' if self.key else 'missing'} "
                f"iv={'found' if self.iv else 'missing'} reason={self.reason}")


def _last_marker_value(data: bytes, marker: bytes) -> Tuple[Optional[bytes], str]:
    """آخر قيمة بعد الـ marker (16 بايت). بيرجع (القيمة, سبب الفشل)."""
    found: Optional[bytes] = None
    truncated = False
    start = 0
    while True:
        i = data.find(marker, start)
        if i < 0:
            break
        chunk = data[i + len(marker): i + len(marker) + config.KEY_LENGTH]
        if len(chunk) == config.KEY_LENGTH:
            found = chunk
        else:
            truncated = True
        start = i + 1
    if found:
        return found, ""
    return None, "truncated after marker" if truncated else "marker not found"


def extract_keys_from_packet(data: bytes, source: str = "raw") -> ExtractionResult:
    """بيدوّر على field 22 (KEY) و field 23 (IV) بحجم 16 بايت داخل ``data``.

    ⚠️ الـ pattern ده افتراض من --hex في الكود الأصلي ومحتاج تتأكد منه على ترافيكك.
    النجاح = لقينا واحد على الأقل منهم.
    """
    if not data:
        return ExtractionResult(None, None, False, "empty data", source)
    key, key_err = _last_marker_value(data, KEY_MARKER)
    iv, iv_err = _last_marker_value(data, IV_MARKER)
    if key or iv:
        reason = "ok" if (key and iv) else f"partial ({'iv' if not iv else 'key'}: {iv_err or key_err})"
        return ExtractionResult(key, iv, True, reason, source)
    return ExtractionResult(None, None, False, f"key: {key_err}; iv: {iv_err}", source)


class KeyManager:
    """بيحتفظ بالـ KEY/IV الحاليين (thread-safe) مع fallback للثابتين.

    كل محاولة استخراج بتتسجل في logs/key_extraction.log.
    """

    def __init__(self, fallback_key: bytes = config.FALLBACK_KEY,
                 fallback_iv: bytes = config.FALLBACK_IV) -> None:
        self._lock = threading.Lock()
        self._key = fallback_key
        self._iv = fallback_iv
        self._dynamic_key = False
        self._dynamic_iv = False
        self._last_key_packet: Optional[bytes] = None  # body آخر باكت 2F33 (raw)

    # ---------------------------------------------------------- القراءة
    def current(self) -> Tuple[bytes, bytes]:
        with self._lock:
            return self._key, self._iv

    @property
    def last_key_packet(self) -> Optional[bytes]:
        with self._lock:
            return self._last_key_packet

    def fingerprint(self) -> str:
        """عرض مختصر للـ GUI/الـ CLI: hash قصير مش المفتاح نفسه."""
        with self._lock:
            k = hashlib.sha256(self._key).hexdigest()[:8]
            i = hashlib.sha256(self._iv).hexdigest()[:8]
            src = "dynamic" if (self._dynamic_key and self._dynamic_iv) else (
                "partial" if (self._dynamic_key or self._dynamic_iv) else "fallback")
        return f"K:{k} I:{i} ({src})"

    # ---------------------------------------------------------- التحديث
    def ingest_key_packet(self, body: bytes, decrypted: Optional[bytes]) -> List[ExtractionResult]:
        """بيجرّب الاستخراج من الـ decrypted ثم الـ raw، ويطبّق أول نجاح."""
        with self._lock:
            self._last_key_packet = body
        results: List[ExtractionResult] = []
        for blob, source in ((decrypted, "decrypted"), (body, "raw")):
            if not blob:
                continue
            res = extract_keys_from_packet(blob, source)
            results.append(res)
            self._log(res)
            if res.success:
                self._apply(res)
                break
        if not results:
            key_logger.warning("FAIL no payload to scan (empty body)")
        return results

    def test_extraction(self, current_keys_decrypt: bool = True) -> List[ExtractionResult]:
        """يعرض نتيجة الاستخراج على آخر باكت 2F33 من غير ما يغيّر المفاتيح (زر Test Extraction)."""
        body = self.last_key_packet
        if body is None:
            return [ExtractionResult(None, None, False, "no 2F33 packet captured yet", "raw")]
        results = []
        if current_keys_decrypt:
            key, iv = self.current()
            dec = aes_cbc_decrypt(body, key, iv)
            if dec:
                results.append(extract_keys_from_packet(dec, "decrypted"))
        results.append(extract_keys_from_packet(body, "raw"))
        return results

    def set_keys(self, key: Optional[bytes], iv: Optional[bytes]) -> bool:
        """تعيين يدوي (مثلاً من الإعدادات). بيرجع True لو حصل تغيير."""
        return self._apply(ExtractionResult(key, iv, True, "manual", "raw"), log=False)

    def _apply(self, res: ExtractionResult, log: bool = True) -> bool:
        changed = False
        with self._lock:
            if res.key and len(res.key) == config.KEY_LENGTH and res.key != self._key:
                self._key, self._dynamic_key, changed = res.key, True, True
            if res.iv and len(res.iv) == config.KEY_LENGTH and res.iv != self._iv:
                self._iv, self._dynamic_iv, changed = res.iv, True, True
        if changed and log:
            key_logger.info("KEYS UPDATED (values not logged)")
        return changed

    @staticmethod
    def _log(res: ExtractionResult) -> None:
        (key_logger.info if res.success else key_logger.warning)(res.describe())
