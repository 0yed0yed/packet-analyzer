"""خدمة الـ proxy: بتشغّل Socks5Proxy وتكتب الباكتات في live.jsonl وحالتها في status.json.

بتشتغل في foreground service على أندرويد (service.py)، أو في thread على الكمبيوتر للاختبار.
⚠️ للأغراض التعليمية فقط، على ترافيك حسابك وجهازك. الـ proxy بيسمع على 127.0.0.1 فقط.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import appdata
import config
from core import crypto
from core.proxy import Socks5Proxy

SERVICE_MAX_PACKETS = 2000                  # الباكتات بتتكتب على الديسك، فالذاكرة صغيرة
MAX_HEX_BYTES = 8192                        # قص الـ hex في الملف (الـ parse بيتعمل على الداتا الكاملة قبل القص)
DEFAULT_MAX_LIVE_BYTES = 150 * 1024 * 1024  # بعدها الملف بيتدوّر (live.jsonl → live.old.jsonl)


def load_config() -> config.ProxyConfig:
    """إعدادات الـ proxy من proxy_config.json (الافتراضي: observed preset)."""
    raw = appdata.read_json(appdata.CONFIG_FILE)
    cfg = config.proxy_config_from_dict(raw) if raw is not None else config.default_gui_config()
    cfg.max_packets = SERVICE_MAX_PACKETS
    return cfg


def load_manual_keys(keys: crypto.KeyManager) -> None:
    """KEY/IV اليدوي (اختياري) من keys.json."""
    data = appdata.read_json(appdata.KEYS_FILE) or {}
    try:
        key = bytes.fromhex(data["key"]) if data.get("key") else None
        iv = bytes.fromhex(data["iv"]) if data.get("iv") else None
    except (ValueError, TypeError):
        return
    if key or iv:
        keys.set_keys(key, iv)


class LiveWriter:
    """كاتب JSONL مع rotation بسيط."""

    def __init__(self, path: Path, max_bytes: int = DEFAULT_MAX_LIVE_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self._fh = self._open_new()  # session جديدة = ملف جديد (inode جديد) عشان القارئ يلاحظ
        self.count = 0

    def _open_new(self):  # type: ignore[no-untyped-def]
        """ملف جديد بـ inode جديد: بنكتب ملف مؤقت ونعمله replace (بدل truncate على نفس الملف)."""
        tmp = self.path.with_suffix(".tmp")
        open(tmp, "w", encoding="utf-8").close()
        os.replace(tmp, self.path)
        return open(self.path, "a", encoding="utf-8")

    def write(self, record: Dict[str, Any]) -> None:
        limit = MAX_HEX_BYTES * 2
        for key in ("raw_hex", "decrypted_hex"):
            value = record.get(key)
            if value and len(value) > limit:
                record[key] = value[:limit]
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()
        self.count += 1
        if self._fh.tell() > self.max_bytes:
            self._rotate()

    def _rotate(self) -> None:
        self._fh.close()
        os.replace(self.path, self.path.with_suffix(".old.jsonl"))
        self._fh = self._open_new()

    def close(self) -> None:
        self._fh.close()


class _StatusWriter:
    def __init__(self) -> None:
        self.info: Dict[str, Any] = {"running": False, "port": 0, "keys": "", "packets": 0,
                                     "msg": "", "error": ""}

    def write(self, **updates: Any) -> None:
        self.info.update(updates)
        self.info["ts"] = time.time()
        self.info["pid"] = os.getpid()
        try:
            appdata.write_json_atomic(appdata.STATUS_FILE, self.info)
        except OSError:
            pass


def run(stop_event: Optional[threading.Event] = None,
        max_live_bytes: int = DEFAULT_MAX_LIVE_BYTES) -> int:
    """يشغّل الـ proxy لحد ما ``stop_event`` يتفعّل (أو الـ process يتقتل). بيرجع exit code."""
    stop = stop_event or threading.Event()
    status = _StatusWriter()
    writer: Optional[LiveWriter] = None
    proxy: Optional[Socks5Proxy] = None
    try:
        config.ensure_dirs()
        crypto.setup_key_logger()
        keys = crypto.KeyManager()
        load_manual_keys(keys)
        proxy = Socks5Proxy(load_config(), keys=keys)
        writer = LiveWriter(appdata.data_dir() / appdata.LIVE_FILE, max_live_bytes)
        proxy.start()
    except (OSError, ValueError) as exc:  # بورت مشغول / إعدادات غلط / مشكلة ملفات
        status.write(running=False, error=str(exc))
        if writer:
            writer.close()
        return 1

    status.write(running=True, error="", port=proxy.bound_port, keys=keys.fingerprint(),
                 msg=f"Listening on {config.LISTEN_HOST}:{proxy.bound_port}")
    last_beat = 0.0
    try:
        while not stop.is_set():
            events = []
            try:
                events.append(proxy.events.get(timeout=0.25))   # بيستنى أول event
                while len(events) < 500:                         # وبعدين يسحب الباقي دفعة واحدة
                    events.append(proxy.events.get_nowait())
            except queue.Empty:
                pass
            for ev in events:
                if ev.kind == "packet":
                    writer.write(ev.payload.to_record())
                elif ev.kind == "error":
                    status.info["msg"] = str(ev.payload)
                elif ev.kind == "log" and "skipped" not in str(ev.payload):
                    status.info["msg"] = str(ev.payload)
                elif ev.kind == "keys":
                    status.info["msg"] = f"KEY/IV updated: {ev.payload}"
            now = time.time()
            if now - last_beat >= 1.0:
                last_beat = now
                status.write(running=True, keys=keys.fingerprint(), packets=writer.count)
    finally:
        proxy.stop()
        writer.close()
        status.write(running=False, packets=writer.count, msg="Stopped")
    return 0
