"""مسارات وملفات التبادل بين واجهة Kivy وخدمة الـ proxy.

على أندرويد الخدمة (foreground service) بتشتغل في process منفصل عن الواجهة، فالتواصل بينهم
بيتم بملفات في مجلد التطبيق الخاص (ANDROID_PRIVATE):

    proxy_config.json  الواجهة → الخدمة (الإعدادات، بتتقرأ عند الـ Start)
    keys.json          الواجهة → الخدمة (KEY/IV يدوي، اختياري)
    live.jsonl         الخدمة → الواجهة (سطر JSON لكل باكت)
    status.json        الخدمة → الواجهة (حالة + heartbeat كل ثانية)

المجلد خاص بالتطبيق ومحدش تاني يقدر يقراه (من غير root).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

# لازم تتطابق مع buildozer.spec (package.domain / package.name / services)
PACKAGE_DOMAIN = "org.packetlab"
PACKAGE_NAME = "packetanalyzer"
SERVICE_NAME = "Proxy"

LIVE_FILE = "live.jsonl"
STATUS_FILE = "status.json"
CONFIG_FILE = "proxy_config.json"
KEYS_FILE = "keys.json"
LEGAL_MARKER = "legal_accepted"

STATUS_STALE_SECONDS = 5.0  # لو الـ heartbeat أقدم من كده الخدمة تعتبر واقفة


def data_dir() -> Path:
    """مجلد البيانات. ``PACKET_ANALYZER_DATA`` للاختبار على الكمبيوتر."""
    base = (os.environ.get("PACKET_ANALYZER_DATA") or os.environ.get("ANDROID_PRIVATE")
            or str(Path(__file__).resolve().parent / "appdata"))
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json_atomic(name: str, obj: Any, private: bool = False) -> None:
    """كتابة ذرّية (ملف مؤقت ثم replace) عشان القارئ ما يشوفش ملف نصف مكتوب."""
    path = data_dir() / name
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj), encoding="utf-8")
    if private:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
    os.replace(tmp, path)


def read_json(name: str, default: Optional[Any] = None) -> Any:
    try:
        return json.loads((data_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def read_status() -> Dict[str, Any]:
    """حالة الخدمة. ``running`` بتبقى False تلقائيًا لو الـ heartbeat قديم (الخدمة وقعت أو اتوقفت)."""
    status = read_json(STATUS_FILE, {}) or {}
    age = time.time() - float(status.get("ts", 0) or 0)
    status["age"] = age
    if age > STATUS_STALE_SECONDS:
        status["running"] = False
    return status
