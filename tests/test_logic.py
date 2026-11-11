"""اختبار منطق الخدمة + القارئ على الكمبيوتر (من غير Kivy ولا أندرويد).

    python tests/test_logic.py
"""
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["PACKET_ANALYZER_DATA"] = tempfile.mkdtemp(prefix="pa_test_")
os.environ["ANDROID_PRIVATE"] = os.environ["PACKET_ANALYZER_DATA"]  # يجرّب LOGS_DIR على أندرويد

import appdata  # noqa: E402
import config  # noqa: E402
import service_core  # noqa: E402
from live_reader import LiveReader  # noqa: E402


def check(label: str, ok: bool) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        raise SystemExit(1)


def socks_connect(proxy_port: int, target_port: int) -> socket.socket:
    c = socket.create_connection(("127.0.0.1", proxy_port))
    c.sendall(b"\x05\x01\x00")
    c.recv(2)
    c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", target_port))
    c.recv(10)
    return c


def wait_for(predicate, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


# ---- إعدادات من الواجهة: port=0 (أي بورت فاضي) + preset
cfg = config.default_gui_config()
cfg.port = 0
appdata.write_json_atomic(appdata.CONFIG_FILE, config.proxy_config_to_dict(cfg))
appdata.write_json_atomic(appdata.KEYS_FILE, {"key": "00" * 16, "iv": "11" * 16}, private=True)

stop = threading.Event()
t = threading.Thread(target=service_core.run, kwargs={"stop_event": stop, "max_live_bytes": 40_000}, daemon=True)
t.start()
check("service reports running + port", wait_for(lambda: appdata.read_status().get("running") and appdata.read_status().get("port")))
st = appdata.read_status()
port = st["port"]
check("status has keys fingerprint (no key values)", "K:" in st["keys"] and "00000000" not in st["keys"])

# ---- سيرفر وهمي بيبعت باكتات بشكل الـ observed preset
body = bytes([0x08, 0x96, 0x01, 0x12, 2]) + b"hi"
pkt = b"\x12" + len(body).to_bytes(4, "big") + body
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
sp = srv.getsockname()[1]


def serve():
    c, _ = srv.accept()
    c.recv(200)
    c.sendall(pkt[:4]); time.sleep(0.1)       # باكت مقسوم
    c.sendall(pkt[4:] + pkt)
    big = b"\x1d" + (30000).to_bytes(4, "big") + os.urandom(30000)   # باكت كبير (> MAX_HEX_BYTES)
    for i in range(0, len(big), 1288):
        c.sendall(big[i:i + 1288])
    time.sleep(0.5)
    c.close()


threading.Thread(target=serve, daemon=True).start()
cli = socks_connect(port, sp)
cli.sendall(b"\x7c\x15\x00\x00\x00\x04" + b"a" * 14)  # handshake
reader = LiveReader(appdata.data_dir() / appdata.LIVE_FILE)
got = []
check("reader receives packets", wait_for(lambda: (got.extend(reader.poll()) or len(got) >= 4)))
cli.close()
summary = [(p.direction, p.prefix, p.status, p.size) for p in got]
print("   ", summary)
check("split packet reassembled (2x 12B SERVER 1200)", sum(1 for p in got if p.prefix == "1200" and p.size == 12) == 2)
big_pkt = next((p for p in got if p.prefix == "1D00"), None)
check("big packet reassembled as one (30005B), hex truncated in file",
      big_pkt is not None and big_pkt.size == 30005 and len(big_pkt.raw_hex) == service_core.MAX_HEX_BYTES * 2)
check("handshake shown as-is", any(p.direction == "CLIENT" and p.prefix == "7C15" for p in got))

# ---- reader: سطر ناقص + تقصير الملف
p = appdata.data_dir() / "partial.jsonl"
r2 = LiveReader(p)
p.write_text('{"ts":"t","direction":"CLIENT","prefix":"0515","name":"X","confidence":"guess","size":1,"raw_hex":"00","decrypted_hex":null,"parsed":null,"status":"RAW"}\n{"ts"')
a = r2.poll(); check("partial line waits", len(a) == 1 and r2.poll() == [])
with open(p, "a") as fh:
    fh.write(':"u","direction":"SERVER","prefix":"1200","name":"X","confidence":"guess","size":2,"raw_hex":"00","decrypted_hex":null,"parsed":null,"status":"RAW"}\n')
b = r2.poll(); check("completed line delivered", len(b) == 1 and b[0].direction == "SERVER")
p.write_text("garbage\n")
check("garbage line skipped", r2.poll() == [])
line = '{"ts":"t","direction":"CLIENT","prefix":"0515","name":"X","confidence":"guess","size":1,"raw_hex":"00","decrypted_hex":null,"parsed":null,"status":"RAW"}\n'
# ملف جديد لاختبار القص والاستبدال (القارئ ملفه الأول كان فيه garbage)
p3 = appdata.data_dir() / "trunc.jsonl"
p3.write_text(line * 3)
r3 = LiveReader(p3)
check("3 lines read", len(r3.poll()) == 3)
p3.write_text(line)   # نفس الملف اتقصّ لحجم أصغر من الـ offset
check("same file truncated smaller -> re-read from start", len(r3.poll()) == 1)
new = appdata.data_dir() / "trunc.new"
new.write_text(line * 5)   # ملف جديد (inode جديد) أكبر من الـ offset القديم
os.replace(new, p3)
check("file replaced by a bigger new file -> all 5 read", len(r3.poll()) == 5)

# ---- rotation حقيقي: LiveWriter صغير الحد + قارئ يلاحظ الملف الجديد
rot_dir = Path(tempfile.mkdtemp(prefix="pa_rot_"))
w = service_core.LiveWriter(rot_dir / "live.jsonl", max_bytes=1500)
rr = LiveReader(rot_dir / "live.jsonl")
rec = {"ts": "t", "direction": "CLIENT", "prefix": "0515", "name": "X", "confidence": "guess", "size": 1,
       "raw_hex": "00" * 100, "decrypted_hex": None, "parsed": None, "status": "RAW"}
seen = 0
for _ in range(20):
    w.write(dict(rec))
    seen += len(rr.poll())
w.close()
check("rotation created live.old.jsonl", (rot_dir / "live.old.jsonl").exists())
check("reader kept up across rotations (>= 15 of 20 seen)", seen >= 15)
print("    seen", seen, "of 20 (records still in the rotated-out file at poll time can be missed)")

# ---- إيقاف
stop.set(); t.join(timeout=8)
check("service thread exited", not t.is_alive())
check("status says stopped", appdata.read_status().get("running") is False)
check("key log has no key values", "11" * 16 not in (config.LOGS_DIR / "key_extraction.log").read_text() if (config.LOGS_DIR / "key_extraction.log").exists() else True)

# ---- بورت مشغول → status error بدل crash
busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(1)
cfg.port = busy.getsockname()[1]
appdata.write_json_atomic(appdata.CONFIG_FILE, config.proxy_config_to_dict(cfg))
rc = service_core.run(stop_event=threading.Event())
check("busy port -> rc=1 and error in status", rc == 1 and appdata.read_status().get("error"))
print("ALL OK")
