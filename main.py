"""Packet Analyzer (Android/Kivy): واجهة بتعرض الباكتات اللي بتلتقطها خدمة الـ proxy.

⚠️ للأغراض التعليمية فقط: استخدمه على ترافيك حسابك على جهازك أنت. ممنوع الغش أو مخالفة شروط اللعبة.

التصميم: الخدمة (service.py → service_core.py) بتشتغل في process منفصل (foreground service) عشان
تفضل شغالة والتطبيق في الخلفية، وبتكتب الباكتات في live.jsonl. الواجهة دي بتقرأ الملف كل 0.5 ثانية.
الـ proxy بيسمع على 127.0.0.1 فقط، وأنت اللي بتوجّه ترافيك اللعبة له (بنفس طريقتك الحالية).
"""
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import ListProperty, NumericProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.recycleview.views import RecycleDataViewBehavior
from kivy.uix.textinput import TextInput
from kivy.utils import platform

import appdata
import config
import service_core
from core.packet_store import PacketStore, filter_packets, hex_dump, load_packet_types
from core.protobuf_parser import build_tree, format_tree, load_field_names
from live_reader import LiveReader

ROW_LIMIT = 1000          # آخر 1000 صف بس في القائمة (للأداء)
UI_STORE_LIMIT = 20000    # باكتات الواجهة في الذاكرة
POLL_SECONDS = 0.5
HEX_VIEW_BYTES = 4096     # حد العرض في التفاصيل (النسخ بياخد الكل)
MONO = "RobotoMono-Regular"

COLOR_CLIENT = (0.54, 0.71, 0.98, 1)   # #89b4fa
COLOR_SERVER = (0.65, 0.89, 0.63, 1)   # #a6e3a1
GREEN, RED, TEXT = "a6e3a1", "f38ba8", (0.80, 0.84, 0.96, 1)

KV = """
#:import dp kivy.metrics.dp

<PacketRow>:
    size_hint_y: None
    height: dp(34)
    halign: 'left'
    valign: 'middle'
    text_size: self.size
    padding_x: dp(8)
    font_name: 'RobotoMono-Regular'
    font_size: '12sp'
    background_normal: ''
    background_down: ''
    background_color: (0.19, 0.20, 0.27, 1) if self.idx % 2 else (0.15, 0.15, 0.22, 1)
    color: self.fg
    on_release: app.show_packet(self.idx)

BoxLayout:
    orientation: 'vertical'
    padding: dp(4)
    spacing: dp(4)

    BoxLayout:
        size_hint_y: None
        height: dp(48)
        spacing: dp(6)
        Label:
            id: status
            markup: True
            text: '[color=f38ba8]●[/color] Disconnected'
            halign: 'left'
            valign: 'middle'
            text_size: self.size
            shorten: True
        Button:
            id: start_btn
            text: 'Start'
            size_hint_x: None
            width: dp(84)
            on_release: app.toggle_service()
        Button:
            text: 'Settings'
            size_hint_x: None
            width: dp(84)
            on_release: app.open_settings()

    BoxLayout:
        size_hint_y: None
        height: dp(42)
        spacing: dp(4)
        TextInput:
            id: search
            hint_text: 'Search'
            multiline: False
            write_tab: False
            on_text: app.mark_dirty()
        Spinner:
            id: dir_spinner
            text: 'All'
            values: ['All', 'CLIENT', 'SERVER']
            size_hint_x: None
            width: dp(86)
            on_text: app.mark_dirty()
        ToggleButton:
            id: dec_only
            text: 'Dec'
            size_hint_x: None
            width: dp(50)
            on_state: app.mark_dirty()
        ToggleButton:
            id: autoscroll
            text: 'Auto'
            state: 'down'
            size_hint_x: None
            width: dp(56)
        Button:
            text: 'Clear'
            size_hint_x: None
            width: dp(60)
            on_release: app.clear()

    RecycleView:
        id: rv
        viewclass: 'PacketRow'
        RecycleBoxLayout:
            default_size: None, dp(34)
            default_size_hint: 1, None
            size_hint_y: None
            height: self.minimum_height
            orientation: 'vertical'

    Label:
        id: footer
        markup: True
        size_hint_y: None
        height: dp(40)
        font_size: '11sp'
        halign: 'left'
        valign: 'middle'
        text_size: self.size
        shorten: True
"""


class PacketRow(RecycleDataViewBehavior, Button):
    """صف واحد في القائمة. ``idx`` = ترتيبه في القائمة المعروضة، و``fg`` لون النص."""
    idx = NumericProperty(0)
    fg = ListProperty([0.8, 0.84, 0.96, 1])


def _bind_text_size(label):
    """بيخلّي Label يلفّ النص حسب عرضه."""
    label.bind(size=lambda w, s: setattr(w, "text_size", s))


class PacketAnalyzerApp(App):
    title = "Packet Analyzer"

    # ============================================================ دورة حياة التطبيق
    def build(self):
        Window.clearcolor = (0.117, 0.117, 0.18, 1)
        self.store = PacketStore(UI_STORE_LIMIT)
        self.reader = LiveReader(appdata.data_dir() / appdata.LIVE_FILE)
        self.reader.skip_to_end()  # مبنعرضش باكتات session قديمة غير لما المستخدم يعمل Start
        self.types = load_packet_types()
        self.names = load_field_names()
        self.cfg = self._load_cfg()
        self._rows = []
        self._dirty = True
        self._desktop_stop = None
        self._desktop_thread = None
        return Builder.load_string(KV)

    def on_start(self):
        if platform == "android":
            self._request_permissions()
        if not (appdata.data_dir() / appdata.LEGAL_MARKER).exists():
            self.show_legal()
        Clock.schedule_interval(self.tick, POLL_SECONDS)

    def on_pause(self):
        return True  # الخدمة بتفضل شغالة، والتطبيق ممكن يتوقف مؤقتًا

    # ============================================================ إعدادات
    @staticmethod
    def _load_cfg():
        raw = appdata.read_json(appdata.CONFIG_FILE)
        return config.proxy_config_from_dict(raw) if raw is not None else config.default_gui_config()

    def _request_permissions(self):
        try:  # إشعار الـ foreground service على أندرويد 13+
            from android.permissions import request_permissions
            request_permissions(["android.permission.POST_NOTIFICATIONS"])
        except Exception:
            pass

    # ============================================================ الخدمة
    def service_running(self):
        return bool(appdata.read_status().get("running"))

    def toggle_service(self):
        if self.service_running():
            self.stop_service()
        else:
            self.start_service()

    def start_service(self):
        appdata.write_json_atomic(appdata.CONFIG_FILE, config.proxy_config_to_dict(self.cfg))
        if platform == "android":
            from jnius import autoclass
            service_class = autoclass(
                f"{appdata.PACKAGE_DOMAIN}.{appdata.PACKAGE_NAME}.Service{appdata.SERVICE_NAME}")
            activity = autoclass("org.kivy.android.PythonActivity").mActivity
            service_class.start(activity, "")
        else:  # اختبار على الكمبيوتر: الخدمة في thread
            self._desktop_stop = threading.Event()
            self._desktop_thread = threading.Thread(
                target=service_core.run, kwargs={"stop_event": self._desktop_stop}, daemon=True)
            self._desktop_thread.start()
        self._message("Starting…")

    def stop_service(self):
        if platform == "android":
            from jnius import autoclass
            service_class = autoclass(
                f"{appdata.PACKAGE_DOMAIN}.{appdata.PACKAGE_NAME}.Service{appdata.SERVICE_NAME}")
            activity = autoclass("org.kivy.android.PythonActivity").mActivity
            service_class.stop(activity)
        elif self._desktop_stop is not None:
            self._desktop_stop.set()
        self._message("Stopping…")

    # ============================================================ تحديث دوري
    def tick(self, _dt):
        new = self.reader.poll()
        for pkt in new:
            self.store.add(pkt)
        self._update_status()
        if new or self._dirty:
            self._dirty = False
            self.refresh_rows()

    def mark_dirty(self):
        self._dirty = True

    def _message(self, text):
        self._last_msg = text

    def _update_status(self):
        ids = self.root.ids
        st = appdata.read_status()
        running = bool(st.get("running"))
        if running:
            ids.status.text = (f"[color={GREEN}]●[/color] Connected · {config.LISTEN_HOST}:{st.get('port')}")
        else:
            ids.status.text = f"[color={RED}]●[/color] Disconnected"
        ids.start_btn.text = "Stop" if running else "Start"
        error = st.get("error") or ""
        msg = error if (error and not running) else (st.get("msg") or getattr(self, "_last_msg", ""))
        color = RED if (error and not running) else "a6adc8"
        ids.footer.text = (f"Total {self.store.total:,} | Showing {len(self._rows):,} | "
                           f"{st.get('keys', '')}\n[color={color}]{msg}[/color]")

    # ============================================================ القائمة
    def refresh_rows(self):
        ids = self.root.ids
        direction = None if ids.dir_spinner.text == "All" else ids.dir_spinner.text
        rows = filter_packets(self.store.snapshot(), direction, None, ids.search.text,
                              ids.dec_only.state == "down")[-ROW_LIMIT:]
        self._rows = rows
        ids.rv.data = [self._row_data(i, p) for i, p in enumerate(rows)]
        if ids.autoscroll.state == "down":
            Clock.schedule_once(lambda _dt: setattr(ids.rv, "scroll_y", 0), 0)

    @staticmethod
    def _row_data(index, pkt):
        arrow = "C>" if pkt.direction == "CLIENT" else "S<"   # ASCII بدل الأسهم (خط Roboto Mono)
        name = (pkt.name + ("?" if pkt.confidence == "guess" else ""))[:9]
        text = f"{pkt.num:>5} {arrow} {pkt.prefix} {name:<9} {pkt.size:>6} {pkt.status[:5]}"
        return {"text": text, "idx": index,
                "fg": list(COLOR_CLIENT if pkt.direction == "CLIENT" else COLOR_SERVER)}

    def clear(self):
        self.store.clear()
        self._rows = []
        self.root.ids.rv.data = []
        self.reader.skip_to_end()
        self._message("Cleared")

    # ============================================================ تفاصيل الباكت
    def _tab_text(self, pkt, tab):
        if tab == "tree":
            lines = format_tree(build_tree(pkt.parsed, pkt.prefix, self.names))
            return "\n".join(lines) or "(nothing decoded)"
        if tab == "raw":
            return hex_dump(pkt.raw_hex, HEX_VIEW_BYTES)
        if tab == "dec":
            return (hex_dump(pkt.decrypted_hex, HEX_VIEW_BYTES) if pkt.decrypted_hex
                    else "(no decrypted payload: not encrypted, or KEY/IV are wrong)")
        return pkt.to_json(max_hex=2048)

    def _copy_text(self, pkt, tab):
        """الداتا الكاملة للنسخ (مش المقصوصة اللي في العرض)."""
        if tab == "tree":
            return "\n".join(format_tree(build_tree(pkt.parsed, pkt.prefix, self.names)))
        if tab == "raw":
            return pkt.raw_hex
        if tab == "dec":
            return pkt.decrypted_hex or ""
        return pkt.to_json()

    def show_packet(self, idx):
        if not 0 <= idx < len(self._rows):
            return
        pkt = self._rows[idx]
        header = Label(
            text=(f"#{pkt.num}  {pkt.ts.replace('T', ' ')}\n"
                  f"{pkt.direction}  prefix {pkt.prefix}  {pkt.name}{' (guess)' if pkt.confidence == 'guess' else ''}\n"
                  f"{pkt.size:,} bytes  {pkt.status}  c{pkt.conn} {pkt.peer}"),
            size_hint_y=None, height=dp(64), halign="left", valign="top", font_size="12sp")
        _bind_text_size(header)

        editor = TextInput(readonly=True, font_name=MONO, font_size="11sp",
                           background_color=(0.09, 0.09, 0.15, 1), foreground_color=TEXT)
        state = {"tab": "tree"}

        def switch(tab):
            state["tab"] = tab
            editor.text = self._tab_text(pkt, tab)
            editor.cursor = (0, 0)

        tabs = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(4))
        for tab, label in (("tree", "Tree"), ("raw", "Raw"), ("dec", "Dec"), ("json", "JSON")):
            btn = Button(text=label)
            btn.bind(on_release=lambda _b, t=tab: switch(t))
            tabs.add_widget(btn)

        actions = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
        copy_btn = Button(text="Copy tab")
        copy_btn.bind(on_release=lambda _b: Clipboard.copy(self._copy_text(pkt, state["tab"])))
        copy_json = Button(text="Copy JSON")
        copy_json.bind(on_release=lambda _b: Clipboard.copy(pkt.to_json()))
        close_btn = Button(text="Close")
        for b in (copy_btn, copy_json, close_btn):
            actions.add_widget(b)

        content = BoxLayout(orientation="vertical", spacing=dp(6), padding=dp(6))
        for w in (header, tabs, editor, actions):
            content.add_widget(w)
        popup = Popup(title=f"Packet #{pkt.num}", content=content, size_hint=(0.98, 0.96))
        close_btn.bind(on_release=popup.dismiss)
        switch("tree")
        popup.open()

    # ============================================================ الإعدادات
    def open_settings(self):
        cfg = self.cfg
        preset_on = cfg.reassembly.enabled

        def field(hint, text="", **kw):
            return TextInput(hint_text=hint, text=text, multiline=False, size_hint_y=None,
                             height=dp(40), write_tab=False, **kw)

        port = field("Port", str(cfg.port), input_filter="int")
        only = field("Only ports (e.g. 39699, 39801) — empty = all", ", ".join(map(str, cfg.only_ports)))
        skip = field("Skip ports (e.g. 443)", ", ".join(map(str, cfg.skip_ports)))
        key = field("KEY (32 hex chars, optional)", password=True)
        iv = field("IV (32 hex chars, optional)", password=True)
        preset = CheckBox(active=preset_on, size_hint_x=None, width=dp(40))
        preset_row = BoxLayout(size_hint_y=None, height=dp(40))
        preset_row.add_widget(preset)
        preset_row.add_widget(Label(text="Observed framing (client hdr 6 / server hdr 5)", halign="left",
                                    text_size=(dp(280), None)))
        note = Label(text="Changes apply the next time you press Start.\nKEY/IV are kept in the app's "
                          "private storage only.", size_hint_y=None, height=dp(48), font_size="11sp")
        _bind_text_size(note)
        result = Label(text="", size_hint_y=None, height=dp(28), font_size="12sp", color=(0.95, 0.55, 0.66, 1))

        content = BoxLayout(orientation="vertical", spacing=dp(6), padding=dp(8))
        for w in (Label(text="Listen: 127.0.0.1 (fixed)", size_hint_y=None, height=dp(24)),
                  port, only, skip, preset_row, key, iv, note, result):
            content.add_widget(w)
        buttons = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
        save_btn, cancel_btn = Button(text="Save"), Button(text="Cancel")
        buttons.add_widget(save_btn)
        buttons.add_widget(cancel_btn)
        content.add_widget(buttons)
        popup = Popup(title="Settings", content=content, size_hint=(0.96, 0.9))

        def save(_b):
            try:
                new = self._load_cfg()
                new.port = int(port.text or config.DEFAULT_PORT)
                if not 0 <= new.port <= 65535:
                    raise ValueError("Port must be 0..65535")
                new.only_ports = config.parse_ports(only.text)
                new.skip_ports = config.parse_ports(skip.text)
                if preset.active:
                    new.reassembly, new.server_reassembly = config.observed_preset()
                else:
                    new.reassembly, new.server_reassembly = config.ReassemblyConfig(enabled=False), None
                self._save_keys(key.text, iv.text)
            except ValueError as exc:
                result.text = str(exc)
                return
            self.cfg = new
            appdata.write_json_atomic(appdata.CONFIG_FILE, config.proxy_config_to_dict(new))
            self._message("Settings saved (apply on next Start)")
            popup.dismiss()

        save_btn.bind(on_release=save)
        cancel_btn.bind(on_release=popup.dismiss)
        popup.open()

    @staticmethod
    def _save_keys(key_text, iv_text):
        """بيكتب KEY/IV في ملف خاص بالتطبيق (لو اتدخلوا). بيرفع ValueError لو الـ hex غلط."""
        current = appdata.read_json(appdata.KEYS_FILE, {}) or {}
        for name, text in (("key", key_text), ("iv", iv_text)):
            text = text.replace(" ", "").strip()
            if not text:
                continue
            try:
                raw = bytes.fromhex(text)
            except ValueError:
                raise ValueError(f"{name.upper()} is not valid hex") from None
            if len(raw) != config.KEY_LENGTH:
                raise ValueError(f"{name.upper()} must be 32 hex characters (16 bytes)")
            current[name] = text
        if current:
            appdata.write_json_atomic(appdata.KEYS_FILE, current, private=True)

    # ============================================================ التحذير القانوني
    def show_legal(self):
        text = ("For educational and protocol-analysis purposes only.\n\n"
                "Use this tool only on your OWN account's traffic on your OWN device. Do not use it to "
                "cheat, to abuse other players' accounts, or to violate a game's terms of service.\n\n"
                "للأغراض التعليمية فقط: استخدم الأداة لتحليل ترافيك حسابك على جهازك أنت.\n\n"
                "The proxy listens on 127.0.0.1 only.")
        body = Label(text=text, halign="left", valign="top")
        _bind_text_size(body)
        agree = Button(text="I understand and agree", size_hint_y=None, height=dp(48))
        leave = Button(text="Exit", size_hint_y=None, height=dp(44))
        content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(10))
        for w in (body, agree, leave):
            content.add_widget(w)
        popup = Popup(title="Legal notice", content=content, size_hint=(0.94, 0.8), auto_dismiss=False)

        def accept(_b):
            (appdata.data_dir() / appdata.LEGAL_MARKER).write_text("1")  # بيظهر مرة واحدة بس
            popup.dismiss()

        agree.bind(on_release=accept)
        leave.bind(on_release=lambda _b: self.stop())
        popup.open()


if __name__ == "__main__":
    PacketAnalyzerApp().run()
