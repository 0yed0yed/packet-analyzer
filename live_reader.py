"""قراءة ملف live.jsonl بشكل incremental (tail) من جهة الواجهة."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional, Tuple

from core.packet_store import Packet

MAX_READ_BYTES = 4 * 1024 * 1024  # حد القراءة في الدورة الواحدة عشان الواجهة ما تتجمّدش


class LiveReader:
    """بتتابع ملف JSONL: كل ``poll()`` بترجع الباكتات الجديدة بس.

    - بتقرأ الأسطر الكاملة فقط (آخر سطر ناقص بيستنى الدورة الجاية).
    - لو الملف اتبدّل بملف جديد (inode مختلف: session جديدة أو rotation) أو اتقصّ، بترجع من الأول.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._offset = 0
        self._partial = b""
        self._ident: Optional[Tuple[int, int]] = None  # (device, inode) للملف اللي بنقراه

    def skip_to_end(self) -> None:
        try:
            st = os.stat(self.path)
            self._offset, self._ident = st.st_size, (st.st_dev, st.st_ino)
        except OSError:
            self._offset, self._ident = 0, None
        self._partial = b""

    def poll(self) -> List[Packet]:
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        size, ident = st.st_size, (st.st_dev, st.st_ino)
        if ident != self._ident:  # ملف جديد (بداية session أو rotation)
            if self._ident is not None:
                self._offset, self._partial = 0, b""
            self._ident = ident
        if size < self._offset:  # نفس الملف بس اتقصّ
            self._offset, self._partial = 0, b""
        if size == self._offset:
            return []
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read(MAX_READ_BYTES)
        except OSError:
            return []
        self._offset += len(chunk)
        lines = (self._partial + chunk).split(b"\n")
        self._partial = lines.pop()  # الجزء الأخير غير مكتمل (أو فاضي)
        packets: List[Packet] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                packets.append(Packet.from_record(json.loads(line)))
            except (ValueError, TypeError):
                continue  # سطر بايظ: نتخطاه
        return packets
