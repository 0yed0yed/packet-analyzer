"""Protobuf decoder بدون schema + أسماء الحقول من data/field_names.json.

مبنضيفش أي اسم حقل مش موجود في الملف: الحقل بيظهر برقمه بس.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config

log = logging.getLogger(__name__)
MAX_DEPTH = 10
# الـ message المتداخلة اللي فيها أرقام حقول ضخمة (زي 26750000) غالبًا بيانات packed اتفسّرت غلط
MAX_NESTED_FIELD = 2048


# ---------------------------------------------------------------- الـ parser
@dataclass
class ParseResult:
    """``fields`` = الحقول المفكوكة، و ``complete`` = كل البايتات اتفسّرت بلا أخطاء."""
    fields: Optional[Dict[int, Any]]
    complete: bool
    coverage: float = 0.0  # نسبة البايتات اللي اتفسّرت قبل أول خطأ


def read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """قراءة varint. بيرفع ValueError لو مقطوع."""
    result = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise ValueError("bad varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def _decode_bytes(chunk: bytes, depth: int) -> Any:
    """نص قابل للطباعة ← message متداخلة (strict) ← hex."""
    if not chunk:
        return ""
    try:
        text = chunk.decode("utf-8")
        if text.isprintable():
            return text
    except UnicodeDecodeError:
        pass
    nested, complete, _ = _parse(chunk, depth + 1, strict=True)
    if nested and complete and max(nested) <= MAX_NESTED_FIELD:
        return nested
    return "hex:" + chunk.hex()


def _add(out: Dict[int, Any], fld: int, value: Any) -> None:
    """الحقول المكررة بتتحول list (القيم نفسها عمرها ما تكون list)."""
    if fld not in out:
        out[fld] = value
    elif isinstance(out[fld], list):
        out[fld].append(value)
    else:
        out[fld] = [out[fld], value]


def _parse(data: bytes, depth: int, strict: bool) -> Tuple[Optional[Dict[int, Any]], bool, int]:
    if depth > MAX_DEPTH or not data:
        return None, False, 0
    out: Dict[int, Any] = {}
    pos, n = 0, len(data)
    try:
        while pos < n:
            tag, pos = read_varint(data, pos)
            fld, wtype = tag >> 3, tag & 7
            if fld == 0:
                raise ValueError("field 0")
            if wtype == 0:
                value, pos = read_varint(data, pos)
            elif wtype == 1:
                if pos + 8 > n:
                    raise ValueError("truncated")
                value, pos = int.from_bytes(data[pos:pos + 8], "little"), pos + 8
            elif wtype == 2:
                ln, pos = read_varint(data, pos)
                if pos + ln > n:
                    raise ValueError("truncated")
                value = _decode_bytes(data[pos:pos + ln], depth)
                pos += ln
            elif wtype == 5:
                if pos + 4 > n:
                    raise ValueError("truncated")
                value, pos = int.from_bytes(data[pos:pos + 4], "little"), pos + 4
            else:
                raise ValueError("unsupported wire type")
            _add(out, fld, value)
    except ValueError:
        # المستوى الأعلى متسامح (بيرجع اللي اتفك)، والمتداخل صارم
        return (None if strict else (out or None)), False, pos
    return (out or None), bool(out), pos


def parse_message(data: bytes) -> ParseResult:
    """فك ``data`` كـ protobuf بدون schema."""
    fields, complete, pos = _parse(data, 0, strict=False)
    return ParseResult(fields, complete, (pos / len(data)) if data else 0.0)


# ---------------------------------------------------------------- أسماء الحقول
@dataclass(frozen=True)
class FieldInfo:
    name: str
    type: str = ""


FieldNames = Dict[str, Dict[int, FieldInfo]]


def load_field_names(path: Path = config.FIELD_NAMES_FILE) -> FieldNames:
    """يقرأ {"prefix": {"field_num": {"name":..., "type":...}}}؛ ملف ناقص/غلط = {}."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        log.warning("field_names.json unreadable: %s", exc)
        return {}
    names: FieldNames = {}
    for prefix, fields in raw.items():
        if prefix.startswith("_") or not isinstance(fields, dict):
            continue
        for num, info in fields.items():
            if not (str(num).isdigit() and isinstance(info, dict) and info.get("name")):
                continue
            names.setdefault(prefix.upper(), {})[int(num)] = FieldInfo(
                str(info["name"]), str(info.get("type", "")))
    return names


# ---------------------------------------------------------------- شجرة العرض
@dataclass
class TreeNode:
    """عقدة جاهزة لعرضها في QTreeWidget أو كنص."""
    field: int
    name: Optional[str]
    declared_type: Optional[str]
    value: Any = None
    children: List["TreeNode"] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.field})" if self.name else f"field {self.field}"


def build_tree(parsed: Optional[Dict[int, Any]], prefix: str,
               names: Optional[FieldNames] = None) -> List[TreeNode]:
    """بيحوّل dict الـ parser لشجرة عقد، ويلصق الأسماء الموجودة في الملف فقط."""
    if not parsed:
        return []
    table = (names or {}).get(prefix.upper(), {})
    nodes: List[TreeNode] = []
    for fld, value in parsed.items():
        info = table.get(int(fld))
        values = value if isinstance(value, list) else [value]
        for v in values:
            node = TreeNode(int(fld), info.name if info else None,
                            (info.type or None) if info else None)
            if isinstance(v, dict):
                node.children = build_tree(v, prefix, names)
            else:
                node.value = v
            nodes.append(node)
    return nodes


def format_tree(nodes: List[TreeNode], indent: int = 0, max_str: int = 80) -> List[str]:
    """عرض نصي للشجرة (للـ CLI)."""
    pad = "  " * indent
    lines: List[str] = []
    for n in nodes:
        suffix = f" <{n.declared_type}>" if n.declared_type else ""
        if n.children:
            lines.append(f"{pad}{n.label}{suffix}:")
            lines.extend(format_tree(n.children, indent + 1, max_str))
        elif isinstance(n.value, str):
            shown = n.value if len(n.value) <= max_str else n.value[:max_str] + "…"
            lines.append(f'{pad}{n.label}{suffix}: "{shown}"')
        else:
            lines.append(f"{pad}{n.label}{suffix}: {n.value}")
    return lines
