#!/usr/bin/env python3
"""Verify the private Go<->LumiCore ABI contract against live Rust source."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/apps/daemon/internal/native/bridge/lumicore_abi.h"
LEGACY_ACTIVE = [
    ROOT / "src/apps/daemon/internal/native/bridge/lumiffi.h",
    ROOT / "luminet_core.h",
    ROOT / "src/packages/lumicore/cbindgen.toml",
]
BRIDGE = ROOT / "src/apps/daemon/internal/native/bridge"
RUST = ROOT / "src/packages/lumicore/src"

C_TO_RUST = {
    "uint8_t": "u8",
    "uint16_t": "u16",
    "uint32_t": "u32",
    "uint64_t": "u64",
    "int32_t": "i32",
    "size_t": "usize",
}
EXPECTED_STRUCTS = {
    "FfiEnvelope": False,
    "FfiStatus": False,
    "StreamHandle": False,
}
EXPECTED_STREAM_EVENTS = {
    "LUMICORE_STREAM_EVT_PROBE_RESULT": ("STREAM_EVT_PROBE_RESULT", 1),
    "LUMICORE_STREAM_EVT_POOL_UPDATE": ("STREAM_EVT_POOL_UPDATE", 2),
    "LUMICORE_STREAM_EVT_SCAN_DONE": ("STREAM_EVT_SCAN_DONE", 3),
    "LUMICORE_STREAM_EVT_ERROR": ("STREAM_EVT_ERROR", 255),
}


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def c_structs(text: str) -> dict[str, tuple[list[tuple[str, str]], bool]]:
    clean = strip_c_comments(text)
    pack_ranges: list[tuple[int, int]] = []
    stack: list[int] = []
    for m in re.finditer(r"#pragma\s+pack\s*\(\s*(push\s*,\s*1|pop)\s*\)", clean):
        token = m.group(1)
        if token.startswith("push"):
            stack.append(m.end())
        elif stack:
            pack_ranges.append((stack.pop(), m.start()))
    out: dict[str, tuple[list[tuple[str, str]], bool]] = {}
    for m in re.finditer(r"typedef\s+struct\s*\{(?P<body>.*?)\}\s*(?P<name>[A-Za-z_]\w*)\s*;", clean, flags=re.S):
        fields: list[tuple[str, str]] = []
        for raw in m.group("body").split(";"):
            raw = " ".join(raw.split())
            if not raw:
                continue
            fm = re.fullmatch(r"(?P<type>[A-Za-z_]\w*)\s+(?P<name>[A-Za-z_]\w*)(?:\[(?P<n>\d+)\])?", raw)
            if not fm:
                raise ValueError(f"cannot parse C field {raw!r} in {m.group('name')}")
            ctype = fm.group("type")
            rust_type = C_TO_RUST.get(ctype)
            if rust_type is None:
                raise ValueError(f"unsupported C field type {ctype!r} in {m.group('name')}")
            if fm.group("n"):
                rust_type = f"[{rust_type}; {fm.group('n')}]"
            fields.append((fm.group("name"), rust_type))
        packed = any(start <= m.start() and m.end() <= end for start, end in pack_ranges)
        out[m.group("name")] = (fields, packed)
    return out


def rust_struct(text: str, name: str) -> tuple[list[tuple[str, str]], bool] | None:
    pattern = re.compile(
        r"#\[repr\((?P<repr>[^\]]+)\)\]\s*"
        r"(?:#\[[^\]]+\]\s*)*"
        r"pub\s+struct\s+" + re.escape(name) + r"\s*\{(?P<body>.*?)\}",
        flags=re.S,
    )
    m = pattern.search(text)
    if not m:
        return None
    body = re.sub(r"//.*", "", m.group("body"))
    fields: list[tuple[str, str]] = []
    for fm in re.finditer(r"pub\s+([A-Za-z_]\w*)\s*:\s*([^,]+),", body):
        fields.append((fm.group(1), " ".join(fm.group(2).split())))
    packed = "packed" in m.group("repr")
    return fields, packed


def main() -> int:
    errors: list[str] = []
    if not HEADER.is_file():
        errors.append(f"missing active private ABI header: {HEADER.relative_to(ROOT)}")
        header_text = ""
    else:
        header_text = HEADER.read_text(encoding="utf-8")

    for path in LEGACY_ACTIVE:
        if path.exists():
            errors.append(f"legacy/parallel ABI authority remains active: {path.relative_to(ROOT)}")

    if header_text:
        old_include = 'lumiffi.h'
        for path in sorted(BRIDGE.glob("*.go")):
            text = path.read_text(encoding="utf-8")
            if 'import "C"' not in text:
                continue
            if old_include in text:
                errors.append(f"{path.relative_to(ROOT)} still includes {old_include}")
            if "C.lumicore_" in text and '#include "lumicore_abi.h"' not in text:
                errors.append(f"{path.relative_to(ROOT)} calls LumiCore without including lumicore_abi.h")

        cm = re.search(r"#define\s+LUMICORE_ABI_VERSION\s+(\d+)", header_text)
        if not cm:
            errors.append("lumicore_abi.h does not define LUMICORE_ABI_VERSION")
        else:
            envelope = (RUST / "ffi/envelope.rs").read_text(encoding="utf-8")
            rm = re.search(r"pub\s+const\s+LUMICORE_ABI_VERSION\s*:\s*u16\s*=\s*(\d+)\s*;", envelope)
            if not rm or cm.group(1) != rm.group(1):
                errors.append(f"ABI version mismatch: C={cm.group(1)} Rust={rm.group(1) if rm else 'missing'}")

        rust_all = "\n".join(p.read_text(encoding="utf-8") for p in RUST.rglob("*.rs"))
        for c_name, (rust_name, expected_value) in EXPECTED_STREAM_EVENTS.items():
            cm = re.search(rf"\b{re.escape(c_name)}\s*=\s*(\d+)", header_text)
            rm = re.search(
                rf"pub\s+const\s+{re.escape(rust_name)}\s*:\s*u16\s*=\s*(\d+)\s*;",
                rust_all,
            )
            c_value = int(cm.group(1)) if cm else None
            r_value = int(rm.group(1)) if rm else None
            if c_value != expected_value or r_value != expected_value:
                errors.append(
                    f"stream event mismatch {c_name}/{rust_name}: "
                    f"C={c_value if c_value is not None else 'missing'} "
                    f"Rust={r_value if r_value is not None else 'missing'} expected={expected_value}"
                )

        try:
            cdefs = c_structs(header_text)
        except ValueError as exc:
            errors.append(str(exc))
            cdefs = {}
        for name, should_pack in EXPECTED_STRUCTS.items():
            cdef = cdefs.get(name)
            rdef = rust_struct(rust_all, name)
            if cdef is None:
                errors.append(f"C ABI missing struct {name}")
                continue
            if rdef is None:
                errors.append(f"Rust ABI missing #[repr(C)] struct {name}")
                continue
            cfields, cpacked = cdef
            rfields, rpacked = rdef
            if cfields != rfields:
                errors.append(f"{name} field/type mismatch: C={cfields} Rust={rfields}")
            if cpacked != should_pack or rpacked != should_pack:
                errors.append(
                    f"{name} packing mismatch: expected packed={should_pack} C={cpacked} Rust={rpacked}"
                )

        clean_header = strip_c_comments(header_text)
        rust_exports = set(
            re.findall(r"pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\b", rust_all)
        )
        go_calls: set[str] = set()
        for path in BRIDGE.glob("*.go"):
            go_calls.update(re.findall(r"C\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", path.read_text(encoding="utf-8")))
        go_used = go_calls & rust_exports
        declared = {name for name in rust_exports if re.search(rf"\b{re.escape(name)}\s*\(", clean_header)}
        if declared != go_used:
            missing = sorted(go_used - declared)
            unused = sorted(declared - go_used)
            if missing:
                errors.append(f"private header missing Go-used Rust exports: {', '.join(missing)}")
            if unused:
                errors.append(f"private header declares Rust exports unused by Go: {', '.join(unused)}")

        for path in sorted(BRIDGE.glob("*.go")):
            text = path.read_text(encoding="utf-8")
            if 'import "C"' not in text:
                continue
            preamble = text.split('import "C"', 1)[0]
            inline = sorted(name for name in rust_exports if re.search(rf"\b{re.escape(name)}\s*\(", preamble))
            if inline:
                errors.append(
                    f"{path.relative_to(ROOT)} redeclares Rust ABI symbols outside lumicore_abi.h: {', '.join(inline)}"
                )

    print(f"lumicore_abi errors={len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
