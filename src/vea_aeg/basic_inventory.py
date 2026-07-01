from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .exploit_builder_types import BinaryResourceInventory


PE_MACHINES = {
    0x014C: "i386",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "aarch64",
}

ELF_MACHINES = {
    0x03: "i386",
    0x3E: "x86_64",
    0x28: "arm",
    0xB7: "aarch64",
}


def read_c_string(data: bytes, offset: int, *, max_len: int = 4096) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("ascii", errors="ignore")


def extract_ascii_strings(data: bytes, *, min_length: int = 5, limit: int = 200) -> List[str]:
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode("ascii") + rb",}"
    strings = []
    for match in re.finditer(pattern, data):
        strings.append(match.group(0).decode("ascii", errors="ignore"))
        if len(strings) >= limit:
            break
    return strings


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _safe_slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or offset + size > len(data):
        return b""
    return data[offset : offset + size]


def _rva_to_offset(sections: Iterable[Dict[str, int | str]], rva: int) -> Optional[int]:
    for section in sections:
        vaddr = int(section.get("vaddr", 0))
        raw_size = int(section.get("raw_size", section.get("size", 0)))
        virtual_size = int(section.get("size", raw_size))
        raw_ptr = int(section.get("raw_ptr", 0))
        span = max(raw_size, virtual_size)
        if vaddr <= rva < vaddr + span:
            return raw_ptr + (rva - vaddr)
    return None


def inventory_pe(data: bytes, binary: str) -> BinaryResourceInventory:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe_offset = _u32(data, 0x3C)
    if _safe_slice(data, pe_offset, 4) != b"PE\x00\x00":
        raise ValueError("invalid PE signature")

    coff = pe_offset + 4
    machine = _u16(data, coff)
    number_of_sections = _u16(data, coff + 2)
    optional_header_size = _u16(data, coff + 16)
    optional = coff + 20
    magic = _u16(data, optional)
    is_pe32_plus = magic == 0x20B
    data_directory_base = optional + (112 if is_pe32_plus else 96)
    import_rva = _u32(data, data_directory_base + 8)

    section_base = optional + optional_header_size
    sections: Dict[str, Dict[str, int | str]] = {}
    section_list: List[Dict[str, int | str]] = []
    for idx in range(number_of_sections):
        offset = section_base + idx * 40
        if offset + 40 > len(data):
            break
        raw_name = _safe_slice(data, offset, 8).split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", errors="ignore") or f"section_{idx}"
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_ptr = _u32(data, offset + 20)
        item = {
            "vaddr": virtual_address,
            "size": virtual_size,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
            "perm": "pe-section",
        }
        sections[name] = item
        section_list.append(item)

    imports: List[str] = []
    import_offset = _rva_to_offset(section_list, import_rva) if import_rva else None
    if import_offset is not None:
        descriptor = import_offset
        for _ in range(512):
            if descriptor + 20 > len(data):
                break
            original_first_thunk = _u32(data, descriptor)
            name_rva = _u32(data, descriptor + 12)
            first_thunk = _u32(data, descriptor + 16)
            if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll_offset = _rva_to_offset(section_list, name_rva)
            dll_name = read_c_string(data, dll_offset or -1) or "unknown.dll"
            thunk_rva = original_first_thunk or first_thunk
            thunk_offset = _rva_to_offset(section_list, thunk_rva)
            if thunk_offset is not None:
                thunk_size = 8 if is_pe32_plus else 4
                for idx in range(2048):
                    entry_offset = thunk_offset + idx * thunk_size
                    if entry_offset + thunk_size > len(data):
                        break
                    thunk_value = _u64(data, entry_offset) if is_pe32_plus else _u32(data, entry_offset)
                    if thunk_value == 0:
                        break
                    ordinal_mask = 1 << (63 if is_pe32_plus else 31)
                    if thunk_value & ordinal_mask:
                        imports.append(f"{dll_name}!ordinal_{thunk_value & 0xFFFF}")
                        continue
                    hint_name_offset = _rva_to_offset(section_list, int(thunk_value))
                    func_name = read_c_string(data, (hint_name_offset or 0) + 2)
                    if func_name:
                        imports.append(f"{dll_name}!{func_name}")
            descriptor += 20

    strings = extract_ascii_strings(data)
    return BinaryResourceInventory(
        binary=binary,
        format="PE",
        arch=PE_MACHINES.get(machine, f"machine_0x{machine:x}"),
        imports=sorted(set(imports)),
        strings=strings,
        sections=sections,
        has_libc_dependency=any("libc" in item.lower() for item in imports),
        has_syscall_text=any("syscall" in item.lower() for item in imports + strings),
        backend="basic",
    )


def inventory_elf(data: bytes, binary: str) -> BinaryResourceInventory:
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    endian = data[5]
    if endian != 1:
        raise ValueError("only little-endian ELF is supported by basic inventory")
    machine = _u16(data, 18)
    return BinaryResourceInventory(
        binary=binary,
        format="ELF",
        arch=ELF_MACHINES.get(machine, f"machine_0x{machine:x}"),
        strings=extract_ascii_strings(data),
        sections={},
        backend="basic",
        notes=[
            f"ELF{64 if elf_class == 2 else 32} detected",
            "basic backend does not replace angr/radare2 for real ELF reproduction",
        ],
    )


def inventory_binary_basic(binary_path: str | Path) -> BinaryResourceInventory:
    path = Path(binary_path)
    data = path.read_bytes()
    binary = str(path)
    if data[:2] == b"MZ":
        return inventory_pe(data, binary)
    if data[:4] == b"\x7fELF":
        return inventory_elf(data, binary)
    return BinaryResourceInventory(
        binary=binary,
        format="unknown",
        arch="unknown",
        strings=extract_ascii_strings(data),
        backend="basic",
        notes=["unknown binary format; extracted ASCII strings only"],
    )

