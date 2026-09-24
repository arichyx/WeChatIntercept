"""LLDB diagnostic: locate one emoticon MD5 and nearby metadata in WeChat.

The command prints only the requested hash, hexadecimal candidates and Tencent
resource URLs. It deliberately excludes arbitrary surrounding strings.
"""
import re
import struct

import lldb


HEX32 = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
TENCENT_URL = re.compile(
    rb"https?://[^\x00\s\"'<>]{1,2048}", re.IGNORECASE
)
ALLOWED_SUFFIXES = (b"qq.com", b"qpic.cn", b"weixin.qq.com", b"wechat.com")


def _allowed_url(value):
    lowered = value.lower()
    try:
        authority = lowered.split(b"://", 1)[1].split(b"/", 1)[0]
    except IndexError:
        return False
    authority = authority.rsplit(b"@", 1)[-1].split(b":", 1)[0].rstrip(b".")
    return any(authority == root or authority.endswith(b"." + root)
               for root in ALLOWED_SUFFIXES)


def emoticon_md5_probe(debugger, command, result, _dictionary):
    requested = command.strip().lower().encode("ascii", "ignore")
    if not re.fullmatch(rb"[0-9a-f]{32}", requested):
        result.SetError("usage: emoticon-md5-probe <32 lowercase hex md5>")
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    def read(address, size):
        if not address or size <= 0:
            return None
        error = lldb.SBError()
        try:
            value = process.ReadMemory(address, size, error)
        except (OverflowError, ValueError):
            return None
        return value if error.Success() and len(value) == size else None

    regions = process.GetMemoryRegions()
    matches = []
    chunk_size = 16 * 1024 * 1024
    for index in range(regions.GetSize()):
        region = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(index, region):
            continue
        if not region.IsReadable() or region.IsExecutable():
            continue
        start = region.GetRegionBase()
        end = region.GetRegionEnd()
        if end <= start or end - start > 2 * 1024 * 1024 * 1024:
            continue
        cursor = start
        overlap = b""
        while cursor < end:
            length = min(chunk_size, end - cursor)
            blob = read(cursor, length)
            if not blob:
                break
            haystack = overlap + blob
            base = cursor - len(overlap)
            position = haystack.lower().find(requested)
            while position >= 0:
                address = base + position
                if address not in matches:
                    matches.append(address)
                position = haystack.lower().find(requested, position + 1)
            overlap = blob[-31:]
            cursor += length
            if len(matches) >= 64:
                break
        if len(matches) >= 64:
            break

    result.AppendMessage(
        "EMOTICON_MD5_PROBE md5={} matches={}".format(
            requested.decode(), len(matches)
        )
    )
    for address in matches[:64]:
        candidates = set()
        urls = set()
        for center in (address,):
            start = max(0x1000, center - 8192)
            blob = read(start, 16384)
            if blob:
                candidates.update(item.decode().lower() for item in HEX32.findall(blob))
                urls.update(item.decode("utf-8", "replace")
                            for item in TENCENT_URL.findall(blob)
                            if _allowed_url(item))

        # Metadata is often stored in separate std::string/QByteArray buffers.
        # Follow only aligned pointers located near the exact MD5 occurrence.
        pointer_area = read(max(0x1000, address - 1024), 2048)
        if pointer_area:
            for offset in range(0, len(pointer_area) - 8, 8):
                pointer = struct.unpack_from("<Q", pointer_area, offset)[0]
                if pointer < 0x100000000 or pointer >= (1 << 63):
                    continue
                pointed = read(pointer, 8192)
                if not pointed:
                    continue
                candidates.update(item.decode().lower() for item in HEX32.findall(pointed))
                urls.update(item.decode("utf-8", "replace")
                            for item in TENCENT_URL.findall(pointed)
                            if _allowed_url(item))
        result.AppendMessage(
            "EMOTICON_MD5_PROBE address=0x{:x} hex32={} urls={}".format(
                address,
                ",".join(sorted(candidates)) or "none",
                " | ".join(sorted(urls)) or "none",
            )
        )


def __lldb_init_module(debugger, _dictionary):
    debugger.HandleCommand(
        "command script add -f emoticon_md5_probe.emoticon_md5_probe "
        "emoticon-md5-probe"
    )
