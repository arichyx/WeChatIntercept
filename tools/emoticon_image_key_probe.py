"""LLDB diagnostic for WeChat 4's account-level media AES key.

Given one encrypted 16-byte block, scan readable non-executable regions for
16-byte lowercase-hex ASCII key candidates. Report candidates whose AES-128-ECB
result starts with an image/container signature; this is not full validation.
This diagnostic is separate from the production sticker-download AES decoder.
"""
import ctypes
import re

import lldb


# Test standalone 16-byte ASCII candidates. Requiring token boundaries avoids
# testing every 16-byte window inside MD5s, URLs and paths.
KEY_RUN = re.compile(rb"(?<![0-9A-Za-z])([0-9a-f]{16})(?![0-9A-Za-z])")
MAGICS = (
    b"GIF87a", b"GIF89a", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff",
    b"RIFF", b"wxgf", b"V1MMWX", b"V2MMWX",
)


def _common_crypto():
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    crypt = library.CCCrypt
    crypt.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    crypt.restype = ctypes.c_int32
    return crypt


def _decrypt_block(crypt, block, key):
    source = ctypes.create_string_buffer(block, len(block))
    key_buffer = ctypes.create_string_buffer(key, len(key))
    output = ctypes.create_string_buffer(32)
    moved = ctypes.c_size_t()
    status = crypt(
        1, 0, 2, key_buffer, 16, None, source, 16,
        output, len(output), ctypes.byref(moved),
    )
    return output.raw[:moved.value] if status == 0 else b""


def emoticon_image_key_probe(debugger, command, result, _dictionary):
    try:
        block = bytes.fromhex(command.strip())
    except ValueError:
        block = b""
    if len(block) != 16:
        result.SetError("usage: emoticon-image-key-probe <32 hex ciphertext bytes>")
        return

    crypt = _common_crypto()
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    def read(address, size):
        error = lldb.SBError()
        try:
            value = process.ReadMemory(address, size, error)
        except (OverflowError, ValueError):
            return None
        return value if error.Success() and len(value) == size else None

    tested = set()
    matches = []
    regions = process.GetMemoryRegions()
    chunk_size = 16 * 1024 * 1024
    for index in range(regions.GetSize()):
        region = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(index, region):
            continue
        if not region.IsReadable() or region.IsExecutable():
            continue
        start, end = region.GetRegionBase(), region.GetRegionEnd()
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
            for found in KEY_RUN.finditer(haystack):
                key = found.group(1)
                if key in tested:
                    continue
                tested.add(key)
                plain = _decrypt_block(crypt, block, key)
                if any(plain.startswith(magic) for magic in MAGICS):
                    matches.append((base + found.start(1), key, plain[:16]))
            overlap = blob[-15:]
            cursor += length

    result.AppendMessage(
        "EMOTICON_IMAGE_KEY_PROBE tested={} matches={}".format(
            len(tested), len(matches)
        )
    )
    for address, key, plain in matches:
        result.AppendMessage(
            "EMOTICON_IMAGE_KEY_PROBE address=0x{:x} key={} plain_head={}".format(
                address, key.decode("ascii"), plain.hex()
            )
        )


def __lldb_init_module(debugger, _dictionary):
    debugger.HandleCommand(
        "command script add -f emoticon_image_key_probe.emoticon_image_key_probe "
        "emoticon-image-key-probe"
    )
