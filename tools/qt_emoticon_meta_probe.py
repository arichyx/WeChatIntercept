"""Privacy-safe runtime probe for WeChat's Qt EmoticonDataStore service.

The command reports only class/method names, code offsets and object counts. It
does not print account data, message contents, resource hashes, URLs or keys.
"""
import struct

import lldb


SUPPORTED_CORE_UUID = "918FFBFD-E18D-363F-B07C-B8D7F1436727"


def emoticon_meta_probe(debugger, _command, result, _dictionary):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    target_class = _command.strip() or "mmui::EmoticonDataStore"

    def read(address, size):
        if not address or size <= 0:
            return None
        error = lldb.SBError()
        try:
            value = process.ReadMemory(address, size, error)
        except (OverflowError, ValueError):
            return None
        return value if error.Success() and len(value) == size else None

    def pointer(address):
        value = read(address, 8)
        return struct.unpack("<Q", value)[0] if value else 0

    module = None
    for candidate in target.module_iter():
        if candidate.file.fullpath.endswith("/Resources/wechat.dylib"):
            module = candidate
            break
    if not module:
        result.SetError("wechat core module not found")
        return
    if (module.GetUUIDString() or "").upper() != SUPPORTED_CORE_UUID:
        result.SetError("unsupported wechat core; expected " + SUPPORTED_CORE_UUID)
        return
    header = module.GetObjectFileHeaderAddress().GetLoadAddress(target)

    # Exact offsets for the UUID checked above (WeChat 4.1.13 arm64).
    text_start = header + 0x18000
    text_end = header + 0x6D93454
    ro_start = header + 0x72207B0
    ro_end = header + 0x93AB8DD
    data_const_start = header + 0x9698420
    data_const_end = header + 0x9B24B70
    data_start = header + 0x9B368C0
    data_end = header + 0x9D841D8
    bss_start = header + 0x9D85840
    bss_end = header + 0xA019AC0
    got_start = header + 0x9694000

    def in_module(value):
        return header <= value < header + 0xA048000

    def meta_string(strings, index):
        if not strings or index > 20000:
            return None
        entry = strings + index * 24
        raw = read(entry, 24)
        if not raw:
            return None
        size = struct.unpack_from("<i", raw, 4)[0]
        offset = struct.unpack_from("<q", raw, 16)[0]
        if size < 0 or size > 1024 or abs(offset) > 0x10000000:
            return None
        value = read(entry + offset, size)
        if value is None:
            return None
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def parse_meta(address):
        raw = read(address, 48)
        if not raw:
            return None
        superdata, strings, data, metacall, related, extra = struct.unpack("<6Q", raw)
        if not in_module(strings) or not in_module(data):
            return None
        if metacall and not text_start <= metacall < text_end:
            return None
        header_data = read(data, 56)
        if not header_data:
            return None
        values = struct.unpack("<14I", header_data)
        revision, class_index = values[:2]
        method_count, method_offset = values[4], values[5]
        if revision not in range(6, 20) or method_count > 512 or method_offset > 100000:
            return None
        name = meta_string(strings, class_index)
        if not name or len(name) > 255:
            return None
        return {
            "address": address,
            "super": superdata,
            "strings": strings,
            "data": data,
            "metacall": metacall,
            "revision": revision,
            "name": name,
            "method_count": method_count,
            "method_offset": method_offset,
            "signal_count": values[13],
        }

    matches = []
    for start, end in ((data_const_start, data_const_end), (data_start, data_end)):
        blob = read(start, end - start)
        if not blob:
            continue
        for offset in range(0, len(blob) - 48, 8):
            strings, data = struct.unpack_from("<QQ", blob, offset + 8)
            if not (in_module(strings) and in_module(data)):
                continue
            parsed = parse_meta(start + offset)
            if parsed and parsed["name"] == target_class:
                matches.append(parsed)

    if not matches:
        result.AppendMessage(
            "EMOTICON_META_PROBE class={} core_header=0x{:x} metaobjects=0".format(
                target_class, header
            )
        )
        return

    meta = matches[0]
    methods = []
    cursor = meta
    seen_meta = set()
    while cursor and cursor["address"] not in seen_meta:
        seen_meta.add(cursor["address"])
        table = read(cursor["data"] + cursor["method_offset"] * 4,
                     cursor["method_count"] * 20)
        if table:
            for index in range(cursor["method_count"]):
                name_index, argc, parameters, tag, flags = struct.unpack_from(
                    "<5I", table, index * 20
                )
                name = meta_string(cursor["strings"], name_index)
                if name:
                    methods.append((cursor["name"], index, name, argc, flags))
        cursor = parse_meta(cursor["super"]) if cursor["super"] else None

    # Find the small metaObject() virtual function whose ADRP+ADD resolves to
    # this static QMetaObject, then find vtables beginning with that function.
    code = read(text_start, text_end - text_start)
    meta_functions = set()
    if code:
        first_instruction = struct.pack("<I", 0xF9400400)
        offset = code.find(first_instruction)
        while offset >= 0:
            if offset + 28 > len(code):
                break
            if offset % 4:
                offset = code.find(first_instruction, offset + 1)
                continue
            words = struct.unpack_from("<7I", code, offset)
            if not (
                words[0] == 0xF9400400
                and words[1] == 0xF9401408
                and words[2] & 0xFF00001F == 0xB4000008
                and words[4] & 0x9F00001F == 0x90000000
                and words[5] & 0xFFC003FF == 0x91000000
                and words[6] == 0xD65F03C0
            ):
                offset = code.find(first_instruction, offset + 4)
                continue
            function = text_start + offset
            pages = ((words[4] >> 5) & 0x7FFFF) << 2 | ((words[4] >> 29) & 3)
            if pages & (1 << 20):
                pages -= 1 << 21
            resolved = ((function + 16) & ~4095) + pages * 4096
            resolved += (words[5] >> 10) & 4095
            if resolved == meta["address"]:
                meta_functions.add(function)
            offset = code.find(first_instruction, offset + 4)

    vtables = set()
    for start, end in ((data_const_start, data_const_end), (data_start, data_end)):
        blob = read(start, end - start)
        if not blob:
            continue
        for function in meta_functions:
            needle = struct.pack("<Q", function)
            position = blob.find(needle)
            while position >= 0:
                if position % 8 == 0:
                    vtables.add(start + position)
                position = blob.find(needle, position + 1)

    # Singletons are normally rooted from a global pointer. Search only the
    # module's writable globals rather than arbitrary process heap regions.
    instances = set()
    for start, end in ((data_start, data_end), (bss_start, bss_end)):
        blob = read(start, end - start)
        if not blob:
            continue
        for offset in range(0, len(blob) - 8, 8):
            candidate = struct.unpack_from("<Q", blob, offset)[0]
            if candidate < 0x100000000 or candidate >= 1 << 63:
                continue
            if pointer(candidate) in vtables:
                instances.add(candidate)

    result.AppendMessage(
        "EMOTICON_META_PROBE class={} core_header=0x{:x} metaobjects={} revision={} "
        "own_methods={} signals={} meta_functions={} vtables={} global_instances={} "
        "meta=0x{:x} meta_function_offsets={} vtable_offsets={} instance_addresses={}".format(
            target_class, header, len(matches), meta["revision"], meta["method_count"],
            meta["signal_count"], len(meta_functions), len(vtables), len(instances),
            meta["address"],
            ",".join("0x{:x}".format(value - header)
                     for value in sorted(meta_functions)) or "none",
            ",".join("0x{:x}".format(value - header)
                     for value in sorted(vtables)) or "none",
            ",".join("0x{:x}".format(value) for value in sorted(instances)) or "none",
        )
    )
    for vtable in sorted(vtables):
        references = []
        for start, end in ((got_start, data_const_start),
                           (data_const_start, data_const_end),
                           (data_start, data_end), (bss_start, bss_end)):
            blob = read(start, end - start)
            if not blob:
                continue
            wanted = {vtable, vtable - 8, vtable - 16, vtable - 24}
            for offset in range(0, len(blob) - 8, 8):
                if struct.unpack_from("<Q", blob, offset)[0] in wanted:
                    references.append(start + offset)
        entries = []
        for index in range(80):
            function = pointer(vtable + index * 8)
            if function and text_start <= function < text_end:
                entries.append("{}:0x{:x}".format(index, function - header))
        result.AppendMessage(
            "EMOTICON_META_PROBE class={} vtable=0x{:x} references={} entries={}".format(
                target_class, vtable - header,
                ",".join("0x{:x}".format(value - header)
                         for value in references) or "none",
                ",".join(entries) or "none"
            )
        )
    for owner, index, name, argc, flags in methods:
        result.AppendMessage(
            "EMOTICON_META_PROBE owner={} method_index={} name={} argc={} flags=0x{:x}".format(
                owner, index, name, argc, flags
            )
        )


def __lldb_init_module(debugger, _dictionary):
    debugger.HandleCommand(
        "command script add -f qt_emoticon_meta_probe.emoticon_meta_probe "
        "emoticon-meta-probe"
    )
