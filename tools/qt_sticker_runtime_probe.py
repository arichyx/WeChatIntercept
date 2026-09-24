"""Privacy-safe LLDB probe for visible WeChat 4.x sticker rows.

Reports only Qt class names and validation booleans. It never prints message
contents, account/session IDs, hashes, keys, or URLs.
"""
import struct
import urllib.parse
import xml.etree.ElementTree as ET
import re
from collections import Counter

import lldb


MESSAGE_INFO_OFFSET = 0x99F5260
SUPPORTED_CORE_UUID = "918FFBFD-E18D-363F-B07C-B8D7F1436727"


def _eval_unsigned(frame, expression):
    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC_plus_plus)
    value = frame.EvaluateExpression(expression, options)
    return value.GetValueAsUnsigned() if value.GetError().Success() else 0


def _url_allowed(raw):
    if not raw or len(raw) > 8192:
        return False
    if raw.startswith("//"):
        raw = "https:" + raw
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    roots = ("qq.com", "qpic.cn", "weixin.qq.com", "wechat.com")
    return (
        parsed.scheme.lower() in ("http", "https")
        and not parsed.username
        and not parsed.password
        and port in (None, 80, 443)
        and not host.endswith(".")
        and ":" not in host
        and any(host == root or host.endswith("." + root) for root in roots)
    )


def sticker_runtime_probe(debugger, _command, result, _dictionary):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetFrameAtIndex(0)

    def read(address, size):
        if not address:
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

    def cpp_string_alternate(address, limit=65535):
        value = read(address, 24)
        if not value:
            return None
        length = value[23]
        if length & 0x80:
            string_pointer, length, _capacity = struct.unpack("<QQQ", value)
            if (string_pointer < 0x1000 or string_pointer >= 1 << 63 or
                    not length or length > limit):
                return None
            value = read(string_pointer, length)
        else:
            if length > 22 or length > limit:
                return None
            value = value[:length]
        try:
            return value.decode("utf-8") if value is not None else None
        except UnicodeDecodeError:
            return None

    def cpp_string_default(address, limit=65535):
        value = read(address, 24)
        if not value:
            return None
        if value[0] & 1:
            _capacity, length, string_pointer = struct.unpack("<QQQ", value)
            if (string_pointer < 0x1000 or string_pointer >= 1 << 63 or
                    not length or length > limit):
                return None
            value = read(string_pointer, length)
        else:
            length = value[0] >> 1
            if not length or length > 22 or length > limit:
                return None
            value = value[1:1 + length]
        try:
            return value.decode("utf-8") if value is not None else None
        except UnicodeDecodeError:
            return None

    def meta_name(obj):
        private = pointer(obj + 8)
        if not private or pointer(private + 8) != obj or pointer(private + 40):
            return None
        function = pointer(pointer(obj))
        code = read(function, 28)
        if not code:
            return None
        words = struct.unpack("<7I", code)
        if not (
            words[0] == 0xF9400400
            and words[1] == 0xF9401408
            and words[2] & 0xFF00001F == 0xB4000008
            and words[4] & 0x9F00001F == 0x90000000
            and words[5] & 0xFFC003FF == 0x91000000
            and words[6] == 0xD65F03C0
        ):
            return None
        pages = ((words[4] >> 5) & 0x7FFFF) << 2 | ((words[4] >> 29) & 3)
        if pages & (1 << 20):
            pages -= 1 << 21
        meta = ((function + 16) & ~4095) + pages * 4096 + ((words[5] >> 10) & 4095)
        strings, data = pointer(meta + 8), pointer(meta + 16)
        index = read(data + 4, 4)
        if not index:
            return None
        entry = strings + struct.unpack("<I", index)[0] * 24
        size_value, offset_value = read(entry + 4, 4), read(entry + 16, 8)
        if not size_value or not offset_value:
            return None
        size = struct.unpack("<i", size_value)[0]
        offset = struct.unpack("<q", offset_value)[0]
        if size < 1 or size > 255:
            return None
        value = read(entry + offset, size)
        return value.decode("utf-8", "replace") if value else None

    def payload_state(content):
        if not content or len(content.encode("utf-8")) > 65535:
            return None
        lowered = content.lower()
        if "<!doctype" in lowered or "<!entity" in lowered:
            return None
        start = content.find("<msg")
        wrapped = False
        if start < 0:
            start = content.find("<emoji")
            wrapped = start >= 0
        if start < 0:
            return None
        xml = content[start:]
        if wrapped:
            xml = "<msg>" + xml + "</msg>"
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        emojis = list(root.findall("./emoji")) if root.tag == "msg" else []
        if len(emojis) != 1:
            return None
        attributes = {str(key).lower(): value for key, value in emojis[0].attrib.items()}
        md5 = attributes.get("md5", "")
        md5_ok = len(md5) == 32 and all(c in "0123456789abcdefABCDEF" for c in md5)
        plain = sum(
            _url_allowed(attributes.get(key))
            for key in ("cdnurl", "tpurl", "externurl", "url", "thumburl")
        )
        encrypted = _url_allowed(attributes.get("encrypturl"))
        aes = attributes.get("aeskey", "")
        aes_ok = len(aes) == 32 and all(c in "0123456789abcdefABCDEF" for c in aes)
        return md5_ok, plain, encrypted, aes_ok, md5_ok and (plain or (encrypted and aes_ok))

    wechat_header = 0
    for module in target.module_iter():
        if module.file.fullpath.endswith("/Resources/wechat.dylib"):
            if (module.GetUUIDString() or "").upper() != SUPPORTED_CORE_UUID:
                result.SetError("unsupported wechat core; expected " + SUPPORTED_CORE_UUID)
                return
            wechat_header = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
            break
    if not wechat_header:
        result.SetError("wechat core module not found")
        return
    table = wechat_header + MESSAGE_INFO_OFFSET

    window_count = _eval_unsigned(frame, "(NSUInteger)NSApp.windows.count")
    roots = []
    for index in range(min(window_count, 64)):
        expression = """(uintptr_t)({
            NSWindow *w = NSApp.windows[%d];
            NSView *h = w.contentView;
            uintptr_t r = 0;
            if ([h isKindOfClass:NSClassFromString(@\"QNSView\")] &&
                [h respondsToSelector:sel_getUid(\"platformWindow\")]) {
                uintptr_t p = (uintptr_t)((void *(*)(id, SEL))objc_msgSend)
                    (h, sel_getUid(\"platformWindow\"));
                uintptr_t s = *(uintptr_t *)(p + 24);
                if (s >= 16) r = *(uintptr_t *)(s - 16 + 48);
            }
            r;
        })""" % index
        root = _eval_unsigned(frame, expression)
        if root and root not in roots:
            roots.append(root)

    def qt_geometry(obj):
        private = pointer(obj + 8)
        flags_raw = read(private + 32, 4) if private else None
        data_pointer = pointer(obj + 40)
        raw = read(data_pointer, 36) if data_pointer else None
        if not flags_raw or not raw:
            return None
        flags = struct.unpack("<I", flags_raw)[0]
        words = struct.unpack("<9I", raw)
        if not (flags & 1) or not (words[2] & (1 << 15)) or words[4] & (1 << 18):
            return None
        x, y, right, bottom = (struct.unpack("<i", struct.pack("<I", value))[0]
                               for value in words[5:9])
        width, height = right - x + 1, bottom - y + 1
        if not (0 < width <= 16384 and 0 < height <= 16384):
            return None
        return x, y, width, height

    def qt_global_rect(obj):
        if not roots:
            return None
        root = roots[0]
        result = qt_geometry(obj)
        if not result:
            return None
        x, y, width, height = result
        parent = pointer(pointer(obj + 8) + 16)
        for _ in range(30):
            if not parent:
                return None
            if parent == root:
                return x, y, width, height
            parent_rect = qt_geometry(parent)
            if not parent_rect:
                return None
            x += parent_rect[0]
            y += parent_rect[1]
            parent = pointer(pointer(parent + 8) + 16)
        return None

    visited = set()
    rows = []
    chat_rows = 0
    validated_rows = 0
    decoded_content_rows = 0
    content_lengths = []
    string_layouts = []
    info_offsets = []
    validated_names = []
    xml_pointer_paths = []
    sticker_subtrees = []
    emoticon_views = []
    emoticon_rows = set()
    message_string_maps = []
    sticker_info_rows = []
    class_counts = Counter()
    chat_class_counts = Counter()
    model_paths = Counter()

    def image_magic(data):
        if not data:
            return None
        if data.startswith((b"GIF87a", b"GIF89a")):
            return "gif"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return "webp"
        if data.startswith(b"\xff\xd8\xff"):
            return "jpg"
        return None

    def inspect_sticker_subtree(root):
        queue = [(root, 0)]
        seen = set()
        classes = []
        buffers = []
        while queue and len(seen) < 256:
            obj, depth = queue.pop(0)
            if not obj or obj in seen or depth > 12:
                continue
            seen.add(obj)
            private = pointer(obj + 8)
            if not private or pointer(private + 8) != obj:
                continue
            name = meta_name(obj) or "<unknown>"
            if name not in classes:
                classes.append(name)
            body = read(obj, 0x800)
            if body:
                for offset in range(0, len(body) - 8, 8):
                    candidate = struct.unpack_from("<Q", body, offset)[0]
                    if candidate < 0x100000000 or candidate >= 1 << 63:
                        continue
                    prefix = read(candidate, 64)
                    kind = image_magic(prefix)
                    if kind:
                        buffers.append((name, "ptr+0x{:x}".format(offset), kind))
                        continue
                    # Qt 5 QByteArray: member -> QArrayData, payload at data + offset.
                    header = read(candidate, 24)
                    if not header:
                        continue
                    refcount, size, allocation, data_offset = struct.unpack("<iiQq", header)
                    if not (0 < size <= 20 * 1024 * 1024 and
                            0 <= allocation <= 64 * 1024 * 1024 and
                            16 <= data_offset <= 4096):
                        continue
                    kind = image_magic(read(candidate + data_offset, 64))
                    if kind:
                        buffers.append((
                            name,
                            "qbytearray+0x{:x}/size={}".format(offset, size),
                            kind,
                        ))
            children = pointer(private + 24)
            header = read(children, 16)
            if not header:
                continue
            _ref, allocated, begin, end = struct.unpack("<4i", header)
            if begin < 0 or end < begin or end > allocated or end - begin > 512:
                continue
            for child_index in range(begin, end):
                queue.append((pointer(children + 16 + child_index * 8), depth + 1))
        return classes, buffers

    def find_emoji_path(model):
        queue = [(model, "model", 0)]
        seen = set()
        while queue and len(seen) < 300:
            address, path, depth = queue.pop(0)
            if address in seen:
                continue
            seen.add(address)
            data = read(address, 4096)
            if not data:
                continue
            marker = data.find(b"<emoji")
            if marker >= 0:
                for expanded_size in (65535, 32768, 16384, 8192):
                    expanded = read(address, expanded_size)
                    if expanded:
                        data = expanded
                        marker = data.find(b"<emoji")
                        break
                start = data.rfind(b"<msg", 0, marker + 1)
                end = data.find(b"</msg>", marker)
                content = None
                if start >= 0 and end >= 0:
                    try:
                        content = data[start:end + 6].decode("utf-8")
                    except UnicodeDecodeError:
                        pass
                if content is None:
                    end = data.find(b"/>", marker)
                    close_length = 2
                    if end < 0:
                        end = data.find(b"</emoji>", marker)
                        close_length = 8
                    if end >= 0:
                        try:
                            fragment = data[marker:end + close_length].decode("utf-8")
                            content = "<msg>" + fragment + "</msg>"
                        except UnicodeDecodeError:
                            pass
                return ("{}+0x{:x}".format(path, marker), "utf8",
                        payload_state(content))
            marker = data.find(b"<\x00e\x00m\x00o\x00j\x00i\x00")
            if marker >= 0:
                start = data.rfind(b"<\x00m\x00s\x00g\x00", 0, marker + 1)
                end = data.find(b"<\x00/\x00m\x00s\x00g\x00>\x00", marker)
                content = None
                if start >= 0 and end >= 0:
                    try:
                        content = data[start:end + 12].decode("utf-16-le")
                    except UnicodeDecodeError:
                        pass
                return ("{}+0x{:x}".format(path, marker), "utf16",
                        payload_state(content))
            if depth >= 3:
                continue
            for offset in range(0, 0x800, 8):
                candidate = struct.unpack_from("<Q", data, offset)[0]
                if (candidate < 0x100000000 or candidate >= 1 << 63 or
                        candidate in seen or candidate & 7):
                    continue
                queue.append((candidate, "{}->0x{:x}".format(path, offset), depth + 1))
        return None
    emoji_content_rows = 0

    def string_kind(value):
        if value is None:
            return None
        encoded = value.encode("utf-8", "replace")
        if re.fullmatch(r"[0-9A-Fa-f]{32}", value):
            return "hex32/{}".format(len(encoded))
        if _url_allowed(value):
            return "allowed_url/{}".format(len(encoded))
        if "/" in value or "\\" in value:
            suffix = value.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            extension = suffix.rsplit(".", 1)[-1].lower() if "." in suffix else "none"
            return "path/len={}/ext={}".format(len(encoded), extension[:12])
        return "text/{}".format(len(encoded))

    def inspect_emoticon_view(obj):
        strings = []
        for offset in (0x258, 0x280):
            kind = string_kind(cpp_string_alternate(obj + offset, 65535))
            strings.append("+0x{:x}={}".format(offset, kind or "none"))
        related = []
        for owner_offset in (0x250, 0x270, 0x298):
            owner = pointer(obj + owner_offset)
            if not owner:
                related.append("+0x{:x}=null".format(owner_offset))
                continue
            found = []
            body = read(owner, 0x600)
            if body:
                for offset in range(0, 0x600 - 23, 8):
                    for layout, decoder in (("alt", cpp_string_alternate),
                                            ("def", cpp_string_default)):
                        kind = string_kind(decoder(owner + offset, 8192))
                        if kind and kind != "text/0":
                            found.append("0x{:x}:{}:{}".format(offset, layout, kind))
                            break
                    if len(found) >= 24:
                        break
            related.append("+0x{:x}=[{}]".format(
                owner_offset, ",".join(found) if found else "none"
            ))
        ancestors = []
        parent = pointer(pointer(obj + 8) + 16)
        for _ in range(12):
            if not parent:
                break
            parent_name = meta_name(parent) or "<unknown>"
            ancestors.append(parent_name)
            if (parent_name.startswith("mmui::Chat") and
                    parent_name.endswith("ItemView")):
                emoticon_rows.add(parent)
            parent = pointer(pointer(parent + 8) + 16)
        return strings, related, ancestors, qt_global_rect(obj)

    def inspect_message_graph(info):
        queue = [(info, "info", 0, 0x350)]
        seen = set()
        hits = []
        while queue and len(seen) < 220 and len(hits) < 64:
            address, path, depth, preferred_size = queue.pop(0)
            if address in seen:
                continue
            seen.add(address)
            data = None
            for size in (preferred_size, 4096, 2048, 1024, 512, 256, 128, 64):
                if size <= 0:
                    continue
                data = read(address, size)
                if data:
                    break
            if not data:
                continue
            for match in re.finditer(
                    rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])", data):
                hits.append("{}+0x{:x}=raw_hex32".format(path, match.start()))
            for match in re.finditer(rb"https?://[^\x00\s\"'<>]{1,2048}", data):
                try:
                    value = match.group(0).decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if _url_allowed(value):
                    hits.append("{}+0x{:x}=raw_allowed_url".format(
                        path, match.start()
                    ))
            for offset in range(0, max(0, len(data) - 23), 8):
                for layout, decoder in (("alt", cpp_string_alternate),
                                        ("def", cpp_string_default)):
                    kind = string_kind(decoder(address + offset, 8192))
                    if kind and (kind.startswith("hex32/") or
                                 kind.startswith("allowed_url/") or
                                 kind.startswith("path/")):
                        hits.append("{}+0x{:x}={}:{}".format(
                            path, offset, layout, kind
                        ))
                        break
            if depth >= 3:
                continue
            for offset in range(0, max(0, min(len(data), 0x800) - 7), 8):
                candidate = struct.unpack_from("<Q", data, offset)[0]
                if (candidate < 0x100000000 or candidate >= 1 << 63 or
                        candidate & 7 or candidate in seen or
                        wechat_header <= candidate < wechat_header + 0xA048000):
                    continue
                queue.append((candidate, "{}->0x{:x}".format(path, offset),
                              depth + 1, 4096))
        return hits

    def visit(obj, depth=0):
        nonlocal chat_rows, validated_rows, decoded_content_rows, emoji_content_rows
        if not obj or obj in visited or len(visited) >= 12000 or depth > 30:
            return
        visited.add(obj)
        private = pointer(obj + 8)
        if not private or pointer(private + 8) != obj:
            return
        name = meta_name(obj)
        if name:
            class_counts[name] += 1
        if name == "mmui::CommonEmoticonView" and len(emoticon_views) < 32:
            emoticon_views.append((obj,) + inspect_emoticon_view(obj))
        if name and name.startswith("mmui::Chat") and name.endswith("ItemView"):
            chat_rows += 1
            chat_class_counts[name] += 1
            if name == "mmui::ChatItemView" and len(sticker_subtrees) < 8:
                sticker_subtrees.append((name,) + inspect_sticker_subtree(obj))
            # Subclasses do not all keep the shared message model at the
            # ChatItemView base offset. Locate it structurally by looking for
            # the validated MessageInfo vtable in objects referenced by the
            # visible row. Only offsets are reported; no message data leaves
            # the process.
            object_data = read(obj, 0x500)
            if object_data:
                seen_candidates = set()
                for view_offset in range(0x20, 0x500, 8):
                    candidate = struct.unpack_from("<Q", object_data, view_offset)[0]
                    if (candidate < 0x100000000 or candidate >= 1 << 63 or
                            candidate & 7 or candidate in seen_candidates):
                        continue
                    seen_candidates.add(candidate)
                    candidate_data = read(candidate, 0x508)
                    if not candidate_data:
                        continue
                    needle = struct.pack("<Q", table)
                    for info_offset in range(0, 0x501, 8):
                        if candidate_data[info_offset:info_offset + 8] == needle:
                            model_paths[(name, view_offset, info_offset)] += 1
            model = pointer(obj + 0x230)
            if model:
                info_offset = next(
                    (offset for offset in range(0, 0x501, 8)
                     if pointer(model + offset) == table),
                    None,
                )
                if info_offset is None:
                    content = None
                else:
                    validated_rows += 1
                    info_offsets.append(info_offset)
                    validated_names.append(name)
                    known_strings = []
                    for field_offset in (0x248, 0x260, 0x278, 0x290, 0x2A8):
                        value = cpp_string_alternate(
                            model + info_offset + field_offset, 65535
                        )
                        known_strings.append("+0x{:x}={}".format(
                            field_offset, string_kind(value) or "none"
                        ))
                    type_candidates = []
                    info_data = read(model + info_offset, 0x350)
                    if info_data:
                        for candidate_offset in range(0, 0x350 - 3, 4):
                            value = struct.unpack_from("<I", info_data,
                                                       candidate_offset)[0]
                            if value in (1, 3, 34, 43, 47, 48, 49, 10000):
                                type_candidates.append("0x{:x}={}".format(
                                    candidate_offset, value
                                ))
                        if struct.unpack_from("<I", info_data, 8)[0] == 47:
                            sticker_info_rows.append((
                                model + info_offset, qt_global_rect(obj)
                            ))
                    message_string_maps.append((
                        obj, name, known_strings, type_candidates,
                        qt_global_rect(obj)
                    ))
                    content = None
                    payload_offset = None
                    payload_layout = None
                    for offset in range(8, 0x350 - 23, 8):
                        for layout, decoder in (
                                ("alternate", cpp_string_alternate),
                                ("default", cpp_string_default)):
                            candidate = decoder(model + info_offset + offset, 65535)
                            if candidate and "<emoji" in candidate:
                                content = candidate
                                payload_offset = offset
                                payload_layout = layout
                                break
                        if content:
                            break
                    if not content and len(xml_pointer_paths) < 32:
                        info_data = read(model + info_offset, 0x350)
                        if info_data:
                            direct_offset = info_data.find(b"<emoji")
                            if direct_offset >= 0:
                                xml_pointer_paths.append(
                                    (name, "info+0x{:x}".format(direct_offset),
                                     "inline-utf8")
                                )
                            direct_offset = info_data.find(
                                b"<\x00e\x00m\x00o\x00j\x00i\x00"
                            )
                            if direct_offset >= 0:
                                xml_pointer_paths.append(
                                    (name, "info+0x{:x}".format(direct_offset),
                                     "inline-utf16")
                                )
                        for pointer_offset in range(0, 0x800, 8):
                            candidate_pointer = pointer(model + pointer_offset)
                            if (candidate_pointer < 0x1000 or
                                    candidate_pointer >= 1 << 63):
                                continue
                            candidate_data = read(candidate_pointer, 2048)
                            if not candidate_data:
                                continue
                            encoding = None
                            if b"<emoji" in candidate_data:
                                encoding = "utf8"
                            elif b"<\x00e\x00m\x00o\x00j\x00i\x00" in candidate_data:
                                encoding = "utf16"
                            if encoding:
                                xml_pointer_paths.append(
                                    (name, "model+0x{:x}->data".format(pointer_offset),
                                     encoding)
                                )
                                break
                            for nested_offset in range(0, 0x300, 8):
                                nested_pointer = struct.unpack_from(
                                    "<Q", candidate_data, nested_offset
                                )[0]
                                if (nested_pointer < 0x1000 or
                                        nested_pointer >= 1 << 63):
                                    continue
                                nested_data = read(nested_pointer, 2048)
                                if not nested_data:
                                    continue
                                nested_encoding = None
                                if b"<emoji" in nested_data:
                                    nested_encoding = "utf8"
                                elif (b"<\x00e\x00m\x00o\x00j\x00i\x00"
                                      in nested_data):
                                    nested_encoding = "utf16"
                                if nested_encoding:
                                    xml_pointer_paths.append((
                                        name,
                                        "model+0x{:x}->+0x{:x}->data".format(
                                            pointer_offset, nested_offset
                                        ),
                                        nested_encoding,
                                    ))
                                    break
                            if xml_pointer_paths and xml_pointer_paths[-1][0] == name:
                                break
                    raw_string = read(model + info_offset + 8, 24)
                    if raw_string and len(string_layouts) < 16:
                        fields = struct.unpack("<QQQ", raw_string)
                        string_layouts.append((raw_string[23], fields[1]))
                if content is not None:
                    decoded_content_rows += 1
                    content_lengths.append(len(content))
                if content and "<emoji" in content:
                    emoji_content_rows += 1
                state = payload_state(content)
                if state:
                    rows.append((name, payload_offset, payload_layout, state))
                if len(xml_pointer_paths) < 32:
                    path = find_emoji_path(model)
                    if path:
                        xml_pointer_paths.append((name, path[0], path[1], path[2]))
                        if (name != "mmui::ChatItemView" and path[2] and
                                path[2][0] and len(sticker_subtrees) < 8):
                            sticker_subtrees.append((name,) + inspect_sticker_subtree(obj))
        children = pointer(private + 24)
        header = read(children, 16)
        if not header:
            return
        _ref, allocated, begin, end = struct.unpack("<4i", header)
        if begin < 0 or end < begin or end > allocated or end - begin > 2000:
            return
        for child_index in range(begin, end):
            visit(pointer(children + 16 + child_index * 8), depth + 1)

    for root in roots:
        visit(root)

    result.AppendMessage(
        "STICKER_RUNTIME_PROBE core_header=0x{:x} roots={} inspected={} chat_rows={} "
        "validated_rows={} decoded_content_rows={} content_length_range={} "
        "emoji_content_rows={} parsed_rows={}".format(
            wechat_header, len(roots), len(visited), chat_rows,
            validated_rows, decoded_content_rows,
            "{}-{}".format(min(content_lengths), max(content_lengths))
            if content_lengths else "none",
            emoji_content_rows, len(rows)
        )
    )
    result.AppendMessage(
        "STICKER_RUNTIME_PROBE classes={} info_offsets={} string_layouts={}".format(
            ",".join(validated_names) if validated_names else "none",
            ",".join("0x{:x}".format(offset) for offset in info_offsets)
            if info_offsets else "none",
            ",".join("{:02x}/{}".format(marker, length)
                     for marker, length in string_layouts)
            if string_layouts else "none"
        )
    )
    result.AppendMessage(
        "STICKER_RUNTIME_PROBE top_classes={}".format(
            ",".join("{}:{}".format(name, count)
                     for name, count in class_counts.most_common(40))
            if class_counts else "none"
        )
    )
    result.AppendMessage(
        "STICKER_RUNTIME_PROBE chat_classes={}".format(
            ",".join("{}:{}".format(name, count)
                     for name, count in chat_class_counts.most_common())
            if chat_class_counts else "none"
        )
    )
    result.AppendMessage(
        "STICKER_RUNTIME_PROBE model_paths={}".format(
            ",".join("{}:view+0x{:x}->info+0x{:x}:{}".format(
                name, view_offset, info_offset, count
            ) for (name, view_offset, info_offset), count in model_paths.most_common())
            if model_paths else "none"
        )
    )
    for entry in xml_pointer_paths:
        name, pointer_path, encoding = entry[:3]
        state = entry[3] if len(entry) > 3 else None
        detail = ""
        if state:
            md5_ok, plain, encrypted, aes_ok, _accepted = state
            detail = " md5={} plain_urls={} encrypted_url={} aes_key={}".format(
                "yes" if md5_ok else "no",
                plain,
                "yes" if encrypted else "no",
                "yes" if aes_ok else "no",
            )
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE class={} xml_path={} encoding={} "
            "xml_complete={} parser_accepted={}{}".format(
                name, pointer_path, encoding,
                "yes" if state else "no",
                "yes" if state and state[-1] else "no",
                detail,
            )
        )
    for name, payload_offset, payload_layout, state in rows:
        md5_ok, plain, encrypted, aes_ok, accepted = state
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE class={} payload_offset=0x{:x} layout={} md5={} "
            "plain_urls={} encrypted_url={} "
            "aes_key={} parser_accepted={}".format(
                name,
                payload_offset,
                payload_layout,
                "yes" if md5_ok else "no",
                plain,
                "yes" if encrypted else "no",
                "yes" if aes_ok else "no",
                "yes" if accepted else "no",
            )
        )
    for name, classes, buffers in sticker_subtrees:
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE target_class={} subtree_classes={}".format(
                name, ",".join(classes) if classes else "none"
            )
        )
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE target_class={} decoded_buffers={}".format(
                name,
                ",".join("{}:{}:{}".format(*entry) for entry in buffers)
                if buffers else "none",
            )
        )
    for _obj, strings, related, ancestors, rect in emoticon_views:
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE emoticon_view rect={} strings={} related={} ancestors={}".format(
                "{},{},{},{}".format(*rect) if rect else "none",
                ",".join(strings), ";".join(related),
                "->".join(ancestors) if ancestors else "none",
            )
        )
    for _obj, name, strings, type_candidates, rect in message_string_maps:
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE message_info class={} rect={} types={} strings={}".format(
                name, "{},{},{},{}".format(*rect) if rect else "none",
                ",".join(type_candidates) if type_candidates else "none",
                ",".join(strings)
            )
        )
    for row in sorted(emoticon_rows):
        model = pointer(row + 0x230)
        if not model or pointer(model + 0x120) != table:
            continue
        hits = inspect_message_graph(model + 0x120)
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE emoticon_message_graph hits={}".format(
                ",".join(hits) if hits else "none"
            )
        )
    for info, rect in sticker_info_rows:
        hits = inspect_message_graph(info)
        detail = []
        metadata_object = pointer(info + 0x218)
        payload_object = pointer(info + 0x238)
        md5_value = (cpp_string_alternate(metadata_object + 0x1B0, 64)
                     if metadata_object else None)
        detail.append("metadata_md5={}".format(
            "yes" if md5_value and re.fullmatch(r"[0-9A-Fa-f]{32}", md5_value)
            else "no"
        ))
        for field_offset in (0x130, 0x160, 0x430, 0x460, 0x508, 0x510):
            value = (cpp_string_alternate(payload_object + field_offset, 65535)
                     if payload_object else None)
            state = payload_state(value)
            detail.append("payload+0x{:x}=len:{}/emoji:{}/parsed:{}".format(
                field_offset,
                len(value.encode("utf-8")) if value is not None else -1,
                "yes" if value and "<emoji" in value else "no",
                "yes" if state else "no",
            ))
        result.AppendMessage(
            "STICKER_RUNTIME_PROBE sticker_message_graph rect={} detail={} hits={}".format(
                "{},{},{},{}".format(*rect) if rect else "none",
                ",".join(detail),
                ",".join(hits) if hits else "none"
            )
        )


def __lldb_init_module(debugger, _dictionary):
    debugger.HandleCommand(
        "command script add -f qt_sticker_runtime_probe.sticker_runtime_probe "
        "sticker-runtime-probe"
    )
