"""Read-only, one-event LLDB check; never print message bodies or identifiers."""
import struct
import xml.etree.ElementTree as ET
import lldb


def on_revoke(frame, _location, _dictionary):
    process = frame.GetThread().GetProcess()

    def read(address, size):
        error = lldb.SBError()
        result = process.ReadMemory(address, size, error)
        return result if error.Success() and len(result) == size else None

    def pointer(address):
        value = read(address, 8)
        return struct.unpack("<Q", value)[0] if value else 0

    def text(address):
        value = read(address, 24)
        if not value:
            return None
        if value[23] & 0x80:
            string_pointer, length, _ = struct.unpack("<QQQ", value)
            if length > 4095:
                return None
            value = read(string_pointer, length)
        else:
            length = value[23]
            if length > 22:
                return None
            value = value[:length]
        try:
            return value.decode("utf-8") if value is not None else None
        except UnicodeDecodeError:
            return None

    message = frame.FindRegister("x0").GetValueAsUnsigned()
    message_type = read(message + 12, 4)
    if not message_type or struct.unpack("<I", message_type)[0] != 0x2712:
        return False
    xml = text(message + 0x130)
    try:
        root = ET.fromstring(xml)
        identifier = int(root.findtext(".//newmsgid"))
        session = root.findtext(".//session")
    except (ET.ParseError, ValueError, TypeError):
        print("RECALL_PROBE: XML could not be decoded; no UI changes")
        return True

    visited = set()
    matches = []
    ids = 0

    def visit(obj, depth=0):
        nonlocal ids
        if not obj or obj in visited or len(visited) >= 5000 or depth > 30:
            return
        visited.add(obj)
        private = pointer(obj + 8)
        if pointer(private + 8) != obj:
            return
        function = pointer(pointer(obj))
        code = read(function, 28)
        class_name = None
        if code and not pointer(private + 40):
            words = struct.unpack("<7I", code)
            if words[0] == 0xF9400400 and words[1] == 0xF9401408:
                pages = ((words[4] >> 5) & 0x7FFFF) << 2 | ((words[4] >> 29) & 3)
                if pages & (1 << 20):
                    pages -= 1 << 21
                meta = ((function + 16) & ~4095) + pages * 4096 + ((words[5] >> 10) & 4095)
                strings, data = pointer(meta + 8), pointer(meta + 16)
                index_bytes = read(data + 4, 4)
                if index_bytes:
                    entry = strings + struct.unpack("<I", index_bytes)[0] * 24
                    size_bytes, offset_bytes = read(entry + 4, 4), read(entry + 16, 8)
                    if size_bytes and offset_bytes:
                        size = struct.unpack("<i", size_bytes)[0]
                        offset = struct.unpack("<q", offset_bytes)[0]
                        if 0 < size < 255:
                            value = read(entry + offset, size)
                            if value:
                                class_name = value.decode("utf-8", "replace")
        if class_name and class_name.startswith("mmui::Chat") and class_name.endswith("ItemView"):
            model = pointer(obj + 0x230)
            if model:
                original_id = pointer(model + 0x1B0)
                original_session = text(model + 0x160)
                if original_id:
                    ids += 1
                if original_id == identifier:
                    matches.append((class_name, original_session == session))
        children = pointer(private + 24)
        header = read(children, 16)
        if not header:
            return
        _, allocated, begin, end = struct.unpack("<4i", header)
        if begin < 0 or end < begin or end > allocated or end - begin > 2000:
            return
        for index in range(begin, end):
            visit(pointer(children + 16 + index * 8), depth + 1)

    visit(0x75140A5E00)
    print("RECALL_PROBE: inspected={} candidate_ids={} exact_id_matches={}".format(
        len(visited), ids, len(matches)))
    for class_name, session_matches in matches:
        print("RECALL_PROBE: {} session_matches={}".format(class_name, session_matches))
    return True
