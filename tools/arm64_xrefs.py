#!/usr/bin/env python3
"""Find direct arm64 ADRP+ADD/LDR references in a thin Mach-O image."""
import argparse
import struct


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("targets", nargs="+", type=lambda value: int(value, 0))
    parser.add_argument("--text-start", type=lambda value: int(value, 0), default=0x18000)
    parser.add_argument("--text-end", type=lambda value: int(value, 0), default=0x6D93454)
    parser.add_argument("--target-page", action="store_true",
                        help="match any address on the target 4 KiB page")
    parser.add_argument("--branches", action="store_true",
                        help="find direct BL references to the targets")
    args = parser.parse_args()
    with open(args.image, "rb") as handle:
        image = handle.read()
    if not (0 <= args.text_start < args.text_end <= len(image)):
        parser.error("text range must be non-empty and contained in the image")
    if args.text_start % 4 or args.text_end % 4:
        parser.error("text range must be aligned to 4-byte arm64 instructions")
    targets = set(args.targets)
    target_pages = {value & ~0xFFF for value in targets}
    text = image[args.text_start:args.text_end]
    for offset in range(0, len(text), 4):
        instruction = struct.unpack_from("<I", text, offset)[0]
        pc = args.text_start + offset
        if args.branches and instruction & 0xFC000000 == 0x94000000:
            immediate = sign_extend(instruction & 0x03FFFFFF, 26) << 2
            address = pc + immediate
            if address in targets:
                print("target=0x{:x} bl=0x{:x}".format(address, pc))
        if args.branches:
            continue
        if instruction & 0x9F000000 != 0x90000000:
            continue
        register = instruction & 31
        immediate = ((instruction >> 5) & 0x7FFFF) << 2 | ((instruction >> 29) & 3)
        page = (pc & ~0xFFF) + sign_extend(immediate, 21) * 4096
        if page not in target_pages:
            continue
        for step in range(1, 17):
            if offset + step * 4 + 4 > len(text):
                break
            candidate = struct.unpack_from("<I", text, offset + step * 4)[0]
            destination = candidate & 31
            source = (candidate >> 5) & 31
            if candidate & 0xFF000000 == 0x91000000:
                if destination != register or source != register:
                    continue
                immediate12 = (candidate >> 10) & 0xFFF
                if candidate & (1 << 22):
                    immediate12 <<= 12
                address = page + immediate12
                kind = "add"
            elif candidate & 0xFFC00000 == 0xF9400000:
                if source != register:
                    continue
                address = page + ((candidate >> 10) & 0xFFF) * 8
                kind = "ldr"
            else:
                continue
            if address in targets or (args.target_page and (address & ~0xFFF) in target_pages):
                print("target=0x{:x} adrp=0x{:x} {}=0x{:x} register=x{} result=x{}".format(
                    address, pc, kind, pc + step * 4, register, destination
                ))


if __name__ == "__main__":
    main()
