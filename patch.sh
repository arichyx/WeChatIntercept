#!/bin/bash
# 微信防撤回一键安装脚本
# 适用：微信 4.1.x (Apple Silicon + Intel)
# 依赖：clang / codesign / python3 (macOS 自带)
# 用法：./patch.sh [--install|--monitor-install|--uninstall|--debug|--help]
# 详细原理 / 版本适配指南见 doc/reverse-engineering-guide.md

set -e
set -E
set -o pipefail

WECHAT_APP="/Applications/WeChat.app"
WECHAT_BIN="$WECHAT_APP/Contents/MacOS/WeChat"
DYLIB_DST="$WECHAT_APP/Contents/Resources/WeChatAntiRevoke.dylib"
DYLIB_INSTALL_NAME="@executable_path/../Resources/WeChatAntiRevoke.dylib"
STATE_DIR="$HOME/Library/Application Support/WeChatIntercept"
ORIGINAL_APP="$STATE_DIR/WeChat.original.app"
ORIGINAL_BIN="$STATE_DIR/WeChat.original"
ORIGINAL_VERSION_FILE="$STATE_DIR/WeChat.original.version"
HOOK_LOG="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Library/Logs/WeChatIntercept/hook.log"
INSTALL_SWAPPED=0
INSTALL_PREVIOUS_APP=""
INSTALL_LIVE_APP="$WECHAT_APP"

print_banner() {
    echo ""
    echo "=============================="
    echo " 微信防撤回安装工具"
    echo " 适用: macOS / 微信 4.1.9+"
    echo " 支持: Apple Silicon + Intel"
    echo "=============================="
    echo ""
}

check_environment() {
    if [ ! -d "$WECHAT_APP" ]; then
        echo "[ERROR] 未找到微信: $WECHAT_APP"
        exit 1
    fi

    SHORT_VER=$(defaults read "$WECHAT_APP/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
    VERSION=$(defaults read "$WECHAT_APP/Contents/Info.plist" CFBundleVersion 2>/dev/null)

    if [ -z "$SHORT_VER" ]; then
        echo "[ERROR] 无法读取微信版本号，请检查 /Applications/WeChat.app 是否完整"
        exit 1
    fi

    # 大版本校验：仅支持 4.1.x 系列（C++ 架构）
    case "$SHORT_VER" in
        4.1.*)
            echo "[INFO] 微信版本: $SHORT_VER ($VERSION)"
            ;;
        *)
            echo "[ERROR] 不支持的微信大版本: $SHORT_VER"
            echo "        本工具仅支持 4.1.x 系列"
            echo "        旧版 3.x 请使用 Install.sh"
            echo "        如果你认为这是误判，请提交 issue"
            exit 1
            ;;
    esac

    if ! command -v clang &>/dev/null; then
        echo "[ERROR] 未找到 clang，请安装 Xcode Command Line Tools:"
        echo "        xcode-select --install"
        exit 1
    fi
}

kill_wechat() {
    if pgrep -x WeChat >/dev/null 2>&1; then
        echo "[INFO] 关闭微信..."
        killall WeChat 2>/dev/null || true
        sleep 2
        if pgrep -x WeChat >/dev/null 2>&1; then
            echo "[WARN] 微信未响应，强制结束残留进程..."
            killall -KILL WeChat 2>/dev/null || true
            sleep 1
        fi
    fi
}

has_injected_load_command() {
    otool -l "$WECHAT_BIN" 2>/dev/null | grep -F "WeChatAntiRevoke" >/dev/null
}

# patch.sh 的动态库注入只增加了一个 LC_LOAD_DYLIB。删除 dylib 文件本身
# 是不够的，必须同步删除这个命令，否则 dyld 会在启动阶段报 Library missing。
remove_injected_load_command() {
    if [ ! -f "$WECHAT_BIN" ]; then
        return 0
    fi

    if ! has_injected_load_command; then
        echo "[INFO] 主程序没有 WeChatAntiRevoke 注入"
        return 0
    fi

    echo "[INFO] 移除主程序中的 WeChatAntiRevoke 加载命令..."
    python3 - "$WECHAT_BIN" <<'REMOVE_INJECTED_LOAD_COMMAND'
import struct
import sys

path = sys.argv[1]
TARGET = b"@executable_path/../Resources/WeChatAntiRevoke.dylib"
FAT_MAGIC = 0xCAFEBABE
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
LC_LOAD_DYLIB = 0xC

def read_u32(f, offset):
    f.seek(offset)
    raw = f.read(4)
    if len(raw) != 4:
        raise RuntimeError("读取 Mach-O 头失败")
    return struct.unpack("<I", raw)[0]

with open(path, "r+b") as f:
    f.seek(0)
    magic = struct.unpack(">I", f.read(4))[0]
    if magic == FAT_MAGIC:
        narch = struct.unpack(">I", f.read(4))[0]
        slices = []
        for _ in range(narch):
            raw = f.read(20)
            if len(raw) != 20:
                raise RuntimeError("读取 Universal Mach-O 架构表失败")
            _cpu, _sub, offset, size, _align = struct.unpack(">IIIII", raw)
            slices.append((offset, size))
    elif magic in (MH_MAGIC, MH_MAGIC_64):
        f.seek(0, 2)
        slices = [(0, f.tell())]
    else:
        raise RuntimeError("不是支持的 Mach-O 文件")

    targets = []
    for slice_offset, _slice_size in slices:
        f.seek(slice_offset)
        slice_magic = f.read(4)
        if slice_magic == b"\xcf\xfa\xed\xfe":
            header_size = 32
        elif slice_magic == b"\xce\xfa\xed\xfe":
            header_size = 28
        else:
            continue

        ncmds = read_u32(f, slice_offset + 16)
        sizeofcmds = read_u32(f, slice_offset + 20)
        command_start = slice_offset + header_size
        f.seek(command_start)
        commands = f.read(sizeofcmds)
        if len(commands) != sizeofcmds:
            raise RuntimeError("读取 Mach-O load commands 失败")

        pos = 0
        found = []
        for index in range(ncmds):
            if pos + 8 > sizeofcmds:
                raise RuntimeError("Mach-O load commands 越界")
            cmd, cmdsize = struct.unpack_from("<II", commands, pos)
            if cmdsize < 8 or pos + cmdsize > sizeofcmds:
                raise RuntimeError("Mach-O load command 大小非法")

            if cmd == LC_LOAD_DYLIB and cmdsize >= 24:
                name_offset = struct.unpack_from("<I", commands, pos + 8)[0]
                if 24 <= name_offset < cmdsize:
                    name = commands[pos + name_offset:pos + cmdsize].split(b"\0", 1)[0]
                    if name == TARGET:
                        found.append((index, pos, cmdsize))
            pos += cmdsize

        if len(found) > 1:
            raise RuntimeError("同一架构发现多个 WeChatAntiRevoke 加载命令，拒绝自动修改")
        if found:
            _index, command_pos, command_size = found[0]
            targets.append((slice_offset, command_start, ncmds, sizeofcmds,
                            commands, command_pos, command_size))

    if not targets:
        raise RuntimeError("没有找到可移除的 WeChatAntiRevoke 加载命令")

    for slice_offset, command_start, ncmds, sizeofcmds, commands, command_pos, command_size in targets:
        new_commands = commands[:command_pos] + commands[command_pos + command_size:]
        f.seek(command_start)
        f.write(new_commands)
        f.write(b"\0" * command_size)
        f.seek(slice_offset + 16)
        f.write(struct.pack("<I", ncmds - 1))
        f.seek(slice_offset + 20)
        f.write(struct.pack("<I", sizeofcmds - command_size))

print("ok")
REMOVE_INJECTED_LOAD_COMMAND
}

backup_original_app() {
    local current_version="${VERSION:-unknown}"
    local saved_version=""
    if [ -f "$ORIGINAL_VERSION_FILE" ]; then
        read -r saved_version < "$ORIGINAL_VERSION_FILE" || true
    fi

    mkdir -p "$STATE_DIR"
    if [ -d "$ORIGINAL_APP" ] && [ "$saved_version" = "$current_version" ]; then
        codesign --verify --deep --strict "$ORIGINAL_APP"
        echo "[INFO] 使用已有微信整包备份: $ORIGINAL_APP"
        return 0
    fi

    # 已经是旧插件现场却没有整包备份时，不能把带补丁的 app 当作原始备份。
    if [ -f "$DYLIB_DST" ] || has_injected_load_command; then
        echo "[ERROR] 当前微信已被修改，但没有同版本的整包原始备份"
        echo "        请先用未修改的微信副本恢复后再安装"
        return 1
    fi

    local tmp_dir
    if [ -e "$ORIGINAL_APP" ]; then
        echo "[ERROR] 原始备份路径已存在但版本记录不一致，拒绝覆盖: $ORIGINAL_APP"
        return 1
    fi
    tmp_dir=$(mktemp -d "$STATE_DIR/.wechat-backup.XXXXXX")
    codesign --verify --deep --strict "$WECHAT_APP"
    if ! ditto --rsrc --extattr --acl "$WECHAT_APP" "$tmp_dir/WeChat.original.app"; then
        echo "[ERROR] 保存微信整包备份失败"
        return 1
    fi
    codesign --verify --deep --strict "$tmp_dir/WeChat.original.app"
    mv "$tmp_dir/WeChat.original.app" "$ORIGINAL_APP"
    rmdir "$tmp_dir"
    printf '%s\n' "$current_version" > "$ORIGINAL_VERSION_FILE"
    echo "[INFO] 已保存微信整包备份: $ORIGINAL_APP"
}

restore_original_app() {
    if [ ! -d "$ORIGINAL_APP" ]; then
        return 1
    fi

    local current_version="${VERSION:-unknown}"
    local saved_version=""
    if [ -f "$ORIGINAL_VERSION_FILE" ]; then
        read -r saved_version < "$ORIGINAL_VERSION_FILE" || true
    fi
    if [ "$saved_version" != "$current_version" ]; then
        echo "[WARN] 微信版本与整包备份不一致，跳过整包恢复"
        return 1
    fi

    codesign --verify --deep --strict "$ORIGINAL_APP" || return 1

    local rescue_dir
    rescue_dir=$(mktemp -d /private/tmp/WeChatIntercept-restore.XXXXXX)
    if [ -d "$WECHAT_APP" ]; then
        mv "$WECHAT_APP" "$rescue_dir/WeChat.before-restore.app"
    fi
    if ! ditto --rsrc --extattr --acl "$ORIGINAL_APP" "$WECHAT_APP"; then
        echo "[ERROR] 恢复微信整包失败，尝试放回当前 app"
        rm -rf "$WECHAT_APP" 2>/dev/null || true
        if [ -d "$rescue_dir/WeChat.before-restore.app" ]; then
            mv "$rescue_dir/WeChat.before-restore.app" "$WECHAT_APP"
        fi
        return 1
    fi
    echo "[INFO] 已恢复微信整包原始副本"
    echo "[INFO] 修改前副本保留在: $rescue_dir/WeChat.before-restore.app"
}

backup_original_binary() {
    local current_version="${VERSION:-unknown}"
    local saved_version=""
    if [ -f "$ORIGINAL_VERSION_FILE" ]; then
        read -r saved_version < "$ORIGINAL_VERSION_FILE" || true
    fi

    mkdir -p "$STATE_DIR"
    if [ ! -f "$ORIGINAL_BIN" ] || [ "$saved_version" != "$current_version" ]; then
        if otool -l "$WECHAT_BIN" 2>/dev/null | grep -F "WeChatAntiRevoke" >/dev/null; then
            echo "[ERROR] 备份前仍检测到动态库注入"
            return 1
        fi
        cp -p "$WECHAT_BIN" "$ORIGINAL_BIN"
        printf '%s\n' "$current_version" > "$ORIGINAL_VERSION_FILE"
        echo "[INFO] 已保存微信主程序备份: $ORIGINAL_BIN"
    else
        echo "[INFO] 使用已有微信主程序备份: $ORIGINAL_BIN"
    fi
}

restore_original_binary() {
    if [ ! -f "$ORIGINAL_BIN" ]; then
        return 1
    fi

    local current_version="${VERSION:-unknown}"
    local saved_version=""
    if [ -f "$ORIGINAL_VERSION_FILE" ]; then
        read -r saved_version < "$ORIGINAL_VERSION_FILE" || true
    fi
    if [ "$saved_version" != "$current_version" ]; then
        echo "[WARN] 微信版本与备份不一致，跳过主程序恢复"
        return 1
    fi

    cp -p "$ORIGINAL_BIN" "$WECHAT_BIN"
    echo "[INFO] 已恢复微信主程序备份"
}

remove_provenance() {
    echo "[INFO] 尝试解除系统文件保护..."
    TMP_DIR=$(mktemp -d)
    tar --no-xattrs -cf - -C /Applications WeChat.app | tar -xf - -C "$TMP_DIR/"
    rm -rf "$WECHAT_APP"
    mv "$TMP_DIR/WeChat.app" "$WECHAT_APP"
    rm -rf "$TMP_DIR"

    # 递归清除残留 xattr（best-effort）
    xattr -cr "$WECHAT_APP" 2>/dev/null || true
    # 不要在脚本中无条件调用 sudo：没有缓存凭据时会卡在密码提示，且
    # provenance 可能被系统重新附加；重签名阶段的 entitlements 才是实际兜底。
    if ! sudo -n xattr -cr "$WECHAT_APP" 2>/dev/null; then
        echo "[INFO] 没有可用的免交互 sudo 权限，跳过 root 级 xattr 清理"
    fi

    # 检查结果（仅警告，不阻断安装）
    if xattr "$WECHAT_APP" 2>/dev/null | grep -F "com.apple.provenance" >/dev/null; then
        echo "[WARN] provenance 未能完全清除（macOS Sequoia 可能会自动重新附加）"
        echo "[INFO] 将通过 entitlements 绕过此限制"
    else
        echo "[INFO] 文件保护已解除"
    fi
}

compile_dylib() {
    echo "[INFO] 编译 hook 动态库..."

    local SRC_FILE
    SRC_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hook.m"

    clang -arch arm64 -arch x86_64 -fobjc-arc -shared -framework Foundation -framework AppKit \
        -framework ImageIO -framework CoreGraphics \
        -o "$DYLIB_DST" \
        -install_name "$DYLIB_INSTALL_NAME" \
        "$SRC_FILE" 2>&1

    if [ ! -f "$DYLIB_DST" ]; then
        echo "[ERROR] 编译失败"
        exit 1
    fi
    echo "[INFO] 编译成功"
}

inject_dylib() {
    echo "[INFO] 注入动态库到微信..."

    python3 - "$WECHAT_BIN" << 'INJECT_SCRIPT'
import struct
import sys

wechat_path = sys.argv[1]
target_name = b'@executable_path/../Resources/WeChatAntiRevoke.dylib'
dylib_name = target_name + b'\x00'
while len(dylib_name) % 8 != 0:
    dylib_name += b'\x00'

cmd_size = 24 + len(dylib_name)
while cmd_size % 8 != 0:
    cmd_size += 1
    dylib_name += b'\x00'

with open(wechat_path, 'r+b') as f:
    fat_magic = struct.unpack('>I', f.read(4))[0]
    if fat_magic != 0xCAFEBABE:
        raise RuntimeError('仅支持 Universal Mach-O 微信主程序')
    narch = struct.unpack('>I', f.read(4))[0]

    slices = []
    for _ in range(narch):
        cpu, sub, offset, size, align = struct.unpack('>IIIII', f.read(20))
        slices.append((cpu, offset, size))

    plans = []
    for cpu, slice_offset, slice_size in slices:
        f.seek(slice_offset)
        magic = f.read(4)
        if magic != b'\xcf\xfa\xed\xfe':
            continue

        f.seek(slice_offset + 16)
        ncmds, sizeofcmds = struct.unpack('<II', f.read(8))
        command_start = slice_offset + 32
        f.seek(command_start)
        commands = f.read(sizeofcmds)
        if len(commands) != sizeofcmds:
            raise RuntimeError('读取 Mach-O load commands 失败')

        pos = 0
        already = False
        code_signature_pos = None
        first_section_offset = slice_size
        for _ in range(ncmds):
            if pos + 8 > sizeofcmds:
                raise RuntimeError('Mach-O load commands 越界')
            cmd, command_size = struct.unpack_from('<II', commands, pos)
            if command_size < 8 or pos + command_size > sizeofcmds:
                raise RuntimeError('Mach-O load command 大小非法')
            if cmd == 0x1D:
                code_signature_pos = pos
            if cmd == 0x19 and command_size >= 72:
                nsects = struct.unpack_from('<I', commands, pos + 64)[0]
                if 72 + nsects * 80 > command_size:
                    raise RuntimeError('Mach-O section 表越界')
                for index in range(nsects):
                    section = pos + 72 + index * 80
                    section_size = struct.unpack_from('<Q', commands, section + 40)[0]
                    section_offset = struct.unpack_from('<I', commands, section + 48)[0]
                    flags = struct.unpack_from('<I', commands, section + 64)[0]
                    if section_size and section_offset and flags & 0xff not in (1, 0xc, 0x12):
                        first_section_offset = min(first_section_offset, section_offset)
            if cmd == 0xC and command_size >= 24:
                name_offset = struct.unpack_from('<I', commands, pos + 8)[0]
                if 24 <= name_offset < command_size:
                    name = commands[pos + name_offset:pos + command_size].split(b'\0', 1)[0]
                    if name == target_name:
                        already = True
            pos += command_size
        if pos != sizeofcmds:
            raise RuntimeError('Mach-O sizeofcmds 与命令表不一致')

        if already:
            continue

        lc = struct.pack('<II', 0xC, cmd_size)
        lc += struct.pack('<IIII', 24, 2, 0x10000, 0x10000)
        lc += dylib_name
        lc += b'\x00' * (cmd_size - len(lc))

        # LC_CODE_SIGNATURE 必须保持在 load commands 的最后；否则 codesign
        # 会在重签名时丢掉刚追加的动态库依赖。
        if code_signature_pos is None:
            new_commands = commands + lc
        else:
            new_commands = (commands[:code_signature_pos] + lc +
                            commands[code_signature_pos:])

        if 32 + len(new_commands) > first_section_offset:
            raise RuntimeError('Mach-O header 没有足够空隙，拒绝覆盖 section')
        f.seek(command_start + sizeofcmds)
        if f.read(cmd_size) != b'\0' * cmd_size:
            raise RuntimeError('Mach-O header 扩展区域不是空白，拒绝覆盖')
        plans.append((slice_offset, command_start, ncmds, sizeofcmds, new_commands))

    if not plans:
        raise RuntimeError('没有可注入的 arm64 Mach-O slice')

    for slice_offset, command_start, ncmds, sizeofcmds, new_commands in plans:
        f.seek(command_start)
        f.write(new_commands)
        f.seek(slice_offset + 16)
        f.write(struct.pack('<I', ncmds + 1))
        f.seek(slice_offset + 20)
        f.write(struct.pack('<I', sizeofcmds + cmd_size))

print('ok')
INJECT_SCRIPT

    echo "[INFO] 注入完成"
}

make_hook_entitlements() {
    local ent_file="$1"
    local dumped=""

    # 保留微信原始的 app-sandbox / application-identifier / application-groups
    # 等配置，只在其上追加本地 hook 所需权限。直接用一个精简 plist 会让
    # 微信失去原始沙盒身份，启动后立即退出。
    dumped=$(codesign -d --entitlements :- "$WECHAT_BIN" 2>/dev/null)
    printf '%s\n' "$dumped" | sed -n '/<?xml/,/<\/plist>/p' > "$ent_file"
    if ! grep -F '<plist' "$ent_file" >/dev/null; then
        echo "[ERROR] 无法读取微信原始 entitlements，拒绝使用空配置重签名"
        return 1
    fi
    plutil -lint "$ent_file" >/dev/null

    local key
    for key in \
        com.apple.security.cs.disable-library-validation \
        com.apple.security.cs.allow-unsigned-executable-memory \
        com.apple.security.get-task-allow; do
        /usr/libexec/PlistBuddy -c "Set :$key true" "$ent_file" 2>/dev/null || \
            /usr/libexec/PlistBuddy -c "Add :$key bool true" "$ent_file"
    done
}

resign_app() {
    echo "[INFO] 重签名（保留微信原始 entitlements，追加 hook 权限）..."

    local ENT_FILE="/tmp/antirevoke_ent.plist"
    make_hook_entitlements "$ENT_FILE"

    # 只重签新增 dylib、主程序和 bundle 本身，不 deep 重签腾讯的嵌套组件。
    codesign --force --sign - "$DYLIB_DST" 2>/dev/null
    codesign --force --sign - --entitlements "$ENT_FILE" "$WECHAT_BIN" 2>/dev/null
    codesign --force --sign - --entitlements "$ENT_FILE" "$WECHAT_APP" 2>/dev/null

    xattr -cr "$WECHAT_APP" 2>/dev/null || true

    if codesign -d --entitlements - "$WECHAT_BIN" 2>&1 | grep -F "disable-library-validation" >/dev/null; then
        echo "[INFO] 重签名完成（原始 entitlements 已保留，Library Validation 已禁用）"
    else
        echo "[WARN] entitlements 可能未生效，请确认 SIP 状态"
    fi

    rm -f "$ENT_FILE"
}

resign_main_with_entitlements() {
    echo "[INFO] 注入后重签名主程序（保留原始 entitlements 和动态库依赖）..."

    local ENT_FILE="/tmp/antirevoke_ent.plist"
    make_hook_entitlements "$ENT_FILE"

    codesign --force --sign - --entitlements "$ENT_FILE" "$WECHAT_BIN" 2>/dev/null
    # 只更新 bundle 的外层签名，不使用 --deep，避免再次改写主程序或腾讯组件。
    codesign --force --sign - --entitlements "$ENT_FILE" "$WECHAT_APP" 2>/dev/null
    xattr -cr "$WECHAT_APP" 2>/dev/null || true

    if codesign -d --entitlements - "$WECHAT_BIN" 2>&1 | grep -F "disable-library-validation" >/dev/null; then
        echo "[INFO] 注入后重签名完成（Library Validation 已禁用）"
    else
        echo "[WARN] 注入后 entitlements 可能未生效，请确认 SIP 状态"
    fi

    rm -f "$ENT_FILE"
}

resign_clean_app() {
    echo "[INFO] 重签名已恢复的微信..."
    codesign --force --deep --sign - "$WECHAT_APP" 2>/dev/null
    codesign --force --sign - "$WECHAT_BIN" 2>/dev/null
    xattr -cr "$WECHAT_APP" 2>/dev/null || true
}

verify_install() {
    echo "[INFO] 验证安装（必须确认当前进程 HOOK_READY）..."
    codesign --verify --deep --strict "$WECHAT_APP"
    codesign --verify --strict "$DYLIB_DST"
    local arch
    for arch in $(lipo -archs "$WECHAT_BIN"); do
        if ! otool -arch "$arch" -L "$WECHAT_BIN" | grep -F "$DYLIB_INSTALL_NAME" >/dev/null; then
            echo "[ERROR] $arch 架构没有防撤回依赖"
            return 1
        fi
    done

    local started_at marker_required=0
    if [ "$(uname -m)" = arm64 ] && xcrun dwarfdump --uuid \
        "$WECHAT_APP/Contents/Resources/wechat.dylib" | grep -F \
        '918FFBFD-E18D-363F-B07C-B8D7F1436727 (arm64)' >/dev/null; then
        marker_required=1
    fi
    started_at=$(date '+%Y-%m-%d %H:%M:%S')
    open "$WECHAT_APP"
    local PID="" start=$SECONDS output=""
    while [ $((SECONDS - start)) -lt 30 ]; do
        PID=$(pgrep -x WeChat 2>/dev/null | head -n 1 || true)
        if [ -n "$PID" ]; then
            # 系统日志只包含本插件主动发布的非敏感状态，无需读取受保护的微信数据。
            output=$(/usr/bin/log show --start "$started_at" --style compact \
                --predicate "processIdentifier == $PID AND subsystem == \"local.WeChatIntercept\"" 2>/dev/null) || {
                echo "[ERROR] 无法读取系统 hook 状态日志"
                return 1
            }
            if printf '%s\n' "$output" | grep -F 'ERROR:' >/dev/null; then
                printf '%s\n' "$output"
                echo "[ERROR] hook 初始化失败"
                return 1
            fi
            if printf '%s\n' "$output" | grep -F 'HOOK_READY' >/dev/null; then
                if [ "$marker_required" -eq 1 ]; then
                    if ! printf '%s\n' "$output" | grep -F 'MARKER_READY' >/dev/null || \
                       ! printf '%s\n' "$output" | grep -F 'STICKER_EXPORT_QT_READY' >/dev/null || \
                       ! printf '%s\n' "$output" | grep -F 'STICKER_METADATA_HOOK_READY' >/dev/null; then
                        sleep 1
                        continue
                    fi
                fi
                sleep 2
                if kill -0 "$PID" 2>/dev/null && vmmap "$PID" 2>/dev/null | grep -F 'WeChatAntiRevoke.dylib' >/dev/null; then
                    printf '%s\n' "$output"
                    echo "[INFO] 当前微信进程 hook 已初始化并通过加载验证"
                    return 0
                fi
                echo "[ERROR] hook 初始化后微信未持续正常运行"
                return 1
            fi
        fi
        sleep 1
    done
    echo "[ERROR] 30 秒内未确认当前进程 HOOK_READY，不保留未验证的安装"
    echo "[INFO] 日志路径: $HOOK_LOG"
    if [ -n "$PID" ]; then
        sample "$PID" 1 1 -file "/private/tmp/WeChatIntercept-startup.$PID.sample.txt" >/dev/null 2>&1 || true
    fi
    return 1
}

rollback_install() {
    local status=${1:-$?}
    trap - ERR INT TERM
    set +e
    if [ "$INSTALL_SWAPPED" -eq 1 ]; then
        WECHAT_APP="$INSTALL_LIVE_APP"
        WECHAT_BIN="$WECHAT_APP/Contents/MacOS/WeChat"
        DYLIB_DST="$WECHAT_APP/Contents/Resources/WeChatAntiRevoke.dylib"
        echo "[ERROR] 安装未完成，恢复安装前的完整应用..."
        kill_wechat
        if [ -d "$WECHAT_APP" ]; then
            mv "$WECHAT_APP" "${INSTALL_PREVIOUS_APP%.app}.failed.app" || exit "$status"
        fi
        mv "$INSTALL_PREVIOUS_APP" "$WECHAT_APP" || exit "$status"
        codesign --verify --deep --strict "$WECHAT_APP" || exit "$status"
        echo "[INFO] 已恢复安装前的应用与签名，未修改聊天数据"
        open "$WECHAT_APP"
    else
        echo "[ERROR] 临时副本准备失败，当前微信未被替换"
    fi
    exit "$status"
}

do_install() {
    print_banner
    check_environment

    # 检查是否已安装
    if [ -f "$DYLIB_DST" ]; then
        echo "[INFO] 检测到已安装，将重新安装..."
    fi

    trap rollback_install ERR
    trap 'rollback_install 130' INT
    trap 'rollback_install 143' TERM

    # 在任何重签名或 xattr 处理之前保存完整原始 app，卸载时可恢复原始
    # Developer ID 签名；仅保存主程序不足以恢复嵌套组件的签名状态。
    backup_original_app

    # 在独立副本编译、注入、签名并验签；失败不会破坏正在运行的微信。
    local stage_dir stage_app
    stage_dir=$(mktemp -d /private/tmp/WeChatIntercept-install.XXXXXX)
    stage_app="$stage_dir/WeChat.app"
    ditto --rsrc --noqtn --acl "$ORIGINAL_APP" "$stage_app"
    WECHAT_APP="$stage_app"
    WECHAT_BIN="$WECHAT_APP/Contents/MacOS/WeChat"
    DYLIB_DST="$WECHAT_APP/Contents/Resources/WeChatAntiRevoke.dylib"
    remove_injected_load_command
    compile_dylib
    inject_dylib
    resign_app
    codesign --verify --deep --strict "$WECHAT_APP"

    WECHAT_APP="$INSTALL_LIVE_APP"
    WECHAT_BIN="$WECHAT_APP/Contents/MacOS/WeChat"
    DYLIB_DST="$WECHAT_APP/Contents/Resources/WeChatAntiRevoke.dylib"
    kill_wechat
    if pgrep -x WeChat >/dev/null 2>&1; then
        echo "[ERROR] 微信仍在运行，拒绝替换应用"
        return 1
    fi
    INSTALL_PREVIOUS_APP="$stage_dir/WeChat.previous.app"
    mv "$WECHAT_APP" "$INSTALL_PREVIOUS_APP"
    INSTALL_SWAPPED=1
    mv "$stage_app" "$WECHAT_APP"
    verify_install
    INSTALL_SWAPPED=0
    trap - ERR INT TERM

    # 验证成功后，临时目录里只剩安装前的已修改应用。原始签名整包已经
    # 保存在 ORIGINAL_APP，无需在 /private/tmp 再保留一份完整副本。
    if ! rm -rf "$INSTALL_PREVIOUS_APP"; then
        echo "[WARN] 安装已成功，但无法删除临时应用副本: $INSTALL_PREVIOUS_APP"
    elif ! rmdir "$stage_dir"; then
        echo "[WARN] 安装已成功，但临时目录仍有其他内容: $stage_dir"
    fi
    INSTALL_PREVIOUS_APP=""



    echo ""
    echo "=============================="
    echo " 安装成功！"
    echo "=============================="
    echo ""
    echo " 功能: 对方撤回的消息将保留可见"
    echo "       自己撤回消息正常工作"
     echo ""
    echo " 卸载: $0 --uninstall"
    echo ""
}

do_debug() {
    print_banner
    echo "[INFO] 调试模式（不安装 hook，仅签名允许 lldb attach）"

    check_environment
    kill_wechat
    remove_provenance

    # 删除已有的 hook dylib（确保无 hook）
    rm -f "$DYLIB_DST" 2>/dev/null || true

    # 签名（带 get-task-allow，允许 lldb attach）
    echo "[INFO] 重签名（注入调试 entitlements）..."
    local ENT_FILE=$(mktemp /tmp/entitlements_XXXXXX.plist)
    cat > "$ENT_FILE" << 'ENTITLEMENTS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
ENTITLEMENTS

    codesign --force --deep --sign - "$WECHAT_APP" 2>/dev/null
    codesign --force --sign - --entitlements "$ENT_FILE" "$WECHAT_BIN" 2>/dev/null
    xattr -cr "$WECHAT_APP" 2>/dev/null || true
    rm -f "$ENT_FILE"

    echo "[INFO] 启动微信..."
    open "$WECHAT_APP"
    sleep 3

    echo ""
    echo "=============================="
    echo " 调试模式已启用"
    echo "=============================="
    echo ""
    echo " 微信无 hook，撤回流程完整执行"
    echo " 可使用 lldb attach 进行逆向分析"
    echo ""
    echo " 命令："
    echo "   lldb -p \$(pgrep -x WeChat)"
    echo "   image list wechat.dylib"
    echo "   # Resources 行地址 = slide"
    echo "   br set -a <slide+0x4D5FD70>"
    echo "   c"
    echo ""
    echo " 恢复防撤回: $0"
    echo ""
}

do_uninstall() {
    print_banner
    echo "[INFO] 卸载防撤回插件..."

    if [ ! -d "$WECHAT_APP" ] || [ ! -f "$WECHAT_BIN" ]; then
        echo "[ERROR] 未找到完整的微信安装: $WECHAT_APP"
        exit 1
    fi
    VERSION=$(defaults read "$WECHAT_APP/Contents/Info.plist" CFBundleVersion 2>/dev/null || true)

    local was_patched=0
    if [ -f "$DYLIB_DST" ] || has_injected_load_command; then
        was_patched=1
    fi
    if [ "$was_patched" -eq 0 ]; then
        echo "[INFO] 当前微信没有 WeChatIntercept 修改，无需重签名或恢复"
        return 0
    fi

    kill_wechat

    # 优先恢复安装时保存的完整原始 app；旧版本没有整包备份时，退回到
    # 移除 load command + 主程序备份的兼容路径。
    if restore_original_app; then
        :
    else
        if restore_original_binary; then
            echo "[INFO] 已恢复微信主程序备份"
        else
            remove_injected_load_command
        fi
        rm -f "$DYLIB_DST" 2>/dev/null || true

        if [ -f "$DYLIB_DST" ]; then
            echo "[ERROR] 无法删除 dylib，请手动重新安装微信"
            exit 1
        fi

        resign_clean_app
        if has_injected_load_command; then
            echo "[ERROR] 卸载失败：主程序仍保留 WeChatAntiRevoke 加载命令"
            exit 1
        fi
    fi

    echo ""
    echo "=============================="
    echo " 已卸载，微信已恢复为无防撤回状态"
    echo "=============================="
    echo ""
}

# ======================== 消息监听（撤回原文）========================

MONITOR_INSTALL_DIR="$HOME/.local/share/wechatintercept"

deploy_monitor_files() {
    mkdir -p "$MONITOR_INSTALL_DIR"

    # wechat_msg_monitor.py
    cat > "$MONITOR_INSTALL_DIR/wechat_msg_monitor.py" << 'MONITOR_PY'
# -*- coding: utf-8 -*-
"""
WeChat 消息监听器（lldb Python 脚本）
在 wechat.dylib __TEXT 段扫描 CMessageWrap 虚方法特征码，
断点命中时读消息字段写入 TSV 缓存供 dylib 反查撤回原文。
用法：./monitor.sh 或 ./monitor.sh --install
"""

import lldb
import struct
import datetime

# CMessageWrap 虚方法（257712）特征码（4.1.10 实测）
# PREFIX 4条 + 通配 bl(4字节) + SUFFIX 1条
PATTERN_PREFIX = bytes.fromhex("f44fbea9" "fd7b01a9" "fd430091" "f30301aa")
PATTERN_SUFFIX = bytes.fromhex("683a40f9")
PATTERN_GAP = 4

# 消息对象字段偏移（4.1.10 验证；微信升级后可能变化）
OFF_FLAG1       = 0x28
OFF_FLAG2       = 0x2c
OFF_CONTENT_PTR = 0x40   # wrapper ptr; wrapper+0x00 → content char*
OFF_CREATE_TIME = 0x48
OFF_MSG_LOCAL   = 0x4c
OFF_MSG_SVR     = 0x50   # int64, 与撤回 XML <newmsgid> 对应
OFF_FROM_PTR    = 0x08   # wrapper ptr; wrapper+0x08 → wxid char*

WRAPPER_DATA_PTR = 0x08

_g_msg_count = 0
_g_seen_svrid = set()
_g_debug_dump = False

# 缓存文件：dylib 反查撤回原文用。svrid 十进制，字段 \t 分隔，原子 rename 写入
CACHE_FILE = "/tmp/wechat_msg_cache.tsv"
_CACHE_MAX_LINES = 500
_g_cache_lines = []


def _sanitize_field(s):
    if not s:
        return ""
    return s.replace("\t", " ").replace("\n", " ").replace("\r", " ")


def _strip_sender_prefix(content):
    # 微信 +0x40 存的是 "<昵称> : <正文>" 格式，剥掉前缀只留正文
    if not content:
        return content
    idx = content.find(" : ")
    if idx > 0 and idx < 64:  # 昵称不会超过 64 字符
        return content[idx + 3:]
    return content


def _is_valid_content(stripped, from_user):
    if not stripped or len(stripped) < 2:
        return False
    if stripped == from_user:
        return False
    if stripped.startswith("<"):
        return False
    return True


def _cache_append(svrid, from_user, content):
    if svrid == 0 or not content:
        return
    try:
        body = _strip_sender_prefix(content)
        line = "{}\t{}\t{}\n".format(
            svrid,
            _sanitize_field(from_user)[:63],
            _sanitize_field(body)[:511],
        )
        _g_cache_lines.append(line)
        if len(_g_cache_lines) > _CACHE_MAX_LINES:
            del _g_cache_lines[: len(_g_cache_lines) - _CACHE_MAX_LINES]

        # 原子写，避免 dylib 读到半行
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8", errors="replace") as f:
            f.writelines(_g_cache_lines)
        import os
        os.replace(tmp, CACHE_FILE)
    except Exception as e:
        print("    [cache] write failed: {}".format(e))


def _read_mem(process, addr, size):
    if addr == 0:
        return None
    err = lldb.SBError()
    data = process.ReadMemory(addr, size, err)
    if not err.Success():
        return None
    return data


def _read_u32(process, addr):
    data = _read_mem(process, addr, 4)
    if data is None:
        return None
    return struct.unpack("<I", data)[0]


def _read_u64(process, addr):
    data = _read_mem(process, addr, 8)
    if data is None:
        return None
    return struct.unpack("<Q", data)[0]


def _read_cstring(process, addr, max_len=256):
    if addr == 0:
        return ""
    data = _read_mem(process, addr, max_len)
    if data is None:
        return ""
    nul = data.find(b"\x00")
    if nul >= 0:
        data = data[:nul]
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return repr(data)


def _read_std_string_via_wrapper(process, wrapper_ptr):
    # wrapper 结构: +0x00 vtable, +0x08 data ptr
    if wrapper_ptr == 0:
        return ""
    data_ptr = _read_u64(process, wrapper_ptr + WRAPPER_DATA_PTR)
    if data_ptr is None or data_ptr == 0:
        return ""

    # 简化：不区分 char*/SSO，直接当 C 字符串读
    s = _read_cstring(process, data_ptr, max_len=512)
    return s


def _read_std_string_inplace(process, addr):
    # libc++ std::string 24字节布局: LSB of byte[23] == 0 → SSO, == 1 → heap
    data = _read_mem(process, addr, 24)
    if data is None:
        return ""
    last_byte = data[23]
    if last_byte & 0x01 == 0:
        # SSO（最低位=0）
        size = last_byte >> 1
        if size > 22:
            return ""
        return data[:size].decode("utf-8", errors="replace")
    else:
        # 长字符串
        ptr = struct.unpack("<Q", data[0:8])[0]
        size = struct.unpack("<Q", data[8:16])[0]
        if size > 4096:
            return ""
        body = _read_mem(process, ptr, size)
        if body is None:
            return ""
        return body.decode("utf-8", errors="replace")



def _try_read_content(process, msg_obj):
    # +0x40 是 std::string inplace（libc++ [data_ptr][size][cap|0x80...]）
    # 注意：断点命中瞬间 data_ptr 指向的内存可能还没就绪（时序问题），
    # 所以尝试两次读取：第一次失败就 fallback，最后再试一次
    def _try_str40():
        # +0x40 存的是指针 → 指向 std::string 结构
        ptr40 = _read_u64(process, msg_obj + 0x40)
        if not ptr40 or ptr40 < 0x100000000 or ptr40 > 0x10000000000:
            return ""
        raw = _read_mem(process, ptr40, 24)
        if not raw or len(raw) < 24:
            return ""
        dp = struct.unpack("<Q", raw[0:8])[0]
        sz = struct.unpack("<Q", raw[8:16])[0]
        # 长字符串：dp 是堆指针，sz 是长度
        if 0x100000000 < dp < 0x10000000000 and 0 < sz < 4096:
            text = _read_cstring(process, dp, min(int(sz) + 1, 512))
            if text and len(text) >= 2:
                return text
        # SSO：数据直接在 raw[0:22]
        nul = raw.find(b"\x00", 0, 22)
        sso_data = raw[:nul] if nul >= 0 else raw[:22]
        if sso_data and len(sso_data) >= 2:
            try:
                return sso_data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                pass
        return ""

    t = _try_str40()
    if t:
        return (t, "+0x40(str)")

    return ("", "")


def on_msg_hit(frame, bp_loc, dict_):
    # 返回 False = 自动 continue（不停在 lldb）
    global _g_msg_count, _g_seen_svrid

    process = frame.GetThread().GetProcess()

    # x19 = msg obj; callee-saved, 在 +12 (mov x19,x1) 后已就绪
    x19 = frame.FindRegister("x19").GetValueAsUnsigned()
    if x19 == 0:
        return False

    msg_obj = x19
    if msg_obj < 0x100000000 or msg_obj > 0x1000000000000:
        return False

    create_time = _read_u32(process, msg_obj + OFF_CREATE_TIME)
    msg_local = _read_u32(process, msg_obj + OFF_MSG_LOCAL)
    msg_svr_lo = _read_u32(process, msg_obj + OFF_MSG_SVR)
    msg_svr_hi = _read_u32(process, msg_obj + OFF_MSG_SVR + 4)
    if create_time is None or msg_svr_lo is None or msg_svr_hi is None:
        return False
    msg_svr = (msg_svr_hi << 32) | msg_svr_lo

    if create_time < 1577836800 or create_time > 1893456000:  # 2020~2030
        return False

    if msg_svr in _g_seen_svrid:
        return False
    if msg_svr != 0:
        _g_seen_svrid.add(msg_svr)
        if len(_g_seen_svrid) > 1000:
            _g_seen_svrid = set(list(_g_seen_svrid)[-500:])

    # from: +0x08 wrapper, wrapper+0x08 才是字符串
    from_wrapper = _read_u64(process, msg_obj + OFF_FROM_PTR)
    from_user = _read_std_string_via_wrapper(process, from_wrapper) if from_wrapper else ""

    flag1 = _read_u32(process, msg_obj + OFF_FLAG1)
    flag2 = _read_u32(process, msg_obj + OFF_FLAG2)
    subtype_vtbl = _read_u64(process, msg_obj + 0x10)

    # flag2=1: +0x40 → ptr → std::string（已验证）
    # flag2=2: 不同类结构，尝试扩大范围搜索
    content, content_off = _try_read_content(process, msg_obj)

    try:
        ts = datetime.datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = str(create_time)

    _g_msg_count += 1
    print("─" * 60)
    print("[wx_msg #{}] {}".format(_g_msg_count, ts))
    print("  obj      : 0x{:016x}".format(msg_obj))
    print("  svrid    : 0x{:016x}".format(msg_svr))
    print("  localid  : 0x{:08x}".format(msg_local or 0))
    print("  flag     : 0x{:x} / 0x{:x}".format(flag1 or 0, flag2 or 0))
    print("  subtype  : 0x{:x}".format(subtype_vtbl or 0))  # +0x10 处的 vtable，用于区分消息类型
    print("  from     : {}".format(from_user))
    if content:
        print("  content@{}: {}".format(content_off, content[:200]))
    else:
        print("  content  : <empty>")



    # 写缓存前排除误读
    if content and msg_svr != 0:
        stripped = _strip_sender_prefix(content)
        if stripped and _is_valid_content(stripped, from_user):
            _cache_append(msg_svr, from_user, content)

    if _g_debug_dump:
        _dump_msg_object(process, msg_obj)
        # must be in breakpoint context or object freed
        _deep_scan(process, msg_obj)

    return False


def _dump_msg_object(process, addr, obj_size=0x100):
    raw = _read_mem(process, addr, obj_size)
    if raw is None:
        print("    [dump] 读取失败")
        return
    print("    [dump] obj @ 0x{:x} ({} bytes):".format(addr, obj_size))
    for off in range(0, obj_size, 16):
        line = raw[off:off + 16]
        hex_part = " ".join("{:02x}".format(b) for b in line)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in line)
        print("      +0x{:03x}: {}  {}".format(off, hex_part, ascii_part))

    print("    [deref] 候选指针字段:")
    for off in range(0, obj_size, 8):
        if off + 8 > len(raw):
            break
        ptr = struct.unpack("<Q", raw[off:off + 8])[0]
        if ptr < 0x100000000 or ptr > 0x10000000000:
            continue
        sub = _read_mem(process, ptr, 64)
        if sub is None:
            continue
        printable = sum(1 for b in sub[:32] if 0x20 <= b < 0x7F)
        if printable < 4:
            continue
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in sub[:48])
        print("      +0x{:03x} -> 0x{:x}: {}".format(off, ptr, ascii_part))


def scan_pattern(process, start_addr, size, max_size=512 * 1024 * 1024):
    if size > max_size:
        size = max_size

    chunk_size = 4 * 1024 * 1024  # 4MB
    overlap = len(PATTERN_PREFIX) + PATTERN_GAP + len(PATTERN_SUFFIX)

    pos = 0
    chunks_read = 0
    chunks_failed = 0
    prefix_hits = 0  # PREFIX 匹配但 SUFFIX 不匹配的次数
    bytes_scanned = 0

    while pos < size:
        read_size = min(chunk_size + overlap, size - pos)
        data = _read_mem(process, start_addr + pos, read_size)
        if data is None:
            chunks_failed += 1
            pos += chunk_size
            continue

        chunks_read += 1
        bytes_scanned += len(data)

        idx = 0
        while True:
            i = data.find(PATTERN_PREFIX, idx)
            if i < 0:
                break
            prefix_hits += 1
            suffix_pos = i + len(PATTERN_PREFIX) + PATTERN_GAP
            if suffix_pos + len(PATTERN_SUFFIX) <= len(data):
                if data[suffix_pos:suffix_pos + len(PATTERN_SUFFIX)] == PATTERN_SUFFIX:
                    print("    扫描完成: chunks ok={} fail={} bytes={} prefix_hits={}".format(
                        chunks_read, chunks_failed, bytes_scanned, prefix_hits))
                    return start_addr + pos + i
            idx = i + 1

        pos += chunk_size

    print("    扫描完成（未找到）: chunks ok={} fail={} bytes={} prefix_hits={}".format(
        chunks_read, chunks_failed, bytes_scanned, prefix_hits))
    return 0


def find_wechat_dylib_text(target):
    # NOTE: 微信 4.1.x 有两个 wechat.dylib (Resources/ 核心 vs Frameworks/ stub)
    # 必须用完整路径区分
    candidates = []
    for module in target.module_iter():
        spec = module.GetFileSpec()
        filename = spec.GetFilename() or ""
        if filename != "wechat.dylib":
            continue
        directory = spec.GetDirectory() or ""
        full_path = directory + "/" + filename
        for sec in module.section_iter():
            if sec.GetName() == "__TEXT":
                load_addr = sec.GetLoadAddress(target)
                size = sec.GetByteSize()
                candidates.append((full_path, load_addr, size))
                break

    if not candidates:
        return (0, 0)

    for path, addr, size in candidates:
        if "/Resources/" in path:
            print("    [match] {} __TEXT @ 0x{:x} size=0x{:x}".format(path, addr, size))
            return (addr, size)

    candidates.sort(key=lambda x: x[2], reverse=True)
    path, addr, size = candidates[0]
    print("    [fallback] {} __TEXT @ 0x{:x} size=0x{:x}".format(path, addr, size))
    return (addr, size)


def cmd_start(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    if not target:
        result.SetError("没有 target，先 attach 微信进程")
        return
    process = target.GetProcess()
    if not process or not process.IsValid():
        result.SetError("没有 process")
        return

    print(">>> 扫描 wechat.dylib __TEXT 特征码 ...")
    text_addr, text_size = find_wechat_dylib_text(target)
    if text_addr == 0:
        print("    候选模块：")
        for module in target.module_iter():
            spec = module.GetFileSpec()
            fn = spec.GetFilename() or ""
            if "wechat" in fn.lower():
                print("      - {}/{}".format(spec.GetDirectory() or "", fn))
        result.SetError("未找到 wechat.dylib __TEXT 段（确认 wechat.dylib 已加载）")
        return
    if text_size < 1024 * 1024:
        print("    [WARN] __TEXT size=0x{:x} 异常偏小，可能匹配到 stub".format(text_size))

    func_addr = scan_pattern(process, text_addr, text_size)
    if func_addr == 0:
        result.SetError("特征码未匹配（可能版本不一致，需更新 PATTERN）")
        return
    # 断点在 +20: +12 mov x19,x1 已执行(obj ready), +16 bl已完成(content ready)
    # 不能更早，否则 x19 或 content 还没就绪
    BP_OFFSET_FROM_FUNC_HEAD = 20
    bp_addr = func_addr + BP_OFFSET_FROM_FUNC_HEAD

    print("    msg func @ 0x{:x}（断点 @ 0x{:x} = +{}）".format(
        func_addr, bp_addr, BP_OFFSET_FROM_FUNC_HEAD))

    bp = target.BreakpointCreateByAddress(bp_addr)
    if not bp.IsValid():
        result.SetError("断点创建失败")
        return
    bp.SetScriptCallbackFunction("wechat_msg_monitor.on_msg_hit")
    bp.SetAutoContinue(True)
    print(">>> 断点 #{} 已设置 @ 0x{:x}（自动 continue）".format(bp.GetID(), bp_addr))
    print(">>> 输入 'continue' 让微信跑起来；收到的消息会打印在这里")
    print(">>> 停止监听：bp delete {}".format(bp.GetID()))


def cmd_stop(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    if not target:
        return
    print("请手动 'breakpoint delete <id>' 删除断点")


def cmd_stats(debugger, command, result, internal_dict):
    print("已捕获消息数: {}".format(_g_msg_count))
    print("去重表大小  : {}".format(len(_g_seen_svrid)))
    print("调试 dump 模式: {}".format("ON" if _g_debug_dump else "OFF"))


def cmd_debug_on(debugger, command, result, internal_dict):
    global _g_debug_dump
    _g_debug_dump = True
    print("[debug] dump 模式已打开。下次命中会输出原始字节。")


def cmd_debug_off(debugger, command, result, internal_dict):
    global _g_debug_dump
    _g_debug_dump = False
    print("[debug] dump 模式已关闭。")


def _deep_scan(process, addr, scan_size=0x200):
    print("    [deep_scan] @ 0x{:x}".format(addr))
    raw = _read_mem(process, addr, scan_size)
    if raw is None:
        print("    [deep_scan] 读取失败")
        return

    found = 0
    seen_ptrs = set()
    seen_ptrs.add(addr)
    for off in range(0, len(raw), 8):
        if off + 8 > len(raw):
            break
        ptr = struct.unpack("<Q", raw[off:off + 8])[0]
        if ptr < 0x100000000 or ptr > 0x10000000000:
            continue
        if ptr in seen_ptrs:
            continue
        seen_ptrs.add(ptr)

        sub = _read_mem(process, ptr, 96)
        if sub is None:
            continue

        for start in range(0, min(64, len(sub))):
            ok = 0
            for i in range(start, min(start + 8, len(sub))):
                b = sub[i]
                if 0x20 <= b < 0x7F:
                    ok += 1
                else:
                    break
            if ok >= 4:  # 放宽到 4 个连续字符
                end = start
                for i in range(start, min(start + 80, len(sub))):
                    if sub[i] == 0:
                        break
                    end = i + 1
                txt = sub[start:end]
                try:
                    s = txt.decode("utf-8", errors="replace")
                    print("      L1 +0x{:03x} -> 0x{:x} +0x{:02x}: {}".format(off, ptr, start, s))
                    found += 1
                except Exception:
                    pass
                break

        for sub_off in range(0, len(sub), 8):
            if sub_off + 8 > len(sub):
                break
            sub_ptr = struct.unpack("<Q", sub[sub_off:sub_off + 8])[0]
            if sub_ptr < 0x100000000 or sub_ptr > 0x10000000000:
                continue
            if sub_ptr in seen_ptrs:
                continue
            seen_ptrs.add(sub_ptr)
            sub2 = _read_mem(process, sub_ptr, 96)
            if sub2 is None:
                continue
            ok = 0
            for i in range(min(8, len(sub2))):
                if 0x20 <= sub2[i] < 0x7F:
                    ok += 1
                else:
                    break
            if ok >= 4:
                end = 0
                for i in range(min(80, len(sub2))):
                    if sub2[i] == 0:
                        break
                    end = i + 1
                txt = sub2[:end]
                try:
                    s = txt.decode("utf-8", errors="replace")
                    print("      L2 +0x{:03x}/+0x{:02x} -> 0x{:x}: {}".format(off, sub_off, sub_ptr, s))
                    found += 1
                except Exception:
                    pass

    if found == 0:
        print("    [deep_scan] 未发现可读字符串")
    else:
        print("    [deep_scan] 共 {} 处".format(found))


def cmd_scan_strings(debugger, command, result, internal_dict):
    # must be in breakpoint context or object freed
    args = command.strip().split()
    if not args:
        print("用法: wx_scan_strings <addr>")
        return
    try:
        addr = int(args[0], 16) if args[0].startswith("0x") else int(args[0])
    except ValueError:
        print("地址格式错误")
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    if not process or not process.IsValid():
        print("没有 process")
        return

    _deep_scan(process, addr)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f wechat_msg_monitor.cmd_start wx_monitor_start'
    )
    debugger.HandleCommand(
        'command script add -f wechat_msg_monitor.cmd_stop wx_monitor_stop'
    )
    debugger.HandleCommand(
        'command script add -f wechat_msg_monitor.cmd_stats wx_monitor_stats'
    )
    debugger.HandleCommand(
        'command script add -f wechat_msg_monitor.cmd_debug_on wx_monitor_debug_on'
    )
    debugger.HandleCommand(
        'command script add -f wechat_msg_monitor.cmd_debug_off wx_monitor_debug_off'
    )
    debugger.HandleCommand(
        'command script add -f wechat_msg_monitor.cmd_scan_strings wx_scan_strings'
    )
    print("[wechat_msg_monitor] 已加载。命令：")
    print("  wx_monitor_start      — 扫描特征码、下断点、开始监听")
    print("  wx_monitor_stop       — 停止监听")
    print("  wx_monitor_stats      — 查看统计")
    print("  wx_monitor_debug_on   — 打开 dump 调试模式")
    print("  wx_monitor_debug_off  — 关闭 dump 调试模式")
    print("  wx_scan_strings <addr> — 深度扫描对象里的字符串（需先 process interrupt）")

MONITOR_PY

}




do_monitor_foreground() {
    WECHAT_PID=$(pgrep -x WeChat | head -1 || true)
    if [ -z "$WECHAT_PID" ]; then
        echo "[ERROR] 微信未运行"; exit 1
    fi
    deploy_monitor_files
    INIT_FILE=$(mktemp /tmp/wx_monitor_init.XXXXXX)
    cat > "$INIT_FILE" << EOF
command script import "$MONITOR_INSTALL_DIR/wechat_msg_monitor.py"
process attach --pid $WECHAT_PID
wx_monitor_start
continue
EOF
    trap "rm -f $INIT_FILE" EXIT
    echo "[INFO] attach 微信 (pid=$WECHAT_PID)，Ctrl+C 退出"
    lldb -s "$INIT_FILE"
}

# ── 后台 daemon ──────────────────────────────────────────
MONITOR_LABEL="com.wechatintercept.monitor"
MONITOR_PLIST="$HOME/Library/LaunchAgents/${MONITOR_LABEL}.plist"
MONITOR_DAEMON="$MONITOR_INSTALL_DIR/monitor_daemon.sh"
MONITOR_LOG="/tmp/wechat_monitor_daemon.log"
MONITOR_PID="/tmp/wechat_monitor_daemon.pid"

deploy_daemon() {
    deploy_monitor_files
    cat > "$MONITOR_DAEMON" << 'DAEMON_SH'
#!/bin/bash
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PY_SCRIPT="$SCRIPT_DIR/wechat_msg_monitor.py"
LOG="/tmp/wechat_monitor_daemon.log"
PID_FILE="/tmp/wechat_monitor_daemon.pid"
log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }
cleanup() { [ -n "${LLDB_PID:-}" ] && kill "$LLDB_PID" 2>/dev/null; rm -f "$PID_FILE"; exit 0; }
trap cleanup INT TERM EXIT
[ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null && exit 0
echo $$ > "$PID_FILE"
log "daemon start pid=$$"
LLDB_PID="" ; LAST_PID=""
while true; do
    WPID=$(pgrep -x WeChat | head -1 || true)
    if [ -z "$WPID" ]; then
        [ -n "$LLDB_PID" ] && kill "$LLDB_PID" 2>/dev/null && wait "$LLDB_PID" 2>/dev/null
        LLDB_PID="" ; LAST_PID=""
        sleep 3; continue
    fi
    if [ "$WPID" != "$LAST_PID" ] || [ -z "$LLDB_PID" ] || ! kill -0 "$LLDB_PID" 2>/dev/null; then
        [ -n "$LLDB_PID" ] && kill "$LLDB_PID" 2>/dev/null && wait "$LLDB_PID" 2>/dev/null
        log "attach wechat pid=$WPID"
        INIT=$(mktemp /tmp/wx_mon.XXXXXX)
        cat > "$INIT" << LLDBEOF
command script import "$PY_SCRIPT"
process attach --pid $WPID
wx_monitor_start
continue
LLDBEOF
        lldb -b -s "$INIT" >> "$LOG" 2>&1 &
        LLDB_PID=$!
        LAST_PID="$WPID"
        sleep 5
        rm -f "$INIT"
    fi
    sleep 5
done
DAEMON_SH
    chmod +x "$MONITOR_DAEMON"
}

do_monitor_install() {
    deploy_daemon
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$MONITOR_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MONITOR_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${MONITOR_DAEMON}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${MONITOR_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${MONITOR_LOG}</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
EOF
    launchctl unload "$MONITOR_PLIST" 2>/dev/null || true
    launchctl load "$MONITOR_PLIST"
    echo "[OK] 消息监听已安装（后台自动运行）"
    echo "     日志：tail -f $MONITOR_LOG"
    echo "     状态：$0 --monitor-status"
    echo "     卸载：$0 --monitor-uninstall"
}

do_monitor_uninstall() {
    [ -f "$MONITOR_PLIST" ] && launchctl unload "$MONITOR_PLIST" 2>/dev/null && rm -f "$MONITOR_PLIST"
    [ -f "$MONITOR_PID" ] && kill "$(cat "$MONITOR_PID" 2>/dev/null)" 2>/dev/null; rm -f "$MONITOR_PID"
    [ -d "$MONITOR_INSTALL_DIR" ] && rm -rf "$MONITOR_INSTALL_DIR"
    echo "[OK] 消息监听已卸载"
}

do_monitor_status() {
    [ -f "$MONITOR_PLIST" ] && echo "LaunchAgent: 已安装" || echo "LaunchAgent: 未安装"
    if [ -f "$MONITOR_PID" ] && kill -0 "$(cat "$MONITOR_PID" 2>/dev/null)" 2>/dev/null; then
        echo "daemon: 运行中 (pid=$(cat "$MONITOR_PID"))"
    else echo "daemon: 未运行"; fi
    WPID=$(pgrep -x WeChat | head -1 || true)
    [ -n "$WPID" ] && echo "微信: 运行中 (pid=$WPID)" || echo "微信: 未运行"
    [ -f /tmp/wechat_msg_cache.tsv ] && echo "缓存: $(wc -l < /tmp/wechat_msg_cache.tsv) 行" || echo "缓存: 空"
    [ -f "$MONITOR_LOG" ] && echo "" && echo "── 最近日志 ──" && tail -5 "$MONITOR_LOG"
}

# ======================== 入口 ========================
# 允许回归测试只载入函数定义，不触发安装或关闭微信。
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi
case "${1:-}" in
    --install|-i)
        do_install
        ;;
    --debug|-d)
        do_debug
        ;;
    --uninstall|-u)
        do_uninstall
        ;;
    --monitor)
        do_monitor_foreground
        ;;
    --monitor-install)
        do_monitor_install
        ;;
    --monitor-uninstall)
        do_monitor_uninstall
        ;;
    --monitor-status)
        do_monitor_status
        ;;
    --help|-h)
        print_banner
        echo "用法:"
        echo "  $0                     安装防撤回"
        echo "  $0 --install           安装防撤回"
        echo "  $0 --monitor-install   安装消息监听（后台自动运行）"
        echo "  $0 --monitor-uninstall 卸载消息监听"
        echo "  $0 --monitor-status    查看监听状态"
        echo "  $0 --monitor           前台运行消息监听（调试用）"
        echo "  $0 --debug             调试模式（无 hook，允许 lldb）"
        echo "  $0 --uninstall         卸载防撤回"
        echo "  $0 --help              帮助"
        ;;
    "")
        do_install
        ;;
    *)
        echo "[ERROR] 未知参数: $1"
        echo "用法: $0 [--help]"
        exit 1
        ;;
esac
