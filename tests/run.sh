#!/bin/bash
set -euo pipefail

TEST_REPO=$(cd "$(dirname "$0")/.." && pwd)
TEST_TMP=$(mktemp -d /private/tmp/WeChatIntercept-tests.XXXXXX)
source "$TEST_REPO/patch.sh"

bash -n "$TEST_REPO/patch.sh"
clang -arch arm64 -arch x86_64 -fobjc-arc -fsyntax-only -x objective-c \
    "$TEST_REPO/hook.m" -Wno-incompatible-pointer-types
clang -fobjc-arc -framework Foundation -framework AppKit -Wno-incompatible-pointer-types \
    "$TEST_REPO/tests/hook_test.m" -o "$TEST_TMP/hook_test"
"$TEST_TMP/hook_test"
clang -fobjc-arc -framework Foundation -framework AppKit -Wno-incompatible-pointer-types \
    "$TEST_REPO/tests/marker_test.m" -o "$TEST_TMP/marker_test"
"$TEST_TMP/marker_test"

# 只对临时主程序副本做双架构往返测试，不签名或触碰实际应用。
TEST_ORIGINAL="/Applications/WeChat.app/Contents/MacOS/WeChat"
if [ -f "$ORIGINAL_APP/Contents/MacOS/WeChat" ]; then
    TEST_ORIGINAL="$ORIGINAL_APP/Contents/MacOS/WeChat"
fi
WECHAT_BIN="$TEST_TMP/WeChat"
cp -p "$TEST_ORIGINAL" "$WECHAT_BIN"
inject_dylib
for TEST_ARCH in $(lipo -archs "$WECHAT_BIN"); do
    otool -arch "$TEST_ARCH" -L "$WECHAT_BIN" | grep -F "$DYLIB_INSTALL_NAME" >/dev/null
done
remove_injected_load_command
cmp "$TEST_ORIGINAL" "$WECHAT_BIN"
printf '%s\n' 'PASS: Mach-O injection/uninstall restores both slices byte-for-byte'
printf 'Test artifacts: %s\n' "$TEST_TMP"
