#define WECHATINTERCEPT_TEST 1
#include "../hook.m"
#include <assert.h>

#if defined(__arm64__)
// The fifth instruction saves x19/x20. A 20-byte detour with a 16-byte
// gateway silently skips it and corrupts the caller after the function returns.
__attribute__((naked, noinline)) static int step_fixture(void) {
    __asm__ volatile(
        "stp x28, x27, [sp, #-0x60]!\n"
        "stp x26, x25, [sp, #0x10]\n"
        "stp x24, x23, [sp, #0x20]\n"
        "stp x22, x21, [sp, #0x30]\n"
        "stp x20, x19, [sp, #0x40]\n"
        "stp x29, x30, [sp, #0x50]\n"
        "add x29, sp, #0x50\n"
        "mov x19, #0x55\n"
        "mov x20, #0x66\n"
        "mov w0, #100\n"
        "ldp x29, x30, [sp, #0x50]\n"
        "ldp x20, x19, [sp, #0x40]\n"
        "ldp x22, x21, [sp, #0x30]\n"
        "ldp x24, x23, [sp, #0x20]\n"
        "ldp x26, x25, [sp, #0x10]\n"
        "ldp x28, x27, [sp], #0x60\n"
        "ret\n");
}

static int (*step_gateway)(void);
static int step_hook(void) { return step_gateway(); }

__attribute__((naked, noinline)) static int saved_registers_survive(void *function) {
    __asm__ volatile(
        "stp x20, x19, [sp, #-0x20]!\n"
        "stp x29, x30, [sp, #0x10]\n"
        "add x29, sp, #0x10\n"
        "mov x16, x0\n"
        "mov x19, #0x123\n"
        "mov x20, #0x456\n"
        "blr x16\n"
        "cmp w0, #100\n"
        "cset w9, eq\n"
        "cmp x19, #0x123\n"
        "cset w0, eq\n"
        "and w0, w0, w9\n"
        "cmp x20, #0x456\n"
        "cset w1, eq\n"
        "and w0, w0, w1\n"
        "ldp x29, x30, [sp, #0x10]\n"
        "ldp x20, x19, [sp], #0x20\n"
        "ret\n");
}

static void test_resuming_trampoline(void) {
    size_t size = (size_t)getpagesize();
    uint8_t *code = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(code != MAP_FAILED);
    memcpy(code, (void *)step_fixture, 17 * sizeof(uint32_t));
    memcpy(code + 128, code, 16);
    uint32_t fifth;
    memcpy(&fifth, code + 16, sizeof(fifth));
    assert(fifth == 0xa9044ff4);
    assert(install_arm64_trampoline((uintptr_t)code + 144, (uintptr_t)code + 16));
    step_gateway = (int (*)(void))(code + 128);
    assert(saved_registers_survive(code));
    assert(install_arm64_trampoline((uintptr_t)code, (uintptr_t)step_hook));
    assert(saved_registers_survive(code));
    assert(!memcmp(code + 16, &fifth, sizeof(fifth)));
    munmap(code, size);
}
#endif

int main(void) {
#if defined(__arm64__)
    test_resuming_trampoline();
#endif
    const uint32_t arm_pattern[] = {
        0xB9400C08u, 0x5284E249u, 0x6B09011Fu, 0x1A9F17E0u, 0xD65F03C0u
    };
    const uint8_t x86_pattern[] = {
        0x55, 0x48, 0x89, 0xE5, 0x81, 0x7F, 0x0C, 0x12,
        0x27, 0x00, 0x00, 0x0F, 0x94, 0xC0, 0x5D, 0xC3
    };
    uint32_t arm_text[32] = {0};
    uint8_t x86_text[128] = {0};
    assert(scan_isRevokeMessage_arm64((uintptr_t)arm_text, sizeof(arm_text)) == 0);
    assert(scan_isRevokeMessage_x86_64((uintptr_t)x86_text, sizeof(x86_text)) == 0);
    memcpy(arm_text + 4, arm_pattern, sizeof(arm_pattern));
    memcpy(x86_text + 16, x86_pattern, sizeof(x86_pattern));
    assert(scan_isRevokeMessage_arm64((uintptr_t)arm_text, sizeof(arm_text)) == (uintptr_t)(arm_text + 4));
    assert(scan_isRevokeMessage_x86_64((uintptr_t)x86_text, sizeof(x86_text)) == (uintptr_t)(x86_text + 16));
    memcpy(arm_text + 16, arm_pattern, sizeof(arm_pattern));
    memcpy(x86_text + 64, x86_pattern, sizeof(x86_pattern));
    assert(scan_isRevokeMessage_arm64((uintptr_t)arm_text, sizeof(arm_text)) == 0);
    assert(scan_isRevokeMessage_x86_64((uintptr_t)x86_text, sizeof(x86_text)) == 0);

    // 不读取真实登录信息、不发送通知、不操作实际微信。
    g_my_id_loaded = 1;
    strcpy(g_my_id, "wxid_me");
    uint8_t msg[0x150] = {0};
    assert(hook_isRevokeMessage(NULL) == 0);
    assert(hook_isRevokeMessage((void *)1) == 0);
    assert(hook_isRevokeMessage(msg) == 0);
    memcpy(msg + 0x0C, &kRevokeType, sizeof(kRevokeType));
    assert(hook_isRevokeMessage(msg) == 1);
    strcpy((char *)msg + 0x18, "wxid_me");
    assert(hook_isRevokeMessage(msg) == 1);
    strcpy((char *)msg + 0x18, "wxid_other");
    assert(hook_isRevokeMessage(msg) == 0);
    strcpy((char *)msg + 0x18, "wxid_me_suffix");
    assert(hook_isRevokeMessage(msg) == 0);
    strcpy((char *)msg + 0x18, "wxid_other");
    uint64_t bad_xml[] = {1, 128};
    memcpy(msg + 0x130, bad_xml, sizeof(bad_xml));
    assert(hook_isRevokeMessage(msg) == 0);
    memset(msg + 0x18, 0xff, 72);
    assert(hook_isRevokeMessage(msg) == 1);
    memset(msg + 0x18, 'a', 72);
    assert(hook_isRevokeMessage(msg) == 1);
    memset(msg + 0x18, 0, 72);
    strcpy((char *)msg + 0x18, "wxid_other");

    // 在独立匿名页验证真正的跳转指令与执行权限恢复，不修改应用代码页。
    size_t page_size = (size_t)getpagesize();
    void *code = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(code != MAP_FAILED);
#if defined(__arm64__)
    memcpy(code, arm_pattern, sizeof(arm_pattern));
    sys_icache_invalidate(code, sizeof(arm_pattern));
#else
    memcpy(code, x86_pattern, sizeof(x86_pattern));
#endif
    assert(make_rx((uintptr_t)code, page_size) == KERN_SUCCESS);
    _Bool (*predicate)(void *) = (_Bool (*)(void *))code;
    assert(predicate(msg) == 1);
#if defined(__arm64__)
    assert(install_arm64_trampoline((uintptr_t)code, (uintptr_t)&hook_isRevokeMessage));
#else
    assert(install_x86_64_trampoline((uintptr_t)code, (uintptr_t)&hook_isRevokeMessage));
#endif
    assert(predicate(msg) == 0);
    munmap(code, page_size);
    puts("PASS: unique pattern scans, bounded message reads, revoke decisions, executable trampoline");
    return 0;
}
