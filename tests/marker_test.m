#define WECHATINTERCEPT_TEST 1
#include "../hook.m"
#include <assert.h>

typedef struct {
    uint8_t object[0x600];
    uint8_t private[64];
    uint32_t widgetData[9];
    uintptr_t table[1];
    uint32_t getter[7];
    uintptr_t meta[4];
    uint32_t metadata[2];
    struct { int32_t ref, length; uint32_t flags, padding; intptr_t offset; char name[64]; } strings;
} FakeWidget;

static void set_pointer(void *memory, size_t offset, uintptr_t value) {
    memcpy((uint8_t *)memory + offset, &value, sizeof(value));
}

static void widget_init(FakeWidget *fixture, const char *name, uintptr_t parent,
                        int x, int y, int width, int height) {
    memset(fixture, 0, sizeof(*fixture));
    set_pointer(fixture->object, 0, (uintptr_t)fixture->table);
    set_pointer(fixture->object, 8, (uintptr_t)fixture->private);
    set_pointer(fixture->object, 40, (uintptr_t)fixture->widgetData);
    set_pointer(fixture->private, 8, (uintptr_t)fixture->object);
    set_pointer(fixture->private, 16, parent);
    fixture->private[32] = 1;
    fixture->widgetData[2] = 1 << 15;
    fixture->widgetData[5] = x;
    fixture->widgetData[6] = y;
    fixture->widgetData[7] = x + width - 1;
    fixture->widgetData[8] = y + height - 1;
    fixture->table[0] = (uintptr_t)fixture->getter;
    fixture->getter[0] = 0xf9400400;
    fixture->getter[1] = 0xf9401408;
    fixture->getter[2] = 0xb4000048;
    fixture->getter[3] = 0x14000000;
    intptr_t pages = ((uintptr_t)fixture->meta & ~(uintptr_t)4095) -
                     (((uintptr_t)fixture->getter + 16) & ~(uintptr_t)4095);
    uint32_t immediate = (uint32_t)(pages / 4096) & 0x1fffff;
    fixture->getter[4] = 0x90000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5);
    fixture->getter[5] = 0x91000000 | (((uintptr_t)fixture->meta & 4095) << 10);
    fixture->getter[6] = 0xd65f03c0;
    fixture->meta[1] = (uintptr_t)&fixture->strings;
    fixture->meta[2] = (uintptr_t)fixture->metadata;
    fixture->metadata[0] = 8;
    fixture->strings.length = (int32_t)strlen(name);
    fixture->strings.offset = 24;
    strcpy(fixture->strings.name, name);
}

int main(void) {
    @autoreleasepool {
        uint64_t identifier;
        assert(ar_decimal_id(@"18446744073709551615", &identifier) && identifier == UINT64_MAX);
        assert(!ar_decimal_id(@"18446744073709551616", &identifier));
        assert(!ar_decimal_id(@"0", &identifier));
        assert(!ar_decimal_id(@"123x", &identifier));
        NSString *xml = @"<sysmsg type=\"revokemsg\"><revokemsg><session>123@chatroom</session>"
            "<newmsgid>9876543210123456789</newmsgid><replacemsg><![CDATA[test]]>"
            "</replacemsg></revokemsg></sysmsg>";
        NSDictionary *parsed = ar_recall_from_xml(xml);
        assert([parsed[@"session"] isEqual:@"123@chatroom"]);
        assert([parsed[@"id"] unsignedLongLongValue] == 9876543210123456789ull);
        assert(!ar_recall_from_xml([xml stringByReplacingOccurrencesOfString:@"9876543210123456789"
                                                               withString:@"18446744073709551616"]));
        assert(!ar_recall_from_xml([xml stringByReplacingOccurrencesOfString:@"</newmsgid>"
                              withString:@"</newmsgid><newmsgid>42</newmsgid>"]));
        assert(!ar_recall_from_xml([xml stringByReplacingOccurrencesOfString:@"123@chatroom"
                                                               withString:@"bad|session"]));
        assert(!ar_recall_from_xml([@"<!DOCTYPE sysmsg>" stringByAppendingString:xml]));
        assert(!ar_recall_from_xml(@"<sysmsg><revokemsg><newmsgid>1</newmsgid></revokemsg></sysmsg>"));
        assert(ar_valid_stored_key(@"wxid_me|123@chatroom|42"));
        assert(!ar_valid_stored_key(@"wxid_me|123@chatroom|0"));
        assert(!ar_valid_stored_key((id)@42));

        uint8_t shortString[24] = {0};
        strcpy((char *)shortString, "wxid_short");
        shortString[23] = 10;
        assert([ar_cpp_string((uintptr_t)shortString, 127) isEqual:@"wxid_short"]);
        shortString[23] = 23;
        assert(!ar_cpp_string((uintptr_t)shortString, 127));
        const char *longText = "123456789012345678901234567890";
        uint64_t longString[] = {(uintptr_t)longText, 30, 0x8000000000000020ull};
        assert([ar_cpp_string((uintptr_t)longString, 127) isEqual:@"123456789012345678901234567890"]);
        assert(!ar_cpp_string((uintptr_t)longString, 20));
        longString[0] = 1;
        assert(!ar_cpp_string((uintptr_t)longString, 127));

        NSRect viewport = NSMakeRect(0, 0, 500, 500), cell = NSMakeRect(0, 10, 500, 57);
        NSRect bubble = NSMakeRect(60, 18, 100, 37);
        NSRect badge = ar_badge_rect(bubble, cell, viewport, @[[NSValue valueWithRect:bubble]]);
        assert(!NSIsEmptyRect(badge) && NSMinX(badge) == 166);
        assert(NSIsEmptyRect(ar_badge_rect(bubble, cell, NSMakeRect(0, 0, 500, 10), @[])));
        assert(NSIsEmptyRect(ar_badge_rect(bubble, cell, viewport,
            @[[NSValue valueWithRect:NSMakeRect(165, 10, 100, 60)]])));
        bubble.size.width = 420;
        badge = ar_badge_rect(bubble, cell, viewport, @[]);
        assert(!NSIsEmptyRect(badge) && NSMinY(badge) == 56);
        assert(NSIsEmptyRect(ar_badge_rect(bubble, cell, viewport,
            @[[NSValue valueWithRect:NSMakeRect(60, 56, 100, 15)]])));

#if defined(__arm64__)
        gARMetaCache = [NSMutableDictionary dictionary];
        FakeWidget root, row;
        widget_init(&root, "QWidget", 0, 111, 222, 500, 500);
        widget_init(&row, "mmui::ChatItemView", (uintptr_t)root.object, 60, 40, 100, 57);
        assert(ar_qt_inherits((uintptr_t)row.object, @"mmui::ChatItemView"));
        NSRect geometry;
        assert(ar_qt_global_rect((uintptr_t)row.object, (uintptr_t)root.object, &geometry));
        assert(NSEqualRects(geometry, NSMakeRect(60, 40, 100, 57)));
        root.widgetData[2] = 0;
        assert(!ar_qt_global_rect((uintptr_t)row.object, (uintptr_t)root.object, &geometry));
        root.widgetData[2] = 1 << 15;
        uint8_t model[0x350] = {0};
        gARMessageInfoTable = 0x12345678;
        set_pointer(row.object, 0x230, (uintptr_t)model);
        set_pointer(model, 0x120, gARMessageInfoTable);
        set_pointer(model, 0x1b0, 9876543210123456789ull);
        memcpy(model + 0x160, "123@chatroom", 12);
        model[0x177] = 12;
        assert([ar_cpp_string((uintptr_t)model + 0x160, 127) isEqual:@"123@chatroom"]);
        NSString *key = ar_message_key((uintptr_t)row.object, @"wxid_me");
        assert([key isEqual:@"wxid_me|123@chatroom|9876543210123456789"]);
        set_pointer(model, 0x1b0, 42); // 行复用：必须读取新的 ID，不能沿用旧标记。
        assert(![ar_message_key((uintptr_t)row.object, @"wxid_me") isEqual:key]);
        set_pointer(model, 0x120, 0);
        assert(!ar_message_key((uintptr_t)row.object, @"wxid_me"));
        set_pointer(row.object, 0x230, 1);
        assert(!ar_message_key((uintptr_t)row.object, @"wxid_me"));
        assert(!ar_qt_meta(1));
        assert(!ar_marker_supported_core(NULL));
#endif
    }
    puts("PASS: recall XML, full-width IDs, account/session isolation, safe Qt reads, reuse and clipping");
    return 0;
}
