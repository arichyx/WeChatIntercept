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

        NSString *stickerXML = @"<msg><emoji "
            "md5=\"0123456789abcdef0123456789ABCDEF\" "
            "cdnurl=\"http://vweixinf.tc.qq.com/stodownload?m=1&amp;n=2\" "
            "tpurl=\"https://evil.example.invalid/sticker\" "
            "encrypturl=\"http://wxapp.tc.qq.com:80/encrypted\" "
            "aeskey=\"00112233445566778899aabbccddeeff\"/></msg>";
        ARStickerPayload *sticker = ar_sticker_payload_from_xml(stickerXML);
        assert(sticker);
        assert([sticker.identifier isEqual:@"0123456789abcdef0123456789abcdef"]);
        assert(sticker.plainURLs.count == 2);
        assert([sticker.plainURLs[0].scheme isEqual:@"https"]);
        assert([sticker.plainURLs[0].host isEqual:@"vweixinf.tc.qq.com"]);
        assert([sticker.plainURLs[1].scheme isEqual:@"https"]);
        assert([sticker.plainURLs[1].host isEqual:@"wxapp.tc.qq.com"]);
        assert(sticker.aesKey.length == 16);
        assert([sticker.encryptedURL.absoluteString isEqual:
            @"https://wxapp.tc.qq.com/encrypted"]);
        assert([sticker.plainURLs[0].query isEqual:@"m=1&n=2"]);
        assert([ar_sticker_safe_url(@"http://qpic.cn:80/a?token=a%2Fb#fragment").absoluteString
            isEqual:@"https://qpic.cn/a?token=a%2Fb"]);
        assert(!ar_sticker_safe_url(@"https://qq.com.evil.example/sticker"));
        assert(!ar_sticker_safe_url(@"https://evilqq.com/sticker"));
        assert(!ar_sticker_safe_url(@"https://user@qq.com/sticker"));
        assert(!ar_sticker_safe_url(@"https://qpic.cn:444/sticker"));
        assert(!ar_sticker_payload_from_xml(
            [@"<!DOCTYPE msg>" stringByAppendingString:stickerXML]));
        assert(!ar_sticker_payload_from_xml(
            [stickerXML stringByReplacingOccurrencesOfString:@"</msg>"
                withString:@"<emoji md5=\"0123456789abcdef0123456789abcdef\"/></msg>"]));
        ARStickerPayload *md5Only = ar_sticker_payload_from_xml(
            @"<msg><emoji md5=\"0123456789abcdef0123456789abcdef\" "
             "cdnurl=\"https://example.invalid/sticker\"/></msg>");
        assert(md5Only && md5Only.plainURLs.count == 0 && !md5Only.encryptedURL);
        uint8_t xmlBuffer[8192] = {0};
        memcpy(xmlBuffer + 0x4f0, stickerXML.UTF8String,
               strlen(stickerXML.UTF8String));
        assert([ar_sticker_xml_in_buffer(xmlBuffer, sizeof(xmlBuffer))
            isEqual:stickerXML]);
        memset(xmlBuffer, 0, sizeof(xmlBuffer));
        memcpy(xmlBuffer, "<msg><emoji", 11);
        assert(!ar_sticker_xml_in_buffer(xmlBuffer, sizeof(xmlBuffer)));

        // Actual 2x2 images, not signatures that a decoder would reject.
        NSData *pngBytes = [[NSData alloc] initWithBase64EncodedString:
            @"iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAFklEQVR42mPUrb3OwMDAxMDAwMDAAAARjAGFEWmcowAAAABJRU5ErkJggg=="
            options:0];
        NSMutableData *wrappedPNG = [NSMutableData dataWithBytes:"prefix" length:6];
        [wrappedPNG appendData:pngBytes];
        [wrappedPNG appendBytes:"suffix" length:6];
        ARStickerImage *png = ar_sticker_image(wrappedPNG);
        assert([png.extension isEqual:@"png"]);
        assert([png.data isEqual:pngBytes]);
        NSData *jpegBytesValid = [[NSData alloc] initWithBase64EncodedString:
            @"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAACAAIDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAX/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAABv/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AJwBoKv/2Q=="
            options:0];
        assert([ar_sticker_image(jpegBytesValid).extension isEqual:@"jpg"]);
        const uint8_t jpegBytes[] = {0xff,0xd8,0xff,0xe0,0x01,0x02,0xff,0xd9};
        assert(!ar_sticker_image([NSData dataWithBytes:jpegBytes length:sizeof(jpegBytes)]));
        NSData *webpBytesValid = [[NSData alloc] initWithBase64EncodedString:
            @"UklGRh4AAABXRUJQVlA4TBEAAAAvAUAAAAfQvrb0uv+BiOh/AAA=" options:0];
        assert([ar_sticker_image(webpBytesValid).extension isEqual:@"webp"]);
        const uint8_t webpBytes[] = {
            'R','I','F','F',4,0,0,0,'W','E','B','P'
        };
        assert(!ar_sticker_image([NSData dataWithBytes:webpBytes length:sizeof(webpBytes)]));
        assert(!ar_sticker_image([@"not an image" dataUsingEncoding:NSUTF8StringEncoding]));

        NSData *aesKey = ar_sticker_hex_data(@"00112233445566778899aabbccddeeff");
        const uint8_t clearBytes[16] = {
            0x89,'P','N','G',0x0d,0x0a,0x1a,0x0a,0,0,0,0,'I','E','N','D'
        };
        NSMutableData *cipher = [NSMutableData dataWithLength:32];
        size_t cipherLength = 0;
        assert(CCCrypt(kCCEncrypt, kCCAlgorithmAES, 0, aesKey.bytes, aesKey.length,
            aesKey.bytes, clearBytes, sizeof(clearBytes), cipher.mutableBytes,
            cipher.length, &cipherLength) == kCCSuccess);
        cipher.length = cipherLength;
        assert([ar_sticker_decrypt(cipher, aesKey)
            isEqual:[NSData dataWithBytes:clearBytes length:sizeof(clearBytes)]]);
        assert(!ar_sticker_decrypt([cipher subdataWithRange:NSMakeRange(0, 15)], aesKey));

        const uint32_t qtSignal[] = {
            0x90000001, 0x91000021, 0x52800002, 0xd2800003, 0x14000000
        };
        assert(ar_sticker_qt_signal_shape(qtSignal));
        uint32_t badQtSignal[5];
        memcpy(badQtSignal, qtSignal, sizeof(badQtSignal));
        badQtSignal[2] = 0x52800022;
        assert(!ar_sticker_qt_signal_shape(badQtSignal));
        memcpy(badQtSignal, qtSignal, sizeof(badQtSignal));
        badQtSignal[4] = 0xd65f03c0;
        assert(!ar_sticker_qt_signal_shape(badQtSignal));
        uintptr_t decoderAddress = (uintptr_t)qtSignal;
        assert(ar_sticker_qt_adrp_add_target(decoderAddress,
            0x90000001, 0x91000021) == (decoderAddress & ~(uintptr_t)0xfff));
        assert(ar_sticker_qt_branch_target(decoderAddress,
            0x14000002) == decoderAddress + 8);
        assert(ar_sticker_qt_branch_target(decoderAddress,
            0x17ffffff) == decoderAddress - 4);

        NSData *gifBytes = [[NSData alloc] initWithBase64EncodedString:
            @"R0lGODlhAgACAIEAAC191wAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQACAAAACwAAAAAAgACAAAIBgABCAQQEAAh+QQBCAABACwAAAAAAgACAIHweBQAAAAAAAAAAAAIBgABCAQQEAA7"
            options:0];
        ARStickerImage *gif = ar_sticker_image(gifBytes);
        assert([gif.extension isEqual:@"gif"] && [gif.data isEqual:gifBytes]);
        CGImageSourceRef gifSource = CGImageSourceCreateWithData((__bridge CFDataRef)gif.data, NULL);
        assert(gifSource && CGImageSourceGetCount(gifSource) == 2);
        CFRelease(gifSource);
        assert(!ar_sticker_image([gifBytes subdataWithRange:NSMakeRange(0, gifBytes.length - 4)]));
        assert(!ar_sticker_image([@"GIF89a1234" dataUsingEncoding:NSUTF8StringEncoding]));
        const uint8_t ivBytes[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        NSMutableData *encryptedSticker = [NSMutableData dataWithLength:
            sizeof(ivBytes) + gifBytes.length + 16];
        memcpy(encryptedSticker.mutableBytes, ivBytes, sizeof(ivBytes));
        size_t encryptedStickerLength = 0;
        assert(CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            aesKey.bytes, aesKey.length, ivBytes, gifBytes.bytes, gifBytes.length,
            (uint8_t *)encryptedSticker.mutableBytes + sizeof(ivBytes),
            encryptedSticker.length - sizeof(ivBytes),
            &encryptedStickerLength) == kCCSuccess);
        encryptedSticker.length = sizeof(ivBytes) + encryptedStickerLength;
        assert([ar_sticker_decrypt_image(encryptedSticker, aesKey).extension
            isEqual:@"gif"]);
        assert([ar_sticker_decrypt_image(encryptedSticker, aesKey).data isEqual:gifBytes]);

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
        uint8_t model[0x1200] = {0};
        uint8_t stickerBuffer[8192] = {0};
        gARMessageInfoTable = 0x12345678;
        set_pointer(row.object, 0x230, (uintptr_t)model);
        set_pointer(model, 0x120, gARMessageInfoTable);
        uint8_t payloadObject[0x300] = {0};
        size_t stickerLength = strlen(stickerXML.UTF8String);
        uint64_t *payloadString = (uint64_t *)(payloadObject + 0x130);
        payloadString[0] = (uintptr_t)stickerXML.UTF8String;
        payloadString[1] = stickerLength;
        payloadString[2] = 0x8000000000000000ull | (stickerLength + 1);
        *(uint32_t *)(model + 0x128) = 47;
        set_pointer(model, 0x358, (uintptr_t)payloadObject);
        gARMarkerReady = YES;
        assert(ar_sticker_payload_for_view((uintptr_t)row.object));
        *(uint32_t *)(model + 0x128) = 1;
        assert(!ar_sticker_payload_for_view((uintptr_t)row.object));
        *(uint32_t *)(model + 0x128) = 47;
        set_pointer(model, 0x358, 0);
        memcpy(model + 0x5f8, stickerXML.UTF8String,
               strlen(stickerXML.UTF8String));
        assert(ar_sticker_payload_for_view((uintptr_t)row.object));
        memset(model + 0x5f8, 0, strlen(stickerXML.UTF8String));
        memcpy(stickerBuffer + 0x502, stickerXML.UTF8String,
               strlen(stickerXML.UTF8String));
        set_pointer(model, 0x530, (uintptr_t)stickerBuffer);
        assert(ar_sticker_payload_for_view((uintptr_t)row.object));
        gARMarkerReady = NO;
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
    puts("PASS: recall/sticker XML, safe URLs, image/AES validation, Qt reads, reuse and clipping");
    return 0;
}
