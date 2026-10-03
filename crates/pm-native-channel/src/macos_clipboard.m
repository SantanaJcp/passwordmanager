// SPDX-License-Identifier: AGPL-3.0-only

#import <AppKit/AppKit.h>
#include <stdint.h>

int32_t pm_macos_clipboard_copy(const uint8_t *bytes, uintptr_t length,
                                int64_t *change_count) {
  @autoreleasepool {
    if (bytes == NULL || length == 0 || change_count == NULL) return -1;
    NSString *value = [[NSString alloc] initWithBytes:bytes
                                               length:length
                                             encoding:NSUTF8StringEncoding];
    if (value == nil) return -1;
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    if (pasteboard == nil) return -1;
    [pasteboard clearContents];
    if (![pasteboard setString:value forType:NSPasteboardTypeString]) return -1;
    *change_count = (int64_t)[pasteboard changeCount];
    return 0;
  }
}

int32_t pm_macos_clipboard_clear_if_owned(int64_t change_count) {
  @autoreleasepool {
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    if (pasteboard == nil) return -1;
    if ((int64_t)[pasteboard changeCount] != change_count) return 0;
    [pasteboard clearContents];
    return 1;
  }
}
