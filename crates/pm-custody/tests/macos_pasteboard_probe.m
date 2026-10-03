// SPDX-License-Identifier: AGPL-3.0-only
// Test-only observer. Never emits pasteboard contents or their digest.
#import <AppKit/AppKit.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 3 || strlen(argv[2]) != 64) return 64;
    char *end = NULL;
    unsigned long expectedLength = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || expectedLength == 0 || expectedLength > UINT32_MAX) return 64;
    for (size_t i = 0; i < 64; i++) {
      if (!((argv[2][i] >= '0' && argv[2][i] <= '9') ||
            (argv[2][i] >= 'a' && argv[2][i] <= 'f'))) return 64;
    }
    NSPasteboard *board = [NSPasteboard generalPasteboard];
    if (board == nil) {
      // An explicit completed native rejection, distinguishable from timeout,
      // malformed observation, bad arguments, signal or a nil types response.
      puts("PM26_PB denied=pasteboard-null");
      return 69;
    }
    NSInteger before = [board changeCount];
    NSArray *types = [board types];
    NSString *text = [board stringForType:NSPasteboardTypeString];
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    BOOL canary = NO;
    if (data != nil && [data length] >= expectedLength) {
      const unsigned char *bytes = [data bytes];
      // Preserve the original probe's substring oracle, including a canary
      // surrounded by other bytes. No data or digest leaves this observer.
      for (NSUInteger offset = 0; offset <= [data length] - expectedLength; offset++) {
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(bytes + offset, (CC_LONG)expectedLength, digest);
        char hex[65];
        for (size_t i = 0; i < sizeof(digest); i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
        if (strcmp(hex, argv[2]) == 0) { canary = YES; break; }
      }
    }
    const char *typeCategory = types == nil ? "unavailable" :
      [types count] == 0 ? "empty" :
      [types containsObject:NSPasteboardTypeString] ? "string" : "other";
    printf("PM26_PB types=%s text=%s canary=%s stable=%s\n", typeCategory,
           text == nil ? "nil" : "value", canary ? "present" : "absent",
           before == [board changeCount] ? "yes" : "no");
    return 0;
  }
}
