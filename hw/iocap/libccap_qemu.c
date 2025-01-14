// Implementations of the platform-specific libccap functions for QEMU.
// NOT PART OF libccap!

#include "hw/iocap/iocap.h"

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "crypto/aes.h"

void aes_encrypt_128_func(const CCapU128* secret, const CCapU128* data, CCapU128* result) {
    AES_KEY key;
    AES_set_encrypt_key(*secret, 128, &key); // TODO signal failure if this is nonzero?
    AES_encrypt(*data, *result, &key);
}

uint64_t ccap_panic_write_utf8(const uint8_t *utf8, uint64_t utf_len) {
    error_printf("libccap panic: %.*s\n", utf_len, utf8);
}