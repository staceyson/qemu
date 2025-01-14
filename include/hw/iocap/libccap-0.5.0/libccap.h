/**
* A library for using I/O capabilities with cryptographic protection, a.k.a. crypto-caps, a.k.a. ccaps.
* Minimal C reimplementation of rust_caps_c version 0.5.0, with the following caveats:
* - no cap2024_02 support
* - no random generation support
* - ccap2024_11_read_secret_id does not try to decode the capability beyond the secret_key_id bitfield
* - requires an extern function for doing AES encryption
* - secret_key_id is currently NOT bounds checked (TODO fix this)
*/

#ifndef LIBRUST_CAPS_C_H
#define LIBRUST_CAPS_C_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * One of the flags that can be set in [CCapNativeVirtqDesc],
 * equivalent to `VIRTQ_DESC_F_NEXT`
 */
#define CCAP_VIRTQ_F_NEXT (1 << 0)

/**
 * One of the flags that can be set in [CCapNativeVirtqDesc],
 * equivalent to `VIRTQ_DESC_F_WRITE`
 */
#define CCAP_VIRTQ_F_WRITE (1 << 1)

/**
 * One of the flags that can be set in [CCapNativeVirtqDesc],
 * equivalent to `VIRTQ_DESC_F_INDIRECT`
 */
#define CCAP_VIRTQ_F_INDIRECT (1 << 2)

enum CCapPerms
#ifdef __cplusplus
  : uint8_t
#endif // __cplusplus
 {
  CCapPerms_Read = 1,
  CCapPerms_Write = 2,
  CCapPerms_ReadWrite = 3,
};
#ifndef __cplusplus
typedef uint8_t CCapPerms;
#endif // __cplusplus

enum CCapResult
#ifdef __cplusplus
  : int32_t
#endif // __cplusplus
 {
  CCapResult_Success = 0,
  CCapResult_Encode_UnrepresentableBaseRange = 1,
  CCapResult_Encode_UnrepresentableCaveat = 2,
  CCapResult_Encode_InvalidCaveat = 3,
  CCapResult_Encode_NoCaveatsLeft = 4,
  CCapResult_Encode_CantShrinkPerms = 5,
  CCapResult_Decode_InvalidCaveat = 6,
  CCapResult_Decode_InvalidSignature = 7,
  CCapResult_Decode_InvalidCapPermsChain = 8,
  CCapResult_Decode_UnexpectedCaveat = 9,
  CCapResult_Encode_TooBigSecretId = 10,
  CCapResult_Encode_InvalidPerms = 11,
  CCapResult_Decode_NotVirtio = 12,
  CCapResult_NullRequiredArgs = 100,
};
#ifndef __cplusplus
typedef int32_t CCapResult;
#endif // __cplusplus

/**
 * Little-endian representation of a 128-bit number
 */
typedef uint8_t CCapU128[16];

/**
 * A struct matching the virtio virtqueue descriptor layout except the data is native-byte-order
 * instead of little-endian.
 * On a little-endian machine it should be possible to cast a pointer to this struct directly to whatever
 * virtio descriptor struct you have in your own C code.
 */
typedef struct CCapNativeVirtqDesc {
  uint64_t addr;
  uint32_t len;
  /**
   * Must be 3-bits, a bitfield of [CCAP_VIRTQ_F_NEXT], [CCAP_VIRTQ_F_WRITE], and [CCAP_VIRTQ_F_INDIRECT]
   */
  uint16_t flags;
  /**
   * Must be 13-bits, will be packed into bits of the secret_id
   */
  uint16_t next;
} CCapNativeVirtqDesc;

typedef struct CCap2024_11 {
  CCapU128 signature;
  CCapU128 data;
} CCap2024_11;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * A function called when librust_caps_c needs to perform AES encryption.
 *
 * This function is *not* defined by librust_caps_c, and must be defined by the target linking the library in.
 * 
 * It must support (secret) and (result) being the same pointer.
 */
extern void aes_encrypt_128_func(const CCapU128* secret, const CCapU128* data, CCapU128* result);

/**
 * Convert a CCapPerms enum to a null-terminated static immutable C string.
 * Invokes undefined behaviour if passed an value not in the enumeration.
 */
const char *ccap_perms_str(CCapPerms perms);

/**
 * Convert a CCapResult enum to a null-terminated static immutable C string.
 * Invokes undefined behaviour if passed an value not in the enumeration.
 */
const char *ccap_result_str(CCapResult res);

/**
 * Initialize a capability from scratch allowing access to the full 64-bit address range (base = 0, len = 1<<64), given the permissions (Read|Write|Both), and the secret id.
 * Calculates the capability signature given the packed data and the secret.
 *
 * cap and secret are non-optional, and the function returns `NullRequiredArgs` if either are null.
 *
 * Does not use caveats.
 */
CCapResult ccap2024_11_init_almighty(struct CCap2024_11 *cap,
                                     const CCapU128 *secret,
                                     uint32_t secret_id,
                                     CCapPerms perms);

/**
 * Initialize a capability from scratch, given the contiguous memory range it grants access to, the permissions (Read|Write|Both), and the secret_id.
 * Only uses the initial resource.
 * Calculates the capability signature given the packed data and the secret.
 *
 * cap and secret are non-optional, and the function returns `NullRequiredArgs` if either are null.
 *
 * Returns an Encode error if the base/length is not exactly representable.
 * Use [ccap$version_init_inexact] to allow rounding the bounds up in this case instead of returning an error.
 *
 * Does not use caveats.
 */
CCapResult ccap2024_11_init_exact(struct CCap2024_11 *cap,
                                  const CCapU128 *secret,
                                  uint64_t base,
                                  uint64_t len,
                                  uint32_t secret_id,
                                  CCapPerms perms);

/**
 * Initialize a capability from scratch, given the contiguous memory range it grants access to, the permissions (Read|Write|Both), and the secret_id.
 * Uses the initial resource and both caveats if necessary.
 * Calculates the capability signature given the packed data and the secret.
 */
CCapResult ccap2024_11_init_cavs_exact(struct CCap2024_11 *cap,
                                       const CCapU128 *secret,
                                       uint64_t base,
                                       uint64_t len,
                                       uint32_t secret_id,
                                       CCapPerms perms);

/**
 * Initialize a capability from scratch, given the contiguous memory range it grants access to, the permissions (Read|Write|Both), and the secret_id.
 * Calculates the capability signature given the packed data and the secret.
 *
 * cap and secret are non-optional, and the function returns `NullRequiredArgs` if either are null.
 *
 * Will round the bounds up to the smallest possible value that encloses [base, base+len].
 * If exact bounds are required use [ccap$version_init_exact].
 *
 * Does not use caveats.
 */
CCapResult ccap2024_11_init_inexact(struct CCap2024_11 *cap,
                                    const CCapU128 *secret,
                                    uint64_t base,
                                    uint64_t len,
                                    uint32_t secret_id,
                                    CCapPerms perms);

/**
 * Check if a capability has a valid signature, assuming it was encrypted with the given secret.
 *
 * cap and secret are non-optional, and the function returns `CCapResult_NullRequiredArgs` if either are null.
 *
 * Returns `CCapResult_Success` if the signature is valid.
 * Returns `CCapResult_DecodeInvalidSignature` if the signature is invalid.
 * Returns other errors if the capability is otherwise malformed.
 */
CCapResult ccap2024_11_check_signature(const struct CCap2024_11 *cap,
                                       const CCapU128 *secret);

/**
 * Given a pointer to a capability, read off its base and length.
 * len_64 will be set if the range.len() has the 64th bit set.
 * base, len, and len_64 are optional arguments, and are ignored if null.
 * cap is non-optional, and the function returns `NullRequiredArgs` if null.
 * Returns a Decode error if the capability data is invalid.
 * Doesn't check the capability signature.
 */
CCapResult ccap2024_11_read_range(const struct CCap2024_11 *cap,
                                  uint64_t *base,
                                  uint64_t *len,
                                  bool *len_64);

/**
 * Given a pointer to a capability, read off it's permissions (Read, Write, or both).
 * cap and perms are non-optional, and the function returns `NullRequiredArgs` if they're null.
 * Returns a Decode error if the capability permissions field is invalid, but does not check any other part of the capability.
 * Doesn't check the capability signature.
 */
CCapResult ccap2024_11_read_perms(const struct CCap2024_11 *cap,
                                  CCapPerms *perms);

/**
 * Given a pointer to a capability, read off the secret-key id it claims to use.
 * cap and secret_id are non-optional, and the function returns `NullRequiredArgs` if they're null.
 * Returns a Decode error if the capability data is invalid.
 * Doesn't check the capability signature.
 */
CCapResult ccap2024_11_read_secret_id(const struct CCap2024_11 *cap, uint32_t *secret_id);

/**
 * Initialize a capability from scratch, given the contiguous memory range it grants access to, the permissions (Read|Write), and the secret_id.
 * Uses the initial resource and both caveats if necessary.
 * Calculates the capability signature given the packed data and the secret.
 *
 * The memory range, permissions, and some parts of the secret_id are extracted from the virtio_desc.
 *
 * The addr and len fields of virtio_desc dictate the base and len of the capability respectively.
 *
 * The INDIRECT and NEXT virtio flags are packed into the top two bits of the secret_id.
 * The `next` field of the virtio descriptor is packed into the next thirteen bits of the secret_id,
 * leaving only 8 bits for the actual secret_id.
 *
 * |- INDIRECT -|- NEXT -|- next[12:0] -|- key[7:0] -|
 *      [22]       [21]       [20:8]         [7:0]
 *
 * The WRITE virtio flag determines the capability permissions: if it is set, the permissions are `CCapPerms::Write`, else `CCapPerms::Read`.
 *
 * cap, secret, and virtio_desc are non-optional, and the function returns `NullRequiredArgs` if any are null.
 *
 * Returns an Encode error if the base/length is not exactly representable.
 * Use [ccap$version_init_virtio_cavs_inexact] to allow rounding the bounds up in this case instead of returning an error.
 *
 * Returns `Encode_TooBigSecretId` if `virtio_desc.next` does not fit into 13 bits.
 *
 * Uses caveats
 */
CCapResult ccap2024_11_init_virtio_cavs_exact(struct CCap2024_11 *cap,
                                              const CCapU128 *secret,
                                              const struct CCapNativeVirtqDesc *virtio_desc,
                                              uint8_t secret_id);

/**
 * Given a pointer to a capability, extract all data into a virtio-esque descriptor.
 *
 * The INDIRECT and NEXT virtio flags are packed into the top two bits of the secret_id.
 * The `next` field of the virtio descriptor is packed into the next thirteen bits of the secret_id,
 * leaving only 8 bits for the actual secret_id.
 *
 * |- INDIRECT -|- NEXT -|- next[12:0] -|- key[7:0] -|
 *      [22]       [21]       [20:8]         [7:0]
 *
 * The WRITE virtio flag determines the capability permissions: if it is set, the permissions are `CCapPerms::Write`, else `CCapPerms::Read`.
 *
 * cap and virtio_desc are non-optional, and the function returns `NullRequiredArgs` if they're null.
 *
 * Returns a Decode error if the capability data is invalid.
 *
 * Additionally, returns `Decode_NotVirtio` if
 * - the permissions allow both read and write
 * - the length does not fit into a u32
 *
 * In practice this means you should only call this function on capabilities encoded through [$ccap_version_init_virtio_exact], where those invariants are enforced.
 */
CCapResult ccap2024_11_read_virtio(const struct CCap2024_11 *cap,
                                   struct CCapNativeVirtqDesc *virtio_desc);

#if !defined(LIBRUST_CAPS_C_HOSTED)
/**
 * A function called when librust_caps_c panics to print debug information.
 *
 * This function is *not* defined by librust_caps_c, and must be defined by the target linking the library in.
 */
extern uint64_t ccap_panic_write_utf8(const uint8_t *utf8,
                                      uint64_t utf_len);
#endif

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* LIBRUST_CAPS_C_H */
