/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Alex Richardson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once
#include "qemu/compiler.h"
#include "qemu/osdep.h"
#include "qemu/error-report.h"

#include "cheri_defs.h"

#ifdef TARGET_AARCH64
#define PRINT_CAP_FMT_EXTRA " bv: %d"
#define PRINT_CAP_ARGS_EXTRA(cr) , (cr)->cr_bounds_valid
#else
#define PRINT_CAP_FMT_EXTRA
#define PRINT_CAP_ARGS_EXTRA(cr)
#endif

#define PRINT_CAP_FMTSTR_L1                                                    \
    "v:%d s:%d p:%08x f:%d b:" TARGET_FMT_lx " l:" TARGET_FMT_lx
#define COMBINED_PERMS_VALUE(cr)                                               \
    (unsigned)(((cap_get_uperms(cr) & CAP_UPERMS_ALL) << CAP_UPERMS_SHFT) |    \
               (cap_get_perms(cr) & CAP_PERMS_ALL))
#define PRINT_CAP_ARGS_L1(cr)                                                  \
    (cr)->cr_tag, cap_is_sealed_with_type(cr), COMBINED_PERMS_VALUE(cr),       \
        cap_get_flags(cr), cap_get_base(cr), cap_get_length_sat(cr)
#define PRINT_CAP_FMTSTR_L2                                                    \
    "o:" TARGET_FMT_lx " t:" TARGET_FMT_lx PRINT_CAP_FMT_EXTRA
#define PRINT_CAP_ARGS_L2(cr)                                                  \
    (target_ulong) cap_get_offset(cr),                                         \
        cap_get_otype_unsigned(cr) PRINT_CAP_ARGS_EXTRA(cr)

#define PRINT_CAP_FMTSTR PRINT_CAP_FMTSTR_L1 " " PRINT_CAP_FMTSTR_L2
#define PRINT_CAP_ARGS(cr) PRINT_CAP_ARGS_L1(cr), PRINT_CAP_ARGS_L2(cr)

#define GET_HOST_RETPC() const uintptr_t _host_return_address = GETPC()

#ifdef TARGET_CHERI

static inline target_ulong cap_get_cursor(const cap_register_t *c)
{
    return c->_cr_cursor;
}

// Getters to allow future changes to the cap_register_t struct layout:
static inline target_ulong cap_get_base(const cap_register_t *c)
{
    return c->cr_base;
}

static inline cap_offset_t cap_get_offset(const cap_register_t *c)
{
    return (cap_offset_t)c->_cr_cursor - (cap_offset_t)c->cr_base;
}

static inline uint32_t cap_get_uperms(const cap_register_t *c)
{
    return CAP_cc(get_uperms)(c);
}

static inline uint32_t cap_get_perms(const cap_register_t *c)
{
    return CAP_cc(get_perms)(c);
}

static inline uint8_t cap_get_flags(const cap_register_t *c)
{
    return CAP_cc(get_flags)(c);
}

static inline bool cap_has_reserved_bits_set(const cap_register_t *c)
{
    return CAP_cc(get_reserved)(c) != 0;
}

// The top of the capability (exclusive -- i.e., one past the end)
static inline target_ulong cap_get_top(const cap_register_t *c)
{
    // TODO: should handle last byte of address space properly
    cap_length_t top = c->_cr_top;
    return top > ~(target_ulong)0 ? ~(target_ulong)0 : (target_ulong)top;
}

static inline cap_length_t cap_get_length_full(const cap_register_t *c)
{
    return c->_cr_top - c->cr_base;
}

static inline target_ulong cap_get_length_sat(const cap_register_t *c)
{
#ifndef TARGET_AARCH64
    cheri_debug_assert((!c->cr_tag || c->_cr_top >= c->cr_base) &&
                       "Tagged capabilities must be in bounds!");
#endif
    cap_length_t length = cap_get_length_full(c);
    // Clamp the length to ~(target_ulong)0
    return length > ~(target_ulong)0 ? ~(target_ulong)0 : (target_ulong)length;
}

static inline cap_length_t cap_get_top_full(const cap_register_t *c)
{
    return c->_cr_top;
}

static inline bool cap_otype_is_reserved(target_ulong otype)
{
    cheri_debug_assert(otype <= CAP_MAX_REPRESENTABLE_OTYPE &&
                       "Should only be called for in-range otypes!");
    return otype >= CAP_CC(MIN_RESERVED_OTYPE) &&
           otype <= CAP_CC(MAX_RESERVED_OTYPE);
}

static inline target_ulong cap_get_otype_unsigned(const cap_register_t *c)
{
    target_ulong otype = CAP_cc(get_otype)(c);
    /*
     * It is impossible to have out-of-range otypes in all targets for the
     * currently used capability compression schemes.
     */
    cheri_debug_assert(otype <= CAP_MAX_REPRESENTABLE_OTYPE);
    return otype;
}

static inline target_long cap_get_otype_signext(const cap_register_t *c)
{
    target_ulong result = cap_get_otype_unsigned(c);
    if (result > CAP_MAX_REPRESENTABLE_OTYPE) {
        // raw bits loaded from memory
        assert(!c->cr_tag && "Capabilities with otype > max cannot be tagged!");
        return result;
    }
#ifdef TARGET_AARCH64
    /*
     * Morello does not sign extend like the rest of CHERI.
     */
    return result;
#else
    /*
     * We "sign" extend to a 64-bit number by subtracting the maximum:
     * e.g. for 64-bit CHERI-RISC-V unsigned 2^18-1 maps to 2^64-1
     */
    return result < CAP_CC(MIN_RESERVED_OTYPE)
               ? result
               : result - CAP_MAX_REPRESENTABLE_OTYPE - 1;
#endif
}

static inline bool cap_exactly_equal(const cap_register_t *cbp,
                                     const cap_register_t *ctp)
{
    return CAP_cc(exactly_equal)(cbp, ctp);
}

static inline bool cap_is_sealed_with_type(const cap_register_t *c)
{
    /* cap_otype_is_reserved() returns true for unsealed capabilities. */
    return !cap_otype_is_reserved(cap_get_otype_unsigned(c));
}

static inline bool cap_is_sealed_with_reserved_otype(const cap_register_t *c)
{
    target_ulong otype = cap_get_otype_unsigned(c);
    return cap_otype_is_reserved(otype) && otype != CAP_OTYPE_UNSEALED;
}

// Check if num_bytes bytes at addr can be read using capability c
static inline bool cap_is_in_bounds(const cap_register_t *c, target_ulong addr,
                                    size_t num_bytes)
{
#ifdef TARGET_AARCH64
    // Invalid exponent caps are always considered out of bounds.
    if (!c->cr_bounds_valid)
        return false;
#endif
    if (addr < cap_get_base(c)) {
        return false;
    }
    /*
     * Use __builtin_add_overflow to detect avoid wrapping around the end of
     * the address space. However, we have to be careful to allow accesses to
     * the last byte (wrapping to exactly zero) since that is fine when
     * checking against given an omnipotent capability.
     */
    target_ulong access_end_addr = 0;
    if (unlikely(__builtin_add_overflow(addr, num_bytes, &access_end_addr))) {
        /* Only do the extended precision addition if we do overflow. */
        if (cap_get_top_full(c) >= (cap_length_t)addr + num_bytes) {
            return true;
        }
        if (c->cr_tag)
            warn_report("Found capability access that wraps around: 0x" TARGET_FMT_lx
                        " + %zd. Authorizing cap: " PRINT_CAP_FMTSTR,
                        addr, num_bytes, PRINT_CAP_ARGS(c));
        return false;
    }
    if (access_end_addr > cap_get_top_full(c)) {
        return false;
    }
    return true;
}

static inline QEMU_ALWAYS_INLINE bool
addr_in_cap_bounds(const cap_register_t *c, target_ulong addr)
{
    return addr >= cap_get_base(c) && addr < cap_get_top_full(c);
}

static inline QEMU_ALWAYS_INLINE bool
cap_cursor_in_bounds(const cap_register_t *c)
{
    return addr_in_cap_bounds(c, cap_get_cursor(c));
}

static inline QEMU_ALWAYS_INLINE bool cap_has_perms(const cap_register_t *reg,
                                                    uint32_t perms)
{
    return (cap_get_perms(reg) & perms) == perms;
}

static inline bool cap_is_unsealed(const cap_register_t *c)
{
    target_ulong otype = cap_get_otype_unsigned(c);
    return otype == CAP_OTYPE_UNSEALED;
}

static inline void cap_set_sealed(cap_register_t *c, uint32_t type)
{
    assert(c->cr_tag);
    assert(cap_is_unsealed(c) && "Should only use this with unsealed caps");
    assert(!cap_otype_is_reserved(type) &&
           "Can't use this to set reserved otypes");
    CAP_cc(update_otype)(c, type);
}

static inline void cap_set_unsealed(cap_register_t *c)
{
    assert(c->cr_tag);
    assert(cap_is_sealed_with_type(c) &&
           "should not use this to unseal reserved types");
    CAP_cc(update_otype)(c, CAP_OTYPE_UNSEALED);
}

static inline bool cap_is_sealed_entry(const cap_register_t *c)
{
    return cap_get_otype_unsigned(c) == CAP_OTYPE_SENTRY;
}

static inline void cap_unseal_reserved_otype(cap_register_t *c)
{
    assert(c->cr_tag && cap_is_sealed_with_reserved_otype(c) &&
           "Should only be used with reserved object types");
    CAP_cc(update_otype)(c, CAP_OTYPE_UNSEALED);
}

static inline void cap_unseal_entry(cap_register_t *c)
{
    assert(c->cr_tag && cap_is_sealed_entry(c) &&
           "Should only be used with sentry capabilities");
    CAP_cc(update_otype)(c, CAP_OTYPE_UNSEALED);
}

static inline void cap_make_sealed_entry(cap_register_t *c)
{
    assert(c->cr_tag && cap_is_unsealed(c) &&
           "Should only be used with unsealed capabilities");
    CAP_cc(update_otype)(c, CAP_OTYPE_SENTRY);
}

static inline bool cap_is_representable(const cap_register_t *c)
{
    return CAP_cc(is_representable_cap_exact)(c);
}

static inline void assert_valid_jump_target(const cap_register_t *target)
{
    // All of these properties should have been checked in the helper:
    cheri_debug_assert(cap_is_unsealed(target));
    cheri_debug_assert(cap_has_perms(target, CAP_PERM_EXECUTE));
    cheri_debug_assert(target->cr_tag);
    cheri_debug_assert(cap_cursor_in_bounds(target));
}

static inline cap_register_t *null_capability(cap_register_t *cp)
{
    *cp = CAP_cc(make_null_derived_cap(0));
    cp->cr_extra = CREG_FULLY_DECOMPRESSED;
    return cp;
}

static inline bool is_null_capability(const cap_register_t *cp)
{
    cap_register_t null;
    // This also compares padding but it should always be NULL assuming
    // null_capability() was used
    return memcmp(null_capability(&null), cp, sizeof(cap_register_t)) == 0;
}

/*
 * Convert 64-bit integer into a capability that holds the integer in
 * its offset field.
 *
 *       cap.base = 0, cap.tag = false, cap.offset = x
 *
 * The contents of other fields of int to cap depends on the capability
 * compression scheme in use (e.g. 256-bit capabilities or 128-bit
 * compressed capabilities). In particular, with 128-bit compressed
 * capabilities, length is not always zero. The length of a capability
 * created via int to cap is not semantically meaningful, and programs
 * should not rely on it having any particular value.
 */
static inline const cap_register_t *int_to_cap(target_ulong x,
                                               cap_register_t *cr)
{

    (void)null_capability(cr);
    cr->_cr_cursor = x;
    return cr;
}

/**
 * Clear the tag bit of a capability that became unrepresenable and update
 * the cursor to point to @p addr.
 * Only clearing the tag bit instead of updating the offset to be semantically
 * valid improves timing on the FPGA and with the shift towards address-based
 * interpretation it becomes less useful to retain the offset value.
 *
 * Previous behaviour was to use int_to_cap instead
 *
 */
static inline cap_register_t *cap_mark_unrepresentable(target_ulong addr,
                                                       cap_register_t *cr)
{
    // Clear the tag and update the address:
    cr->_cr_cursor = addr;
    cr->cr_tag = false;
    /*
     * Recompute the decompressed bounds relative to the new address. In most
     * cases they will refer to a different region of memory now.
     */
    CAP_cc(decompress_raw)(cr->cr_pesbt, addr, false, cr);
    cr->cr_extra = CREG_FULLY_DECOMPRESSED;
    return cr;
}

static inline void set_max_perms_capability(cap_register_t *crp,
                                            target_ulong cursor)
{
    *crp = CAP_cc(make_max_perms_cap)(0, cursor, CAP_MAX_TOP);
    crp->cr_extra = CREG_FULLY_DECOMPRESSED;
}

static inline QEMU_ALWAYS_INLINE bool
is_representable_cap_with_addr(const cap_register_t *cap, target_ulong new_addr)
{
    return CAP_cc(is_representable_with_addr)(
        cap, new_addr, /*precise_representable_check=*/true);
}

int gdb_get_capreg(GByteArray *buf, const cap_register_t *cap);
int gdb_get_general_purpose_capreg(GByteArray *buf, CPUArchState *env,
                                   unsigned regnum);

#define raise_cheri_exception(env, cause, reg)                                 \
    raise_cheri_exception_impl(env, cause, reg, 0, true, _host_return_address)

#define raise_cheri_exception_addr(env, cause, reg, addr)                      \
    raise_cheri_exception_impl(env, cause, reg, addr, true,                    \
                               _host_return_address)

#ifdef TARGET_AARCH64
#define raise_cheri_exception_if(env, cause, addr, reg)                        \
    raise_cheri_exception_impl_if_wnr(env, cause, reg, addr, true, /*pc=*/0,   \
                                      true, false)
#define raise_cheri_exception_addr_wnr(env, cause, reg, addr, is_write)        \
    raise_cheri_exception_impl_if_wnr(env, cause, reg, addr, true,             \
                                      _host_return_address, false, is_write)
#else
#define raise_cheri_exception_if(env, cause, addr, reg)                        \
    raise_cheri_exception_impl(env, cause, reg, addr, true, /*pc=*/0)
#define raise_cheri_exception_addr_wnr(env, cause, reg, addr, is_write)        \
    raise_cheri_exception_addr(env, cause, reg, addr)
#endif

static inline void cap_set_cursor(cap_register_t *cap, uint64_t new_addr)
{
    if (!is_representable_cap_with_addr(cap, new_addr)) {
        cap_mark_unrepresentable(new_addr, cap);
    } else {
        cap->_cr_cursor = new_addr;
    }
}

static inline void cap_increment_offset(cap_register_t *cap, uint64_t offset)
{
    uint64_t new_addr = cap->_cr_cursor + offset;
    return cap_set_cursor(cap, new_addr);
}

static inline void cap_and_perms(cap_register_t *cap, uint32_t andperms)
{
    uint32_t perms, uperms;

    perms = (uint32_t)andperms & (CAP_PERMS_ALL);
    uperms = ((uint32_t)andperms >> CAP_UPERMS_SHFT) & CAP_UPERMS_ALL;

    CAP_cc(update_perms)(cap, cap_get_perms(cap) & perms);
    CAP_cc(update_uperms)(cap, cap_get_uperms(cap) & uperms);
}

static inline void cap_set_flags(cap_register_t *cap, target_ulong flags)
{

    flags &= CAP_FLAGS_ALL_BITS;
    CAP_cc(update_flags)(cap, flags);
}

static inline void cap_set_state(cap_register_t *cap, CapRegState state)
{

    cap->cr_extra = state;
}

#endif /* TARGET_CHERI */
