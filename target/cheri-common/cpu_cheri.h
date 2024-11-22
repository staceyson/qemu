/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018-2020 Alex Richardson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
// This file should be included from cpu.h after CPURISCVState has been defined
#include "qemu/log.h"
#include "cheri_utils.h"

bool cpu_restore_state(CPUState *cpu, uintptr_t host_pc, bool will_exit);
static inline bool pc_is_current(CPUArchState *env);
static inline target_ulong cpu_get_recent_pc(CPUArchState *env);

#ifdef TARGET_CHERI
static inline const cap_register_t *_cheri_get_pcc_unchecked(CPUArchState *env);
#include "cheri-archspecific-early.h"
// Returns a recent PCC value. This means that the cursor field may be out of
// date (possibly pointing to the beginning of the translation block). However,
// all permissions, flags and bounds are valid and can be accessed.
// This function exists since updating pcc.cursor on every instruction is
// expensive and generally not required. If the current value is needed, it can
// be computed from the return address (GETPC() in the toplevel helper function)
// by calling cpu_restore_state(). However, it is preferable if the translator
// code writes the updated pcc.cursor before calling the helper if this is the
// common case (for example, it should not be saved if the current pc value is
// only needed if a trap is raised).
static inline const cap_register_t *cheri_get_recent_pcc(CPUArchState *env)
{
    return _cheri_get_pcc_unchecked(env);
}
// This function can be called if the pcc.cursor value must be accurate.
static inline const cap_register_t *cheri_get_current_pcc(CPUArchState *env)
{
    cheri_debug_assert(pc_is_current(env));
    return _cheri_get_pcc_unchecked(env);
}

static inline const cap_register_t *
cheri_get_current_pcc_fetch_from_tcg(CPUArchState *env, uintptr_t retpc)
{
    cpu_restore_state(env_cpu(env), retpc, false);
    return cheri_get_current_pcc(env);
}

static inline void cheri_update_pcc(cap_register_t *pcc, target_ulong pc_addr,
                                    bool can_be_unrepresenable)
{
    // Note: This function is mostly called when updating PCC.cursor from the
    // generated TCG state. Therefore the new value must be in-bounds (or at
    // least representable). The only case where this may not hold is on
    // exception handler entry/return. For jumps/branches an out-of-bounds PCC
    // value should raise a trap on the branch/jump so we can't get an
    // unrpresentable value here.
    cheri_debug_assert(!pcc->cr_tag || cap_is_unsealed(pcc) ||
                       pcc->_cr_cursor == pc_addr);
    if (can_be_unrepresenable) {
        if (pcc->cr_tag && !is_representable_cap_with_addr(pcc, pc_addr)) {
            error_report(
                "Attempting to set unrepresentable cursor (0x" TARGET_FMT_lx
                ") on PCC: " PRINT_CAP_FMTSTR "\r",
                pc_addr, PRINT_CAP_ARGS(pcc));
            cap_mark_unrepresentable(pc_addr, pcc);
        }
    } else {
        // TODO: once we do bounds checks in the translator, this can assert
        // that the value is in-bounds.
        cheri_debug_assert(is_representable_cap_with_addr(pcc, pc_addr));
    }
    pcc->_cr_cursor = pc_addr;
}

static inline bool cap_has_capmode_flag(const cap_register_t *cap) {
    return (cap_get_flags(cap) & CHERI_FLAG_CAPMODE) == CHERI_FLAG_CAPMODE;
}

static inline bool cheri_in_capmode(CPUArchState *env) {
    // Note: No need to synchronize the PCC.cursor value from TCG since
    // Every change to capmode will exit the current translation block.
    return cap_has_capmode_flag(cheri_get_recent_pcc(env));
}

// Note: this function does not check the bounds of pcc!
static inline bool cheri_cap_perms_valid_for_exec(const cap_register_t *pcc)
{
    // When executing, PCC must be tagged, executable and unsealed (and
    // in-bounds).
    return pcc->cr_tag && cap_has_perms(pcc, CAP_PERM_EXECUTE) &&
           cap_is_unsealed(pcc);
}

// Note: can't use an inline function here since TranslationBlock isn't defined
#define tb_in_capmode(tb)                                                      \
    ((tb->cheri_flags & TB_FLAG_CHERI_CAPMODE) == TB_FLAG_CHERI_CAPMODE)

static inline void cheri_cpu_get_tb_cpu_state(const cap_register_t *pcc,
                                              const cap_register_t *ddc,
                                              target_ulong *pcc_base,
                                              target_ulong *pcc_top,
                                              uint32_t *cheri_flags)
{
    *pcc_base = cap_get_base(pcc);
    *pcc_top = cap_get_top(pcc);
    cheri_debug_assert(*cheri_flags == 0);
    if (cap_has_capmode_flag(pcc))
        *cheri_flags |= TB_FLAG_CHERI_CAPMODE;
    if (cheri_cap_perms_valid_for_exec(pcc))
        *cheri_flags |= TB_FLAG_CHERI_PCC_EXECUTABLE;

    if (pcc->cr_tag && cap_is_unsealed(pcc)) {
        if (cap_has_perms(pcc, CAP_PERM_LOAD))
            *cheri_flags |= TB_FLAG_CHERI_PCC_READABLE;
    }

    if (*pcc_base == 0)
        *cheri_flags |= TB_FLAG_CHERI_PCC_BASE_ZERO;
    if (cap_get_top_full(pcc) == CAP_MAX_TOP)
        *cheri_flags |= TB_FLAG_CHERI_PCC_TOP_MAX;

    if (ddc->cr_tag && cap_is_unsealed(ddc)
#ifdef TARGET_AARCH64
        && ddc->cr_bounds_valid
#endif
    ) {
        if (cap_has_perms(ddc, CAP_PERM_LOAD))
            *cheri_flags |= TB_FLAG_CHERI_DDC_READABLE;
        if (cap_has_perms(ddc, CAP_PERM_STORE))
            *cheri_flags |= TB_FLAG_CHERI_DDC_WRITABLE;
        if (cap_get_base(ddc) == 0)
            *cheri_flags |= TB_FLAG_CHERI_DDC_BASE_ZERO;
        if (cap_get_cursor(ddc) == 0)
            *cheri_flags |= TB_FLAG_CHERI_DDC_CURSOR_ZERO;
        if (cap_get_top_full(ddc) == CAP_MAX_TOP)
            *cheri_flags |= TB_FLAG_CHERI_DDC_TOP_MAX;
    }
}

#endif

static inline target_ulong cpu_get_current_pc(CPUArchState *env,
                                              uintptr_t retpc, bool will_exit)
{
    cpu_restore_state(env_cpu(env), retpc, will_exit);
    cheri_debug_assert(pc_is_current(env));
    return cpu_get_recent_pc(env);
}

static inline target_ulong cpu_get_current_pc_checked(CPUArchState *env)
{
    cheri_debug_assert(pc_is_current(env));
    return cpu_get_recent_pc(env);
}

static inline target_ulong PC_ADDR(CPUArchState *env)
{
#ifdef CONFIG_DEBUG_TCG
    assert(pc_is_current(env));
#endif
    return cpu_get_recent_pc(env);
}

static inline bool should_log_mem_access(CPUArchState *env, int log_mask, target_ulong addr) {
    if (likely(!(qemu_loglevel_mask(log_mask))))
        return false;

    // Try not to dump all stores when -dfilter is enabled
    // Note: we check both PC and memory location in -dfilter
    if (likely(!qemu_log_in_addr_range(cpu_get_recent_pc(env)) &&
        !qemu_log_in_addr_range(addr)))
        return false;
    return true;
}
