/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Alex Richardson <Alexander.Richardson@cl.cam.ac.uk>
 * All rights reserved.
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

#include "cpu.h"
#include "cheri-lazy-capregs.h"

extern bool cheri_debugger_on_trap;

static inline void QEMU_NORETURN raise_cheri_exception_impl(
    CPUArchState *env, CheriCapExcCause cause, unsigned regnum,
    target_ulong addr, bool instavail, uintptr_t hostpc)
{
    env->last_cap_cause = cause;
    env->last_cap_index = regnum;
    // Allow drop into debugger on first CHERI trap:
    // FIXME: allow c command to work by adding another boolean flag to skip
    // this breakpoint when GDB asks to continue
    if (cheri_debugger_on_trap)
        riscv_raise_exception(env, EXCP_DEBUG, hostpc);
    riscv_raise_exception(env, RISCV_EXCP_CHERI, hostpc);
}

static inline void QEMU_NORETURN raise_load_tag_exception(
    CPUArchState *env, target_ulong va, int cb, uintptr_t retpc)
{
#ifdef TARGET_RISCV32
    g_assert_not_reached();
#else
    env->badaddr = va;
    riscv_raise_exception(env, RISCV_EXCP_LOAD_CAP_PAGE_FAULT, retpc);
#endif
}

static inline void QEMU_NORETURN raise_store_tag_exception(CPUArchState *env,
                                                           target_ulong va,
                                                           int reg,
                                                           uintptr_t retpc)
{
#ifdef TARGET_RISCV32
    g_assert_not_reached();
#else
    env->badaddr = va;
    riscv_raise_exception(env, RISCV_EXCP_STORE_AMO_CAP_PAGE_FAULT, retpc);
#endif
}

static inline void QEMU_NORETURN raise_unaligned_load_exception(
    CPUArchState *env, target_ulong addr, uintptr_t retpc)
{
    env->badaddr = addr;
    riscv_raise_exception(env, RISCV_EXCP_LOAD_ADDR_MIS, retpc);
}

static inline void QEMU_NORETURN raise_unaligned_store_exception(
    CPUArchState *env, target_ulong addr, uintptr_t retpc)
{
    env->badaddr = addr;
    // Note: RISCV_EXCP_STORE_AMO_ADDR_MIS means "Store/AMO address misaligned"
    riscv_raise_exception(env, RISCV_EXCP_STORE_AMO_ADDR_MIS, retpc);

}

static inline bool validate_jump_target(CPUArchState *env,
                                        const cap_register_t *cap,
                                        target_ulong addr,
                                        unsigned regnum, uintptr_t retpc)
{
    target_ulong base = cap_get_base(cap);
    unsigned min_insn_size = riscv_has_ext(env, RVC) ? 2 : 4;
    if (!cap_is_in_bounds(cap, addr, min_insn_size)) {
        raise_cheri_exception_impl(env, CapEx_LengthViolation, regnum, addr,
                                   true, retpc);
    }
    if (!QEMU_IS_ALIGNED(base, min_insn_size)) {
        raise_cheri_exception_impl(env, CapEx_UnalignedBase, regnum, addr, true,
                                   retpc);
    }
    // XXX: Sail only checks bit 1 why not also bit zero? Is it because that is
    // ignored?
    if (!riscv_has_ext(env, RVC) && (addr & 0x2)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, retpc);
    }
    return true;
}

static inline void update_next_pcc_for_tcg(CPUArchState *env,
                                           cap_register_t *target,
                                           uint32_t cjalr_flags)
{
    assert_valid_jump_target(target);
    // On return to TCG we will jump there immediately, so update env->pcc now.
    env->pcc = *target;
#ifdef CONFIG_DEBUG_TCG
    env->_pc_is_current = true; // PCC.cursor is up-to-date again.
#endif
}

static inline target_ulong cheri_ddc_relative_addr(CPURISCVState *env,
                                                   target_ulong addr)
{
    /*
     * CHERI-RISC-V ISAv8 relocated all integer accesses by DDC.address, but
     * this was removed in later versions.
     */
    if (CHERI_NO_RELOCATION(env)) {
        return addr;
    } else {
        return cap_get_cursor(cheri_get_ddc(env)) + addr;
    }
}
