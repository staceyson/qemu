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
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/log.h"
#ifdef TARGET_CHERI
#include "cheri-lazy-capregs.h"
#endif

static inline void gpr_set_int_value(CPUArchState *env, unsigned reg,
                                     target_ulong value)
{
    assert(reg != 0);
#ifdef TARGET_CHERI
    update_capreg_to_intval(env, reg, value);
#else
    env->gpr[reg] = value;
#endif
#if defined(CONFIG_TCG_LOG_INSTR)
    // TODO(am2419): should be using qemu_log_isntr_cap_int()?
    helper_riscv_log_gpr_write(env, reg, value);
#endif
}

static inline target_ulong gpr_int_value(CPURISCVState* env, unsigned reg) {
#ifdef TARGET_CHERI
    return get_cap_in_gpregs(&env->gpcapregs, reg)->_cr_cursor;
#else
    return env->gpr[reg];
#endif
}

static inline void riscv_update_pc(CPURISCVState *env, target_ulong pc_addr,
                                   bool can_be_unrepresentable)
{
#ifdef TARGET_CHERI
    cheri_update_pcc(&env->pcc, pc_addr, can_be_unrepresentable);
#else
    env->pc = pc_addr;
#endif
#ifdef CONFIG_DEBUG_TCG
    env->_pc_is_current = true;
#endif
}
