/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Alfredo Mazzinghi
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

#include "qemu/osdep.h"
#include "exec/log_instr.h"
#include "exec/helper-proto.h"
#include "cheri-lazy-capregs.h"
#include "cpu.h"

#ifdef TARGET_CHERI
#define get_gpr_value(env, regnum) get_capreg_cursor(env, regnum)
#else
#define get_gpr_value(env, regnum) (env->gpr[regnum])
#endif

void HELPER(riscv_log_gpr_write)(CPURISCVState *env, uint32_t regnum,
                                 target_ulong value)
{
    if (qemu_log_instr_enabled(env)) {
        // TODO(am2419): should be using qemu_log_isntr_cap_int() when TARGET_CHERI?
        qemu_log_instr_reg(env, riscv_int_regnames[regnum], value);
    }
}

void HELPER(riscv_log_instr)(CPURISCVState *env, target_ulong pc,
                             uint32_t opcode, uint32_t opcode_size)
{
    if (qemu_log_instr_enabled(env)) {
        qemu_log_instr_asid(env, cpu_get_asid(env, pc));
        qemu_log_instr(env, pc, (char *)&opcode, opcode_size);
    }
}

/*
 * Events are triggered by a magic no-op. The arguments for the event
 * are passed via the target ABI argument registers.
 * There is a maximum of 7 arguments supported.
 * void event_noop(event_type, a1, a2, a3, a4, a5, a6, a7)
 *
 * We access GPRs directly from env to work around the argument limit
 * for TCG helpers.
 */
void HELPER(riscv_log_instr_event)(CPURISCVState *env, target_ulong pc)
{
    log_event_t event;

    event.id = get_gpr_value(env, 10);
    if (!qemu_log_instr_enabled(env) &&
        (event.id != LOG_EVENT_CTX_UPDATE ||
         event.ctx_update.op != LOG_EVENT_CTX_OP_SETUP)) {
        return;
    }

    switch (event.id) {
    case LOG_EVENT_CTX_UPDATE:
    case LOG_EVENT_CTX_OP_SETUP:
        event.ctx_update.op = get_gpr_value(env, 11);
        event.ctx_update.pid = get_gpr_value(env, 12);
        event.ctx_update.tid = get_gpr_value(env, 13);
        event.ctx_update.cid = get_gpr_value(env, 14);
        event.ctx_update.mode = cpu_priv_to_mode(env->priv);
        break;
    default:
        warn_report("Unsupported event ID for TCG instr logging %d", event.id);
        return;
    }
    qemu_log_instr_event(env, &event);
}
