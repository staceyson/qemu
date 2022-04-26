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
#include "cpu.h"
#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#include "cheri-lazy-capregs.h"
#endif

#ifdef TARGET_CHERI
#define get_gpr_value(env, regnum) get_capreg_cursor(env, regnum)
#else
#define get_gpr_value(env, regnum) (env->gpr[regnum])
#endif

/*
 * Read a null-terminated guest string without requiring a strlen() in
 * the guest. This is probably slower but does not perturb guest call-graph.
 */
static int read_guest_cstring(CPURISCVState *env, target_ulong vaddr,
                              char *buffer, size_t maxlen)
{
    int ret = 0;

    buffer[maxlen - 1] = '\0';
    while (maxlen > 1) {
        ret = cpu_memory_rw_debug(env_cpu(env), vaddr, buffer, 1, false);
        if (ret != 0 || *buffer == '\0') {
            break;
        }
        maxlen--;
        vaddr++;
        buffer++;
    }

    return ret;
}

void HELPER(riscv_log_gpr_write)(CPURISCVState *env, uint32_t regnum,
                                 target_ulong value)
{
    if (qemu_log_instr_enabled(env)) {
        /*
         * TODO(am2419): should be using qemu_log_isntr_cap_int() when
         * TARGET_CHERI?
         */
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
    target_ulong vaddr;
    int ret;

    event.id = get_gpr_value(env, 10);

    if (qemu_log_instr_enabled(env)) {
        switch (event.id) {
        case LOG_EVENT_CTX_UPDATE:
            event.ctx_update.op = get_gpr_value(env, 11);
            event.ctx_update.pid = get_gpr_value(env, 12);
            event.ctx_update.tid = get_gpr_value(env, 13);
            event.ctx_update.cid = get_gpr_value(env, 14);
            event.ctx_update.mode = cpu_priv_to_mode(env->priv);
            break;
        case LOG_EVENT_MARKER:
            event.marker = get_gpr_value(env, 11);
            break;
        case LOG_EVENT_REGDUMP:
            cpu_log_instr_event_regdump(env, &event);
            break;
        case LOG_EVENT_COUNTER:
            vaddr = get_gpr_value(env, 11);
            ret = read_guest_cstring(env, vaddr, (char *)event.counter.name,
                                     sizeof(event.counter.name));
            if (ret != 0) {
                warn_report("LOG EVENT HELPER: Could not read guest string at"
                            " vaddr 0x" TARGET_FMT_lx, vaddr);
                return;
            }
            event.counter.value = (int64_t)get_gpr_value(env, 12);
            event.counter.flags = get_gpr_value(env, 13);
            break;
        default:
            warn_report("Unsupported event ID for TCG instr logging %d",
                        event.id);
            return;
        }

        qemu_log_instr_event(env, &event);
    }
}

/*
 * Target-dependent hook to emit register dump events.
 * This is automatically called by the tracing subsystem
 * when tracing is resumed.
 */
bool cpu_log_instr_event_regdump(CPURISCVState *env, log_event_t *event)
{
    int i;
    int nregs;

    event->id = LOG_EVENT_REGDUMP;
#ifdef TARGET_CHERI
    nregs = NUM_LAZY_CAP_REGS;
#else
    nregs = 32;
#endif
    qemu_log_instr_event_create_regdump(event, nregs);
    for (i = 0; i < nregs; i++) {
#ifdef TARGET_CHERI
        const cap_register_t *value = get_readonly_capreg(env, i);
        if (value->cr_tag)
            qemu_log_instr_event_dump_cap(event, riscv_int_regnames[i], value);
        else
            qemu_log_instr_event_dump_cap_int(event, riscv_int_regnames[i],
                                              cap_get_cursor(value));
#else
        target_ulong value = env->gpr[i];
        qemu_log_instr_event_dump_reg(event, riscv_int_regnames[i], value);
#endif
    }

    return false;
}
