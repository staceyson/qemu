/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Alfredo Mazzinghi
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

/*
 * Text instruction logging backend
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"

/*
 * Emit textual trace representation of memory access
 */
static inline void emit_text_ldst(log_meminfo_t *minfo, const char *direction)
{

#ifndef TARGET_CHERI
    log_assert((minfo->flags & LMI_CAP) == 0 &&
               "Capability memory access without CHERI support");
#else
    if (minfo->flags & LMI_CAP) {
        qemu_log("    Cap Memory %s [" TARGET_FMT_lx
                 "] = v:%d PESBT:" TARGET_FMT_lx " Cursor:" TARGET_FMT_lx "\n",
                 direction, minfo->addr, minfo->cap.cr_tag,
                 CAP_cc(compress_mem)(&minfo->cap),
                 cap_get_cursor(&minfo->cap));
    } else
#endif
    {
        switch (memop_size(minfo->op)) {
        default:
            qemu_log("    Unknown memory access width\n");
            /* fallthrough */
        case 8:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = " TARGET_FMT_plx "\n",
                     direction, minfo->addr, minfo->value);
            break;
        case 4:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = %08x\n", direction,
                     minfo->addr, (uint32_t)minfo->value);
            break;
        case 2:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = %04x\n", direction,
                     minfo->addr, (uint16_t)minfo->value);
            break;
        case 1:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = %02x\n", direction,
                     minfo->addr, (uint8_t)minfo->value);
            break;
        }
    }
}

/*
 * Emit textual trace representation of register modification
 */
static inline void emit_text_reg(log_reginfo_t *rinfo)
{
#ifndef TARGET_CHERI
    log_assert(!reginfo_is_cap(rinfo) && "Register marked as capability "
                                         "register whitout CHERI support");
#else
    if (reginfo_is_cap(rinfo)) {
        if (reginfo_has_cap(rinfo))
            qemu_log("    Write %s|" PRINT_CAP_FMTSTR_L1 "\n"
                     "             |" PRINT_CAP_FMTSTR_L2 "\n",
                     rinfo->name, PRINT_CAP_ARGS_L1(&rinfo->cap),
                     PRINT_CAP_ARGS_L2(&rinfo->cap));
        else
            qemu_log("  %s <- " TARGET_FMT_lx " (setting integer value)\n",
                     rinfo->name, rinfo->gpr);
    } else
#endif
    {
        qemu_log("    Write %s = " TARGET_FMT_lx "\n", rinfo->name, rinfo->gpr);
    }
}

/*
 * Emit textual representation of the instruction in the given
 * trace entry to the log.
 */
void emit_text_instr(CPUArchState *env, cpu_log_entry_t *entry)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    QemuLogFile *logfile;
    const log_event_t *event;
    const char *log_state_op;
    int i;

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA) {
        /* Dump CPU-ID:ASID + address */
        qemu_log("[%d:%d] ", env_cpu(env)->cpu_index, entry->asid);

        /*
         * Instruction disassembly, note that we use the instruction info
         * opcode bytes, without accessing target memory here.
         */
        rcu_read_lock();
        logfile = qatomic_rcu_read(&qemu_logfile);
        if (logfile) {
            target_disas_buf(logfile->fd, env_cpu(env), entry->insn_bytes,
                             sizeof(entry->insn_bytes), entry->pc, 1);
        }
        rcu_read_unlock();

        /*
         * TODO(am2419): what to do with injected instructions?
         * Is the rvfi_dii_trace state valid at log commit?
         */

        /* Dump mode switching info */
        if (entry->flags & LI_FLAG_MODE_SWITCH)
            qemu_log("-> Switch to %s mode\n",
                     cpu_get_mode_name(entry->next_cpu_mode));
        /* Dump interrupt/exception info */
        switch (entry->flags & LI_FLAG_INTR_MASK) {
        case LI_FLAG_INTR_TRAP:
            qemu_log("-> Exception #%u vector 0x" TARGET_FMT_lx
                     " fault-addr 0x" TARGET_FMT_lx "\n",
                     entry->intr_code, entry->intr_vector,
                     entry->intr_faultaddr);
            break;
        case LI_FLAG_INTR_ASYNC:
            qemu_log("-> Interrupt #%04x vector 0x" TARGET_FMT_lx "\n",
                     entry->intr_code, entry->intr_vector);
            break;
        default:
            /* No interrupt */
            break;
        }

        /* Dump memory access */
        for (i = 0; i < entry->mem->len; i++) {
            log_meminfo_t *minfo = &g_array_index(entry->mem, log_meminfo_t, i);
            if (minfo->flags & LMI_LD) {
                emit_text_ldst(minfo, "Read");
            } else if (minfo->flags & LMI_ST) {
                emit_text_ldst(minfo, "Write");
            }
        }

        /* Dump register changes and side-effects */
        for (i = 0; i < entry->regs->len; i++) {
            log_reginfo_t *rinfo =
                &g_array_index(entry->regs, log_reginfo_t, i);
            emit_text_reg(rinfo);
        }
    }

    /* Dump extra logged messages, if any */
    if (entry->txt_buffer->len > 0) {
        qemu_log("%s", entry->txt_buffer->str);
    }

    /* Emit events recorded by the given trace entry */
    for (i = 0; i < entry->events->len; i++) {
        event = &g_array_index(entry->events, const log_event_t, i);
        switch (event->id) {
        case LOG_EVENT_STATE:
            if (event->state.next_state == LOG_EVENT_STATE_START) {
                log_state_op = "Requested";
            } else if (event->state.next_state == LOG_EVENT_STATE_STOP) {
                log_state_op = "Disabled";
            } else {
                continue;
            }

            if (cpulog->loglevel == QEMU_LOG_INSTR_LOGLEVEL_USER) {
                qemu_log(
                    "[%u:%u] %s user-mode only instruction logging @ %lx\n",
                    env_cpu(env)->cpu_index, cpu_get_asid(env), log_state_op,
                    event->state.pc);
            } else {
                qemu_log("[%u:%u] %s instruction logging @ %lx\n",
                         env_cpu(env)->cpu_index, cpu_get_asid(env),
                         log_state_op, event->state.pc);
            }
            break;
        case LOG_EVENT_CTX_UPDATE:
            qemu_log("Context switch pid=0x%lx tid=0x%lx cid=0x%lx\n",
                     event->ctx_update.pid, event->ctx_update.tid,
                     event->ctx_update.cid);
        default:
            assert(0 && "unknown event ID");
        }
    }
}
