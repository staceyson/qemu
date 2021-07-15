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
 * CHERI Trace binary format backend
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"

/*
 * CHERI binary trace format, originally used for MIPS only.
 * The format is limited to one entry per instruction, each
 * entry can hold at most one register modification and one
 * memory address.
 * Note that the CHERI format is the legacy MIPS format and
 * assumes big-endian byte order.
 */
typedef struct {
    uint8_t entry_type;
#define CTE_NO_REG 0   /* No register is changed. */
#define CTE_GPR    1   /* GPR change (val2) */
#define CTE_LD_GPR 2   /* Load into GPR (val2) from address (val1) */
#define CTE_ST_GPR 3   /* Store from GPR (val2) to address (val1) */
#define CTE_CAP    11  /* Cap change (val2,val3,val4,val5) */
#define CTE_LD_CAP 12  /* Load Cap (val2,val3,val4,val5) from addr (val1) */
#define CTE_ST_CAP 13  /* Store Cap (val2,val3,val4,val5) to addr (val1) */
    uint8_t exception; /* 0=none, 1=TLB Mod, 2=TLB Load, 3=TLB Store, etc. */
#define CTE_EXCEPTION_NONE 31
    uint16_t cycles; /* Currently not used. */
    uint32_t inst;   /* Encoded instruction. */
    uint64_t pc;     /* PC value of instruction. */
    uint64_t val1;   /* val1 is used for memory address. */
    uint64_t val2;   /* val2, val3, val4, val5 are used for reg content. */
    uint64_t val3;
    uint64_t val4;
    uint64_t val5;
    uint8_t thread; /* Hardware thread/CPU (i.e. cpu->cpu_index ) */
    uint8_t asid;   /* Address Space ID */
} __attribute__((packed)) cheri_trace_entry_t;

/* Version 3 Cheri Stream Trace header info */
#define CTE_QEMU_VERSION (0x80U + 3)
#define CTE_QEMU_MAGIC   "CheriTraceV03"

/*
 * Emit cvtrace trace trace header. This is a magic byte + string
 */
void emit_cvtrace_header(CPUArchState *env)
{
    FILE *logfile = qemu_log_lock();
    char buffer[sizeof(cheri_trace_entry_t)];

    buffer[0] = CTE_QEMU_VERSION;
    g_strlcpy(buffer + 1, CTE_QEMU_MAGIC, sizeof(buffer) - 2);
    fwrite(buffer, sizeof(buffer), 1, logfile);
    qemu_log_unlock(logfile);
}

/*
 * Emit cvtrace trace entry.
 * Note: this format is very MIPS-specific.
 */
void emit_cvtrace_entry(CPUArchState *env, cpu_log_entry_t *entry)
{
    FILE *logfile;
    cheri_trace_entry_t ct_entry;
    /* TODO(am2419): this should be a per-cpu counter. */
    static uint16_t cycles;
    uint32_t *insn = (uint32_t *)&entry->insn_bytes[0];

    ct_entry.entry_type = CTE_NO_REG;
    ct_entry.thread = (uint8_t)env_cpu(env)->cpu_index;
    ct_entry.asid = (uint8_t)entry->asid;
    ct_entry.pc = cpu_to_be64(entry->pc);
    ct_entry.cycles = cpu_to_be16(cycles++);
    /*
     * TODO(am2419): The instruction bytes are alread in target byte-order,
     * however cheritrace does not currently expect this.
     */
    ct_entry.inst = cpu_to_be32(*insn);
    switch (entry->flags & LI_FLAG_INTR_MASK) {
    case LI_FLAG_INTR_TRAP:
        ct_entry.exception = (uint8_t)(entry->intr_code & 0xff);
    case LI_FLAG_INTR_ASYNC:
        ct_entry.exception = 0;
    default:
        ct_entry.exception = CTE_EXCEPTION_NONE;
    }

    if (entry->regs->len) {
        log_reginfo_t *rinfo = &g_array_index(entry->regs, log_reginfo_t, 0);
#ifndef TARGET_CHERI
        log_assert(!reginfo_is_cap(rinfo) && "Capability register access "
                                             "without CHERI support");
#else
        if (reginfo_is_cap(rinfo)) {
            cap_register_t intcap;
            cap_register_t *cr = &rinfo->cap;

            if (!reginfo_has_cap(rinfo)) {
                /* cvtrace expects a null capability in the integer case */
                cr = null_capability(&intcap);
            }
            uint64_t metadata = (((uint64_t)cr->cr_tag << 63) |
                                 ((uint64_t)cap_get_otype(cr) << 32) |
                                 ((uint64_t)COMBINED_PERMS_VALUE(cr) << 1) |
                                 (uint64_t)(cap_is_unsealed(cr) ? 0 : 1));

            ct_entry.entry_type = CTE_CAP;
            ct_entry.val2 = cpu_to_be64(metadata);
            ct_entry.val3 = cpu_to_be64(cap_get_cursor(cr));
            ct_entry.val4 = cpu_to_be64(cap_get_base(cr));
            ct_entry.val5 = cpu_to_be64(cap_get_length_sat(cr));
        } else
#endif
        {
            ct_entry.entry_type = CTE_GPR;
            ct_entry.val2 = cpu_to_be64(rinfo->gpr);
        }
    }

    if (entry->mem->len) {
        log_meminfo_t *minfo = &g_array_index(entry->mem, log_meminfo_t, 0);
#ifndef TARGET_CHERI
        log_assert((minfo->flags & LMI_CAP) == 0 && "Capability memory access "
                                                    "without CHERI support");
#endif
        ct_entry.val1 = cpu_to_be64(minfo->addr);
        /* Hack to avoid checking for GPR or CAP */
        if (minfo->flags & LMI_LD) {
            ct_entry.entry_type += 1;
        } else if (minfo->flags & LMI_ST) {
            ct_entry.entry_type += 2;
        }
    }

    logfile = qemu_log_lock();
    fwrite(&ct_entry, sizeof(ct_entry), 1, logfile);
    qemu_log_unlock(logfile);
}
