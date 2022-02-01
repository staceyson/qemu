/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2016 Stacey Son <sson@FreeBSD.org>
 * Copyright (c) 2016-2018 Alfredo Mazzinghi <am2419@cl.cam.ac.uk>
 * Copyright (c) 2016-2018 Alex Richardson <Alexander.Richardson@cl.cam.ac.uk>
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
#include "qemu/osdep.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/helper-proto.h"
#include "exec/log.h"
#include "cpu.h"
#include "internal.h"
#include "exec/log_instr.h"

#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

#ifdef CONFIG_TCG_LOG_INSTR

/*
 * Log general purpose register modification.
 */
void helper_mips_log_instr_gpr(CPUArchState *env, uint32_t reg,
                               target_ulong value)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_reg(env, mips_gp_regnames[reg], value);
}

/*
 * Log Cop0 register modification.
 * Most of the mtc0 logging is done in cp0_helper, this takes care
 * of logging updates that do not go though helpers in cp0_helper.
 */
void helper_mips_log_instr_cop0(CPUArchState *env, uint32_t reg, uint32_t sel,
                                target_ulong value)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_reg(env, mips_cop0_regnames[reg * 8 + sel], value);
}

/*
 * Log HI/LO register modification.
 * Note: sel is 0 for HI registers and 1 for LO registers
 */
void helper_mips_log_instr_hilo(CPUArchState *env, uint32_t sel, uint32_t index,
                                target_ulong value)
{
    if (!qemu_log_instr_enabled(env))
        return;

    if (sel) {
        qemu_log_instr_reg(env, mips_regnames_LO[index], value);
    } else {
        qemu_log_instr_reg(env, mips_regnames_HI[index], value);
    }
}

void helper_mips_log_instr32(CPUMIPSState *env, target_ulong pc,
                             uint32_t opcode)
{
    uint8_t asid = cpu_get_asid(env, pc);
    uint32_t target_opcode = cpu_to_be32(opcode);

    qemu_log_instr_asid(env, asid);
    qemu_log_instr(env, pc, (char *)&target_opcode, sizeof(opcode));
}

void helper_mips_log_instr_drop(CPUMIPSState *env)
{
    qemu_log_instr_drop(env);
}

bool cpu_log_instr_event_regdump(CPUMIPSState *env, log_event_t *event)
{
    return true;
}

/*
 * Note: do not check for logging enabled first, as this triggers
 * user logging start.
 */
void mips_log_instr_mode_changed(CPUMIPSState *env, target_ulong pc)
{
    qemu_log_instr_cpu_mode_t mode;

    if (env->CP0_Debug & (1 << CP0DB_DM)) {
        mode = MIPS_LOG_INSTR_CPU_DEBUG;
    } else if (env->CP0_Status & (1 << CP0St_ERL)) {
        mode = MIPS_LOG_INSTR_CPU_KERNEL;
    } else if (env->CP0_Status & (1 << CP0St_EXL)) {
        mode = MIPS_LOG_INSTR_CPU_KERNEL;
    } else {
        switch (extract32(env->CP0_Status, CP0St_KSU, 2)) {
        case 0:
            mode = MIPS_LOG_INSTR_CPU_KERNEL;
            break;
        case 1:
            mode = MIPS_LOG_INSTR_CPU_SUPERVISOR;
            break;
        default:
            mode = MIPS_LOG_INSTR_CPU_USER;
            break;
        }
    }
    qemu_log_instr_mode_switch(env, mode, pc);
}

/*
 * Log a special user-specified message to the trace
 * TODO(am2419): Always print these messages even if user-space only tracing is on.
 */
void helper_cheri_debug_message(struct CPUMIPSState* env, uint64_t pc)
{
    if (!qemu_log_instr_enabled(env) || !qemu_loglevel_mask(CPU_LOG_GUEST_DEBUG_MSG))
        return;

    uint8_t buffer[4096];
    /* Address loaded from a0, length from a1, print mode in a2 */
    typedef enum _PrintMode {
        DEBUG_MESSAGE_CSTRING = 0,
        DEBUG_MESSAGE_HEXDUMP = 1,
        DEBUG_MESSAGE_PTR = 2,
        DEBUG_MESSAGE_DECIMAL= 3
    } PrintMode;
    target_ulong vaddr = env->active_tc.gpr[4];
    target_ulong length = MIN(sizeof(buffer), env->active_tc.gpr[5]);
    PrintMode print_mode = (PrintMode)env->active_tc.gpr[6];

    // For ptr + decimal mode we only need
    if (print_mode == DEBUG_MESSAGE_PTR) {
        qemu_log_instr_extra(env, "   ptr = 0x" TARGET_FMT_lx "\r\n", vaddr);
        return;
    } else if (print_mode == DEBUG_MESSAGE_DECIMAL) {
        qemu_log_instr_extra(env, "   value = " TARGET_FMT_ld "\r\n", vaddr); 
        return;
    }
    // Otherwise we meed to fetch the memory referenced by vaddr+length
    // NB: length has already been capped at sizeof(buffer)
    int ret = cpu_memory_rw_debug(env_cpu(env), vaddr, buffer, length, false);
    if (ret != 0) {
        warn_report("CHERI DEBUG HELPER: Could not read " TARGET_FMT_ld
                    " bytes at vaddr 0x" TARGET_FMT_lx "\r\n", length, vaddr);
    }

    qemu_log_instr_extra(env, "DEBUG MESSAGE @ 0x" TARGET_FMT_lx " addr=0x"
            TARGET_FMT_lx " len=" TARGET_FMT_ld "\r\n", pc, vaddr, length);
    if (print_mode == DEBUG_MESSAGE_CSTRING) {
        /* XXXAR: Escape newlines, etc.? */
        qemu_log_instr_extra(env, "    message = \"%*.*s\"\n", (int)length,
            (int)length, buffer);
    } else if (print_mode == DEBUG_MESSAGE_HEXDUMP) {
        /* This is probably inefficient but we don't dump that much.. */
        qemu_log_instr_extra(env, "   Dumping " TARGET_FMT_lu
            " bytes starting at 0x" TARGET_FMT_lx "\r\n", length, vaddr);
        GString *strbuf = g_string_new(NULL);
        do_hexdump(strbuf, buffer, length, vaddr);
        qemu_log_instr_extra(env, "%s", strbuf);
        g_string_free(strbuf, true);
    } else {
        assert(false && "logic error");
    }
}

#ifndef CONFIG_USER_ONLY

void r4k_dump_tlb(CPUMIPSState *env, int idx)
{
    r4k_tlb_t *tlb = &env->tlb->mmu.r4k.tlb[idx];
    target_ulong pagemask, hi, lo0, lo1;

    if (!qemu_log_instr_or_mask_enabled(env, CPU_LOG_MMU))
        return;

    if (tlb->EHINV) {
        pagemask = 0;
        hi  = 1 << CP0EnHi_EHINV;
        lo0 = 0;
        lo1 = 0;
    } else {
        pagemask = tlb->PageMask;
        hi = tlb->VPN | tlb->ASID;
        lo0 = tlb->G | (tlb->V0 << 1) | (tlb->D0 << 2) |
#ifdef TARGET_CHERI
            ((target_ulong)tlb->S0 << CP0EnLo_S) |
            ((target_ulong)tlb->L0 << CP0EnLo_L) |
            ((target_ulong)tlb->CLG0 << CP0EnLo_CLG) |
#else
            ((target_ulong)tlb->RI0 << CP0EnLo_RI) |
            ((target_ulong)tlb->XI0 << CP0EnLo_XI) |
#endif
            (tlb->C0 << 3) | (tlb->PFN[0] >> 6);
        lo1 = tlb->G | (tlb->V1 << 1) | (tlb->D1 << 2) |
#ifdef TARGET_CHERI
            ((target_ulong)tlb->S1 << CP0EnLo_S) |
            ((target_ulong)tlb->L1 << CP0EnLo_L) |
            ((target_ulong)tlb->CLG1 << CP0EnLo_CLG) |
#else
            ((target_ulong)tlb->RI1 << CP0EnLo_RI) |
            ((target_ulong)tlb->XI1 << CP0EnLo_XI) |
#endif
            (tlb->C1 << 3) | (tlb->PFN[1] >> 6);
    }

    qemu_log_instr_or_mask_msg(env, CPU_LOG_MMU,
        "    Write TLB[%u] = pgmsk:%08lx hi:%08lx lo0:%08lx lo1:%08lx\n",
        idx, (long)pagemask, (long)hi, (long)lo0, (long)lo1);
}
#endif /* !CONFIG_USER_ONLY */

#endif // CONFIG_TCG_LOG_INSTR

static void simple_dump_state(CPUMIPSState *env, FILE *f,
                              fprintf_function cpu_fprintf)
{

/* gxemul compat:
    cpu_fprintf(f, "pc = 0x" TARGET_FMT_lx "\n", PC_ADDR(env));
    cpu_fprintf(f, "hi = 0x" TARGET_FMT_lx "    lo = 0x" TARGET_FMT_lx "\n",
            env->active_tc.HI[0], env->active_tc.LO[0]);
    cpu_fprintf(f, "                       ""    s0 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[16]);
    cpu_fprintf(f, "at = 0x" TARGET_FMT_lx "    s1 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[1], env->active_tc.gpr[17]);
    cpu_fprintf(f, "v0 = 0x" TARGET_FMT_lx "    s2 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[2], env->active_tc.gpr[18]);
    cpu_fprintf(f, "v1 = 0x" TARGET_FMT_lx "    s3 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[3], env->active_tc.gpr[19]);
    cpu_fprintf(f, "a0 = 0x" TARGET_FMT_lx "    s4 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[4], env->active_tc.gpr[20]);
    cpu_fprintf(f, "a1 = 0x" TARGET_FMT_lx "    s5 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[5], env->active_tc.gpr[21]);
    cpu_fprintf(f, "a2 = 0x" TARGET_FMT_lx "    s6 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[6], env->active_tc.gpr[22]);
    cpu_fprintf(f, "a3 = 0x" TARGET_FMT_lx "    s7 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[7], env->active_tc.gpr[23]);
    cpu_fprintf(f, "t0 = 0x" TARGET_FMT_lx "    t8 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[8], env->active_tc.gpr[24]);
    cpu_fprintf(f, "t1 = 0x" TARGET_FMT_lx "    t9 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[9], env->active_tc.gpr[25]);
    cpu_fprintf(f, "t2 = 0x" TARGET_FMT_lx "    k0 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[10], env->active_tc.gpr[26]);
    cpu_fprintf(f, "t3 = 0x" TARGET_FMT_lx "    k1 = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[11], env->active_tc.gpr[27]);
    cpu_fprintf(f, "t4 = 0x" TARGET_FMT_lx "    gp = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[12], env->active_tc.gpr[28]);
    cpu_fprintf(f, "t5 = 0x" TARGET_FMT_lx "    sp = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[13], env->active_tc.gpr[29]);
    cpu_fprintf(f, "t6 = 0x" TARGET_FMT_lx "    fp = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[14], env->active_tc.gpr[30]);
    cpu_fprintf(f, "t7 = 0x" TARGET_FMT_lx "    ra = 0x" TARGET_FMT_lx "\n",
            env->active_tc.gpr[15], env->active_tc.gpr[31]);
*/

    /* sim compatible register dump: */
    cpu_fprintf(f, "DEBUG MIPS COREID 0\n");
    cpu_fprintf(f, "DEBUG MIPS PC 0x" TARGET_FMT_lx "\n", PC_ADDR(env));
    cpu_fprintf(f, "DEBUG MIPS REG 00 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[0]);
    cpu_fprintf(f, "DEBUG MIPS REG 01 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[1]);
    cpu_fprintf(f, "DEBUG MIPS REG 02 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[2]);
    cpu_fprintf(f, "DEBUG MIPS REG 03 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[3]);
    cpu_fprintf(f, "DEBUG MIPS REG 04 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[4]);
    cpu_fprintf(f, "DEBUG MIPS REG 05 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[5]);
    cpu_fprintf(f, "DEBUG MIPS REG 06 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[6]);
    cpu_fprintf(f, "DEBUG MIPS REG 07 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[7]);
    cpu_fprintf(f, "DEBUG MIPS REG 08 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[8]);
    cpu_fprintf(f, "DEBUG MIPS REG 09 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[9]);
    cpu_fprintf(f, "DEBUG MIPS REG 10 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[10]);
    cpu_fprintf(f, "DEBUG MIPS REG 11 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[11]);
    cpu_fprintf(f, "DEBUG MIPS REG 12 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[12]);
    cpu_fprintf(f, "DEBUG MIPS REG 13 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[13]);
    cpu_fprintf(f, "DEBUG MIPS REG 14 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[14]);
    cpu_fprintf(f, "DEBUG MIPS REG 15 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[15]);
    cpu_fprintf(f, "DEBUG MIPS REG 16 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[16]);
    cpu_fprintf(f, "DEBUG MIPS REG 17 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[17]);
    cpu_fprintf(f, "DEBUG MIPS REG 18 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[18]);
    cpu_fprintf(f, "DEBUG MIPS REG 19 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[19]);
    cpu_fprintf(f, "DEBUG MIPS REG 20 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[20]);
    cpu_fprintf(f, "DEBUG MIPS REG 21 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[21]);
    cpu_fprintf(f, "DEBUG MIPS REG 22 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[22]);
    cpu_fprintf(f, "DEBUG MIPS REG 23 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[23]);
    cpu_fprintf(f, "DEBUG MIPS REG 24 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[24]);
    cpu_fprintf(f, "DEBUG MIPS REG 25 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[25]);
    cpu_fprintf(f, "DEBUG MIPS REG 26 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[26]);
    cpu_fprintf(f, "DEBUG MIPS REG 27 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[27]);
    cpu_fprintf(f, "DEBUG MIPS REG 28 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[28]);
    cpu_fprintf(f, "DEBUG MIPS REG 29 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[29]);
    cpu_fprintf(f, "DEBUG MIPS REG 30 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[30]);
    cpu_fprintf(f, "DEBUG MIPS REG 31 0x" TARGET_FMT_lx "\n", env->active_tc.gpr[31]);

}

void helper_mtc0_dumpstate(CPUMIPSState *env, target_ulong arg1)
{
    FILE* logfile = qemu_log_enabled() ? qemu_log_lock() : stderr;
#if 0
    cpu_dump_state(env_cpu(env), logfile, fprintf, CPU_DUMP_CODE);
#else
    simple_dump_state(env, logfile, fprintf);
#endif
    if (logfile != stderr)
        qemu_log_unlock(logfile);
}
