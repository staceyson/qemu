/*
 *  MIPS Exceptions processing helpers for QEMU.
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#ifdef TARGET_CHERI
#include "cheri_utils.h"
#endif
#include "exec/helper-proto.h"
#include "exec/exec-all.h"

target_ulong exception_resume_pc(CPUMIPSState *env)
{
    target_ulong bad_pc;
    target_ulong isa_mode;

    isa_mode = !!(env->hflags & MIPS_HFLAG_M16);
    bad_pc = PC_ADDR(env) | isa_mode;
    if (env->hflags & MIPS_HFLAG_BMASK) {
        /*
         * If the exception was raised from a delay slot, come back to
         * the jump.
         */
        bad_pc -= (env->hflags & MIPS_HFLAG_B16 ? 2 : 4);
    }

    return bad_pc;
}

void helper_raise_exception_err(CPUMIPSState *env, uint32_t exception,
                                int error_code)
{
    do_raise_exception_err(env, exception, error_code, 0);
}

void helper_raise_exception(CPUMIPSState *env, uint32_t exception)
{
    do_raise_exception(env, exception, GETPC());
}

void helper_raise_exception_debug(CPUMIPSState *env)
{
    do_raise_exception(env, EXCP_DEBUG, 0);
}

static void raise_exception(CPUMIPSState *env, uint32_t exception)
{
    do_raise_exception(env, exception, 0);
}

void helper_wait(CPUMIPSState *env)
{
    CPUState *cs = env_cpu(env);

    cs->halted = 1;
    cpu_reset_interrupt(cs, CPU_INTERRUPT_WAKE);
    /*
     * Last instruction in the block, PC was updated before
     * - no need to recover PC and icount.
     */
    raise_exception(env, EXCP_HLT);
}

void mips_cpu_synchronize_from_tb(CPUState *cs, const TranslationBlock *tb)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;

    mips_update_pc(env, tb->pc, /*can_be_unrepresentable=*/false);
    env->hflags &= ~MIPS_HFLAG_BMASK;
    env->hflags |= tb->flags & MIPS_HFLAG_BMASK;

    /*
     * Break any load-link that's in flight on this CPU since we've been
     * preempted.  This is sufficiently rare that it shouldn't hurt to do it
     * every preemption.  Of course, it's also only really safe to use ->lladdr
     * for capability work at all because we're forcing MTTCG off for CHERI due
     * to its tag table implementation.  But this doesn't make it any worse!
     *
     * See also target/mips/op_helper:/helper_eret
     */
    env->lladdr = 1;
}

static const char * const excp_names[EXCP_LAST + 1] = {
    [EXCP_RESET] = "reset",
    [EXCP_SRESET] = "soft reset",
    [EXCP_DSS] = "debug single step",
    [EXCP_DINT] = "debug interrupt",
    [EXCP_NMI] = "non-maskable interrupt",
    [EXCP_MCHECK] = "machine check",
    [EXCP_EXT_INTERRUPT] = "interrupt",
    [EXCP_DFWATCH] = "deferred watchpoint",
    [EXCP_DIB] = "debug instruction breakpoint",
    [EXCP_IWATCH] = "instruction fetch watchpoint",
    [EXCP_AdEL] = "address error load",
    [EXCP_AdES] = "address error store",
    [EXCP_TLBF] = "TLB refill",
    [EXCP_IBE] = "instruction bus error",
    [EXCP_DBp] = "debug breakpoint",
    [EXCP_SYSCALL] = "syscall",
    [EXCP_BREAK] = "break",
    [EXCP_CpU] = "coprocessor unusable",
    [EXCP_RI] = "reserved instruction",
    [EXCP_OVERFLOW] = "arithmetic overflow",
    [EXCP_TRAP] = "trap",
    [EXCP_FPE] = "floating point",
    [EXCP_DDBS] = "debug data break store",
    [EXCP_DWATCH] = "data watchpoint",
    [EXCP_LTLBL] = "TLB modify",
    [EXCP_TLBL] = "TLB load",
    [EXCP_TLBS] = "TLB store",
    [EXCP_DBE] = "data bus error",
    [EXCP_DDBL] = "debug data break load",
    [EXCP_THREAD] = "thread",
    [EXCP_MDMX] = "MDMX",
    [EXCP_C2E] = "precise coprocessor 2",
    [EXCP_CACHE] = "cache error",
    [EXCP_TLBXI] = "TLB execute-inhibit",
    [EXCP_TLBRI] = "TLB read-inhibit",
    [EXCP_MSADIS] = "MSA disabled",
    [EXCP_MSAFPE] = "MSA floating point",
};

const char *mips_exception_name(int32_t exception)
{
    if (exception < 0 || exception > EXCP_LAST) {
        return "unknown";
    }
    return excp_names[exception];
}

void do_raise_exception_err(CPUMIPSState *env, MipsExcp exception,
                            int error_code, uintptr_t pc)
{
    CPUState *cs = env_cpu(env);

#ifdef TARGET_CHERI
    // Translate CP0 Unusable to CP2 ASR fault if we are in kernel mode and
    // PCC is missing ASR:
    if (exception == EXCP_CpU && error_code == 0 && in_kernel_mode(env)) {
        if (!cheri_have_access_sysregs(env)) {
            do_raise_c2_exception_noreg(env, CapEx_AccessSystemRegsViolation, pc);
        }
    }
#endif
    qemu_log_mask(CPU_LOG_INT, "%s: %d (%s) %d\n",
                  __func__, exception, mips_exception_name(exception),
                  error_code);
    cs->exception_index = exception;
    env->error_code = error_code;

    cpu_loop_exit_restore(cs, pc);
}

void helper_check_breakcount(struct CPUMIPSState* env)
{
    CPUState *cs = env_cpu(env);
    /* Decrement the startup breakcount, if set. */
    if (unlikely(cs->breakcount)) {
        cs->breakcount--;
        if (cs->breakcount == 0UL) {
            if (qemu_log_instr_or_mask_enabled(env, CPU_LOG_INT | CPU_LOG_EXEC))
                qemu_log_instr_or_mask_msg(env, CPU_LOG_INT | CPU_LOG_EXEC,
                    "Reached breakcount!\n");
            helper_raise_exception_debug(env);
        }
    }
}
