/*
 *  QEMU MIPS emulation: Special opcode helpers
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
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "internal.h"

/* Specials */
target_ulong helper_di(CPUMIPSState *env)
{
    target_ulong t0 = env->CP0_Status;

    env->CP0_Status = t0 & ~(1 << CP0St_IE);
    return t0;
}

target_ulong helper_ei(CPUMIPSState *env)
{
    target_ulong t0 = env->CP0_Status;

    env->CP0_Status = t0 | (1 << CP0St_IE);
    return t0;
}

static void debug_pre_eret(CPUMIPSState *env)
{
    if (qemu_log_instr_or_mask_enabled(env, CPU_LOG_EXEC)) {
        qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC,
            "ERET: PC " TARGET_FMT_lx " EPC " TARGET_FMT_lx,
             PC_ADDR(env), get_CP0_EPC(env));
        if (should_use_error_epc(env)) {
            qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC,
                " ErrorEPC " TARGET_FMT_lx, get_CP0_ErrorEPC(env));
        }
        if (env->hflags & MIPS_HFLAG_DM) {
            qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC,
                " DEPC " TARGET_FMT_lx, env->CP0_DEPC);
        }
        qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC, "\n");
    }

#if defined(CONFIG_TCG_LOG_INSTR) && defined(TARGET_CHERI)
    if (qemu_log_instr_enabled(env)) {
        // Print the new PCC value for debugging traces (compare to null
        // so that we always print it)
        qemu_log_instr_cap(env, "PCC", &env->active_tc.PCC);
        qemu_log_instr_cap(env, "EPCC", &env->active_tc.CHWR.EPCC);
        qemu_log_instr_cap(env, "ErrorEPCC", &env->active_tc.CHWR.ErrorEPCC);
    }
#endif /* defined(CONFIG_TCG_LOG_INSTR) && defined(TARGET_CHERI) */
}

static void debug_post_eret(CPUMIPSState *env)
{
    const char *flag;

#ifdef CONFIG_TCG_LOG_INSTR
    mips_log_instr_mode_changed(env, cpu_get_recent_pc(env));
#endif
    if (qemu_log_instr_or_mask_enabled(env, CPU_LOG_EXEC)) {
        qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC,
            "  =>  PC " TARGET_FMT_lx " EPC " TARGET_FMT_lx,
            PC_ADDR(env), get_CP0_EPC(env));
        if (should_use_error_epc(env)) {
            qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC,
                " ErrorEPC " TARGET_FMT_lx, get_CP0_ErrorEPC(env));
        }
        if (env->hflags & MIPS_HFLAG_DM) {
            qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC,
                " DEPC " TARGET_FMT_lx, env->CP0_DEPC);
        }
        switch (cpu_mmu_index(env, false)) {
        case 3:
            flag = ", ERL\n";
            break;
        case MIPS_HFLAG_UM:
            flag = ", UM\n";
            break;
        case MIPS_HFLAG_SM:
            flag = ", SM\n";
            break;
        case MIPS_HFLAG_KM:
            flag = "\n";
            break;
        default:
            cpu_abort(env_cpu(env), "Invalid MMU mode!\n");
            break;
        }
        qemu_log_instr_or_mask_msg(env, CPU_LOG_EXEC, "%s", flag);
    }
}

bool mips_io_recompile_replay_branch(CPUState *cs, const TranslationBlock *tb)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;

    if ((env->hflags & MIPS_HFLAG_BMASK) != 0 && PC_ADDR(env) != tb->pc) {
        mips_update_pc(env, PC_ADDR(env) - (env->hflags & MIPS_HFLAG_B16 ? 2 : 4),
                       /*can_be_unrepresentable=*/false);
        env->hflags &= ~MIPS_HFLAG_BMASK;
        return true;
    }
    return false;
}

#ifdef TARGET_CHERI
static void set_pc_for_eret(CPUMIPSState *env, cap_register_t *error_pcc)
#else
static void set_pc_for_eret(CPUMIPSState *env, target_ulong error_pc)
#endif
{
#ifdef TARGET_CHERI
    target_ulong error_pc = cap_get_cursor(error_pcc);
    cheri_update_pcc_for_exc_return(&env->active_tc.PCC, error_pcc,
                                    error_pc & ~(target_ulong)1);
#else
    mips_update_pc(env, error_pc & ~(target_ulong)1, /*can_be_unrepresentable=*/true);
#endif
    if (error_pc & 1) {
#if defined(TARGET_CHERI)
        warn_report("Got target pc with low bit set, but QEMU-CHERI does not"
                    " support microMIPS: 0x%" PRIx64, error_pc);
#else
        env->hflags |= MIPS_HFLAG_M16;
#endif
    } else {
        env->hflags &= ~(MIPS_HFLAG_M16);
    }
}

static inline void exception_return(CPUMIPSState *env)
{
    debug_pre_eret(env);
    if (env->CP0_Status & (1 << CP0St_ERL)) {
#ifdef TARGET_CHERI
        set_pc_for_eret(env, &env->active_tc.CHWR.ErrorEPCC);
#else
        set_pc_for_eret(env, env->CP0_ErrorEPC);
#endif
        env->CP0_Status &= ~(1 << CP0St_ERL);
    } else {
#ifdef TARGET_CHERI
        set_pc_for_eret(env, &env->active_tc.CHWR.EPCC);
#else
        set_pc_for_eret(env, env->CP0_EPC);
#endif
        env->CP0_Status &= ~(1 << CP0St_EXL);
    }
    compute_hflags(env);
    debug_post_eret(env);
}

void helper_eret(CPUMIPSState *env)
{
    exception_return(env);
    env->CP0_LLAddr = 1;
    env->lladdr = 1;
}

void helper_eretnc(CPUMIPSState *env)
{
#ifdef TARGET_CHERI
    do_raise_exception(env, EXCP_RI, GETPC()); /* This does not unset LL reservation? */
#endif
    exception_return(env);
}

void helper_deret(CPUMIPSState *env)
{
#ifdef TARGET_CHERI
    do_raise_exception(env, EXCP_RI, GETPC()); /* This ignores EPCC */
#else
    debug_pre_eret(env);

    env->hflags &= ~MIPS_HFLAG_DM;
    compute_hflags(env);

    mips_env_set_pc(env, env->CP0_DEPC);

    debug_post_eret(env);
#endif
}

void helper_cache(CPUMIPSState *env, target_ulong addr, uint32_t op)
{
    static const char *const type_name[] = {
        "Primary Instruction",
        "Primary Data or Unified Primary",
        "Tertiary",
        "Secondary"
    };
    uint32_t cache_type = extract32(op, 0, 2);
    uint32_t cache_operation = extract32(op, 2, 3);
    target_ulong index = addr & 0x1fffffff;

    switch (cache_operation) {
    case 0b010: /* Index Store Tag */
        memory_region_dispatch_write(env->itc_tag, index, env->CP0_TagLo,
                                     MO_64, MEMTXATTRS_UNSPECIFIED);
        break;
    case 0b001: /* Index Load Tag */
        memory_region_dispatch_read(env->itc_tag, index, &env->CP0_TagLo,
                                    MO_64, MEMTXATTRS_UNSPECIFIED);
        break;
    case 0b000: /* Index Invalidate */
    case 0b100: /* Hit Invalidate */
    case 0b110: /* Hit Writeback */
        /* no-op */
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "cache operation:%u (type: %s cache)\n",
                      cache_operation, type_name[cache_type]);
        break;
    }
}
