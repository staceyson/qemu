/*
 *  Copyright (c) 2020 Lawrence Esswood
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "cheri-archspecific-early.h"

#define CAP_TAG_GET_MANY_SHFT 2

#include "internals.h"

typedef enum CheriCapExc {
    CapEx_None,
    CapEx_LengthViolation,
    CapEx_TagViolation,
    CapEx_SealViolation,
    CapEx_TypeViolation,
    CapEx_CallTrap,
    CapEx_ReturnTrap,
    CapEx_TSSUnderFlow,
    CapEx_UserDefViolation,
    CapEx_TLBNoStoreCap,
    CapEx_InexactBounds,
    CapEx_UnalignedBase,
    CapEx_CapLoadGen,
    CapEx_GlobalViolation,
    CapEx_PermitExecuteViolation,
    CapEx_PermitLoadViolation,
    CapEx_PermitStoreViolation,
    CapEx_PermitLoadCapViolation,
    CapEx_PermitStoreCapViolation,
    CapEx_PermitStoreLocalCapViolation,
    CapEx_PermitSealViolation,
    CapEx_PermitCCallViolation,
    CapEx_AccessCCallIDCViolation,
    CapEx_PermitUnsealViolation,
    CapEx_PermitSetCIDViolation,
    CapEx_AccessSystemRegsViolation
} CheriCapExcCause;

static inline ARMFaultType cheri_cause_to_arm_fault(CheriCapExcCause cause)
{
    switch (cause) {
    case CapEx_None:
        return ARMFault_None;
    case CapEx_LengthViolation:
        return ARMFault_CapBounds;
    case CapEx_TagViolation:
        return ARMFault_CapTag;
    case CapEx_SealViolation:
    case CapEx_TypeViolation:
        return ARMFault_CapSeal;
    case CapEx_TLBNoStoreCap:
        return ARMFault_CapPagePerm;
    case CapEx_GlobalViolation:
    case CapEx_PermitExecuteViolation:
    case CapEx_PermitLoadViolation:
    case CapEx_PermitStoreViolation:
    case CapEx_PermitLoadCapViolation:
    case CapEx_PermitStoreCapViolation:
    case CapEx_PermitStoreLocalCapViolation:
    case CapEx_PermitSealViolation:
    case CapEx_PermitCCallViolation:
    case CapEx_AccessCCallIDCViolation:
    case CapEx_PermitUnsealViolation:
    case CapEx_PermitSetCIDViolation:
        return ARMFault_CapPerm;
    default:
        assert(0);
    }
}

void QEMU_NORETURN raise_exception(CPUARMState *env, uint32_t excp,
                                   uint32_t syndrome, uint32_t target_el);

static inline const char *cheri_cause_str(CheriCapExcCause cause);

static inline void QEMU_NORETURN raise_cheri_exception_impl_if_wnr(
    CPUArchState *env, CheriCapExcCause cause, unsigned regnum,
    target_ulong addr, bool instavail, uintptr_t hostpc, bool instruction_fetch,
    bool is_write)
{
    ARMFaultType arm_fault = cheri_cause_to_arm_fault(cause);

    int target_el = exception_target_el_capability(env);
    int current_el = arm_current_el(env);

    uint32_t fsc, fsr, syn;
    ARMMMUFaultInfo fi;
    fi.type = arm_fault;
    fsr = arm_fi_to_lfsc(&fi);
    fsc = extract32(fsr, 0, 6);

    int cm = env->exception.cm ? 1 : 0;
    env->exception.cm = 0;

    env->exception.vaddress = addr;
    env->exception.fsr = fsr;
    syn = instruction_fetch
              ? syn_insn_abort(current_el == target_el, 0, 0, fsc)
              : syn_data_abort_no_iss(current_el == target_el, 0, 0, cm, 0,
                                      (is_write || cm) ? 1 : 0, fsc);

    qemu_log_instr_or_mask_msg(env, CPU_LOG_INT,
        "Got CHERI trap %s caused by register %d\n",
        cheri_cause_str(cause), regnum);

    if (hostpc) {
        // AARCH's cpu_restore_state will reset syndrome, so don't use
        // raise_exception_ra here.
        CPUState *cs = env_cpu(env);
        cpu_restore_state(cs, hostpc, true);
    }

    raise_exception(env,
                    instruction_fetch ? EXCP_PREFETCH_ABORT : EXCP_DATA_ABORT,
                    syn, target_el);
}

static inline void QEMU_NORETURN raise_cheri_exception_impl(
    CPUArchState *env, CheriCapExcCause cause, unsigned regnum,
    target_ulong addr, bool instavail, uintptr_t hostpc)
{
    raise_cheri_exception_impl_if_wnr(env, cause, regnum, addr, instavail,
                                      hostpc, false, false);
}

static inline void QEMU_NORETURN raise_load_tag_exception(CPUArchState *env,
                                                          target_ulong va,
                                                          int cb,
                                                          uintptr_t retpc)
{
    raise_cheri_exception_impl_if_wnr(env, CapEx_TLBNoStoreCap, cb, va, false,
                                      retpc, false, false);
}

static inline void QEMU_NORETURN raise_store_tag_exception(CPUArchState *env,
                                                           target_ulong va,
                                                           int reg,
                                                           uintptr_t retpc)
{
    raise_cheri_exception_impl_if_wnr(env, CapEx_TLBNoStoreCap, reg, va, false,
                                      retpc, false, true);
}

static inline void QEMU_NORETURN raise_unaligned_load_exception(
    CPUArchState *env, target_ulong addr, uintptr_t retpc)
{
    arm_cpu_do_unaligned_access(env_cpu(env), addr, MMU_DATA_LOAD,
                                cpu_mmu_index(env, false), retpc);
}

static inline void QEMU_NORETURN raise_unaligned_store_exception(
    CPUArchState *env, target_ulong addr, uintptr_t retpc)
{
    arm_cpu_do_unaligned_access(env_cpu(env), addr, MMU_DATA_STORE,
                                cpu_mmu_index(env, false), retpc);
}

static inline bool validate_jump_target(CPUARMState *env,
                                        const cap_register_t *target,
                                        target_ulong addr, unsigned regnum,
                                        uintptr_t retpc)
{
    // I think arm is meant to take exceptions at the target, so just return
    // true.
    return true;
}

#include "exec/helper-proto.h"

static inline void update_target_for_jump(CPUARMState *env,
                                          cap_register_t *target,
                                          uint32_t cjalr_flags)
{
    // Branches back to executive are allowed
    if (!(cjalr_flags & CJALR_CAN_BRANCH_RESTRICTED) &&
        cap_has_perms(_cheri_get_pcc_unchecked(env), CAP_PERM_EXECUTIVE) &&
        !cap_has_perms(target, CAP_PERM_EXECUTIVE)) {
        target->cr_tag = 0;
    }
}

static inline void update_next_pcc_for_tcg(CPUARMState *env,
                                           cap_register_t *target,
                                           uint32_t cjalr_flags)
{
    if (!cap_is_unsealed(target)) {
        target->cr_tag = 0;
    }

    // TODO: Reading BranchAddr in the arm ARM it looks like there is some
    // top byte sign extending not being respected here
    uint32_t old_perms = cap_get_perms(cheri_get_recent_pcc(env));
    uint32_t new_perms = cap_get_perms(target);

    bool system_changed = ((old_perms ^ new_perms) & CAP_ACCESS_SYS_REGS) != 0;
    bool executive_changed =
        ((old_perms ^ new_perms) & CAP_PERM_EXECUTIVE) != 0;
    bool c64_changed =
        (target->_cr_cursor & 1) != ((env->pstate & PSTATE_C64) != 0);

    unsigned int cur_el;

    env->pc.cap = *target;
    cheri_debug_assert(env->pc.cap.cr_extra == CREG_FULLY_DECOMPRESSED);
    env->pc.cap._cr_cursor &= ~1;

    if (executive_changed) {
        cur_el = arm_current_el(env);
        aarch64_save_sp(env, cur_el);
    }

    // Switch C64. Branches will have already ended a translation block.
    if (c64_changed)
        env->pstate ^= PSTATE_C64;

    // Rebuild cached target-specific cheriflags if anything changed
    if (system_changed || executive_changed || c64_changed)
        arm_rebuild_chflags(env);

    // Executive change can result in a change of stack / DDC
    if (executive_changed)
        aarch64_restore_sp(env, cur_el);
}

static inline target_ulong cheri_ddc_relative_addr(CPUARMState *env,
                                                   target_ulong addr)
{
    /* Morello relocates addresses by DDC.base if CCTLR.DDCBO is set. */
    if ((env->CCTLR_el[arm_current_el(env)] & CCTLR_DDCBO) != 0) {
        return cap_get_base(cheri_get_ddc(env)) + addr;
    }
    return addr;
}
