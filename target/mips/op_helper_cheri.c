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
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internal.h"
#include "qemu/host-utils.h"
#include "qemu/error-report.h"
#include "qemu/qemu-print.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/helper-proto.h"

#ifndef TARGET_CHERI
#error "This file should only be compiled for CHERI"
#endif

#include "cheri_tagmem.h"
#include "cheri-helper-utils.h"
#include "cheri-lazy-capregs.h"

#include "disas/disas.h"
#include "disas/dis-asm.h"

#ifdef __clang__
#pragma clang diagnostic error "-Wdeprecated-declarations"
#else
#pragma GCC diagnostic error "-Wdeprecated-declarations"
#endif
#define CHERI_HELPER_IMPL(name) \
    __attribute__((deprecated("Do not call the helper directly, it will crash at runtime. Call the _impl variant instead"))) helper_##name



void cheri_cpu_dump_statistics_f(CPUState *cs, FILE* f, int flags)
{
#ifndef DO_CHERI_STATISTICS
    qemu_fprintf(f, "CPUSTATS DISABLED, RECOMPILE WITH -DDO_CHERI_STATISTICS\n");
#else
    dump_out_of_bounds_stats(f, &oob_info_cincoffset);
    dump_out_of_bounds_stats(f, &oob_info_csetoffset);
    dump_out_of_bounds_stats(f, &oob_info_csetaddr);
    dump_out_of_bounds_stats(f, &oob_info_candaddr);
    dump_out_of_bounds_stats(f, &oob_info_cfromptr);
    dump_out_of_bounds_stats(f, &oob_info_cgetpccsetoffset);
    dump_out_of_bounds_stats(f, &oob_info_cgetpccincoffset);
    dump_out_of_bounds_stats(f, &oob_info_cgetpccsetaddr);
#endif
}

void cheri_cpu_dump_statistics(CPUState *cs, int flags) {
    cheri_cpu_dump_statistics_f(cs, NULL, flags);
}


static inline bool
is_cap_sealed(const cap_register_t *cp)
{
    // TODO: remove this function and update all callers to use the correct function
    return cap_is_sealed_with_type(cp) || cap_is_sealed_entry(cp);
}

#ifdef CONFIG_TCG_LOG_INSTR
#define log_instr_hwreg_update(env, name, newval) do {          \
        if (qemu_log_instr_enabled(env)) {                      \
            qemu_log_instr_reg(env, name, newval);              \
        }                                                       \
    } while (0)

#else
#define log_instr_hwreg_update(env, name, newval) ((void)0)
#endif

static inline int align_of(int size, uint64_t addr)
{

    switch(size) {
    case 1:
        return 0;
    case 2:
        return (addr & 0x1);
    case 4:
        return (addr & 0x3);
    case 8:
        return (addr & 0x7);
    case 16:
        return (addr & 0xf);
    case 32:
        return (addr & 0x1f);
    case 64:
        return (addr & 0x3f);
    case 128:
        return (addr & 0x7f);
    default:
        return 1;
    }
}

static inline void update_ddc(CPUArchState *env, const cap_register_t* new_ddc) {
    if (!cap_exactly_equal(&env->active_tc.CHWR.DDC, new_ddc)) {
        qemu_log_instr_or_mask_msg(env, CPU_LOG_MMU,
            "Flushing TCG TLB since $ddc is changing to " PRINT_CAP_FMTSTR "\n",
            PRINT_CAP_ARGS(new_ddc));
        // TODO: in the future we may want to move $ddc to the guest -> host addr
        // translation. This would allow skipping $ddc checks for all pages that
        // are fully covered by $ddc for the second load/store check
        // (QEMU has separate TLBs for both cases already).
        // If we implment this, we will have to flush the entire TLB whenever
        // $ddc changes (or at least flush all pages affected by the $ddc chaged)
        // XXX: tlb_flush(env_cpu(env));
        env->active_tc.CHWR.DDC = *new_ddc;
    } else {
        qemu_log_instr_or_mask_msg(env, CPU_LOG_MMU,
            "Installing same $ddc again, not flushing TCG TLB: "
            PRINT_CAP_FMTSTR "\n", PRINT_CAP_ARGS(new_ddc));
    }
    cheri_log_instr_changed_capreg(env, mips_cheri_hw_regnames[0], new_ddc);
}

target_ulong CHERI_HELPER_IMPL(cbez(CPUArchState *env, uint32_t cb, uint32_t offset))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    /*
     * CBEZ: Branch if NULL
     *
     * Note: Only compares the address part of the capability.
     */
    if (cap_get_cursor(cbp) == 0)
        return (target_ulong)1;
    else
        return (target_ulong)0;
}

target_ulong CHERI_HELPER_IMPL(cbnz(CPUArchState *env, uint32_t cb, uint32_t offset))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    /*
     * CBEZ: Branch if not NULL.
     *
     * Note: Only compares the address part of the capability.
     */
    if (cap_get_cursor(cbp) == 0)
        return (target_ulong)0;
    else
        return (target_ulong)1;
}

target_ulong CHERI_HELPER_IMPL(cbts(CPUArchState *env, uint32_t cb, uint32_t offset))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    /*
     * CBTS: Branch if tag is set
     */
    return (target_ulong)cbp->cr_tag;
}

target_ulong CHERI_HELPER_IMPL(cbtu(CPUArchState *env, uint32_t cb, uint32_t offset))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    /*
     * CBTU: Branch if tag is unset
     */
    return (target_ulong)!cbp->cr_tag;
}

static target_ulong ccall_common(CPUArchState *env, uint32_t cs, uint32_t cb, uint32_t selector, uintptr_t _host_return_address)
{
    const cap_register_t *csp = get_readonly_capreg(env, cs);
    const cap_register_t *cbp = get_readonly_capreg(env, cb);

    // This assumes that the non-type sealed things can all be jumped to.
    // This is true for sentries, which behave like unsealed caps in this way.
    // If a new reserved sealing type is used this might have to be re-evaluated.

    int allow_unsealed = (selector == CCALL_SELECTOR_2) && !cap_is_sealed_with_type(csp);
    /*
     * CCall: Call into a new security domain
     */
    if (!csp->cr_tag) {
        raise_cheri_exception(env, CapEx_TagViolation, cs);
    } else if (!cbp->cr_tag && !allow_unsealed) {
        raise_cheri_exception(env, CapEx_TagViolation, cb);
    } else if (cap_is_sealed_with_type(csp) == allow_unsealed) {
        raise_cheri_exception(env, CapEx_SealViolation, cs);
    } else if (cap_is_sealed_with_type(cbp) == allow_unsealed) {
        raise_cheri_exception(env, CapEx_SealViolation, cb);
    } else if ((cap_get_otype_unsigned(csp) != cap_get_otype_unsigned(cbp) ||
                !cap_is_sealed_with_type(csp)) &&
               !allow_unsealed) {
        raise_cheri_exception(env, CapEx_TypeViolation, cs);
    } else if (!cap_has_perms(csp, CAP_PERM_EXECUTE)) {
        raise_cheri_exception(env, CapEx_PermitExecuteViolation, cs);
    } else if (cap_has_perms(cbp, CAP_PERM_EXECUTE) && !allow_unsealed) {
        raise_cheri_exception(env, CapEx_PermitExecuteViolation, cb);
    } else if (!cap_cursor_in_bounds(csp)) {
        // TODO: check for at least one instruction worth of data? Like cjr/cjalr?
        raise_cheri_exception(env, CapEx_LengthViolation, cs);
    } else {
        if (selector == CCALL_SELECTOR_0) {
            raise_cheri_exception(env, CapEx_CallTrap, cs);
        } else if (!cap_has_perms(csp, CAP_PERM_CINVOKE) && !allow_unsealed) {
            raise_cheri_exception(env, CapEx_PermitCCallViolation, cs);
        } else if (!cap_has_perms(cbp, CAP_PERM_CINVOKE) && !allow_unsealed) {
            raise_cheri_exception(env, CapEx_PermitCCallViolation, cb);
        } else {
            cap_register_t idc = *cbp;
            // Use of !allow_unsealed rather than !cap_is_unsealed used on purpose.
            // This should function like a jump and a move in the CCall2 case.
            if (!allow_unsealed) cap_set_unsealed(&idc);
            update_capreg(env, CINVOKE_DATA_REGNUM, &idc);
            // The capability register is loaded into PCC during delay slot
            env->active_tc.CapBranchTarget = *csp;
            // XXXAR: clearing these fields is not strictly needed since they
            // aren't copied from the CapBranchTarget to $pcc but it does make
            // the LOG_INSTR output less confusing.
            cap_register_t *target = &env->active_tc.CapBranchTarget;

            if (cap_is_sealed_with_type(target)) {
                cap_set_unsealed(target);
            } else if (cap_is_sealed_entry(target)) {
                cap_unseal_entry(target);
            }
            // Return the branch target address
            return cap_get_cursor(csp);
        }
    }
    return (target_ulong)0;
}

void CHERI_HELPER_IMPL(ccall(CPUArchState *env, uint32_t cs, uint32_t cb))
{
    (void)ccall_common(env, cs, cb, CCALL_SELECTOR_0, GETPC());
}

target_ulong CHERI_HELPER_IMPL(ccall_notrap(CPUArchState *env, uint32_t cs, uint32_t cb))
{
    return ccall_common(env, cs, cb, CCALL_SELECTOR_1, GETPC());
}

target_ulong CHERI_HELPER_IMPL(ccall_notrap2(CPUArchState *env, uint32_t cs, uint32_t cb))
{
    return ccall_common(env, cs, cb, CCALL_SELECTOR_2, GETPC());
}

void CHERI_HELPER_IMPL(cclearreg(CPUArchState *env, uint32_t mask))
{
    // Register zero means $ddc here since it is useful to clear $ddc on a
    // sandbox switch whereas clearing $NULL is useless
    if (mask & 0x1) {
        update_ddc(env, get_readonly_capreg(env, 0)); // nullify $ddc
    }

    for (int creg = 1; creg < 32; creg++) {
        if (mask & (0x1 << creg)) {
            nullify_capreg(env, creg);
        }
    }
}

void CHERI_HELPER_IMPL(creturn(CPUArchState *env)) {
    do_raise_c2_exception_noreg(env, CapEx_ReturnTrap, GETPC());
}

target_ulong CHERI_HELPER_IMPL(cgetcause(CPUArchState *env))
{
    /*
     * CGetCause: Move the Capability Exception Cause Register to a
     * General- Purpose Register
     */
    if (!cheri_have_access_sysregs(env)) {
        do_raise_c2_exception_noreg(env, CapEx_AccessSystemRegsViolation, GETPC());
    } else {
        return (target_ulong)env->CP2_CapCause;
    }
}

void CHERI_HELPER_IMPL(cgetpcc(CPUArchState *env, uint32_t cd))
{
    /*
     * CGetPCC: Move PCC to capability register
     * See Chapter 4 in CHERI Architecture manual.
     */
    update_capreg(env, cd, cheri_get_current_pcc(env));
}

/* Note: not using CHERI_HELPER_IMPL since it cannot trap */
void helper_cmovz(CPUArchState *env, uint32_t cd, uint32_t cs, target_ulong rs)
{
    const cap_register_t *csp = get_readonly_capreg(env, cs);
    /*
     * CMOVZ: conditionally move capability on zero
     */
    if (rs == 0) {
        update_capreg(env, cd, csp);
    }
}

/* Note: not using CHERI_HELPER_IMPL since it cannot trap */
void helper_cmovn(CPUArchState *env, uint32_t cd, uint32_t cs, target_ulong rs)
{
    helper_cmovz(env, cd, cs, rs == 0);
}

target_ulong CHERI_HELPER_IMPL(cjr(CPUArchState *env, uint32_t cb))
{
    GET_HOST_RETPC();
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    /*
     * CJR: Jump Capability Register
     */
    if (!cbp->cr_tag) {
        raise_cheri_exception(env, CapEx_TagViolation, cb);
    } else if (cap_is_sealed_with_type(cbp)) {
        // Note: "sentry" caps can be called using cjalr
        raise_cheri_exception(env, CapEx_SealViolation, cb);
    } else if (!cap_has_perms(cbp, CAP_PERM_EXECUTE)) {
        raise_cheri_exception(env, CapEx_PermitExecuteViolation, cb);
    } else if (!cap_has_perms(cbp, CAP_PERM_GLOBAL)) {
        raise_cheri_exception(env, CapEx_GlobalViolation, cb);
    } else if (!cap_is_in_bounds(cbp, cap_get_cursor(cbp), 4)) {
        raise_cheri_exception(env, CapEx_LengthViolation, cb);
    } else if (align_of(4, cap_get_cursor(cbp))) {
        do_raise_c0_exception(env, EXCP_AdEL, cap_get_cursor(cbp));
    } else {
        cheri_debug_assert(cap_is_unsealed(cbp) || cap_is_sealed_entry(cbp));
        // The capability register is loaded into PCC during delay slot
        env->active_tc.CapBranchTarget = *cbp;
        // If we are calling a "sentry" cap, remove the sealed flag
        if (cap_is_sealed_entry(cbp))
            cap_unseal_entry(&env->active_tc.CapBranchTarget);
        // Return the branch target address
        return cap_get_cursor(cbp);
    }

    return (target_ulong)0;
}

static inline cap_register_t *
check_writable_cap_hwr_access(CPUArchState *env, enum CP2HWR hwr, target_ulong _host_return_address) {
    cheri_debug_assert((int)hwr >= (int)CP2HWR_BASE_INDEX);
    cheri_debug_assert((int)hwr < (int)(CP2HWR_BASE_INDEX + 32));
    bool access_sysregs = cheri_have_access_sysregs(env);
    switch (hwr) {
    case CP2HWR_DDC: /* always accessible */
        assert(false && "$ddc should not be handled here");
        break;
    case CP2HWR_USER_TLS:  /* always accessible */
        return &env->active_tc.CHWR.UserTlsCap;
    case CP2HWR_PRIV_TLS:
        if (!access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }
        return &env->active_tc.CHWR.PrivTlsCap;
    case CP2HWR_K1RC:
        if (!in_kernel_mode(env) || !access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }
        return &env->active_tc.CHWR.KR1C;
    case CP2HWR_K2RC:
        if (!in_kernel_mode(env) || !access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }
        return &env->active_tc.CHWR.KR2C;
    case CP2HWR_ErrorEPCC:
        if (!in_kernel_mode(env) || !access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }

        return &env->active_tc.CHWR.ErrorEPCC;
    case CP2HWR_KCC:
        if (!in_kernel_mode(env) || !access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }
        return &env->active_tc.CHWR.KCC;
    case CP2HWR_KDC:
        if (!in_kernel_mode(env) || !access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }
        return &env->active_tc.CHWR.KDC;
    case CP2HWR_EPCC:
        if (!in_kernel_mode(env) || !access_sysregs) {
            raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, hwr);
        }
        return &env->active_tc.CHWR.EPCC;
    }
    /* unknown cap hardware register */
    do_raise_exception(env, EXCP_RI, _host_return_address);
    return NULL;  // silence warning
}

static inline const cap_register_t *
check_readonly_cap_hwr_access(CPUArchState *env, enum CP2HWR hwr, target_ulong pc) {
    // Currently there is no difference for access permissions between read
    // and write access but that may change in the future
    if (hwr == CP2HWR_DDC)
        return &env->active_tc.CHWR.DDC;
    return check_writable_cap_hwr_access(env, hwr, pc);
}

target_ulong CHERI_HELPER_IMPL(mfc0_epc(CPUArchState *env))
{
    return get_CP0_EPC(env);
}

target_ulong CHERI_HELPER_IMPL(mfc0_error_epc(CPUArchState *env))
{
    return get_CP0_ErrorEPC(env);
}

void CHERI_HELPER_IMPL(mtc0_epc(CPUArchState *env, target_ulong arg))
{
    GET_HOST_RETPC();
    // Check that we can write to EPCC (should always be true since we would have got a trap when not in kernel mode)
    if (!in_kernel_mode(env)) {
        do_raise_exception(env, EXCP_RI, GETPC());
    } else if (!cheri_have_access_sysregs(env)) {
        raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, CP2HWR_EPCC);
    }
    set_CP0_EPC(env, arg + cap_get_base(&env->active_tc.CHWR.EPCC));
    log_instr_hwreg_update(env, mips_cop0_regnames[14],
                           env->active_tc.CHWR.EPCC._cr_cursor);
}

void CHERI_HELPER_IMPL(mtc0_error_epc(CPUArchState *env, target_ulong arg))
{
    GET_HOST_RETPC();
    // Check that we can write to ErrorEPCC (should always be true since we would have got a trap when not in kernel mode)
    if (!in_kernel_mode(env)) {
        do_raise_exception(env, EXCP_RI, GETPC());
    } else if (!cheri_have_access_sysregs(env)) {
        raise_cheri_exception(env, CapEx_AccessSystemRegsViolation, CP2HWR_ErrorEPCC);
    }
    set_CP0_ErrorEPC(env, arg + cap_get_base(&env->active_tc.CHWR.ErrorEPCC));
    log_instr_hwreg_update(env, mips_cop0_regnames[30],
                           env->active_tc.CHWR.ErrorEPCC._cr_cursor);
}

void CHERI_HELPER_IMPL(creadhwr(CPUArchState *env, uint32_t cd, uint32_t hwr))
{
    cap_register_t result = *check_readonly_cap_hwr_access(
        env, CP2HWR_BASE_INDEX + hwr, GETPC());
    update_capreg(env, cd, &result);
}

void CHERI_HELPER_IMPL(cwritehwr(CPUArchState *env, uint32_t cs, uint32_t hwr))
{
    const cap_register_t *csp = get_readonly_capreg(env, cs);
    if (hwr == CP2HWR_DDC) {
        // $ddc is always writable
        update_ddc(env, csp);
        return;
    }
    cap_register_t *cdp = check_writable_cap_hwr_access(
        env, CP2HWR_BASE_INDEX + hwr, GETPC());
    *cdp = *csp;
    /* Note: DDC updates are logged in update_ddc. */
    cheri_log_instr_changed_capreg(env, mips_cheri_hw_regnames[hwr], csp);
}

void CHERI_HELPER_IMPL(csetcause(CPUArchState *env, target_ulong rt))
{
    /*
     * CSetCause: Set the Capability Exception Cause Register
     */
    if (!cheri_have_access_sysregs(env)) {
        do_raise_c2_exception_noreg(env, CapEx_AccessSystemRegsViolation, GETPC());
    } else {
        env->CP2_CapCause = (uint16_t)(rt & 0xffffUL);
    }
    log_instr_hwreg_update(env, "CapCause", env->CP2_CapCause);
}

/*
 * CPtrCmp Instructions. Capability Pointer Compare.
 */
target_ulong CHERI_HELPER_IMPL(ceq(CPUArchState *env, uint32_t cb, uint32_t ct))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    const cap_register_t *ctp = get_readonly_capreg(env, ct);
    /*
     * CEQ: Capability pointers equal (compares only the cursor)
     */
    return (target_ulong)(cap_get_cursor(cbp) == cap_get_cursor(ctp));
}

target_ulong CHERI_HELPER_IMPL(cne(CPUArchState *env, uint32_t cb, uint32_t ct))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    const cap_register_t *ctp = get_readonly_capreg(env, ct);
    /*
     * CNE: Capability pointers not equal (compares only the cursor)
     */
  return (target_ulong)(cap_get_cursor(cbp) != cap_get_cursor(ctp));

}

target_ulong CHERI_HELPER_IMPL(clt(CPUArchState *env, uint32_t cb, uint32_t ct))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    const cap_register_t *ctp = get_readonly_capreg(env, ct);
    /*
     * CLT: Capability pointers less than (signed)
     */
    int64_t cursor1_signed = (int64_t)cap_get_cursor(cbp);
    int64_t cursor2_signed = (int64_t)cap_get_cursor(ctp);
    return (target_ulong)(cursor1_signed < cursor2_signed);
}

target_ulong CHERI_HELPER_IMPL(cle(CPUArchState *env, uint32_t cb, uint32_t ct))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    const cap_register_t *ctp = get_readonly_capreg(env, ct);
    /*
     * CLE: Capability pointers less than equal (signed)
     */
    int64_t cursor1_signed = (int64_t)cap_get_cursor(cbp);
    int64_t cursor2_signed = (int64_t)cap_get_cursor(ctp);
    return (target_ulong)(cursor1_signed <= cursor2_signed);
}

target_ulong CHERI_HELPER_IMPL(cltu(CPUArchState *env, uint32_t cb, uint32_t ct))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    const cap_register_t *ctp = get_readonly_capreg(env, ct);
    /*
     * CLTU: Capability pointers less than (unsigned)
     */
    uint64_t cursor1_unsigned = cap_get_cursor(cbp);
    uint64_t cursor2_unsigned = cap_get_cursor(ctp);
    return (target_ulong)(cursor1_unsigned < cursor2_unsigned);
}

target_ulong CHERI_HELPER_IMPL(cleu(CPUArchState *env, uint32_t cb, uint32_t ct))
{
    const cap_register_t *cbp = get_readonly_capreg(env, cb);
    const cap_register_t *ctp = get_readonly_capreg(env, ct);
    /*
     * CLEU: Capability pointers less than equal (unsigned)
     */
    uint64_t cursor1_unsigned = cap_get_cursor(cbp);
    uint64_t cursor2_unsigned = cap_get_cursor(ctp);
    return (target_ulong)(cursor1_unsigned <= cursor2_unsigned);
}

target_ulong CHERI_HELPER_IMPL(cgetandaddr(CPUArchState *env, uint32_t cb, target_ulong rt))
{
    target_ulong addr = get_capreg_cursor(env, cb);
    return addr & rt;
}

/*
 * Compute the address for Load Linked Via Capability Register
 */
target_ulong CHERI_HELPER_IMPL(cloadlinked(CPUArchState *env, uint32_t cb, uint32_t size))
{
    GET_HOST_RETPC();
    // CLL[BHWD][U] traps on cbp == NULL so we use reg0 as $ddc to save encoding
    // space and increase code density since loading relative to $ddc is common
    // in the hybrid ABI (and also for backwards compat with old binaries).
    const cap_register_t *cbp = get_capreg_0_is_ddc(env, cb);
    uint64_t addr = cap_get_cursor(cbp);

    env->lladdr = 1;
    if (!cbp->cr_tag) {
        raise_cheri_exception(env, CapEx_TagViolation, cb);
    } else if (is_cap_sealed(cbp)) {
        raise_cheri_exception(env, CapEx_SealViolation, cb);
    } else if (!cap_has_perms(cbp, CAP_PERM_LOAD)) {
        raise_cheri_exception(env, CapEx_PermitLoadViolation, cb);
    } else if (!cap_is_in_bounds(cbp, addr, size)) {
        raise_cheri_exception(env, CapEx_LengthViolation, cb);
    } else if (align_of(size, addr)) {
        // TODO: should #if (CHERI_UNALIGNED) also disable this check?
        do_raise_c0_exception(env, EXCP_AdEL, addr);
    } else {
        env->CP0_LLAddr = do_translate_address(env, addr, 0, _host_return_address);
        env->lladdr = addr;
        return addr;
    }
    return 0;
}

/*
 * Compute the address for Store Conditional Via Capability Register
 */
target_ulong CHERI_HELPER_IMPL(cstorecond(CPUArchState *env, uint32_t cb, uint32_t size))
{
    GET_HOST_RETPC();
    // CSC[BHWD] traps on cbp == NULL so we use reg0 as $ddc to save encoding
    // space and increase code density since storing relative to $ddc is common
    // in the hybrid ABI (and also for backwards compat with old binaries).
    const cap_register_t *cbp = get_capreg_0_is_ddc(env, cb);
    uint64_t addr = cap_get_cursor(cbp);

    if (!cbp->cr_tag) {
        raise_cheri_exception(env, CapEx_TagViolation, cb);
    } else if (is_cap_sealed(cbp)) {
        raise_cheri_exception(env, CapEx_SealViolation, cb);
    } else if (!cap_has_perms(cbp, CAP_PERM_STORE)) {
        raise_cheri_exception(env, CapEx_PermitStoreViolation, cb);
    } else if (!cap_is_in_bounds(cbp, addr, size)) {
        raise_cheri_exception(env, CapEx_LengthViolation, cb);
    } else if (align_of(size, addr)) {
        // TODO: should #if (CHERI_UNALIGNED) also disable this check?
        do_raise_c0_exception(env, EXCP_AdES, addr);
    } else {
        qemu_maybe_log_instr_extra(env, "cstorecond: addr="
            TARGET_FMT_plx "lladdr=" TARGET_FMT_plx " CP0_LLaddr="
            TARGET_FMT_plx "\n", addr, env->lladdr, env->CP0_LLAddr);

        // Can't do this here.  It might miss in the TLB.
        // cheri_tag_invalidate(env, addr, size);
        // Also, rd is set by the actual store conditional operation.
        return addr;
    }
    return 0;
}

static inline target_ulong get_cscc_addr(CPUArchState *env, uint32_t cs, uint32_t cb, uintptr_t _host_return_address)
{
    // CSCC traps on cbp == NULL so we use reg0 as $ddc to save encoding
    // space and increase code density since storing relative to $ddc is common
    // in the hybrid ABI (and also for backwards compat with old binaries).
    const cap_register_t *cbp = get_capreg_0_is_ddc(env, cb);
    const cap_register_t *csp = get_readonly_capreg(env, cs);
    uint64_t addr = cap_get_cursor(cbp);

    if (!cbp->cr_tag) {
        raise_cheri_exception(env, CapEx_TagViolation, cb);
        return (target_ulong)0;
    } else if (is_cap_sealed(cbp)) {
        raise_cheri_exception(env, CapEx_SealViolation, cb);
        return (target_ulong)0;
    } else if (!cap_has_perms(cbp, CAP_PERM_STORE)) {
        raise_cheri_exception(env, CapEx_PermitStoreViolation, cb);
        return (target_ulong)0;
    } else if (!cap_has_perms(cbp, CAP_PERM_STORE_CAP)) {
        raise_cheri_exception(env, CapEx_PermitStoreCapViolation, cb);
        return (target_ulong)0;
    } else if (!cap_has_perms(cbp, CAP_PERM_STORE_LOCAL) && csp->cr_tag &&
               !cap_has_perms(csp, CAP_PERM_GLOBAL)) {
        raise_cheri_exception(env, CapEx_PermitStoreLocalCapViolation, cb);
        return (target_ulong)0;
    } else if (!cap_is_in_bounds(cbp, addr, CHERI_CAP_SIZE)) {
        raise_cheri_exception(env, CapEx_LengthViolation, cb);
        return (target_ulong)0;
    } else if (align_of(CHERI_CAP_SIZE, addr)) {
        do_raise_c0_exception(env, EXCP_AdES, addr);
        return (target_ulong)0;
    }

    return (target_ulong)addr;
}

target_ulong CHERI_HELPER_IMPL(cscc_without_tcg(CPUArchState *env, uint32_t cs, uint32_t cb))
{
    uintptr_t retpc = GETPC();
    target_ulong vaddr = get_cscc_addr(env, cs, cb, retpc);

    qemu_maybe_log_instr_extra(env, "cscc: addr=" TARGET_FMT_plx
        " lladdr=" TARGET_FMT_plx " CP0_LLaddr=" TARGET_FMT_plx "\n",
        vaddr, env->lladdr, env->CP0_LLAddr);
    if (env->lladdr != vaddr)
        return 0;
    store_cap_to_memory(env, cs, vaddr, retpc);
    env->lladdr = 1;
    return 1;
}

void CHERI_HELPER_IMPL(cllc_without_tcg(CPUArchState *env, uint32_t cd, uint32_t cb))
{
    GET_HOST_RETPC();

    // CLLC traps on cbp == NULL so we use reg0 as $ddc to save encoding
    // space and increase code density since loading relative to $ddc is common
    // in the hybrid ABI (and also for backwards compat with old binaries).
    const cap_register_t *cbp = get_capreg_0_is_ddc(env, cb);
    uint64_t addr = cap_get_cursor(cbp);

    /* Clear linked state */
    env->lladdr = 1;
    if (!cbp->cr_tag) {
        raise_cheri_exception(env, CapEx_TagViolation, cb);
    } else if (is_cap_sealed(cbp)) {
        raise_cheri_exception(env, CapEx_SealViolation, cb);
    } else if (!cap_has_perms(cbp, CAP_PERM_LOAD)) {
        raise_cheri_exception(env, CapEx_PermitLoadViolation, cb);
    } else if (!cap_is_in_bounds(cbp, addr, CHERI_CAP_SIZE)) {
        raise_cheri_exception(env, CapEx_LengthViolation, cb);
    } else if (align_of(CHERI_CAP_SIZE, addr)) {
        do_raise_c0_exception(env, EXCP_AdEL, addr);
    }
    cheri_debug_assert(align_of(CHERI_CAP_SIZE, addr) == 0);
    load_cap_from_memory(env, cd, cb, cbp, /*addr=*/cap_get_cursor(cbp),
                         _host_return_address, &env->CP0_LLAddr);
    env->lladdr = addr;
}

void CHERI_HELPER_IMPL(copy_cap_btarget_to_pcc(CPUArchState *env))
{
    // It should not have been possible to create an invalid CapBranchTarget
    cheri_debug_assert(cap_is_representable(&env->active_tc.CapBranchTarget));
    env->active_tc.PCC = env->active_tc.CapBranchTarget;
    // Restore or clear MIPS_HFLAG_CP0 depending on Access_System_Registers permission
#ifdef CONFIG_DEBUG_TCG
    env->active_tc._pc_is_current = true;
#endif
    update_cp0_access_for_pc(env);
}

target_ulong CHERI_HELPER_IMPL(ccheck_load_right(CPUArchState *env, target_ulong offset, uint32_t len))
{
#ifndef TARGET_WORDS_BIGENDIAN
#error "This check is only valid for big endian targets, for little endian the load/store left instructions need to be checked"
#endif
    // For lwr/ldr we load all bytes if offset & 3/7 == 0 we load only the first byte, if all low bits are set we load the full amount
    uint32_t low_bits = (uint32_t)offset & (len - 1);
    uint32_t loaded_bytes = low_bits + 1;
    // From spec:
    //if BigEndianMem = 1 then
    //  pAddr <- pAddr(PSIZE-1)..3 || 000 (for ldr), 00 for lwr
    //endif
    // clear the low bits in offset to perform the length check
    target_ulong read_offset = offset & ~((target_ulong)len - 1);
    // fprintf(stderr, "%s: len=%d, offset=%zd, read_offset=%zd: will touch %d bytes\n",
    //      __func__, len, (size_t)offset, (size_t)read_offset, loaded_bytes);
    // return the actual address by adding the low bits (this is expected by translate.c
    return check_ddc(env, CAP_PERM_LOAD, read_offset, loaded_bytes, GETPC()) + low_bits;
}

target_ulong CHERI_HELPER_IMPL(ccheck_store(CPUArchState *env, target_ulong offset, uint32_t len))
{
    return check_ddc(env, CAP_PERM_STORE, offset, len, GETPC());
}

target_ulong CHERI_HELPER_IMPL(ccheck_load(CPUArchState *env, target_ulong offset, uint32_t len))
{
    return check_ddc(env, CAP_PERM_LOAD, offset, len, GETPC());
}

void CHERI_HELPER_IMPL(ccheck_load_pcrel(CPUArchState *env, target_ulong addr,
                                         uint32_t len)) {
    // Note: the address is already absolute, no need to add pcc.base
    // Also we don't need PCC.cursor to be current since we are only looking at
    // the bounds
    check_cap(env, cheri_get_recent_pcc(env), CAP_PERM_LOAD, addr, /*regnum=*/0,
              len, /*instavail=*/true, GETPC());
}

static const char *cheri_cap_reg[] = {
  "DDC",  "",   "",      "",     "",    "",    "",    "",  /* C00 - C07 */
     "",  "",   "",      "",     "",    "",    "",    "",  /* C08 - C15 */
     "",  "",   "",      "",     "",    "",    "",    "",  /* C16 - C23 */
  "RCC",  "", "IDC", "KR1C", "KR2C", "KCC", "KDC", "EPCC"  /* C24 - C31 */
};

static void cheri_dump_creg(const cap_register_t *crp, const char *name,
                            const char *alias, FILE *f,
                            fprintf_function cpu_fprintf)
{
    cpu_fprintf(f,
                "DEBUG CAP %s t:%d s:%d perms:0x%08x type:0x%016" PRIx64 " "
                "offset:0x%016lx base:0x%016lx length:0x%016lx\n",
                name, crp->cr_tag, is_cap_sealed(crp),
                COMBINED_PERMS_VALUE(crp),
                /* testsuite wants -1 for unsealed */
                (uint64_t)cap_get_otype_signext(crp),
                (uint64_t)cap_get_offset(crp), cap_get_base(crp),
                /* testsuite expects UINT64_MAX for 1 << 64) */
                cap_get_length_sat(crp));
}

void cheri_dump_state(CPUState *cs, FILE *f, fprintf_function cpu_fprintf, int flags)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUArchState *env = &cpu->env;
    int i;
    char name[8];

    cpu_fprintf(f, "DEBUG CAP COREID 0\n");
    cheri_dump_creg(cheri_get_current_pcc(env), "PCC", "", f, cpu_fprintf);
    for (i = 0; i < 32; i++) {
        // snprintf(name, sizeof(name), "C%02d", i);
        snprintf(name, sizeof(name), "REG %02d", i);
        cheri_dump_creg(get_readonly_capreg(env, i), name, cheri_cap_reg[i], f,
                        cpu_fprintf);
    }
    cheri_dump_creg(&env->active_tc.CHWR.DDC,        "HWREG 00 (DDC)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.UserTlsCap, "HWREG 01 (CTLSU)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.PrivTlsCap, "HWREG 08 (CTLSP)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.KR1C,       "HWREG 22 (KR1C)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.KR2C,       "HWREG 23 (KR2C)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.ErrorEPCC,  "HWREG 28 (ErrorEPCC)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.KCC,        "HWREG 29 (KCC)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.KDC,        "HWREG 30 (KDC)", "", f, cpu_fprintf);
    cheri_dump_creg(&env->active_tc.CHWR.EPCC,       "HWREG 31 (EPCC)", "", f, cpu_fprintf);

    cpu_fprintf(f, "\n");
}

void CHERI_HELPER_IMPL(mtc2_dumpcstate(CPUArchState *env, target_ulong arg1))
{
    FILE* logfile = qemu_log_enabled() ? qemu_log_lock() : stderr;
    cheri_dump_state(env_cpu(env), logfile, fprintf, CPU_DUMP_CODE);
    if (logfile != stderr)
        qemu_log_unlock(logfile);
}
