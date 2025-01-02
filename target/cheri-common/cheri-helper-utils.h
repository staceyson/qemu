/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018-2020 Alex Richardson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
#include "cheri_defs.h"
#include "cheri_utils.h"
#include "cheri-lazy-capregs.h"
#include "cheri-bounds-stats.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "exec/exec-all.h"

static inline void derive_cap_from_pcc(CPUArchState *env, uint32_t cd,
                                       target_ulong new_addr, uintptr_t retpc,
                                       struct oob_stats_info *oob_info)
{
#ifdef DO_CHERI_STATISTICS
    oob_info->num_uses++;
#else
    (void)oob_info;
#endif
    // Note: we can use a "stale" PCC value with an outdated cursor here since
    // we only really care about the bounds and permissions to derive the
    // resulting capability (e.g. auipcc or CGetPCCIncOffset).
    // If the result is not representable it will be untagged.
    const cap_register_t *pccp = cheri_get_recent_pcc(env);
    cap_register_t result = *pccp;
    if (!is_representable_cap_with_addr(pccp, new_addr)) {
        if (pccp->cr_tag)
            became_unrepresentable(env, cd, oob_info, retpc);
        cap_mark_unrepresentable(new_addr, &result);
    } else {
        result._cr_cursor = new_addr;
        check_out_of_bounds_stat(env, oob_info, &result, retpc);
    }
    update_capreg(env, cd, &result);
}

// TODO: Delete this in favour of cap_check_common_reg. It gets things right
// that this gets wrong.
// TODO: Still using this in a couple places however.
static inline void check_cap(CPUArchState *env, const cap_register_t *cr,
                             uint32_t perm, target_ulong addr, uint16_t regnum,
                             uint32_t len, bool instavail, uintptr_t pc)
{
    CheriCapExcCause cause;
    /*
     * See section 5.6 in CHERI Architecture.
     *
     * Capability checks (in order of priority):
     * (1) <ctag> must be set (CapEx_TagViolation Violation).
     * (2) Seal bit must be unset (CapEx_SealViolation Violation).
     * (3) <perm> permission must be set (CapEx_PermitExecuteViolation,
     * CapEx_PermitLoadViolation, or CapEx_PermitStoreViolation Violation). (4)
     * <addr> must be within bounds (CapEx_LengthViolation Violation).
     */
    if (!cr->cr_tag) {
        cause = CapEx_TagViolation;
        // qemu_log("CAP Tag VIOLATION: ");
        goto do_exception;
    }
    if (!cap_is_unsealed(cr)) {
        cause = CapEx_SealViolation;
        // qemu_log("CAP Seal VIOLATION: ");
        goto do_exception;
    }
    if ((cap_get_perms(cr) & perm) != perm) {
        if (perm & CAP_PERM_EXECUTE) {
            cause = CapEx_PermitExecuteViolation;
            // qemu_log("CAP Exe VIOLATION: ");
            goto do_exception;
        } else if (perm & CAP_PERM_STORE) {
            cause = CapEx_PermitStoreViolation;
            // qemu_log("CAP ST VIOLATION: ");
            goto do_exception;
        } else if (perm & CAP_PERM_LOAD) {
            cause = CapEx_PermitLoadViolation;
            // qemu_log("CAP LD VIOLATION: ");
            goto do_exception;
        }
        // Multiple missing permissions:
        error_report("Bad permissions check %d", perm);
        tcg_abort();
    }
    // fprintf(stderr, "addr=%zx, len=%zd, cr_base=%zx, cr_len=%zd\n",
    //     (size_t)addr, (size_t)len, (size_t)cr->cr_base,
    //     (size_t)cr->cr_length);
    if (!cap_is_in_bounds(cr, addr, len)) {
        cause = CapEx_LengthViolation;
        // qemu_log("CAP Len VIOLATION: ");
        goto do_exception;
    }
    return;

do_exception:
#ifdef TARGET_AARCH64
    raise_cheri_exception_impl_if_wnr(env, cause, regnum, addr, instavail, pc,
                                      !!(perm & CAP_PERM_EXECUTE),
                                      !!(perm & CAP_PERM_STORE));
#else
    raise_cheri_exception_impl(env, cause, regnum, addr, instavail, pc);
#endif
}

static inline target_ulong check_ddc(CPUArchState *env, uint32_t perm,
                                     target_ulong ddc_offset, uint32_t len,
                                     uintptr_t retpc)
{
    const cap_register_t *ddc = cheri_get_ddc(env);
    target_ulong addr = cheri_ddc_relative_addr(env, ddc_offset);
    check_cap(env, ddc, perm, addr, CHERI_EXC_REGNUM_DDC, len,
        /*instavail=*/true, retpc);
    return addr;
}

static inline bool cheri_have_access_sysregs(CPUArchState* env)
{
    return cap_has_perms(cheri_get_recent_pcc(env), CAP_ACCESS_SYS_REGS);
}

static inline void cheri_update_pcc_for_exc_handler(cap_register_t *pcc,
                                                    cap_register_t *src_cap,
                                                    target_ulong new_pc)
{
    if (cap_exactly_equal(pcc, src_cap) && new_pc == cap_get_cursor(pcc)) {
        if (!pcc->cr_tag || !cap_has_perms(pcc, CAP_PERM_EXECUTE) ||
            !cap_cursor_in_bounds(pcc)) {
            /* Warn about infinite trap loops instead of silently freezing. */
            error_report_once("Detected infinite trap loop due to invalid "
                              "exception handler: " PRINT_CAP_FMTSTR "\r",
                              PRINT_CAP_ARGS(pcc));
        }
    }
    *pcc = *src_cap;
    // FIXME: KCC must not be sealed
    if (!cap_is_unsealed(pcc)) {
        error_report("Sealed PCC set for exception"
                     " handler, detagging: " PRINT_CAP_FMTSTR "\r",
                     PRINT_CAP_ARGS(pcc));
        pcc->cr_tag = false;
    }
    if (!pcc->cr_tag) {
        error_report("Invalid PCC in exception handler: " PRINT_CAP_FMTSTR "\r",
                     PRINT_CAP_ARGS(pcc));
    }
    cheri_update_pcc(pcc, new_pc, /* can_be_unrep=*/true);
}

static inline void cheri_update_pcc_for_exc_return(cap_register_t *pcc,
                                                   cap_register_t *src_cap,
                                                   target_ulong new_cursor)
{
    /*
     * Morello does not require ASR when executing ERET, it will just detag
     * the result. However, this helper is only used for MIPS/RISC-V.
     */
    assert(cap_has_perms(pcc, CAP_ACCESS_SYS_REGS) &&
           "Attempting to return from exception without ASR in PCC");
    *pcc = *src_cap;
    /*
     * On exception return we unseal sentry capabilities (if the address
     * matches).
     */
    if (pcc->cr_tag && cap_is_sealed_entry(pcc)) {
        if (new_cursor == cap_get_cursor(pcc)) {
            cap_unseal_entry(pcc);
            return;
        } else {
            error_report("Sentry PCC in exception return with different target "
                         "addr: " PRINT_CAP_FMTSTR "\r",
                         PRINT_CAP_ARGS(pcc));
            pcc->cr_tag = false;
        }
    } else if (pcc->cr_tag && !cap_is_unsealed(pcc)) {
        if (new_cursor == cap_get_cursor(pcc)) {
            // Don't detag, we should get a seal violation on the next inst fetch
            return;
        } else {
            error_report("Sealed target PCC in exception return" PRINT_CAP_FMTSTR "\r",
                         PRINT_CAP_ARGS(pcc));
            pcc->cr_tag = false;
        }
    }
    cheri_update_pcc(pcc, new_cursor, /*can_be_unrepresentable=*/true);
}

static inline const char* cheri_cause_str(CheriCapExcCause cause) {
    switch (cause) {
    case CapEx_None: return "None";
    case CapEx_LengthViolation: return "Length Violation";
    case CapEx_TagViolation: return "Tag Violation";
    case CapEx_SealViolation: return "Seal Violation";
    case CapEx_TypeViolation: return "Type Violation";
    case CapEx_CallTrap: return "Call Trap";
    case CapEx_ReturnTrap: return "Return Trap";
    case CapEx_TSSUnderFlow: return "Underflow of Trusted System Stack";
    case CapEx_UserDefViolation: return "User-defined Permission Violation";
    case CapEx_TLBNoStoreCap: return "TLB prohibits Store Capability";
    case CapEx_InexactBounds: return "Bounds Cannot Be Represented Exactly";
    case CapEx_UnalignedBase: return "Unaligned Base";
    case CapEx_CapLoadGen: return "Cap Load Gen Mismatch";
    case CapEx_GlobalViolation: return "Global Violation";
    case CapEx_PermitExecuteViolation: return "Permit_Execute Violation";
    case CapEx_PermitLoadViolation: return "Permit_Load Violation";
    case CapEx_PermitStoreViolation: return "Permit_Store Violation";
    case CapEx_PermitLoadCapViolation: return "Permit_Load_Capability Violation";
    case CapEx_PermitStoreCapViolation: return "Permit_Store_Capability Violation";
    case CapEx_PermitStoreLocalCapViolation: return "Permit_Store_Local_Capability Violation";
    case CapEx_PermitSealViolation: return "Permit_Seal Violation";
    case CapEx_AccessSystemRegsViolation: return "Access_System_Registers Violation";
    case CapEx_AccessCCallIDCViolation: return "IDC used in CCall delay slot";
    case CapEx_PermitCCallViolation: return "Permit_CCall Violation";
    case CapEx_PermitUnsealViolation: return "Permit_Unseal Violation";
    case CapEx_PermitSetCIDViolation: return "Permit_SetCID Violation";
    }
    // default: return "Unknown cause";
    __builtin_unreachable();
    abort();
}

void store_cap_to_memory(CPUArchState *env, uint32_t cs, target_ulong vaddr,
                         uintptr_t retpc);
void store_cap_memory_to_memory(CPUArchState *env, uint32_t cs, bool tag,
                                target_ulong pesbt_for_mem, target_ulong cursor,
                                target_ulong vaddr, uintptr_t retpc);
void store_cap_to_memory_mmu_index(CPUArchState *env, uint32_t cs,
                                   target_ulong vaddr, uintptr_t retpc,
                                   int mmu_idx);

void load_cap_from_memory(CPUArchState *env, uint32_t cd, uint32_t cb,
                          const cap_register_t *source, target_ulong vaddr,
                          uintptr_t retpc, hwaddr *physaddr);

static inline bool cap_is_local(CPUArchState *env, uint32_t cs)
{
    return get_capreg_tag(env, cs) &&
           !(get_capreg_hwperms(env, cs) & CAP_PERM_GLOBAL);
}

static inline uint32_t perms_for_load(void) { return CAP_PERM_LOAD; }

static inline uint32_t perms_for_store(CPUArchState *env, uint32_t cs)
{
    uint32_t perms = CAP_PERM_STORE;
    if (get_capreg_tag(env, cs))
        perms |= CAP_PERM_STORE_CAP;
    if (cap_is_local(env, cs))
        perms |= CAP_PERM_STORE_LOCAL;
    return perms;
}

typedef void QEMU_NORETURN (*unaligned_memaccess_handler)(CPUArchState *env,
                                                          target_ulong addr,
                                                          uintptr_t retpc);
/* Do all the permission and bounds checks for loads/stores on cbp.
 * Use perms_for_load() and perms_for_store() for required_perms.
 *
 * Note: This is marked as QEMU_ALWAYS_INLINE since profiling indicates that
 * it has a large impact on overall QEMU speed (since it is called for every
 * capability-based load/store). Not removing dead branches/propagating the
 * constant alignment argument has a noticeable performance impact:
 * Initially this function uses a modulo operation to check the alignment.
 * This resulted in an x86 div instruction since the constant value was not
 * known inside the function. Changing it to a bitwise-and (QEMU_IS_ALIGNED_P2)
 * sped up the CheriBSD purecap kernel multi-user boot from ~314s to ~288s.
 * However, without QEMU_ALWAYS_INLINE this function was still not being
 * inlined so the alignment check was still using a non-constant argument
 * and dead required_perms checks were still being performed every time.
 * Adding QEMU_ALWAYS_INLINE seed up the boot from ~288s to ~278s.
 */
static inline QEMU_ALWAYS_INLINE target_ulong cap_check_common_reg(
    uint32_t required_perms, CPUArchState *env, uint32_t cb, target_ulong addr,
    uint32_t size, uintptr_t _host_return_address, const cap_register_t *cbp,
    uint32_t alignment_required, unaligned_memaccess_handler unaligned_handler)
{
#define MISSING_REQUIRED_PERM(X) ((required_perms & ~cap_get_perms(cbp)) & (X))
    // The check here is a little fiddly if this is a store and a load due to
    // priorities. For either loads or stores, permissions fault > bounds fault.
    // But: load bounds fault > store permissions fault. So all permissions
    // should not be checked before bounds. It is also a bad idea to call this
    // twice, once for load, once for store, because it performs alignment
    // checks and Store permissions fault > load alignment fault

    bool is_load = (required_perms & CAP_PERM_LOAD) != 0;
    bool in_bounds = cap_is_in_bounds(cbp, addr, size);

    if (!cbp->cr_tag) {
        raise_cheri_exception_addr_wnr(env, CapEx_TagViolation, cb, addr,
                                       !is_load);
    } else if (!cap_is_unsealed(cbp)) {
        raise_cheri_exception_addr_wnr(env, CapEx_SealViolation, cb, addr,
                                       !is_load);
    } else if (MISSING_REQUIRED_PERM(CAP_PERM_LOAD)) {
        raise_cheri_exception_addr_wnr(env, CapEx_PermitLoadViolation, cb, addr,
                                       false);
    } else if (MISSING_REQUIRED_PERM(CAP_PERM_LOAD_CAP)) {
        raise_cheri_exception_addr_wnr(env, CapEx_PermitLoadCapViolation, cb,
                                       addr, false);
    } else if (!is_load || in_bounds) {
        if (MISSING_REQUIRED_PERM(CAP_PERM_STORE)) {
            raise_cheri_exception_addr_wnr(env, CapEx_PermitStoreViolation, cb,
                                           addr, true);
        } else if (MISSING_REQUIRED_PERM(CAP_PERM_STORE_CAP)) {
            raise_cheri_exception_addr_wnr(env, CapEx_PermitStoreCapViolation,
                                           cb, addr, true);
        } else if (MISSING_REQUIRED_PERM(CAP_PERM_STORE_LOCAL)) {
            raise_cheri_exception_addr_wnr(
                env, CapEx_PermitStoreLocalCapViolation, cb, addr, true);
        }
    }
#undef MISSING_REQUIRED_PERM

    if (!in_bounds) {
        qemu_log_instr_or_mask_msg(
            env, CPU_LOG_INT,
            "Failed capability bounds check: addr=" TARGET_FMT_lx
            " base=" TARGET_FMT_lx " top=" TARGET_FMT_lx "\n",
            addr, cap_get_base(cbp), cap_get_top(cbp));
        raise_cheri_exception_addr_wnr(env, CapEx_LengthViolation, cb, addr,
                                       !is_load);
    } else if (alignment_required &&
               !QEMU_IS_ALIGNED_P2(addr, alignment_required)) {
        if (unaligned_handler) {
            unaligned_handler(env, addr, _host_return_address);
        }
#if defined(TARGET_MIPS) && defined(CHERI_UNALIGNED)
        const char *access_type =
            (required_perms == (CAP_PERM_STORE | CAP_PERM_LOAD))
                ? "RMW"
                : ((required_perms == CAP_PERM_STORE) ? "store" : "load");
        qemu_maybe_log_instr_extra(env,
                                   "Allowing unaligned %d-byte %s of "
                                   "address 0x%" PRIx64 "\n",
                                   size, access_type, addr);
#endif
    }
    return addr;
}

// Helper for RISCV AMOSWAP
bool load_cap_from_memory_raw(CPUArchState *env, target_ulong *pesbt,
                              target_ulong *cursor, uint32_t cb,
                              const cap_register_t *source, target_ulong vaddr,
                              uintptr_t retpc, hwaddr *physaddr);
bool load_cap_from_memory_raw_tag(CPUArchState *env, target_ulong *pesbt,
                                  target_ulong *cursor, uint32_t cb,
                                  const cap_register_t *source,
                                  target_ulong vaddr, uintptr_t retpc,
                                  hwaddr *physaddr, bool *raw_tag);
bool load_cap_from_memory_raw_tag_mmu_idx(
    CPUArchState *env, target_ulong *pesbt, target_ulong *cursor, uint32_t cb,
    const cap_register_t *source, target_ulong vaddr, uintptr_t retpc,
    hwaddr *physaddr, bool *raw_tag, int mmu_idx);
/* Useful for the load+branch capability helpers. */
cap_register_t load_and_decompress_cap_from_memory_raw(
    CPUArchState *env, uint32_t cb, const cap_register_t *source,
    target_ulong vaddr, uintptr_t retpc, hwaddr *physaddr);

void cheri_jump_and_link(CPUArchState *env, const cap_register_t *target,
                         target_ulong addr, uint32_t link_reg,
                         target_ulong link_pc, uint32_t cjalr_flags);
void cheri_jump_and_link_checked(CPUArchState *env, uint32_t link_reg,
                                 target_ulong link_pc, uint32_t target_reg,
                                 const cap_register_t *target,
                                 target_ulong target_addr, uint32_t flags,
                                 uintptr_t _host_return_address);

void squash_mutable_permissions(CPUArchState *env, target_ulong *pesbt,
                                const cap_register_t *source);
