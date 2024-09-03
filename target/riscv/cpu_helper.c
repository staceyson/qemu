/*
 * RISC-V CPU helpers for qemu.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/log_instr.h"
#include "tcg/tcg-op.h"
#include "trace.h"
#include "semihosting/common-semi.h"
#include "disas/disas.h"
#include "helper_utils.h"
#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

#ifdef TARGET_CHERI
#define COPY_SPECIAL_REG(env, dst, cheri_dst, src, cheri_src)   \
    do {                                                        \
        (env)->cheri_dst = (env)->cheri_src;                    \
    } while (false)
#else
#define COPY_SPECIAL_REG(env, dst, cheri_dst, src, cheri_src)   \
    do {                                                        \
        (env)->dst = (env)->src;                                \
    } while (false)
#endif

#ifdef CONFIG_TCG_LOG_INSTR
#ifdef TARGET_CHERI
#define LOG_SPECIAL_REG(env, csrno, scrno)      \
    riscv_log_instr_scr_changed(env, scrno)
#else
#define LOG_SPECIAL_REG(env, csrno, scrno)      \
    riscv_log_instr_csr_changed(env, csrno);
#endif
#else /* !CONFIG_TCG_LOG_INSTR */
#define LOG_SPECIAL_REG(env, csrno, scrno) ((void)0)
#endif /* !CONFIG_TCG_LOG_INSTR */

int riscv_cpu_mmu_index(CPURISCVState *env, bool ifetch)
{
#ifdef CONFIG_USER_ONLY
    return 0;
#else
    return env->priv;
#endif
}

#ifndef CONFIG_USER_ONLY
static int riscv_cpu_local_irq_pending(CPURISCVState *env)
{
    target_ulong irqs;

    target_ulong mstatus_mie = get_field(env->mstatus, MSTATUS_MIE);
    target_ulong mstatus_sie = get_field(env->mstatus, MSTATUS_SIE);
    target_ulong hs_mstatus_sie = get_field(env->mstatus_hs, MSTATUS_SIE);

    target_ulong pending = env->mip & env->mie &
                               ~(MIP_VSSIP | MIP_VSTIP | MIP_VSEIP);
    target_ulong vspending = (env->mip & env->mie &
                              (MIP_VSSIP | MIP_VSTIP | MIP_VSEIP));

    target_ulong mie    = env->priv < PRV_M ||
                          (env->priv == PRV_M && mstatus_mie);
    target_ulong sie    = env->priv < PRV_S ||
                          (env->priv == PRV_S && mstatus_sie);
    target_ulong hs_sie = env->priv < PRV_S ||
                          (env->priv == PRV_S && hs_mstatus_sie);

    if (riscv_cpu_virt_enabled(env)) {
        target_ulong pending_hs_irq = pending & -hs_sie;

        if (pending_hs_irq) {
            riscv_cpu_set_force_hs_excep(env, FORCE_HS_EXCEP);
            return ctz64(pending_hs_irq);
        }

        pending = vspending;
    }

    irqs = (pending & ~env->mideleg & -mie) | (pending &  env->mideleg & -sie);

    if (irqs) {
        return ctz64(irqs); /* since non-zero */
    } else {
        return EXCP_NONE; /* indicates no pending interrupt */
    }
}
#endif

bool riscv_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
#if !defined(CONFIG_USER_ONLY)
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        RISCVCPU *cpu = RISCV_CPU(cs);
        CPURISCVState *env = &cpu->env;
        int interruptno = riscv_cpu_local_irq_pending(env);
        if (interruptno >= 0) {
            cs->exception_index = RISCV_EXCP_INT_FLAG | interruptno;
            riscv_cpu_do_interrupt(cs);
            return true;
        }
    }
#endif
    return false;
}

#if !defined(CONFIG_USER_ONLY)

/* Return true is floating point support is currently enabled */
bool riscv_cpu_fp_enabled(CPURISCVState *env)
{
    if (env->mstatus & MSTATUS_FS) {
        if (riscv_cpu_virt_enabled(env) && !(env->mstatus_hs & MSTATUS_FS)) {
            return false;
        }
        return true;
    }

    return false;
}

void riscv_cpu_swap_hypervisor_regs(CPURISCVState *env, bool hs_mode_trap)
{
    uint64_t mstatus_mask = MSTATUS_MXR | MSTATUS_SUM | MSTATUS_FS |
                            MSTATUS_SPP | MSTATUS_SPIE | MSTATUS_SIE |
                            MSTATUS64_UXL;
    bool current_virt = riscv_cpu_virt_enabled(env);

    g_assert(riscv_has_ext(env, RVH));

    if (current_virt) {
        /* Current V=1 and we are about to change to V=0 */
        env->vsstatus = env->mstatus & mstatus_mask;
        env->mstatus &= ~mstatus_mask;
        env->mstatus |= env->mstatus_hs;
        riscv_log_instr_csr_changed(env, CSR_VSSTATUS);
        /* mstatus may be modified again by do_interrupt */

        COPY_SPECIAL_REG(env, vstvec, vstcc, stvec, stcc);
        COPY_SPECIAL_REG(env, stvec, stcc, stvec_hs, stcc_hs);
        LOG_SPECIAL_REG(env, CSR_VSTVEC, CheriSCR_BSTCC);
        LOG_SPECIAL_REG(env, CSR_STVEC, CheriSCR_STCC);

        env->vsscratch = env->sscratch;
        env->sscratch = env->sscratch_hs;
        riscv_log_instr_csr_changed(env, CSR_VSSCRATCH);
        riscv_log_instr_csr_changed(env, CSR_SSCRATCH);

        COPY_SPECIAL_REG(env, vsepc, vsepcc, sepc, sepcc);
        COPY_SPECIAL_REG(env, sepc, sepcc, sepc_hs, sepcc_hs);
        LOG_SPECIAL_REG(env, CSR_VSEPC, CheriSCR_BSEPCC);
        LOG_SPECIAL_REG(env, CSR_SEPC, CheriSCR_SEPCC);

        env->vscause = env->scause;
        env->scause = env->scause_hs;
        riscv_log_instr_csr_changed(env, CSR_VSCAUSE);
        if (!hs_mode_trap) {
            /* scause is modified again when trapping to HS-mode */
            riscv_log_instr_csr_changed(env, CSR_SCAUSE);
        }

        env->vstval = env->sbadaddr;
        env->sbadaddr = env->stval_hs;
        riscv_log_instr_csr_changed(env, CSR_VSTVAL);
        if (!hs_mode_trap) {
            /* sbaddaddr is modified again when trapping to HS-mode */
            riscv_log_instr_csr_changed(env, CSR_SBADADDR);
        }

        env->vsatp = env->satp;
        env->satp = env->satp_hs;
        riscv_log_instr_csr_changed(env, CSR_VSATP);
        riscv_log_instr_csr_changed(env, CSR_SATP);
    } else {
        /* Current V=0 and we are about to change to V=1 */
        /*
         * TODO(am2419): Not sure whether we should log assignments to
         * *_hs register variants.
         */
        env->mstatus_hs = env->mstatus & mstatus_mask;
        env->mstatus &= ~mstatus_mask;
        env->mstatus |= env->vsstatus;

        COPY_SPECIAL_REG(env, stvec_hs, stcc_hs, stvec, stcc);
        COPY_SPECIAL_REG(env, stvec, stcc, vstvec, vstcc);
        LOG_SPECIAL_REG(env, CSR_STVEC, CheriSCR_STCC);

        env->sscratch_hs = env->sscratch;
        env->sscratch = env->vsscratch;
        riscv_log_instr_csr_changed(env, CSR_SSCRATCH);

        COPY_SPECIAL_REG(env, sepc_hs, sepcc_hs, sepc, sepcc);
        COPY_SPECIAL_REG(env, sepc, sepcc, vsepc, vsepcc);
        LOG_SPECIAL_REG(env, CSR_SEPC, CheriSCR_SEPCC);

        env->scause_hs = env->scause;
        env->scause = env->vscause;
        riscv_log_instr_csr_changed(env, CSR_SCAUSE);

        env->stval_hs = env->sbadaddr;
        env->sbadaddr = env->vstval;
        riscv_log_instr_csr_changed(env, CSR_SBADADDR);

        env->satp_hs = env->satp;
        env->satp = env->vsatp;
        riscv_log_instr_csr_changed(env, CSR_SATP);
    }
}

bool riscv_cpu_virt_enabled(CPURISCVState *env)
{
    if (!riscv_has_ext(env, RVH)) {
        return false;
    }

    return get_field(env->virt, VIRT_ONOFF);
}

void riscv_cpu_set_virt_enabled(CPURISCVState *env, bool enable)
{
    if (!riscv_has_ext(env, RVH)) {
        return;
    }

    /* Flush the TLB on all virt mode changes. */
    if (get_field(env->virt, VIRT_ONOFF) != enable) {
        tlb_flush(env_cpu(env));
    }

    env->virt = set_field(env->virt, VIRT_ONOFF, enable);
}

bool riscv_cpu_force_hs_excep_enabled(CPURISCVState *env)
{
    if (!riscv_has_ext(env, RVH)) {
        return false;
    }

    return get_field(env->virt, FORCE_HS_EXCEP);
}

void riscv_cpu_set_force_hs_excep(CPURISCVState *env, bool enable)
{
    if (!riscv_has_ext(env, RVH)) {
        return;
    }

    env->virt = set_field(env->virt, FORCE_HS_EXCEP, enable);
}

bool riscv_cpu_two_stage_lookup(int mmu_idx)
{
    return mmu_idx & TB_FLAGS_PRIV_HYP_ACCESS_MASK;
}

int riscv_cpu_claim_interrupts(RISCVCPU *cpu, uint32_t interrupts)
{
    CPURISCVState *env = &cpu->env;
    if (env->miclaim & interrupts) {
        return -1;
    } else {
        env->miclaim |= interrupts;
        return 0;
    }
}

uint32_t riscv_cpu_update_mip(RISCVCPU *cpu, uint32_t mask, uint32_t value)
{
    CPURISCVState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    uint32_t old = env->mip;
    bool locked = false;

    if (!qemu_mutex_iothread_locked()) {
        locked = true;
        qemu_mutex_lock_iothread();
    }

    env->mip = (env->mip & ~mask) | (value & mask);

    if (env->mip) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }

    if (locked) {
        qemu_mutex_unlock_iothread();
    }

    return old;
}

void riscv_cpu_set_rdtime_fn(CPURISCVState *env, uint64_t (*fn)(uint32_t),
                             uint32_t arg)
{
    env->rdtime_fn = fn;
    env->rdtime_fn_arg = arg;
}

void riscv_cpu_set_mode(CPURISCVState *env, target_ulong newpriv)
{
    if (newpriv > PRV_M) {
        g_assert_not_reached();
    }
    if (newpriv == PRV_H) {
        newpriv = PRV_U;
    }
    /* tlb_flush is unnecessary as mode is contained in mmu_idx */
    env->priv = newpriv;

    /*
     * Clear the load reservation - otherwise a reservation placed in one
     * context/process can be used by another, resulting in an SC succeeding
     * incorrectly. Version 2.2 of the ISA specification explicitly requires
     * this behaviour, while later revisions say that the kernel "should" use
     * an SC instruction to force the yielding of a load reservation on a
     * preemptive context switch. As a result, do both.
     */
    env->load_res = -1;

#ifdef CONFIG_TCG_LOG_INSTR
    qemu_log_instr_cpu_mode_t mode;

    switch (newpriv) {
    case PRV_M:
        mode = RISCV_LOG_INSTR_CPU_M;
        break;
    case PRV_S:
        mode = RISCV_LOG_INSTR_CPU_S;
        break;
    case PRV_H:
        mode = RISCV_LOG_INSTR_CPU_H;
        break;
    default:
        mode = RISCV_LOG_INSTR_CPU_U;
    }
    qemu_log_instr_mode_switch(env, mode, cpu_get_recent_pc(env));
#endif
}

#ifdef CONFIG_RVFI_DII
extern bool rvfi_debug_output;
#endif

#ifndef RISCV_PTE_TRAPPY
/*
 * The PTW logic below supports trapping on any subset of PTE_A, PTE_D, PTE_CD
 * being clear during an access that would have them be set.  The RISC-V spec
 * says that PTE_A and PTE_D always go together, and it's probably most sensible
 * that PTE_CD implies PTE_A and PTE_D.  So, sensible values for this constant
 * are 0, (PTE_A | PTE_D), or (PTE_A | PTE_D | PTE_CD).
 */
#define RISCV_PTE_TRAPPY 0
#endif

/*
 * get_physical_address_pmp - check PMP permission for this physical address
 *
 * Match the PMP region and check permission for this physical address and it's
 * TLB page. Returns 0 if the permission checking was successful
 *
 * @env: CPURISCVState
 * @prot: The returned protection attributes
 * @tlb_size: TLB page size containing addr. It could be modified after PMP
 *            permission checking. NULL if not set TLB page for addr.
 * @addr: The physical address to be checked permission
 * @access_type: The type of MMU access
 * @mode: Indicates current privilege level.
 */
static int get_physical_address_pmp(CPURISCVState *env, int *prot,
                                    target_ulong *tlb_size, hwaddr addr,
                                    int size, MMUAccessType access_type,
                                    int mode)
{
    pmp_priv_t pmp_priv;
    target_ulong tlb_size_pmp = 0;

    if (!riscv_feature(env, RISCV_FEATURE_PMP)) {
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    }

    if (!pmp_hart_has_privs(env, addr, size,
                            access_type_to_pmp_priv(access_type), &pmp_priv,
                            mode)) {
        *prot = 0;
        return TRANSLATE_PMP_FAIL;
    }

    *prot = pmp_priv_to_page_prot(pmp_priv);
    if (tlb_size != NULL) {
        if (pmp_is_range_in_tlb(env, addr & ~(*tlb_size - 1), &tlb_size_pmp)) {
            *tlb_size = tlb_size_pmp;
        }
    }

    return TRANSLATE_SUCCESS;
}

/* get_physical_address - get the physical address for this virtual address
 *
 * Do a page table walk to obtain the physical address corresponding to a
 * virtual address. Returns 0 if the translation was successful
 *
 * Adapted from Spike's mmu_t::translate and mmu_t::walk
 *
 * @env: CPURISCVState
 * @physical: This will be set to the calculated physical address
 * @prot: The returned protection attributes
 * @addr: The virtual address to be translated
 * @fault_pte_addr: If not NULL, this will be set to fault pte address
 *                  when a error occurs on pte address translation.
 *                  This will already be shifted to match htval.
 * @access_type: The type of MMU access
 * @mmu_idx: Indicates current privilege level
 * @first_stage: Are we in first stage translation?
 *               Second stage is used for hypervisor guest translation
 * @two_stage: Are we going to perform two stage translation
 */
static int get_physical_address(CPURISCVState *env, hwaddr *physical,
                                int *prot, target_ulong addr,
                                target_ulong *fault_pte_addr,
                                int access_type, int mmu_idx,
                                bool first_stage, bool two_stage)
{
    /* NOTE: the env->pc value visible here will not be
     * correct, but the value visible to the exception handler
     * (riscv_cpu_do_interrupt) is correct */
    MemTxResult res;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    int mode = mmu_idx & TB_FLAGS_PRIV_MMU_MASK;
    bool use_background = false;
#ifdef CONFIG_RVFI_DII
    if (env->rvfi_dii_have_injected_insn && access_type == MMU_INST_FETCH) {
        /*
         * Pretend we have a 1:1 mapping and never fail for instruction
         * fetches since the instruction is injected directly via
         * env->rvfi_dii_injected_insn.
         */
        *physical = addr;
        *prot = PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    }
#endif

    /*
     * Check if we should use the background registers for the two
     * stage translation. We don't need to check if we actually need
     * two stage translation as that happened before this function
     * was called. Background registers will be used if the guest has
     * forced a two stage translation to be on (in HS or M mode).
     */
    if (!riscv_cpu_virt_enabled(env) && two_stage) {
        use_background = true;
    }

    /* MPRV does not affect the virtual-machine load/store
       instructions, HLV, HLVX, and HSV. */
    if (riscv_cpu_two_stage_lookup(mmu_idx)) {
        mode = get_field(env->hstatus, HSTATUS_SPVP);
    } else if (mode == PRV_M && access_type != MMU_INST_FETCH) {
        if (get_field(env->mstatus, MSTATUS_MPRV)) {
            mode = get_field(env->mstatus, MSTATUS_MPP);
        }
    }

    if (first_stage == false) {
        /* We are in stage 2 translation, this is similar to stage 1. */
        /* Stage 2 is always taken as U-mode */
        mode = PRV_U;
    }

    if (mode == PRV_M || !riscv_feature(env, RISCV_FEATURE_MMU)) {
        *physical = addr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    }

    *prot = 0;

    hwaddr base;
    int levels, ptidxbits, ptesize, vm, sum, mxr, widened;

    if (first_stage == true) {
        mxr = get_field(env->mstatus, MSTATUS_MXR);
    } else {
        mxr = get_field(env->vsstatus, MSTATUS_MXR);
    }

    if (first_stage == true) {
        if (use_background) {
            base = (hwaddr)get_field(env->vsatp, SATP_PPN) << PGSHIFT;
            vm = get_field(env->vsatp, SATP_MODE);
        } else {
            base = (hwaddr)get_field(env->satp, SATP_PPN) << PGSHIFT;
            vm = get_field(env->satp, SATP_MODE);
        }
        widened = 0;
    } else {
        base = (hwaddr)get_field(env->hgatp, HGATP_PPN) << PGSHIFT;
        vm = get_field(env->hgatp, HGATP_MODE);
        widened = 2;
    }
    /* status.SUM will be ignored if execute on background */
    sum = get_field(env->mstatus, MSTATUS_SUM) || use_background;
    switch (vm) {
    case VM_1_10_SV32:
      levels = 2; ptidxbits = 10; ptesize = 4; break;
    case VM_1_10_SV39:
      levels = 3; ptidxbits = 9; ptesize = 8; break;
    case VM_1_10_SV48:
      levels = 4; ptidxbits = 9; ptesize = 8; break;
    case VM_1_10_SV57:
      levels = 5; ptidxbits = 9; ptesize = 8; break;
    case VM_1_10_MBARE:
        *physical = addr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TRANSLATE_SUCCESS;
    default:
      g_assert_not_reached();
    }

    CPUState *cs = env_cpu(env);
    int va_bits = PGSHIFT + levels * ptidxbits + widened;
    target_ulong mask, masked_msbs;

    if (TARGET_LONG_BITS > (va_bits - 1)) {
        mask = (1L << (TARGET_LONG_BITS - (va_bits - 1))) - 1;
    } else {
        mask = 0;
    }
    masked_msbs = (addr >> (va_bits - 1)) & mask;

    if (masked_msbs != 0 && masked_msbs != mask) {
        qemu_log_mask(CPU_LOG_MMU,
                      "%s Translate fail: top bits not a sign extension\n",
                      __func__);
        return TRANSLATE_FAIL;
    }

    int ptshift = (levels - 1) * ptidxbits;
    int i;

#if !TCG_OVERSIZED_GUEST
restart:
#endif
    for (i = 0; i < levels; i++, ptshift -= ptidxbits) {
        target_ulong idx;
        if (i == 0) {
            idx = (addr >> (PGSHIFT + ptshift)) &
                           ((1 << (ptidxbits + widened)) - 1);
        } else {
            idx = (addr >> (PGSHIFT + ptshift)) &
                           ((1 << ptidxbits) - 1);
        }

        /* check that physical address of PTE is legal */
        hwaddr pte_addr;

        if (two_stage && first_stage) {
            int vbase_prot;
            hwaddr vbase;

            /* Do the second stage translation on the base PTE address. */
            int vbase_ret = get_physical_address(env, &vbase, &vbase_prot,
                                                 base, NULL, MMU_DATA_LOAD,
                                                 mmu_idx, false, true);

            if (vbase_ret != TRANSLATE_SUCCESS) {
                if (fault_pte_addr) {
                    *fault_pte_addr = (base + idx * ptesize) >> 2;
                }
                return TRANSLATE_G_STAGE_FAIL;
            }

            pte_addr = vbase + idx * ptesize;
        } else {
            pte_addr = base + idx * ptesize;
        }

        int pmp_prot;
        int pmp_ret = get_physical_address_pmp(env, &pmp_prot, NULL, pte_addr,
                                               sizeof(target_ulong),
                                               MMU_DATA_LOAD, PRV_S);
        if (pmp_ret != TRANSLATE_SUCCESS) {
            return TRANSLATE_PMP_FAIL;
        }

        target_ulong pte;
        if (riscv_cpu_is_32bit(env)) {
            pte = address_space_ldl(cs->as, pte_addr, attrs, &res);
        } else {
            pte = address_space_ldq(cs->as, pte_addr, attrs, &res);
        }

        if (res != MEMTX_OK) {
            qemu_log_mask(
                CPU_LOG_MMU,
                "%s Translate fail: could not load pte at " TARGET_FMT_plx "\n",
                __func__, pte_addr);
            return TRANSLATE_FAIL;
        }

#if !defined(TARGET_RISCV32)
        /*
         * The top ten bits of the PTE are reserved.  While there may
         * eventually be a RISCV system with more than 44 bits of ppn (that is,
         * a 56-bit physical address space, or 64 PiB), we aren't one, yet.
         */
        hwaddr ppn = (pte & ~0xFFC0000000000000ULL) >> PTE_PPN_SHIFT;
#else
        hwaddr ppn = pte >> PTE_PPN_SHIFT;
#endif

        if (!(pte & PTE_V)) {
            /* Invalid PTE */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: V not set\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if (!(pte & (PTE_R | PTE_W | PTE_X))) {
            /* Inner PTE, continue walking */
            base = ppn << PGSHIFT;
        } else if ((pte & (PTE_R | PTE_W | PTE_X)) == PTE_W) {
            /* Reserved leaf PTE flags: PTE_W */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: Reserved WRX 100\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if ((pte & (PTE_R | PTE_W | PTE_X)) == (PTE_W | PTE_X)) {
            /* Reserved leaf PTE flags: PTE_W + PTE_X */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: Reserved WRX 011\n",
                          __func__);
            return TRANSLATE_FAIL;
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
        } else if ((pte & (PTE_CR | PTE_CRG)) == PTE_CRG) {
            /* Reserved CHERI-extended PTE flags: no CR but CRG */
            return TRANSLATE_CHERI_FAIL;
        } else if ((pte & (PTE_CR | PTE_CRM | PTE_CRG)) == (PTE_CR | PTE_CRG)) {
            /* Reserved CHERI-extended PTE flags: CR and no CRM but CRG */
            return TRANSLATE_CHERI_FAIL;
#endif
        } else if ((pte & PTE_U) && ((mode != PRV_U) &&
                   (!sum || access_type == MMU_INST_FETCH))) {
            /* User PTE flags when not U mode and mstatus.SUM is not set,
               or the access type is an instruction fetch */
            qemu_log_mask(CPU_LOG_MMU,
                          "%s Translate fail: U set but no SUM in S/M mode\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if (!(pte & PTE_U) && (mode != PRV_S)) {
            /* Supervisor PTE flags when not S mode */
            qemu_log_mask(CPU_LOG_MMU,
                          "%s Translate fail: user accessing non user page\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if (ppn & ((1ULL << ptshift) - 1)) {
            /* Misaligned PPN */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: misaligned PPN\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if ((access_type == MMU_DATA_LOAD ||
                    access_type == MMU_DATA_CAP_LOAD) &&
                   !((pte & PTE_R) || ((pte & PTE_X) && mxr))) {
            /* Read access check failed */
            qemu_log_mask(CPU_LOG_MMU,
                          "%s Translate fail: read access check failed\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if ((access_type == MMU_DATA_STORE ||
                    access_type == MMU_DATA_CAP_STORE) && !(pte & PTE_W)) {
            /* Write access check failed */
            qemu_log_mask(CPU_LOG_MMU,
                          "%s Translate fail: write access check failed\n",
                          __func__);
            return TRANSLATE_FAIL;
        } else if (access_type == MMU_INST_FETCH && !(pte & PTE_X)) {
            /* Fetch access check failed */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: X bit not set\n",
                          __func__);
            return TRANSLATE_FAIL;
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
        } else if (access_type == MMU_DATA_CAP_STORE && !(pte & PTE_CW)) {
            /* CW inhibited */
            return TRANSLATE_CHERI_FAIL;
#endif
#if RISCV_PTE_TRAPPY & PTE_A
        } else if (!(pte & PTE_A)) {
            /* PTE not marked as accessed */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: A not set\n",
                          __func__);
            return TRANSLATE_FAIL;
#endif
#if RISCV_PTE_TRAPPY & PTE_D
        } else if ((access_type == MMU_DATA_STORE) && !(pte & PTE_D)) {
            /* PTE not marked as dirty */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: D not set\n",
                          __func__);
            return TRANSLATE_FAIL;
#endif
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
#if RISCV_PTE_TRAPPY & PTE_D
        } else if (access_type == MMU_DATA_CAP_STORE && !(pte & PTE_D)) {
            /* PTE not marked as dirty for cap store */
            qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: D not set (cap)\n",
                          __func__);
            return TRANSLATE_FAIL;
#endif
#if RISCV_PTE_TRAPPY & PTE_CD
        } else if (access_type == MMU_DATA_CAP_STORE && !(pte & PTE_CD)) {
            /* CD clear; force the software trap handler to get involved */
            return TRANSLATE_CHERI_FAIL;
#endif
#endif
        } else {
            /* if necessary, set accessed and dirty bits. */
            target_ulong updated_pte = pte | PTE_A;
            switch (access_type) {
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
            case MMU_DATA_CAP_STORE:
                updated_pte |= PTE_CD;
                /* FALLTHROUGH */
#endif
            case MMU_DATA_STORE:
                updated_pte |= PTE_D;
                break;
            }

            /* Page table updates need to be atomic with MTTCG enabled */
            if (updated_pte != pte) {
                /*
                 * - if accessed or dirty bits need updating, and the PTE is
                 *   in RAM, then we do so atomically with a compare and swap.
                 * - if the PTE is in IO space or ROM, then it can't be updated
                 *   and we return TRANSLATE_FAIL.
                 * - if the PTE changed by the time we went to update it, then
                 *   it is no longer valid and we must re-walk the page table.
                 */
                MemoryRegion *mr;
                hwaddr l = sizeof(target_ulong), addr1;
                mr = address_space_translate(cs->as, pte_addr,
                    &addr1, &l, false, MEMTXATTRS_UNSPECIFIED);
                if (memory_region_is_ram(mr)) {
                    target_ulong *pte_pa =
                        qemu_map_ram_ptr(mr->ram_block, addr1);
#if TCG_OVERSIZED_GUEST
                    /* MTTCG is not enabled on oversized TCG guests so
                     * page table updates do not need to be atomic */
                    *pte_pa = pte = updated_pte;
#else
                    target_ulong old_pte =
                        qatomic_cmpxchg(pte_pa, pte, updated_pte);
                    if (old_pte != pte) {
                        goto restart;
                    } else {
                        pte = updated_pte;
                    }
#endif
                } else {
                    /* misconfigured PTE in ROM (AD bits are not preset) or
                     * PTE is in IO space and can't be updated atomically */
                    qemu_log_mask(CPU_LOG_MMU,
                                  "%s Translate fail: PTE in IO space\n",
                                  __func__);
                    return TRANSLATE_FAIL;
                }
            }

            /* for superpage mappings, make a fake leaf PTE for the TLB's
               benefit. */
            target_ulong vpn = addr >> PGSHIFT;
            *physical = ((ppn | (vpn & ((1L << ptshift) - 1))) << PGSHIFT) |
                        (addr & ~TARGET_PAGE_MASK);

            /* set permissions on the TLB entry */
            if ((pte & PTE_R) || ((pte & PTE_X) && mxr)) {
                *prot |= PAGE_READ;
            }
            if ((pte & PTE_X)) {
                *prot |= PAGE_EXEC;
            }
            /* add write permission on stores or if the page is already dirty,
               so that we TLB miss on later writes to update the dirty bit */
            if ((pte & PTE_W) &&
                ((access_type == MMU_DATA_STORE) ||
                 (access_type == MMU_DATA_CAP_STORE) || (pte & PTE_D))) {
                *prot |= PAGE_WRITE;
            }
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
            if ((pte & PTE_CR) == 0) {
                if ((pte & PTE_CRM) == 0) {
                    *prot |= PAGE_LC_CLEAR;
                } else {
                    *prot |= PAGE_LC_TRAP;
                }
            } else {
                if (pte & PTE_CRM) {
                    /* Cap-loads checked against [SU]GCLG in CCSR using PTE_U */
                    target_ulong gclgmask =
                        (pte & PTE_U) ? SCCSR_UGCLG : SCCSR_SGCLG;
                    bool gclg = (env->sccsr & gclgmask) != 0;
                    bool lclg = (pte & PTE_CRG) != 0;

                    if (gclg != lclg) {
                        *prot |= PAGE_LC_TRAP;
                    }
                }
            }
            if ((pte & PTE_CW) == 0) {
                *prot |= PAGE_SC_TRAP;
            }
#endif
            return TRANSLATE_SUCCESS;
        }
    }
    qemu_log_mask(CPU_LOG_MMU, "%s Translate fail: fall through?\n", __func__);
    return TRANSLATE_FAIL;
}

static void rvfi_dii_update_mem_addr(CPURISCVState *env,
                                     MMUAccessType access_type, vaddr addr)
{
#if defined(CONFIG_RVFI_DII)
    /*
     * For non-ifetch, we log the mem_addr here to match sail which logs it
     * for all accesses that go down to the physical level (i.e. the ones
     * that passed CHERI and MMU checks) even if they fail then.
     */
    if (access_type != MMU_INST_FETCH) {
        env->rvfi_dii_trace.MEM.rvfi_mem_addr = addr;
        env->rvfi_dii_trace.available_fields |= RVFI_MEM_DATA;
    }
#endif
}

static void raise_mmu_exception(CPURISCVState *env, target_ulong address,
                                MMUAccessType access_type, bool pmp_violation,
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
                                bool cheri_violation,
#endif
                                bool first_stage, bool two_stage)
{
    CPUState *cs = env_cpu(env);
    int page_fault_exceptions;
    if (first_stage) {
        page_fault_exceptions =
            get_field(env->satp, SATP_MODE) != VM_1_10_MBARE &&
            !pmp_violation;
    } else {
        page_fault_exceptions =
            get_field(env->hgatp, HGATP_MODE) != VM_1_10_MBARE &&
            !pmp_violation;
    }
    switch (access_type) {
    case MMU_INST_FETCH:
        if (riscv_cpu_virt_enabled(env) && !first_stage) {
            cs->exception_index = RISCV_EXCP_INST_GUEST_PAGE_FAULT;
        } else {
            cs->exception_index = page_fault_exceptions ?
                RISCV_EXCP_INST_PAGE_FAULT : RISCV_EXCP_INST_ACCESS_FAULT;
        }
        break;
    case MMU_DATA_LOAD:
#if defined(TARGET_CHERI)
    case MMU_DATA_CAP_LOAD:
#endif
        if (two_stage && !first_stage) {
            cs->exception_index = RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT;
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
        } else if (cheri_violation) {
            cs->exception_index = RISCV_EXCP_LOAD_CAP_PAGE_FAULT;
#endif
        } else {
            cs->exception_index = page_fault_exceptions ?
                RISCV_EXCP_LOAD_PAGE_FAULT : RISCV_EXCP_LOAD_ACCESS_FAULT;
        }
        break;
    case MMU_DATA_STORE:
#if defined(TARGET_CHERI)
    case MMU_DATA_CAP_STORE:
#endif
        if (two_stage && !first_stage) {
            cs->exception_index = RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT;
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
        } else if (cheri_violation) {
            cs->exception_index = RISCV_EXCP_STORE_AMO_CAP_PAGE_FAULT;
#endif
        } else {
            cs->exception_index = page_fault_exceptions ?
                RISCV_EXCP_STORE_PAGE_FAULT : RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
        }
        break;
    default:
        g_assert_not_reached();
    }
    if (pmp_violation) {
        /* CHERI and MMU checks passed, so we update mem_addr to match sail. */
        rvfi_dii_update_mem_addr(env, access_type, address);
    }
    env->badaddr = address;
    env->two_stage_lookup = two_stage;
}

hwaddr riscv_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    hwaddr phys_addr;
    int prot;
    int mmu_idx = cpu_mmu_index(&cpu->env, false);

    if (get_physical_address(env, &phys_addr, &prot, addr, NULL, 0, mmu_idx,
                             true, riscv_cpu_virt_enabled(env))) {
        return -1;
    }

    if (riscv_cpu_virt_enabled(env)) {
        if (get_physical_address(env, &phys_addr, &prot, phys_addr, NULL,
                                 0, mmu_idx, false, true)) {
            return -1;
        }
    }

    return phys_addr & TARGET_PAGE_MASK;
}

void riscv_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr,
                                     vaddr addr, unsigned size,
                                     MMUAccessType access_type,
                                     int mmu_idx, MemTxAttrs attrs,
                                     MemTxResult response, uintptr_t retaddr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (access_type == MMU_DATA_STORE) {
        cs->exception_index = RISCV_EXCP_STORE_AMO_ACCESS_FAULT;
    } else if (access_type == MMU_DATA_LOAD) {
        cs->exception_index = RISCV_EXCP_LOAD_ACCESS_FAULT;
    } else {
        cs->exception_index = RISCV_EXCP_INST_ACCESS_FAULT;
    }

    env->badaddr = addr;
    env->two_stage_lookup = riscv_cpu_virt_enabled(env) ||
                            riscv_cpu_two_stage_lookup(mmu_idx);
    /* CHERI and MMU checks passed, so we update mem_addr to match sail. */
    rvfi_dii_update_mem_addr(env, mmu_idx, addr);
    riscv_raise_exception(&cpu->env, cs->exception_index, retaddr);
}

void riscv_cpu_do_unaligned_access(CPUState *cs, vaddr addr,
                                   MMUAccessType access_type, int mmu_idx,
                                   uintptr_t retaddr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    switch (access_type) {
    case MMU_INST_FETCH:
        cs->exception_index = RISCV_EXCP_INST_ADDR_MIS;
        break;
    case MMU_DATA_LOAD:
        cs->exception_index = RISCV_EXCP_LOAD_ADDR_MIS;
        break;
    case MMU_DATA_STORE:
        cs->exception_index = RISCV_EXCP_STORE_AMO_ADDR_MIS;
        break;
    default:
        g_assert_not_reached();
    }
    env->badaddr = addr;
    env->two_stage_lookup = riscv_cpu_virt_enabled(env) ||
                            riscv_cpu_two_stage_lookup(mmu_idx);
    riscv_raise_exception(env, cs->exception_index, retaddr);
}
#endif /* !CONFIG_USER_ONLY */

static inline int rvfi_dii_check_addr(CPURISCVState *env, int ret, hwaddr *pa,
                                      vaddr address, int size, int *prot,
                                      MMUAccessType access_type)
{
#ifdef CONFIG_RVFI_DII
    // For RVFI-DII we have to reject all memory accesses outside of the RAM
    // region (even if there is a valid ROM there)
    // However, we still have to allow MMU_INST_FETCH accesess since they are
    // triggered by tb_find().
    if (env->rvfi_dii_have_injected_insn && ret == TRANSLATE_SUCCESS) {
        if (access_type == MMU_INST_FETCH) {
            // Avoid filling the QEMU guest->host TLB with read/write entries
            // for the faked instr fetch translation
            *prot &= PAGE_EXEC;
        } else if (*pa < RVFI_DII_RAM_START ||
                   (*pa + size) > RVFI_DII_RAM_END) {
            if (rvfi_debug_output) {
                fprintf(stderr,
                        "Rejecting memory access to " TARGET_FMT_plx
                        " since it is outside the RVFI-DII range",
                        address);
            }
            qemu_log_mask(CPU_LOG_MMU,
                          "%s Translate fail: va=" TARGET_FMT_plx
                          " pa=" TARGET_FMT_plx
                          " is outside the RVFI-DII range\n",
                          __func__, address, *pa);
            return TRANSLATE_PMP_FAIL;
        }
    }
#endif
    return ret;
}

bool riscv_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
#ifndef CONFIG_USER_ONLY
    vaddr im_address;
    hwaddr pa = 0;
    int prot, prot2, prot_pmp, prot_lc_preserve, prot_sc_preserve;
    bool pmp_violation = false;
    bool first_stage_error = true;
    bool two_stage_lookup = false;
    int ret = TRANSLATE_FAIL;
    int mode = mmu_idx;
    /* default TLB page size */
    target_ulong tlb_size = TARGET_PAGE_SIZE;

#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
    prot_lc_preserve = PAGE_LC_TRAP | PAGE_LC_CLEAR;
    prot_sc_preserve = PAGE_SC_TRAP;
#else
    prot_lc_preserve = 0;
    prot_sc_preserve = 0;
#endif

    env->guest_phys_fault_addr = 0;

    qemu_log_mask(CPU_LOG_MMU, "%s ad %" VADDR_PRIx " rw %d mmu_idx %d\n",
                  __func__, address, access_type, mmu_idx);

    /* MPRV does not affect the virtual-machine load/store
       instructions, HLV, HLVX, and HSV. */
    if (riscv_cpu_two_stage_lookup(mmu_idx)) {
        mode = get_field(env->hstatus, HSTATUS_SPVP);
    } else if (mode == PRV_M && access_type != MMU_INST_FETCH &&
               get_field(env->mstatus, MSTATUS_MPRV)) {
        mode = get_field(env->mstatus, MSTATUS_MPP);
        if (riscv_has_ext(env, RVH) && get_field(env->mstatus, MSTATUS_MPV)) {
            two_stage_lookup = true;
        }
    }

    if (riscv_cpu_virt_enabled(env) ||
        ((riscv_cpu_two_stage_lookup(mmu_idx) || two_stage_lookup) &&
         access_type != MMU_INST_FETCH)) {
        /* Two stage lookup */
        ret = get_physical_address(env, &pa, &prot, address,
                                   &env->guest_phys_fault_addr, access_type,
                                   mmu_idx, true, true);

        /*
         * A G-stage exception may be triggered during two state lookup.
         * And the env->guest_phys_fault_addr has already been set in
         * get_physical_address().
         */
        if (ret == TRANSLATE_G_STAGE_FAIL) {
            first_stage_error = false;
            access_type = MMU_DATA_LOAD;
        }

        qemu_log_mask(CPU_LOG_MMU,
                      "%s 1st-stage address=%" VADDR_PRIx " ret %d physical "
                      TARGET_FMT_plx " prot %d\n",
                      __func__, address, ret, pa, prot);
        ret = rvfi_dii_check_addr(env, ret, &pa, address, size, &prot, access_type);

        if (ret == TRANSLATE_SUCCESS) {
            /* Second stage lookup */
            im_address = pa;

            ret = get_physical_address(env, &pa, &prot2, im_address, NULL,
                                       access_type, mmu_idx, false, true);

            qemu_log_mask(CPU_LOG_MMU,
                    "%s 2nd-stage address=%" VADDR_PRIx " ret %d physical "
                    TARGET_FMT_plx " prot %d\n",
                    __func__, im_address, ret, pa, prot2);

            /*
             * CHERI's load-side caveats are enforced only on the guest
             * tables at the moment.  Because we are about to AND the two
             * prot words together, *set* both caveats in prot2 so that
             * either bit will be preserved from prot.
             *
             * XXX Eventually we probably want to permit the hypervisor to be
             * able to force tag clearing or trapping.  That probably looks
             * something like this (but details are subject to change):
             *
             *   Host     Guest    Action on tagged load
             *   -------- -------- ---------------------
             *
             *   Clear    _        Clear tag
             *   _        Clear    Clear tag
             *
             *   Accept   Accept   Accept
             *   Accept   Trap     Supervisor (VS/S) fault
             *
             *   Trap     _        Hypervisor (HS) fault
             *
             * The rest of the bits are AND-ed together as before, and
             * get_physical_address already handles the store-side CHERI
             * extensions.
             */
            prot &= prot2 | prot_lc_preserve;

            if (ret == TRANSLATE_SUCCESS) {
                ret = get_physical_address_pmp(env, &prot_pmp, &tlb_size, pa,
                                               size, access_type, mode);

                qemu_log_mask(CPU_LOG_MMU,
                              "%s PMP address=" TARGET_FMT_plx " ret %d prot"
                              " %d tlb_size " TARGET_FMT_lu "\n",
                              __func__, pa, ret, prot_pmp, tlb_size);

                /* PMP has no CHERI permissions; preserve trap/clear */
                prot &= prot_pmp | prot_lc_preserve | prot_sc_preserve;
            }

            if (ret != TRANSLATE_SUCCESS) {
                /*
                 * Guest physical address translation failed, this is a HS
                 * level exception
                 */
                first_stage_error = false;
                env->guest_phys_fault_addr = (im_address |
                                              (address &
                                               (TARGET_PAGE_SIZE - 1))) >> 2;
            }
        }
    } else {
        /* Single stage lookup */
        ret = get_physical_address(env, &pa, &prot, address, NULL,
                                   access_type, mmu_idx, true, false);
        ret = rvfi_dii_check_addr(env, ret, &pa, address, size, &prot, access_type);

        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " ret %d physical "
                      TARGET_FMT_plx " prot %d\n",
                      __func__, address, ret, pa, prot);

        if (ret == TRANSLATE_SUCCESS) {
            ret = get_physical_address_pmp(env, &prot_pmp, &tlb_size, pa,
                                           size, access_type, mode);

            qemu_log_mask(CPU_LOG_MMU,
                          "%s PMP address=" TARGET_FMT_plx " ret %d prot"
                          " %d tlb_size " TARGET_FMT_lu "\n",
                          __func__, pa, ret, prot_pmp, tlb_size);

            /* PMP has no CHERI permissions; preserve trap/clear */
            prot &= prot_pmp | prot_lc_preserve | prot_sc_preserve;
        }
    }

    if (ret == TRANSLATE_PMP_FAIL) {
        pmp_violation = true;
    }

    if (ret == TRANSLATE_SUCCESS) {
        MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
#ifdef TARGET_CHERI
        attrs.tag_setting = access_type == MMU_DATA_CAP_STORE;
#endif
        tlb_set_page_with_attrs(cs, address & ~(tlb_size - 1), pa & ~(tlb_size - 1),
                                attrs, prot, mmu_idx, tlb_size);
        return true;
    } else if (probe) {
        return false;
    } else {
        raise_mmu_exception(env, address, access_type, pmp_violation,
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
                            ret == TRANSLATE_CHERI_FAIL,
#endif
                            first_stage_error,
                            riscv_cpu_virt_enabled(env) ||
                                riscv_cpu_two_stage_lookup(mmu_idx));
        riscv_raise_exception(env, cs->exception_index, retaddr);
    }

    return true;

#else
    switch (access_type) {
    case MMU_INST_FETCH:
        cs->exception_index = RISCV_EXCP_INST_PAGE_FAULT;
        break;
    case MMU_DATA_LOAD:
        cs->exception_index = RISCV_EXCP_LOAD_PAGE_FAULT;
        break;
    case MMU_DATA_STORE:
        cs->exception_index = RISCV_EXCP_STORE_PAGE_FAULT;
        break;
    default:
        g_assert_not_reached();
    }
    env->badaddr = address;
    cpu_loop_exit_restore(cs, retaddr);
#endif
}

#ifdef TARGET_CHERI
/* TODO(am2419): do we log PCC as a changed register? */
#define riscv_update_pc_for_exc_handler(env, src_cap, new_pc)           \
    do {                                                                \
        cheri_update_pcc_for_exc_handler(&env->pcc, src_cap, new_pc);   \
        qemu_log_instr_dbg_cap(env, "PCC", &env->pcc);                  \
    } while (false)
#else
/*
 * TODO(am2419): We don't have a register ID for pc, move to a separate
 * logging helper that maps hwreg id to names for extra registers.
 * TODO(am2419): do we log PCC as a changed register?
 */
#define riscv_update_pc_for_exc_handler(env, src_cap, new_pc)           \
    do {                                                                \
        riscv_update_pc(env, new_pc, /*can_be_unrepresentable=*/true);  \
        qemu_log_instr_dbg_reg(env, "pc", new_pc);                      \
    } while (false)
#endif /* TARGET_CHERI */

/*
 * Handle Traps
 *
 * Adapted from Spike's processor_t::take_trap.
 *
 */
void riscv_cpu_do_interrupt(CPUState *cs)
{
#if !defined(CONFIG_USER_ONLY)

    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    tcg_debug_assert(pc_is_current(env));
    bool force_hs_execp = riscv_cpu_force_hs_excep_enabled(env);
    uint64_t s;

    /* cs->exception is 32-bits wide unlike mcause which is XLEN-bits wide
     * so we mask off the MSB and separate into trap type and cause.
     */
    bool async = !!(cs->exception_index & RISCV_EXCP_INT_FLAG);
    target_ulong cause = cs->exception_index & RISCV_EXCP_INT_MASK;
    target_ulong deleg = async ? env->mideleg : env->medeleg;
    bool write_tval = false;
    target_ulong tval = 0;
    target_ulong htval = 0;
    target_ulong mtval2 = 0;

    if  (cause == RISCV_EXCP_SEMIHOST) {
        if (env->priv >= PRV_S) {
            gpr_set_int_value(env, xA0, do_common_semihosting(cs));
            riscv_update_pc(env, PC_ADDR(env) + 4, /*can_be_unrepresentable=*/false);
            return;
        }
        cause = RISCV_EXCP_BREAKPOINT;
    }

    if (!async) {
        /* set tval to badaddr for traps with address information */
        switch (cause) {
        case RISCV_EXCP_INST_GUEST_PAGE_FAULT:
        case RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT:
        case RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT:
            force_hs_execp = true;
            /* fallthrough */
        case RISCV_EXCP_INST_PAGE_FAULT:
        case RISCV_EXCP_LOAD_PAGE_FAULT:
        case RISCV_EXCP_STORE_PAGE_FAULT:
#if defined(TARGET_CHERI) && !defined(TARGET_RISCV32)
        case RISCV_EXCP_LOAD_CAP_PAGE_FAULT:
        case RISCV_EXCP_STORE_AMO_CAP_PAGE_FAULT:
#endif
        case RISCV_EXCP_INST_ADDR_MIS:
        case RISCV_EXCP_INST_ACCESS_FAULT:
        case RISCV_EXCP_LOAD_ADDR_MIS:
        case RISCV_EXCP_STORE_AMO_ADDR_MIS:
        case RISCV_EXCP_LOAD_ACCESS_FAULT:
        case RISCV_EXCP_STORE_AMO_ACCESS_FAULT:
        case RISCV_EXCP_ILLEGAL_INST:
            write_tval  = true;
            tval = env->badaddr;
            break;
#ifdef TARGET_CHERI
        case RISCV_EXCP_CHERI:
            write_tval  = true;
            tcg_debug_assert(env->last_cap_cause < 32);
            tcg_debug_assert(env->last_cap_index < 64);
            tval = env->last_cap_cause | env->last_cap_index << 5;
            qemu_log_instr_or_mask_msg(env, CPU_LOG_INT,
                "Got CHERI trap %s caused by register %d\n",
                cheri_cause_str(env->last_cap_cause), env->last_cap_index);
            env->last_cap_cause = -1;
            env->last_cap_index = -1;
            break;
#endif
        default:
            break;
        }
        /* ecall is dispatched as one cause so translate based on mode */
        if (cause == RISCV_EXCP_U_ECALL) {
            assert(env->priv <= 3);

            if (env->priv == PRV_M) {
                cause = RISCV_EXCP_M_ECALL;
            } else if (env->priv == PRV_S && riscv_cpu_virt_enabled(env)) {
                cause = RISCV_EXCP_VS_ECALL;
            } else if (env->priv == PRV_S && !riscv_cpu_virt_enabled(env)) {
                cause = RISCV_EXCP_S_ECALL;
            } else if (env->priv == PRV_U) {
                cause = RISCV_EXCP_U_ECALL;
            }
        }
    }

    trace_riscv_trap(env->mhartid, async, cause, PC_ADDR(env), tval,
                     riscv_cpu_get_trap_name(cause, async));

    qemu_log_mask(CPU_LOG_INT,
                  "%s: hart:"TARGET_FMT_ld", async:%d, cause:"TARGET_FMT_lx", "
                  "epc:0x"TARGET_FMT_lx", tval:0x"TARGET_FMT_lx", desc=%s\n",
                  __func__, env->mhartid, async, cause, PC_ADDR(env), tval,
                  riscv_cpu_get_trap_name(cause, async));

    if (env->priv <= PRV_S &&
            cause < TARGET_LONG_BITS && ((deleg >> cause) & 1)) {
        /* handle the trap in S-mode */
        if (riscv_has_ext(env, RVH)) {
            target_ulong hdeleg = async ? env->hideleg : env->hedeleg;

            if (env->two_stage_lookup && write_tval) {
                /*
                 * If we are writing a guest virtual address to stval, set
                 * this to 1. If we are trapping to VS we will set this to 0
                 * later.
                 */
                env->hstatus = set_field(env->hstatus, HSTATUS_GVA, 1);
            } else {
                /* For other HS-mode traps, we set this to 0. */
                env->hstatus = set_field(env->hstatus, HSTATUS_GVA, 0);
            }

            if (riscv_cpu_virt_enabled(env) && ((hdeleg >> cause) & 1) &&
                !force_hs_execp) {
                /* Trap to VS mode */
                /*
                 * See if we need to adjust cause. Yes if its VS mode interrupt
                 * no if hypervisor has delegated one of hs mode's interrupt
                 */
                if (cause == IRQ_VS_TIMER || cause == IRQ_VS_SOFT ||
                    cause == IRQ_VS_EXT) {
                    cause = cause - 1;
                }
                env->hstatus = set_field(env->hstatus, HSTATUS_GVA, 0);
            } else if (riscv_cpu_virt_enabled(env)) {
                /* Trap into HS mode, from virt */
                riscv_cpu_swap_hypervisor_regs(env, /*hs_mode_trap*/true);
                env->hstatus = set_field(env->hstatus, HSTATUS_SPVP,
                                         env->priv);
                env->hstatus = set_field(env->hstatus, HSTATUS_SPV,
                                         riscv_cpu_virt_enabled(env));

                htval = env->guest_phys_fault_addr;

                riscv_cpu_set_virt_enabled(env, 0);
                riscv_cpu_set_force_hs_excep(env, 0);
            } else {
                /* Trap into HS mode */
                env->hstatus = set_field(env->hstatus, HSTATUS_SPV, false);
                htval = env->guest_phys_fault_addr;
            }
        }
        riscv_log_instr_csr_changed(env, CSR_HSTATUS);

        s = env->mstatus;
        s = set_field(s, MSTATUS_SPIE, get_field(s, MSTATUS_SIE));
        s = set_field(s, MSTATUS_SPP, env->priv);
        s = set_field(s, MSTATUS_SIE, 0);
        env->mstatus = s;
        riscv_log_instr_csr_changed(env, CSR_MSTATUS);
        env->scause = cause | ((target_ulong)async << (TARGET_LONG_BITS - 1));
        riscv_log_instr_csr_changed(env, CSR_SCAUSE);

        COPY_SPECIAL_REG(env, sepc, sepcc, pc, pcc);
        LOG_SPECIAL_REG(env, CSR_SEPC, CheriSCR_SEPCC);

        env->sbadaddr = tval;
        riscv_log_instr_csr_changed(env, CSR_SBADADDR);
        env->htval = htval;
        riscv_log_instr_csr_changed(env, CSR_HTVAL);

        target_ulong stvec = GET_SPECIAL_REG_ADDR(env, stvec, stcc);
        target_ulong new_pc = (stvec >> 2 << 2) +
            ((async && (stvec & 3) == 1) ? cause * 4 : 0);
        riscv_update_pc_for_exc_handler(env, &env->stcc, new_pc);
        riscv_cpu_set_mode(env, PRV_S);
    } else {
        /* handle the trap in M-mode */
        if (riscv_has_ext(env, RVH)) {
            if (riscv_cpu_virt_enabled(env)) {
                riscv_cpu_swap_hypervisor_regs(env, /*hs_mode_trap*/false);
            }
            env->mstatus = set_field(env->mstatus, MSTATUS_MPV,
                                     riscv_cpu_virt_enabled(env));
            if (riscv_cpu_virt_enabled(env) && tval) {
                env->mstatus = set_field(env->mstatus, MSTATUS_GVA, 1);
            }

            mtval2 = env->guest_phys_fault_addr;

            /* Trapping to M mode, virt is disabled */
            riscv_cpu_set_virt_enabled(env, 0);
            riscv_cpu_set_force_hs_excep(env, 0);
        }

        s = env->mstatus;
        s = set_field(s, MSTATUS_MPIE, get_field(s, MSTATUS_MIE));
        s = set_field(s, MSTATUS_MPP, env->priv);
        s = set_field(s, MSTATUS_MIE, 0);
        env->mstatus = s;
        riscv_log_instr_csr_changed(env, CSR_MSTATUS);
        env->mcause = cause | ~(((target_ulong)-1) >> async);
        riscv_log_instr_csr_changed(env, CSR_MCAUSE);

        COPY_SPECIAL_REG(env, mepc, mepcc, pc, pcc);
        LOG_SPECIAL_REG(env, CSR_MEPC, CheriSCR_MEPCC);

        env->mbadaddr = tval;
        riscv_log_instr_csr_changed(env, CSR_MBADADDR);
        env->mtval2 = mtval2;
        riscv_log_instr_csr_changed(env, CSR_MTVAL2);

        target_ulong mtvec = GET_SPECIAL_REG_ADDR(env, mtvec, mtcc);
        target_ulong new_pc = (mtvec >> 2 << 2) +
            ((async && (mtvec & 3) == 1) ? cause * 4 : 0);
        riscv_update_pc_for_exc_handler(env, &env->mtcc, new_pc);
        riscv_cpu_set_mode(env, PRV_M);
    }

#ifdef CONFIG_TCG_LOG_INSTR
    if (qemu_log_instr_enabled(env)) {
        if (async) {
            qemu_log_instr_interrupt(env, cause,
                GET_SPECIAL_REG_ADDR(env, pc, pcc));
        } else {
            qemu_log_instr_exception(env, cause,
                GET_SPECIAL_REG_ADDR(env, pc, pcc), tval);
        }
    }
#endif

#ifdef CONFIG_RVFI_DII
    if (unlikely(env->rvfi_dii_have_injected_insn)) {
        qemu_log_mask(CPU_LOG_INT, "%s: Got real exception %d\n", __func__,
                      cs->exception_index);
        env->rvfi_dii_trace.INST.rvfi_trap = true;
        rvfi_dii_communicate(env_cpu(env), env, true);
    }
#endif
    /* NOTE: it is not necessary to yield load reservations here. It is only
     * necessary for an SC from "another hart" to cause a load reservation
     * to be yielded. Refer to the memory consistency model section of the
     * RISC-V ISA Specification.
     */

    env->two_stage_lookup = false;
#endif
    cs->exception_index = EXCP_NONE; /* mark handled to qemu */
}

#ifdef TARGET_CHERI
void update_special_register(CPURISCVState *env, cap_register_t *scr,
                             const char *name, target_ulong new_value)
{
    /* The new behaviour is that SCR updates affect the address. */
    target_ulong new_cursor = new_value;
    if (!CHERI_NO_RELOCATION(env)) {
        /*
         * Legacy behaviour: with relocation enabled, updates to the SCRs update
         * the offset since updates to the architectural PC affect offset:
         * This shall be equivalent to a CSetOffset instruction, but with any
         * exception condition instead just clearing the tag of the SCR.
         */
        target_ulong current_offset = cap_get_offset(scr);
        target_ulong diff = new_value - current_offset;
        new_cursor = cap_get_cursor(scr) + diff;
    }

    if (!cap_is_unsealed(scr)) {
        error_report("Attempting to modify sealed %s: " PRINT_CAP_FMTSTR "\r\n",
                     name, PRINT_CAP_ARGS(scr));
        qemu_log_instr_extra(env, "Attempting to modify sealed %s: "
            PRINT_CAP_FMTSTR "\n", name, PRINT_CAP_ARGS(scr));
        // Clear the tag bit and update the cursor:
        cap_mark_unrepresentable(new_cursor, scr);
    } else if (!is_representable_cap_with_addr(scr, new_cursor)) {
        error_report(
            "Attempting to set unrepresentable cursor (0x" TARGET_FMT_lx
            ") on %s: " PRINT_CAP_FMTSTR "\r\n",
            new_cursor, name, PRINT_CAP_ARGS(scr));
        qemu_log_instr_extra(env, "Attempting to set unrepresentable cursor (0x"
            TARGET_FMT_lx ") on %s: " PRINT_CAP_FMTSTR "\r\n", new_cursor,
            name, PRINT_CAP_ARGS(scr));
        cap_mark_unrepresentable(new_cursor, scr);
    } else {
        scr->_cr_cursor = new_cursor;
    }
    /*
     * TODO(am2419): this is redundant as we are already logging the update
     * of the CSR register? Although it migth be useful in case we are making
     * the capability unrepresentable.
     */
    cheri_log_instr_changed_capreg(env, name, scr);
}
#endif
