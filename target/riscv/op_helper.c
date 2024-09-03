/*
 * RISC-V Emulation Helpers for QEMU.
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
#include "cpu.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

/* Exceptions processing helpers */
void QEMU_NORETURN riscv_raise_exception(CPURISCVState *env,
                                          uint32_t exception, uintptr_t pc)
{
    CPUState *cs = env_cpu(env);
    cs->exception_index = exception;
    // Expand this call to print debug info: cpu_loop_exit_restore(cs, pc);
    if (pc) {
        cpu_restore_state(cs, pc, true);
    }
#ifdef CONFIG_RVFI_DII
    if (exception == RISCV_EXCP_ILLEGAL_INST &&
        env->rvfi_dii_have_injected_insn) {
        env->badaddr = env->rvfi_dii_injected_insn;
    } else
#endif
    if (exception == RISCV_EXCP_ILLEGAL_INST) {
        // Try to fetch the faulting instruction and store it in badaddr
        uint32_t opcode = 0;
        int ret = cpu_memory_rw_debug(env_cpu(env), PC_ADDR(env),
                                      (uint8_t *)&opcode, sizeof(opcode),
                                      /*is_write=*/false);
        opcode = tswap32(opcode); // FIXME is this needed?
        if (ret != 0 && PC_ADDR(env) != 0) {
            warn_report("RISCV_EXCP_ILLEGAL_INST: Could not read %zu bytes at "
                        "vaddr 0x" TARGET_FMT_lx "\r\n",
                        sizeof(opcode), PC_ADDR(env));
        } else {
            env->badaddr = opcode;
        }
    }
    cpu_loop_exit(cs);
}

void helper_raise_exception(CPURISCVState *env, uint32_t exception)
{
    riscv_raise_exception(env, exception, 0);
}

target_ulong helper_csrrw(CPURISCVState *env, target_ulong src,
        target_ulong csr)
{
    target_ulong val = 0;
    int ret = riscv_csrrw(env, csr, &val, src, -1, GETPC());

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}

target_ulong helper_csrrs(CPURISCVState *env, target_ulong src,
        target_ulong csr, target_ulong rs1_pass)
{
    target_ulong val = 0;
    int ret = riscv_csrrw(env, csr, &val, -1, rs1_pass ? src : 0, GETPC());

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}

target_ulong helper_csrrc(CPURISCVState *env, target_ulong src,
        target_ulong csr, target_ulong rs1_pass)
{
    target_ulong val = 0;
    int ret = riscv_csrrw(env, csr, &val, 0, rs1_pass ? src : 0, GETPC());

    if (ret < 0) {
        riscv_raise_exception(env, -ret, GETPC());
    }
    return val;
}

#ifndef CONFIG_USER_ONLY

target_ulong helper_sret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    uint64_t mstatus;
    target_ulong prev_priv, prev_virt;

    if (!(env->priv >= PRV_S)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
#ifdef TARGET_CHERI
    if (!cheri_have_access_sysregs(env)) {
        raise_cheri_exception_impl(env, CapEx_AccessSystemRegsViolation,
                                   CHERI_EXC_REGNUM_PCC, 0, true, GETPC());
    }
#endif

    target_ulong retpc = GET_SPECIAL_REG_ADDR(env, sepc, sepcc);
    // We have to clear the low bit of the address since that is defined as zero
    // in the privileged spec. The cheri_update_pcc_for_exc_return() check below
    // will de-tag pcc if this would result changing the address for sealed caps.
    // If RVC is not supported, we also mask sepc[1] as specified in the RISC-V
    // privileged spec 4.1.7 Supervisor Exception Program Counter (sepc):
    // "This masking occurs also for the implicit read by the SRET instruction."
    retpc &= ~(target_ulong)(riscv_has_ext(env, RVC) ? 1 : 3);

    if (get_field(env->mstatus, MSTATUS_TSR) && !(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    if (riscv_has_ext(env, RVH) && riscv_cpu_virt_enabled(env) &&
        get_field(env->hstatus, HSTATUS_VTSR)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    }

    mstatus = env->mstatus;

    if (riscv_has_ext(env, RVH) && !riscv_cpu_virt_enabled(env)) {
        /* We support Hypervisor extensions and virtulisation is disabled */
        target_ulong hstatus = env->hstatus;

        prev_priv = get_field(mstatus, MSTATUS_SPP);
        prev_virt = get_field(hstatus, HSTATUS_SPV);

        hstatus = set_field(hstatus, HSTATUS_SPV, 0);
        mstatus = set_field(mstatus, MSTATUS_SPP, 0);
        mstatus = set_field(mstatus, SSTATUS_SIE,
                            get_field(mstatus, SSTATUS_SPIE));
        mstatus = set_field(mstatus, SSTATUS_SPIE, 1);

        env->mstatus = mstatus;
        env->hstatus = hstatus;

        if (prev_virt) {
            riscv_cpu_swap_hypervisor_regs(env, /*hs_mode_trap*/true);
        }

        riscv_cpu_set_virt_enabled(env, prev_virt);
    } else {
        prev_priv = get_field(mstatus, MSTATUS_SPP);

        mstatus = set_field(mstatus, MSTATUS_SIE,
                            get_field(mstatus, MSTATUS_SPIE));
        mstatus = set_field(mstatus, MSTATUS_SPIE, 1);
        mstatus = set_field(mstatus, MSTATUS_SPP, PRV_U);
        env->mstatus = mstatus;
        riscv_log_instr_csr_changed(env, CSR_MSTATUS);
    }

    riscv_cpu_set_mode(env, prev_priv);

#ifdef TARGET_CHERI
    cheri_update_pcc_for_exc_return(&env->pcc, &env->sepcc, retpc);
    /* TODO(am2419): do we log PCC as a changed register? */
    qemu_log_instr_dbg_cap(env, "PCC", &env->pcc);
#endif
    return retpc;
}

target_ulong helper_mret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    if (!(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
#ifdef TARGET_CHERI
    if (!cheri_have_access_sysregs(env)) {
        raise_cheri_exception_impl(env, CapEx_AccessSystemRegsViolation,
                                   CHERI_EXC_REGNUM_PCC, 0, true, GETPC());
    }
#endif

    target_ulong retpc = GET_SPECIAL_REG_ADDR(env, mepc, mepcc);
    // We have to clear the low bit of the address since that is defined as zero
    // in the privileged spec. The cheri_update_pcc_for_exc_return() check below
    // will de-tag pcc if this would result changing the address for sealed caps.
    // If RVC is not supported, we also mask sepc[1] as specified in the RISC-V
    // privileged spec 3.1.15 Machine Exception Program Counter (mepc):
    // "This masking occurs also for the implicit read by the MRET instruction."
    retpc &= ~(target_ulong)(riscv_has_ext(env, RVC) ? 1 : 3);

    uint64_t mstatus = env->mstatus;
    target_ulong prev_priv = get_field(mstatus, MSTATUS_MPP);

#if 0
    /* FIXME: upstream diff seems wrong, the ifetch should fail not the mret */
    if (!pmp_get_num_rules(env) && (prev_priv != PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
#endif

    target_ulong prev_virt = get_field(env->mstatus, MSTATUS_MPV);
    mstatus = set_field(mstatus, MSTATUS_MIE,
                        get_field(mstatus, MSTATUS_MPIE));
    mstatus = set_field(mstatus, MSTATUS_MPIE, 1);
    mstatus = set_field(mstatus, MSTATUS_MPP, PRV_U);
    mstatus = set_field(mstatus, MSTATUS_MPV, 0);
    env->mstatus = mstatus;
    riscv_cpu_set_mode(env, prev_priv);

    if (riscv_has_ext(env, RVH)) {
        if (prev_virt) {
            riscv_cpu_swap_hypervisor_regs(env, /*hs_mode_trap*/false);
        }

        riscv_cpu_set_virt_enabled(env, prev_virt);
    }

    riscv_log_instr_csr_changed(env, CSR_MSTATUS);
#ifdef TARGET_RISCV32
    riscv_log_instr_csr_changed(env, CSR_MSTATUSH);
#endif

#ifdef TARGET_CHERI
    cheri_update_pcc_for_exc_return(&env->pcc, &env->mepcc, retpc);
    /* TODO(am2419): do we log PCC as a changed register? */
    qemu_log_instr_dbg_cap(env, "PCC", &env->pcc);
#endif
    return retpc;
}

void HELPER(check_alignment)(CPURISCVState *env, target_ulong addr, MemOp op,
                             uint32_t exc)
{
    if (addr & (memop_size(op) - 1)) {
        env->badaddr = addr;
        riscv_raise_exception(env, exc, GETPC());
    }
}

void helper_wfi(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);

    if ((env->priv == PRV_S &&
        get_field(env->mstatus, MSTATUS_TW)) ||
        riscv_cpu_virt_enabled(env)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    } else {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cpu_loop_exit(cs);
    }
}

void helper_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    if (!(env->priv >= PRV_S) ||
        (env->priv == PRV_S &&
         get_field(env->mstatus, MSTATUS_TVM))) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else if (riscv_has_ext(env, RVH) && riscv_cpu_virt_enabled(env) &&
               get_field(env->hstatus, HSTATUS_VTVM)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    } else {
        tlb_flush(cs);
    }
}

void helper_hyp_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);

    if (env->priv == PRV_S && riscv_cpu_virt_enabled(env)) {
        riscv_raise_exception(env, RISCV_EXCP_VIRT_INSTRUCTION_FAULT, GETPC());
    }

    if (env->priv == PRV_M ||
        (env->priv == PRV_S && !riscv_cpu_virt_enabled(env))) {
        tlb_flush(cs);
        return;
    }

    riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
}

void helper_hyp_gvma_tlb_flush(CPURISCVState *env)
{
    if (env->priv == PRV_S && !riscv_cpu_virt_enabled(env) &&
        get_field(env->mstatus, MSTATUS_TVM)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    helper_hyp_tlb_flush(env);
}

target_ulong helper_hyp_hlvx_hu(CPURISCVState *env, target_ulong address)
{
    int mmu_idx = cpu_mmu_index(env, true) | TB_FLAGS_PRIV_HYP_ACCESS_MASK;

    return cpu_lduw_mmuidx_ra(env, address, mmu_idx, GETPC());
}

target_ulong helper_hyp_hlvx_wu(CPURISCVState *env, target_ulong address)
{
    int mmu_idx = cpu_mmu_index(env, true) | TB_FLAGS_PRIV_HYP_ACCESS_MASK;

    return cpu_ldl_mmuidx_ra(env, address, mmu_idx, GETPC());
}

#endif /* !CONFIG_USER_ONLY */
