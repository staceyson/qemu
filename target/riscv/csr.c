/*
 * RISC-V Control and Status Registers.
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
#include "exec/log_instr.h"
#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

/* CSR update logging API */
#if CONFIG_TCG_LOG_INSTR
void riscv_log_instr_csr_changed(CPURISCVState *env, int csrno)
{
    target_ulong value;

    if (qemu_log_instr_enabled(env)) {
        if (csr_ops[csrno].read)
            csr_ops[csrno].read(env, csrno, &value);
        else if (csr_ops[csrno].op)
            csr_ops[csrno].op(env, csrno, &value, 0, /*write_mask*/0);
        else
            return;
        if (csr_ops[csrno].log_update)
            csr_ops[csrno].log_update(env, csrno, value);
    }
}
#endif

/* CSR function table public API */
void riscv_get_csr_ops(int csrno, riscv_csr_operations *ops)
{
    *ops = csr_ops[csrno & (CSR_TABLE_SIZE - 1)];
}

void riscv_set_csr_ops(int csrno, riscv_csr_operations *ops)
{
    csr_ops[csrno & (CSR_TABLE_SIZE - 1)] = *ops;
}

/* Predicates */
static int fs(CPURISCVState *env, int csrno)
{
#if !defined(CONFIG_USER_ONLY)
    /* loose check condition for fcsr in vector extension */
    if ((csrno == CSR_FCSR) && (env->misa & RVV)) {
        return 0;
    }
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
#endif
    return 0;
}

static int vs(CPURISCVState *env, int csrno)
{
    if (env->misa & RVV) {
        return 0;
    }
    return -RISCV_EXCP_ILLEGAL_INST;
}

static int ctr(CPURISCVState *env, int csrno)
{
#if !defined(CONFIG_USER_ONLY)
    CPUState *cs = env_cpu(env);
    RISCVCPU *cpu = RISCV_CPU(cs);

    if (!cpu->cfg.ext_counters) {
        /* The Counters extensions is not enabled */
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    if (riscv_cpu_virt_enabled(env)) {
        switch (csrno) {
        case CSR_CYCLE:
            if (!get_field(env->hcounteren, HCOUNTEREN_CY) &&
                get_field(env->mcounteren, HCOUNTEREN_CY)) {
                return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
            }
            break;
        case CSR_TIME:
            if (!get_field(env->hcounteren, HCOUNTEREN_TM) &&
                get_field(env->mcounteren, HCOUNTEREN_TM)) {
                return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
            }
            break;
        case CSR_INSTRET:
            if (!get_field(env->hcounteren, HCOUNTEREN_IR) &&
                get_field(env->mcounteren, HCOUNTEREN_IR)) {
                return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
            }
            break;
        case CSR_HPMCOUNTER3...CSR_HPMCOUNTER31:
            if (!get_field(env->hcounteren, 1 << (csrno - CSR_HPMCOUNTER3)) &&
                get_field(env->mcounteren, 1 << (csrno - CSR_HPMCOUNTER3))) {
                return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
            }
            break;
        }
        if (riscv_cpu_is_32bit(env)) {
            switch (csrno) {
            case CSR_CYCLEH:
                if (!get_field(env->hcounteren, HCOUNTEREN_CY) &&
                    get_field(env->mcounteren, HCOUNTEREN_CY)) {
                    return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
                }
                break;
            case CSR_TIMEH:
                if (!get_field(env->hcounteren, HCOUNTEREN_TM) &&
                    get_field(env->mcounteren, HCOUNTEREN_TM)) {
                    return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
                }
                break;
            case CSR_INSTRETH:
                if (!get_field(env->hcounteren, HCOUNTEREN_IR) &&
                    get_field(env->mcounteren, HCOUNTEREN_IR)) {
                    return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
                }
                break;
            case CSR_HPMCOUNTER3H...CSR_HPMCOUNTER31H:
                if (!get_field(env->hcounteren, 1 << (csrno - CSR_HPMCOUNTER3H)) &&
                    get_field(env->mcounteren, 1 << (csrno - CSR_HPMCOUNTER3H))) {
                    return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
                }
                break;
            }
        }
    }
#endif
    return 0;
}

static int ctr32(CPURISCVState *env, int csrno)
{
    if (!riscv_cpu_is_32bit(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    return ctr(env, csrno);
}

#if !defined(CONFIG_USER_ONLY)
static int any(CPURISCVState *env, int csrno)
{
    return 0;
}

static int any32(CPURISCVState *env, int csrno)
{
    if (!riscv_cpu_is_32bit(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    return any(env, csrno);

}

#ifdef TARGET_CHERI
static int umode(CPURISCVState *env, int csrno)
{
    return -!riscv_has_ext(env, RVU);
}
#endif

static int smode(CPURISCVState *env, int csrno)
{
    return -!riscv_has_ext(env, RVS);
}

static int hmode(CPURISCVState *env, int csrno)
{
    if (riscv_has_ext(env, RVS) &&
        riscv_has_ext(env, RVH)) {
        /* Hypervisor extension is supported */
        if ((env->priv == PRV_S && !riscv_cpu_virt_enabled(env)) ||
            env->priv == PRV_M) {
            return 0;
        } else {
            return -RISCV_EXCP_VIRT_INSTRUCTION_FAULT;
        }
    }

    return -RISCV_EXCP_ILLEGAL_INST;
}

static int hmode32(CPURISCVState *env, int csrno)
{
    if (!riscv_cpu_is_32bit(env)) {
        return 0;
    }

    return hmode(env, csrno);

}

static int pmp(CPURISCVState *env, int csrno)
{
    return -!riscv_feature(env, RISCV_FEATURE_PMP);
}
#endif

/* User Floating-Point CSRs */
static int read_fflags(CPURISCVState *env, int csrno, target_ulong *val)
{
#if !defined(CONFIG_USER_ONLY)
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
#endif
    *val = riscv_cpu_get_fflags(env);
    return 0;
}

static int write_fflags(CPURISCVState *env, int csrno, target_ulong val)
{
#if !defined(CONFIG_USER_ONLY)
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    env->mstatus |= MSTATUS_FS;
#endif
    riscv_cpu_set_fflags(env, val & (FSR_AEXC >> FSR_AEXC_SHIFT));
    return 0;
}

static int read_frm(CPURISCVState *env, int csrno, target_ulong *val)
{
#if !defined(CONFIG_USER_ONLY)
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
#endif
    *val = env->frm;
    return 0;
}

static int write_frm(CPURISCVState *env, int csrno, target_ulong val)
{
#if !defined(CONFIG_USER_ONLY)
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    env->mstatus |= MSTATUS_FS;
#endif
    env->frm = val & (FSR_RD >> FSR_RD_SHIFT);
    return 0;
}

static int read_fcsr(CPURISCVState *env, int csrno, target_ulong *val)
{
#if !defined(CONFIG_USER_ONLY)
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
#endif
    *val = (riscv_cpu_get_fflags(env) << FSR_AEXC_SHIFT)
        | (env->frm << FSR_RD_SHIFT);
    if (vs(env, csrno) >= 0) {
        *val |= (env->vxrm << FSR_VXRM_SHIFT)
                | (env->vxsat << FSR_VXSAT_SHIFT);
    }
    return 0;
}

static int write_fcsr(CPURISCVState *env, int csrno, target_ulong val)
{
#if !defined(CONFIG_USER_ONLY)
    if (!env->debugger && !riscv_cpu_fp_enabled(env)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    env->mstatus |= MSTATUS_FS;
#endif
    env->frm = (val & FSR_RD) >> FSR_RD_SHIFT;
    if (vs(env, csrno) >= 0) {
        env->vxrm = (val & FSR_VXRM) >> FSR_VXRM_SHIFT;
        env->vxsat = (val & FSR_VXSAT) >> FSR_VXSAT_SHIFT;
    }
    riscv_cpu_set_fflags(env, (val & FSR_AEXC) >> FSR_AEXC_SHIFT);
    return 0;
}

static int read_vtype(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vtype;
    return 0;
}

static int read_vl(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vl;
    return 0;
}

static int read_vxrm(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vxrm;
    return 0;
}

static int write_vxrm(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vxrm = val;
    return 0;
}

static int read_vxsat(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vxsat;
    return 0;
}

static int write_vxsat(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vxsat = val;
    return 0;
}

static int read_vstart(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vstart;
    return 0;
}

static int write_vstart(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vstart = val;
    return 0;
}

/* User Timers and Counters */
static int read_instret(CPURISCVState *env, int csrno, target_ulong *val)
{
#if !defined(CONFIG_USER_ONLY)
    if (icount_enabled()) {
        *val = icount_get();
    } else {
        *val = cpu_get_host_ticks();
    }
#else
    *val = cpu_get_host_ticks();
#endif
    return 0;
}

static int read_instreth(CPURISCVState *env, int csrno, target_ulong *val)
{
#if !defined(CONFIG_USER_ONLY)
    if (icount_enabled()) {
        *val = icount_get() >> 32;
    } else {
        *val = cpu_get_host_ticks() >> 32;
    }
#else
    *val = cpu_get_host_ticks() >> 32;
#endif
    return 0;
}

#if defined(CONFIG_USER_ONLY)
static int read_time(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = cpu_get_host_ticks();
    return 0;
}

static int read_timeh(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = cpu_get_host_ticks() >> 32;
    return 0;
}

#else /* CONFIG_USER_ONLY */

static int read_time(CPURISCVState *env, int csrno, target_ulong *val)
{
    uint64_t delta = riscv_cpu_virt_enabled(env) ? env->htimedelta : 0;

    if (!env->rdtime_fn) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    *val = env->rdtime_fn(env->rdtime_fn_arg) + delta;
    return 0;
}

static int read_timeh(CPURISCVState *env, int csrno, target_ulong *val)
{
    uint64_t delta = riscv_cpu_virt_enabled(env) ? env->htimedelta : 0;

    if (!env->rdtime_fn) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    *val = (env->rdtime_fn(env->rdtime_fn_arg) + delta) >> 32;
    return 0;
}

/* Machine constants */

#define M_MODE_INTERRUPTS  (MIP_MSIP | MIP_MTIP | MIP_MEIP)
#define S_MODE_INTERRUPTS  (MIP_SSIP | MIP_STIP | MIP_SEIP)
#define VS_MODE_INTERRUPTS (MIP_VSSIP | MIP_VSTIP | MIP_VSEIP)

static const target_ulong delegable_ints = S_MODE_INTERRUPTS |
                                           VS_MODE_INTERRUPTS;
static const target_ulong all_ints = M_MODE_INTERRUPTS | S_MODE_INTERRUPTS |
                                     VS_MODE_INTERRUPTS;
static const target_ulong delegable_excps =
    (1ULL << (RISCV_EXCP_INST_ADDR_MIS)) |
    (1ULL << (RISCV_EXCP_INST_ACCESS_FAULT)) |
    (1ULL << (RISCV_EXCP_ILLEGAL_INST)) |
    (1ULL << (RISCV_EXCP_BREAKPOINT)) |
    (1ULL << (RISCV_EXCP_LOAD_ADDR_MIS)) |
    (1ULL << (RISCV_EXCP_LOAD_ACCESS_FAULT)) |
    (1ULL << (RISCV_EXCP_STORE_AMO_ADDR_MIS)) |
    (1ULL << (RISCV_EXCP_STORE_AMO_ACCESS_FAULT)) |
    (1ULL << (RISCV_EXCP_U_ECALL)) |
    (1ULL << (RISCV_EXCP_S_ECALL)) |
    (1ULL << (RISCV_EXCP_VS_ECALL)) |
    (1ULL << (RISCV_EXCP_M_ECALL)) |
    (1ULL << (RISCV_EXCP_INST_PAGE_FAULT)) |
    (1ULL << (RISCV_EXCP_LOAD_PAGE_FAULT)) |
    (1ULL << (RISCV_EXCP_STORE_PAGE_FAULT)) |
    (1ULL << (RISCV_EXCP_INST_GUEST_PAGE_FAULT)) |
    (1ULL << (RISCV_EXCP_LOAD_GUEST_ACCESS_FAULT)) |
    (1ULL << (RISCV_EXCP_VIRT_INSTRUCTION_FAULT)) |
    (1ULL << (RISCV_EXCP_STORE_GUEST_AMO_ACCESS_FAULT)) |
#ifdef TARGET_CHERI
#ifndef TARGET_RISCV32
    (1ULL << (RISCV_EXCP_LOAD_CAP_PAGE_FAULT)) |
    (1ULL << (RISCV_EXCP_STORE_AMO_CAP_PAGE_FAULT)) |
#endif
    (1ULL << (RISCV_EXCP_CHERI)) |
#endif
    0;
static const target_ulong sstatus_v1_10_mask = SSTATUS_SIE | SSTATUS_SPIE |
    SSTATUS_UIE | SSTATUS_UPIE | SSTATUS_SPP | SSTATUS_FS | SSTATUS_XS |
    SSTATUS_SUM | SSTATUS_MXR |
#if defined(TARGET_RISCV64)
    SSTATUS64_UXL |
#endif
    SSTATUS_SD;
static const target_ulong sip_writable_mask = SIP_SSIP | MIP_USIP | MIP_UEIP;
static const target_ulong hip_writable_mask = MIP_VSSIP;
static const target_ulong hvip_writable_mask = MIP_VSSIP | MIP_VSTIP | MIP_VSEIP;
static const target_ulong vsip_writable_mask = MIP_VSSIP;

static const char valid_vm_1_10_32[16] = {
    [VM_1_10_MBARE] = 1,
    [VM_1_10_SV32] = 1
};

static const char valid_vm_1_10_64[16] = {
    [VM_1_10_MBARE] = 1,
    [VM_1_10_SV39] = 1,
    [VM_1_10_SV48] = 1,
    [VM_1_10_SV57] = 1
};

/* Machine Information Registers */
static int read_zero(CPURISCVState *env, int csrno, target_ulong *val)
{
    return *val = 0;
}

static int read_mhartid(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mhartid;
    return 0;
}

/* Machine Trap Setup */
static int read_mstatus(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mstatus;
    return 0;
}

static int validate_vm(CPURISCVState *env, target_ulong vm)
{
    if (riscv_cpu_is_32bit(env)) {
        return valid_vm_1_10_32[vm & 0xf];
    } else {
        return valid_vm_1_10_64[vm & 0xf];
    }
}

static int write_mstatus(CPURISCVState *env, int csrno, target_ulong val)
{
    uint64_t mstatus = env->mstatus;
    uint64_t mask = 0;
    int dirty;

    /* flush tlb on mstatus fields that affect VM */
    if ((val ^ mstatus) & (MSTATUS_MXR | MSTATUS_MPP | MSTATUS_MPV |
            MSTATUS_MPRV | MSTATUS_SUM)) {
        tlb_flush(env_cpu(env));
    }
    mask = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_MIE | MSTATUS_MPIE |
        MSTATUS_SPP | MSTATUS_FS | MSTATUS_MPRV | MSTATUS_SUM |
        MSTATUS_MPP | MSTATUS_MXR | MSTATUS_TVM | MSTATUS_TSR |
        MSTATUS_TW;

    if (!riscv_cpu_is_32bit(env)) {
        /*
         * RV32: MPV and GVA are not in mstatus. The current plan is to
         * add them to mstatush. For now, we just don't support it.
         */
        if (riscv_has_ext(env, RVH)) {
            mask |= MSTATUS_MPV | MSTATUS_GVA;
        }
    }

    mstatus = (mstatus & ~mask) | (val & mask);

    dirty = ((mstatus & MSTATUS_FS) == MSTATUS_FS) |
            ((mstatus & MSTATUS_XS) == MSTATUS_XS);
    mstatus = set_field(mstatus, MSTATUS_SD, dirty);
    env->mstatus = mstatus;

    return 0;
}

static int read_mstatush(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mstatus >> 32;
    return 0;
}

static int write_mstatush(CPURISCVState *env, int csrno, target_ulong val)
{
    uint64_t valh = (uint64_t)val << 32;
    uint64_t mask = MSTATUS_MPV | MSTATUS_GVA;

    if ((valh ^ env->mstatus) & (MSTATUS_MPV)) {
        tlb_flush(env_cpu(env));
    }

    env->mstatus = (env->mstatus & ~mask) | (valh & mask);

    return 0;
}

static int read_misa(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->misa;
    return 0;
}

static int write_misa(CPURISCVState *env, int csrno, target_ulong val)
{
    if (!riscv_feature(env, RISCV_FEATURE_MISA)) {
        /* drop write to misa */
        return 0;
    }

    /*
     * XXXAR: this code is completely broken:
     * 1) you can only turn **on** misa.C if PC is not aligned to 4 bytes???
     * 2) They use GETPC() for this check! This is a QEMU internal program
     * counter (the current return address, so not even the TCG generated code
     * address since we could be multiple call stack levels down).
     *
     * Fortunately RISCV_FEATURE_MISA should never be enabled so we can't end
     * up here... If we ever do, abort() is the only safe way out!
     */
    abort();

    /* 'I' or 'E' must be present */
    if (!(val & (RVI | RVE))) {
        /* It is not, drop write to misa */
        return 0;
    }

    /* 'E' excludes all other extensions */
    if (val & RVE) {
        /* when we support 'E' we can do "val = RVE;" however
         * for now we just drop writes if 'E' is present.
         */
        return 0;
    }

    /* Mask extensions that are not supported by this hart */
    val &= env->misa_mask;

    /* Mask extensions that are not supported by QEMU */
    val &= (RVI | RVE | RVM | RVA | RVF | RVD | RVC | RVS | RVU);

    /* 'D' depends on 'F', so clear 'D' if 'F' is not present */
    if ((val & RVD) && !(val & RVF)) {
        val &= ~RVD;
    }

    /* Suppress 'C' if next instruction is not aligned
     * TODO: this should check next_pc
     */
    if ((val & RVC) && (GETPC() & ~3) != 0) {
        val &= ~RVC;
    }

    /* misa.MXL writes are not supported by QEMU */
    val = (env->misa & MISA_MXL) | (val & ~MISA_MXL);

    /* flush translation cache */
    if (val != env->misa) {
        tb_flush(env_cpu(env));
    }

    env->misa = val;

    return 0;
}

static int read_medeleg(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->medeleg;
    return 0;
}

static int write_medeleg(CPURISCVState *env, int csrno, target_ulong val)
{
    env->medeleg = (env->medeleg & ~delegable_excps) | (val & delegable_excps);
    return 0;
}

static int read_mideleg(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mideleg;
    return 0;
}

static int write_mideleg(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mideleg = (env->mideleg & ~delegable_ints) | (val & delegable_ints);
    if (riscv_has_ext(env, RVH)) {
        env->mideleg |= VS_MODE_INTERRUPTS;
    }
    return 0;
}

static int read_mie(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mie;
    return 0;
}

static int write_mie(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mie = (env->mie & ~all_ints) | (val & all_ints);
    return 0;
}

static int read_mtvec(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = GET_SPECIAL_REG_ARCH(env, mtvec, MTCC);
    return 0;
}

static int write_mtvec(CPURISCVState *env, int csrno, target_ulong val)
{
    /* bits [1:0] encode mode; 0 = direct, 1 = vectored, 2 >= reserved */
    if ((val & 3) < 2) {
        SET_SPECIAL_REG(env, mtvec, MTCC, val);
    } else {
        qemu_log_mask(LOG_UNIMP, "CSR_MTVEC: reserved mode not supported\n");
    }
    return 0;
}

static int read_mcounteren(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mcounteren;
    return 0;
}

static int write_mcounteren(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mcounteren = val;
    return 0;
}

/* This regiser is replaced with CSR_MCOUNTINHIBIT in 1.11.0 */
static int read_mscounteren(CPURISCVState *env, int csrno, target_ulong *val)
{
    if (env->priv_ver < PRIV_VERSION_1_11_0) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    *val = env->mcounteren;
    return 0;
}

/* This regiser is replaced with CSR_MCOUNTINHIBIT in 1.11.0 */
static int write_mscounteren(CPURISCVState *env, int csrno, target_ulong val)
{
    if (env->priv_ver < PRIV_VERSION_1_11_0) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    env->mcounteren = val;
    return 0;
}

/* Machine Trap Handling */
static int read_mscratch(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mscratch;
    return 0;
}

static int write_mscratch(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mscratch = val;
    return 0;
}

static int read_mepc(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = GET_SPECIAL_REG_ARCH(env, mepc, MEPCC);
    // RISC-V privileged spec 3.1.15 Machine Exception Program Counter (mepc):
    // "The low bit of mepc (mepc[0]) is always zero. [...] Whenever IALIGN=32,
    // mepc[1] is masked on reads so that it appears to be 0."
    *val &= ~(target_ulong)(riscv_has_ext(env, RVC) ? 1 : 3);
    return 0;
}

static int write_mepc(CPURISCVState *env, int csrno, target_ulong val)
{
    SET_SPECIAL_REG(env, mepc, MEPCC, val);
    return 0;
}

static int read_mcause(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mcause;
    return 0;
}

static int write_mcause(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mcause = val;
    return 0;
}

static int read_mbadaddr(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mbadaddr;
    return 0;
}

static int write_mbadaddr(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mbadaddr = val;
    return 0;
}

static int rmw_mip(CPURISCVState *env, int csrno, target_ulong *ret_value,
                   target_ulong new_value, target_ulong write_mask)
{
    RISCVCPU *cpu = env_archcpu(env);
    /* Allow software control of delegable interrupts not claimed by hardware */
    target_ulong mask = write_mask & delegable_ints & ~env->miclaim;
    uint32_t old_mip;

    if (mask) {
        old_mip = riscv_cpu_update_mip(cpu, mask, (new_value & mask));
    } else {
        old_mip = env->mip;
    }

    if (ret_value) {
        *ret_value = old_mip;
    }

    return 0;
}

/* Supervisor Trap Setup */
static int read_sstatus(CPURISCVState *env, int csrno, target_ulong *val)
{
    target_ulong mask = (sstatus_v1_10_mask);
    *val = env->mstatus & mask;
    return 0;
}

static int write_sstatus(CPURISCVState *env, int csrno, target_ulong val)
{
    target_ulong mask = (sstatus_v1_10_mask);
    target_ulong newval = (env->mstatus & ~mask) | (val & mask);
    return write_mstatus(env, CSR_MSTATUS, newval);
}

static int read_vsie(CPURISCVState *env, int csrno, target_ulong *val)
{
    /* Shift the VS bits to their S bit location in vsie */
    *val = (env->mie & env->hideleg & VS_MODE_INTERRUPTS) >> 1;
    return 0;
}

static int read_sie(CPURISCVState *env, int csrno, target_ulong *val)
{
    if (riscv_cpu_virt_enabled(env)) {
        read_vsie(env, CSR_VSIE, val);
    } else {
        *val = env->mie & env->mideleg;
    }
    return 0;
}

static int write_vsie(CPURISCVState *env, int csrno, target_ulong val)
{
    /* Shift the S bits to their VS bit location in mie */
    target_ulong newval = (env->mie & ~VS_MODE_INTERRUPTS) |
                          ((val << 1) & env->hideleg & VS_MODE_INTERRUPTS);
    return write_mie(env, CSR_MIE, newval);
}

static int write_sie(CPURISCVState *env, int csrno, target_ulong val)
{
    if (riscv_cpu_virt_enabled(env)) {
        write_vsie(env, CSR_VSIE, val);
    } else {
        target_ulong newval = (env->mie & ~S_MODE_INTERRUPTS) |
                              (val & S_MODE_INTERRUPTS);
        write_mie(env, CSR_MIE, newval);
    }

    return 0;
}

static int read_stvec(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = GET_SPECIAL_REG_ARCH(env, stvec, STCC);
    return 0;
}

static int write_stvec(CPURISCVState *env, int csrno, target_ulong val)
{
    /* bits [1:0] encode mode; 0 = direct, 1 = vectored, 2 >= reserved */
    if ((val & 3) < 2) {
        SET_SPECIAL_REG(env, stvec, STCC, val);
    } else {
        qemu_log_mask(LOG_UNIMP, "CSR_STVEC: reserved mode not supported\n");
    }
    return 0;
}

static int read_scounteren(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->scounteren;
    return 0;
}

static int write_scounteren(CPURISCVState *env, int csrno, target_ulong val)
{
    env->scounteren = val;
    return 0;
}

/* Supervisor Trap Handling */
static int read_sscratch(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->sscratch;
    return 0;
}

static int write_sscratch(CPURISCVState *env, int csrno, target_ulong val)
{
    env->sscratch = val;
    return 0;
}

static int read_sepc(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = GET_SPECIAL_REG_ARCH(env, sepc, SEPCC);
    // RISC-V privileged spec 4.1.7 Supervisor Exception Program Counter (sepc)
    // "The low bit of sepc (sepc[0]) is always zero. [...] Whenever IALIGN=32,
    // sepc[1] is masked on reads so that it appears to be 0."
    *val &= ~(target_ulong)(riscv_has_ext(env, RVC) ? 1 : 3);
    return 0;
}

static int write_sepc(CPURISCVState *env, int csrno, target_ulong val)
{
    SET_SPECIAL_REG(env, sepc, SEPCC, val);
    return 0;
}

static int read_scause(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->scause;
    return 0;
}

static int write_scause(CPURISCVState *env, int csrno, target_ulong val)
{
    env->scause = val;
    return 0;
}

static int read_sbadaddr(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->sbadaddr;
    return 0;
}

static int write_sbadaddr(CPURISCVState *env, int csrno, target_ulong val)
{
    env->sbadaddr = val;
    return 0;
}

static int rmw_vsip(CPURISCVState *env, int csrno, target_ulong *ret_value,
                    target_ulong new_value, target_ulong write_mask)
{
    /* Shift the S bits to their VS bit location in mip */
    int ret = rmw_mip(env, 0, ret_value, new_value << 1,
                      (write_mask << 1) & vsip_writable_mask & env->hideleg);
    *ret_value &= VS_MODE_INTERRUPTS;
    /* Shift the VS bits to their S bit location in vsip */
    *ret_value >>= 1;
    return ret;
}

static int rmw_sip(CPURISCVState *env, int csrno, target_ulong *ret_value,
                   target_ulong new_value, target_ulong write_mask)
{
    int ret;

    if (riscv_cpu_virt_enabled(env)) {
        ret = rmw_vsip(env, CSR_VSIP, ret_value, new_value, write_mask);
    } else {
        ret = rmw_mip(env, CSR_MSTATUS, ret_value, new_value,
                      write_mask & env->mideleg & sip_writable_mask);
    }

    *ret_value &= env->mideleg;
    return ret;
}

/* Supervisor Protection and Translation */
static int read_satp(CPURISCVState *env, int csrno, target_ulong *val)
{
    if (!riscv_feature(env, RISCV_FEATURE_MMU)) {
        *val = 0;
        return 0;
    }

    if (env->priv == PRV_S && get_field(env->mstatus, MSTATUS_TVM)) {
        return -RISCV_EXCP_ILLEGAL_INST;
    } else {
        *val = env->satp;
    }

    return 0;
}

static int write_satp(CPURISCVState *env, int csrno, target_ulong val)
{
    if (!riscv_feature(env, RISCV_FEATURE_MMU)) {
        return 0;
    }
    if (validate_vm(env, get_field(val, SATP_MODE)) &&
        ((val ^ env->satp) & (SATP_MODE | SATP_ASID | SATP_PPN)))
    {
        if (env->priv == PRV_S && get_field(env->mstatus, MSTATUS_TVM)) {
            return -RISCV_EXCP_ILLEGAL_INST;
        } else {
            if ((val ^ env->satp) & SATP_ASID) {
                tlb_flush(env_cpu(env));
            }
            env->satp = val;
        }
    }
    return 0;
}

/* Hypervisor Extensions */
static int read_hstatus(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->hstatus;
    if (!riscv_cpu_is_32bit(env)) {
        /* We only support 64-bit VSXL */
        *val = set_field(*val, HSTATUS_VSXL, 2);
    }
    /* We only support little endian */
    *val = set_field(*val, HSTATUS_VSBE, 0);
    return 0;
}

static int write_hstatus(CPURISCVState *env, int csrno, target_ulong val)
{
    env->hstatus = val;
    if (!riscv_cpu_is_32bit(env) && get_field(val, HSTATUS_VSXL) != 2) {
        qemu_log_mask(LOG_UNIMP, "QEMU does not support mixed HSXLEN options.");
    }
    if (get_field(val, HSTATUS_VSBE) != 0) {
        qemu_log_mask(LOG_UNIMP, "QEMU does not support big endian guests.");
    }
    return 0;
}

static int read_hedeleg(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->hedeleg;
    return 0;
}

static int write_hedeleg(CPURISCVState *env, int csrno, target_ulong val)
{
    env->hedeleg = val;
    return 0;
}

static int read_hideleg(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->hideleg;
    return 0;
}

static int write_hideleg(CPURISCVState *env, int csrno, target_ulong val)
{
    env->hideleg = val;
    return 0;
}

static int rmw_hvip(CPURISCVState *env, int csrno, target_ulong *ret_value,
                   target_ulong new_value, target_ulong write_mask)
{
    int ret = rmw_mip(env, 0, ret_value, new_value,
                      write_mask & hvip_writable_mask);

    *ret_value &= hvip_writable_mask;

    return ret;
}

static int rmw_hip(CPURISCVState *env, int csrno, target_ulong *ret_value,
                   target_ulong new_value, target_ulong write_mask)
{
    int ret = rmw_mip(env, 0, ret_value, new_value,
                      write_mask & hip_writable_mask);

    *ret_value &= hip_writable_mask;

    return ret;
}

static int read_hie(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mie & VS_MODE_INTERRUPTS;
    return 0;
}

static int write_hie(CPURISCVState *env, int csrno, target_ulong val)
{
    target_ulong newval = (env->mie & ~VS_MODE_INTERRUPTS) | (val & VS_MODE_INTERRUPTS);
    return write_mie(env, CSR_MIE, newval);
}

static int read_hcounteren(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->hcounteren;
    return 0;
}

static int write_hcounteren(CPURISCVState *env, int csrno, target_ulong val)
{
    env->hcounteren = val;
    return 0;
}

static int read_hgeie(CPURISCVState *env, int csrno, target_ulong *val)
{
    qemu_log_mask(LOG_UNIMP, "No support for a non-zero GEILEN.");
    return 0;
}

static int write_hgeie(CPURISCVState *env, int csrno, target_ulong val)
{
    qemu_log_mask(LOG_UNIMP, "No support for a non-zero GEILEN.");
    return 0;
}

static int read_htval(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->htval;
    return 0;
}

static int write_htval(CPURISCVState *env, int csrno, target_ulong val)
{
    env->htval = val;
    return 0;
}

static int read_htinst(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->htinst;
    return 0;
}

static int write_htinst(CPURISCVState *env, int csrno, target_ulong val)
{
    return 0;
}

static int read_hgeip(CPURISCVState *env, int csrno, target_ulong *val)
{
    qemu_log_mask(LOG_UNIMP, "No support for a non-zero GEILEN.");
    return 0;
}

static int write_hgeip(CPURISCVState *env, int csrno, target_ulong val)
{
    qemu_log_mask(LOG_UNIMP, "No support for a non-zero GEILEN.");
    return 0;
}

static int read_hgatp(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->hgatp;
    return 0;
}

static int write_hgatp(CPURISCVState *env, int csrno, target_ulong val)
{
    env->hgatp = val;
    return 0;
}

static int read_htimedelta(CPURISCVState *env, int csrno, target_ulong *val)
{
    if (!env->rdtime_fn) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    *val = env->htimedelta;
    return 0;
}

static int write_htimedelta(CPURISCVState *env, int csrno, target_ulong val)
{
    if (!env->rdtime_fn) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    if (riscv_cpu_is_32bit(env)) {
        env->htimedelta = deposit64(env->htimedelta, 0, 32, (uint64_t)val);
    } else {
        env->htimedelta = val;
    }
    return 0;
}

static int read_htimedeltah(CPURISCVState *env, int csrno, target_ulong *val)
{
    if (!env->rdtime_fn) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    *val = env->htimedelta >> 32;
    return 0;
}

static int write_htimedeltah(CPURISCVState *env, int csrno, target_ulong val)
{
    if (!env->rdtime_fn) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    env->htimedelta = deposit64(env->htimedelta, 32, 32, (uint64_t)val);
    return 0;
}

/* Virtual CSR Registers */
static int read_vsstatus(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vsstatus;
    return 0;
}

static int write_vsstatus(CPURISCVState *env, int csrno, target_ulong val)
{
    uint64_t mask = (target_ulong)-1;
    env->vsstatus = (env->vsstatus & ~mask) | (uint64_t)val;
    return 0;
}

static int read_vstvec(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = GET_SPECIAL_REG_ARCH(env, vstvec, VSTCC);
    return 0;
}

static int write_vstvec(CPURISCVState *env, int csrno, target_ulong val)
{
    SET_SPECIAL_REG(env, vstvec, VSTCC, val);
    return 0;
}

static int read_vsscratch(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vsscratch;
    return 0;
}

static int write_vsscratch(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vsscratch = val;
    return 0;
}

static int read_vsepc(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = GET_SPECIAL_REG_ARCH(env, vsepc, VSEPCC);
    return 0;
}

static int write_vsepc(CPURISCVState *env, int csrno, target_ulong val)
{
    SET_SPECIAL_REG(env, vsepc, VSEPCC, val);
    return 0;
}

static int read_vscause(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vscause;
    return 0;
}

static int write_vscause(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vscause = val;
    return 0;
}

static int read_vstval(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vstval;
    return 0;
}

static int write_vstval(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vstval = val;
    return 0;
}

static int read_vsatp(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->vsatp;
    return 0;
}

static int write_vsatp(CPURISCVState *env, int csrno, target_ulong val)
{
    env->vsatp = val;
    return 0;
}

static int read_mtval2(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mtval2;
    return 0;
}

static int write_mtval2(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mtval2 = val;
    return 0;
}

static int read_mtinst(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = env->mtinst;
    return 0;
}

static int write_mtinst(CPURISCVState *env, int csrno, target_ulong val)
{
    env->mtinst = val;
    return 0;
}

/* Physical Memory Protection */
static int read_pmpcfg(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = pmpcfg_csr_read(env, csrno - CSR_PMPCFG0);
    return 0;
}

static int write_pmpcfg(CPURISCVState *env, int csrno, target_ulong val)
{
    pmpcfg_csr_write(env, csrno - CSR_PMPCFG0, val);
#ifdef CONFIG_TCG_LOG_INSTR
    if (qemu_log_instr_enabled(env)) {
        char buf[16];
        snprintf(buf, sizeof(buf), "pmpcfg%d", csrno - CSR_PMPCFG0);
        qemu_log_instr_reg(env, buf, val);
    }
#endif
    return 0;
}

static int read_pmpaddr(CPURISCVState *env, int csrno, target_ulong *val)
{
    *val = pmpaddr_csr_read(env, csrno - CSR_PMPADDR0);
    return 0;
}

static int write_pmpaddr(CPURISCVState *env, int csrno, target_ulong val)
{
    pmpaddr_csr_write(env, csrno - CSR_PMPADDR0, val);
#ifdef CONFIG_TCG_LOG_INSTR
    if (qemu_log_instr_enabled(env)) {
        char buf[16];
        snprintf(buf, sizeof(buf), "pmpaddr%d", csrno - CSR_PMPADDR0);
        qemu_log_instr_reg(env, buf, val);
    }
#endif
    return 0;
}

#endif

#ifdef TARGET_CHERI
static int read_ccsr(CPURISCVState *env, int csrno, target_ulong *val)
{
    // We report the same values for all modes and don't perform dirty tracking
    // The capability cause has moved to xTVAL so we don't report it here.
    RISCVCPU *cpu = env_archcpu(env);
    target_ulong ccsr = 0;
    ccsr = set_field(ccsr, XCCSR_ENABLE, cpu->cfg.ext_cheri);
    /* Read-only feature bits. */
    ccsr = set_field(ccsr, XCCSR_TAG_CLEARING, CHERI_TAG_CLEAR_ON_INVALID(env));
    ccsr = set_field(ccsr, XCCSR_NO_RELOCATION, CHERI_NO_RELOCATION(env));

#if !defined(TARGET_RISCV32)
    if (csrno == CSR_SCCSR)
        ccsr |= env->sccsr;
#endif

    qemu_log_mask(CPU_LOG_INT, "Reading xCCSR(%#x): %x\n", csrno, (int)ccsr);
    *val = ccsr;
    return 0;
}

static int write_ccsr(CPURISCVState *env, int csrno, target_ulong val)
{
    switch (csrno) {
    default:
        error_report("Attempting to write " TARGET_FMT_lx
                     "to xCCSR(%#x), this is not supported (yet?).",
                     val, csrno);
        return -1;
#if !defined(TARGET_RISCV32)
    case CSR_SCCSR: {
        static const target_ulong gclgmask = (SCCSR_SGCLG | SCCSR_UGCLG);
        /* Take the GCLG bits from the store and update state bits */
        env->sccsr = set_field(env->sccsr, gclgmask, get_field(val, gclgmask));

        /*
         * Our TLB effectively caches whether the PTE and CCSR bits match at the
         * time the PTE is copied up into the TLB.  While PTE updates use
         * SFENCE.VMA to ensure visibility in the TLB, the CCSR writes must
         * implicitly cause TLB invalidation.
         */
        tlb_flush(env_cpu(env));
        break;
      }
#endif
    }

    return 0;
}

static inline bool csr_needs_asr(CPURISCVState *env, int csrno) {
    switch (csrno) {
    case CSR_CYCLE:
    case CSR_CYCLEH:
    case CSR_TIME:
    case CSR_TIMEH:
    case CSR_INSTRET:
    case CSR_INSTRETH:
    case CSR_FFLAGS:
    case CSR_FRM:
    case CSR_FCSR:
        return false;
    default:
        break;
    }
    if (csrno >= CSR_HPMCOUNTER3 && csrno <= CSR_HPMCOUNTER31)
        return false;
    if (csrno >= CSR_HPMCOUNTER3H && csrno <= CSR_HPMCOUNTER31H)
        return false;
    // FIXME: what about MHMPCOUNTER?
    if (csrno >= CSR_MHPMCOUNTER3 && csrno <= CSR_MHPMCOUNTER31)
        return false;
    if (csrno >= CSR_MHPMCOUNTER3H && csrno <= CSR_MHPMCOUNTER31H)
        return false;
    // Assume that all others require ASR.
    return true;
}
#endif

/*
 * riscv_csrrw - read and/or update control and status register
 *
 * csrr   <->  riscv_csrrw(env, csrno, ret_value, 0, 0);
 * csrrw  <->  riscv_csrrw(env, csrno, ret_value, value, -1);
 * csrrs  <->  riscv_csrrw(env, csrno, ret_value, -1, value);
 * csrrc  <->  riscv_csrrw(env, csrno, ret_value, 0, value);
 */

int riscv_csrrw(CPURISCVState *env, int csrno, target_ulong *ret_value,
                target_ulong new_value, target_ulong write_mask, uintptr_t retpc)
{
    int ret;
    target_ulong old_value;
    RISCVCPU *cpu = env_archcpu(env);

    /* check privileges and return -1 if check fails */
#if !defined(CONFIG_USER_ONLY)
    int effective_priv = env->priv;
    int read_only = get_field(csrno, 0xC00) == 3;

    if (riscv_has_ext(env, RVH) &&
        env->priv == PRV_S &&
        !riscv_cpu_virt_enabled(env)) {
        /*
         * We are in S mode without virtualisation, therefore we are in HS Mode.
         * Add 1 to the effective privledge level to allow us to access the
         * Hypervisor CSRs.
         */
        effective_priv++;
    }

    if ((write_mask && read_only) ||
        (!env->debugger && (effective_priv < get_field(csrno, 0x300)))) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
#endif

    /* ensure the CSR extension is enabled. */
    if (!cpu->cfg.ext_icsr) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* check predicate */
    if (!csr_ops[csrno].predicate) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }
    ret = csr_ops[csrno].predicate(env, csrno);
    if (ret < 0) {
        return ret;
    }

    // When CHERI is enabled, only certain CSRs can be accessed without the
    // Access_System_Registers permission in PCC.
    // TODO: could merge this with predicate callback?
#ifdef TARGET_CHERI
    // See Table 5.2 (CSR Whitelist) in ISAv7
    if (!cheri_have_access_sysregs(env) && csr_needs_asr(env, csrno)) {
#if !defined(CONFIG_USER_ONLY)
        if (env->debugger) {
            return -1;
        }
        raise_cheri_exception_impl(env, CapEx_AccessSystemRegsViolation,
                                   /*regnum=*/0, 0, true, retpc);
#endif
    }
#endif // TARGET_CHERI

    /* execute combined read/write operation if it exists */
    if (csr_ops[csrno].op) {
        ret = csr_ops[csrno].op(env, csrno, ret_value, new_value, write_mask);
#ifdef CONFIG_TCG_LOG_INSTR
        if (ret >= 0 && csr_ops[csrno].log_update) {
            csr_ops[csrno].log_update(env, csrno, new_value);
        }
#endif
        return ret;
    }

    /* if no accessor exists then return failure */
    if (!csr_ops[csrno].read) {
        return -RISCV_EXCP_ILLEGAL_INST;
    }

    /* read old value */
    ret = csr_ops[csrno].read(env, csrno, &old_value);
    if (ret < 0) {
        return ret;
    }

    /* write value if writable and write mask set, otherwise drop writes */
    if (write_mask) {
        new_value = (old_value & ~write_mask) | (new_value & write_mask);
        if (csr_ops[csrno].write) {
            ret = csr_ops[csrno].write(env, csrno, new_value);
            if (ret < 0) {
                return ret;
            }
#ifdef CONFIG_TCG_LOG_INSTR
            if (csr_ops[csrno].log_update)
                csr_ops[csrno].log_update(env, csrno, new_value);
#endif
        }
    }

    /* return old value */
    if (ret_value) {
        *ret_value = old_value;
    }

    return 0;
}

/*
 * Debugger support.  If not in user mode, set env->debugger before the
 * riscv_csrrw call and clear it after the call.
 */
int riscv_csrrw_debug(CPURISCVState *env, int csrno, target_ulong *ret_value,
                target_ulong new_value, target_ulong write_mask)
{
    int ret;
#if !defined(CONFIG_USER_ONLY)
    env->debugger = true;
#endif
    ret = riscv_csrrw(env, csrno, ret_value, new_value, write_mask, 0);
#if !defined(CONFIG_USER_ONLY)
    env->debugger = false;
#endif
    return ret;
}


#ifdef CONFIG_TCG_LOG_INSTR
static void log_changed_csr_fn(CPURISCVState *env, int csrno,
                               target_ulong value)
{
    if (qemu_log_instr_enabled(env)) {
        qemu_log_instr_reg(env, csr_ops[csrno].name, value);
    }
}
#else
#define log_changed_csr_fn (NULL)
#endif

/* Define csr_ops entry for read-only CSR register */
#define CSR_OP_FN_R(pred, readfn, csr_name)                        \
    {.predicate=pred, .read=readfn, .write=NULL, .op=NULL,         \
     .log_update=NULL, .name=csr_name}

/* Shorthand for functions following the read_<csr> pattern */
#define CSR_OP_R(pred, name)                                    \
    CSR_OP_FN_R(pred, glue(read_, name), stringify(name))

/* Internal - use CSR_OP_FN_RW, CSR_OP_RW and CSR_OP_NOLOG_RW */
#define _CSR_OP_FN_RW(pred, readfn, writefn, logfn, csr_name)      \
    {.predicate=pred, .read=readfn, .write=writefn,                \
     .op=NULL, .log_update=logfn, .name=csr_name}

/* Define csr_ops entry for read-write CSR register */
#define CSR_OP_FN_RW(pred, readfn, writefn, name)                  \
    _CSR_OP_FN_RW(pred, readfn, writefn, log_changed_csr_fn, name)

/* Shorthand for functions following the read/write_<csr> pattern */
#define CSR_OP_RW(pred, name)                                      \
    CSR_OP_FN_RW(pred, glue(read_, name), glue(write_, name),      \
                 stringify(name))

/*
 * Shorthand for functions following the read/write_<csr> pattern,
 * with custom write logging.
 */
#define CSR_OP_NOLOG_RW(pred, name)                                \
    _CSR_OP_FN_RW(pred, glue(read_, name), glue(write_, name),     \
                  NULL, stringify(name))

/* Define csr_ops entry for read-modify-write CSR register */
#define CSR_OP_RMW(pred, csr_name)                                 \
    {.predicate=pred, .read=NULL, .write=NULL,                     \
     .op=glue(rmw_, csr_name), .log_update=log_changed_csr_fn,     \
     .name=stringify(csr_name)}

/* Control and Status Register function table */
riscv_csr_operations csr_ops[CSR_TABLE_SIZE] = {
    /* User Floating-Point CSRs */
    [CSR_FFLAGS] =              CSR_OP_RW(fs, fflags),
    [CSR_FRM] =                 CSR_OP_RW(fs, frm),
    [CSR_FCSR] =                CSR_OP_RW(fs, fcsr),

    /* Vector CSRs */
    [CSR_VSTART] =              CSR_OP_RW(vs, vstart),
    [CSR_VXSAT] =               CSR_OP_RW(vs, vxsat),
    [CSR_VXRM] =                CSR_OP_RW(vs, vxrm),
    [CSR_VL] =                  CSR_OP_R(vs, vl),
    [CSR_VTYPE] =               CSR_OP_R(vs, vtype),
    /* User Timers and Counters */
    [CSR_CYCLE] =               CSR_OP_FN_R(ctr, read_instret, "cycle"),
    [CSR_INSTRET] =             CSR_OP_FN_R(ctr, read_instret, "instret"),
    [CSR_CYCLEH] =              CSR_OP_FN_R(ctr32, read_instreth, "cycleh"),
    [CSR_INSTRETH] =            CSR_OP_FN_R(ctr32, read_instreth, "instreth"),

    /*
     * In privileged mode, the monitor will have to emulate TIME CSRs only if
     * rdtime callback is not provided by machine/platform emulation.
     */
    [CSR_TIME] =                CSR_OP_R(ctr, time),
    [CSR_TIMEH] =               CSR_OP_R(ctr32, timeh),

#if !defined(CONFIG_USER_ONLY)
    /* Machine Timers and Counters */
    [CSR_MCYCLE] =              CSR_OP_FN_R(any, read_instret, "mcycle"),
    [CSR_MINSTRET] =            CSR_OP_FN_R(any, read_instret, "minstret"),
    [CSR_MCYCLEH] =             CSR_OP_FN_R(any32, read_instreth, "mcycleh"),
    [CSR_MINSTRETH] =           CSR_OP_FN_R(any32, read_instreth, "minstreth"),

    /* Machine Information Registers */
    [CSR_MVENDORID] =           CSR_OP_FN_R(any, read_zero, "mvendorid"),
    [CSR_MARCHID] =             CSR_OP_FN_R(any, read_zero, "marchid"),
    [CSR_MIMPID] =              CSR_OP_FN_R(any, read_zero, "mimppid"),
    [CSR_MHARTID] =             CSR_OP_R(any, mhartid),

    /* Machine Trap Setup */
    [CSR_MSTATUS] =             CSR_OP_RW(any, mstatus),
    [CSR_MISA] =                CSR_OP_RW(any, misa),
    [CSR_MIDELEG] =             CSR_OP_RW(any, mideleg),
    [CSR_MEDELEG] =             CSR_OP_RW(any, medeleg),
    [CSR_MIE] =                 CSR_OP_RW(any, mie),
    [CSR_MTVEC] =               CSR_OP_RW(any, mtvec),
    [CSR_MCOUNTEREN] =          CSR_OP_RW(any, mcounteren),

    [CSR_MSTATUSH] =            CSR_OP_RW(any32, mstatush),

    [CSR_MSCOUNTEREN] =         CSR_OP_RW(any, mscounteren),

    /* Machine Trap Handling */
    [CSR_MSCRATCH] =            CSR_OP_RW(any, mscratch),
    [CSR_MEPC] =                CSR_OP_RW(any, mepc),
    [CSR_MCAUSE] =              CSR_OP_RW(any, mcause),
    [CSR_MBADADDR] =            CSR_OP_RW(any, mbadaddr),
    [CSR_MIP] =                 CSR_OP_RMW(any, mip),

    /* Supervisor Trap Setup */
    [CSR_SSTATUS] =             CSR_OP_RW(smode, sstatus),
    [CSR_SIE] =                 CSR_OP_RW(smode, sie),
    [CSR_STVEC] =               CSR_OP_RW(smode, stvec),
    [CSR_SCOUNTEREN] =          CSR_OP_RW(smode, scounteren),

    /* Supervisor Trap Handling */
    [CSR_SSCRATCH] =            CSR_OP_RW(smode, sscratch),
    [CSR_SEPC] =                CSR_OP_RW(smode, sepc),
    [CSR_SCAUSE] =              CSR_OP_RW(smode, scause),
    [CSR_SBADADDR] =            CSR_OP_RW(smode, sbadaddr),
    [CSR_SIP] =                 CSR_OP_RMW(smode, sip),

    /* Supervisor Protection and Translation */
    [CSR_SATP] =                CSR_OP_RW(smode, satp),

    [CSR_HSTATUS] =             CSR_OP_RW(hmode, hstatus),
    [CSR_HEDELEG] =             CSR_OP_RW(hmode, hedeleg),
    [CSR_HIDELEG] =             CSR_OP_RW(hmode, hideleg),
    [CSR_HVIP] =                CSR_OP_RMW(hmode, hvip),
    [CSR_HIP] =                 CSR_OP_RMW(hmode, hip),
    [CSR_HIE] =                 CSR_OP_RW(hmode, hie),
    [CSR_HCOUNTEREN] =          CSR_OP_RW(hmode, hcounteren),
    [CSR_HGEIE] =               CSR_OP_RW(hmode, hgeie),
    [CSR_HTVAL] =               CSR_OP_RW(hmode, htval),
    [CSR_HTINST] =              CSR_OP_RW(hmode, htinst),
    [CSR_HGEIP] =               CSR_OP_RW(hmode, hgeip),
    [CSR_HGATP] =               CSR_OP_RW(hmode, hgatp),
    [CSR_HTIMEDELTA] =          CSR_OP_RW(hmode, htimedelta),
    [CSR_HTIMEDELTAH] =         CSR_OP_RW(hmode32, htimedeltah),

    [CSR_VSSTATUS] =            CSR_OP_RW(hmode, vsstatus),
    [CSR_VSIP] =                CSR_OP_RMW(hmode, vsip),
    [CSR_VSIE] =                CSR_OP_RW(hmode, vsie),
    [CSR_VSTVEC] =              CSR_OP_RW(hmode, vstvec),
    [CSR_VSSCRATCH] =           CSR_OP_RW(hmode, vsscratch),
    [CSR_VSEPC] =               CSR_OP_RW(hmode, vsepc),
    [CSR_VSCAUSE] =             CSR_OP_RW(hmode, vscause),
    [CSR_VSTVAL] =              CSR_OP_RW(hmode, vstval),
    [CSR_VSATP] =               CSR_OP_RW(hmode, vsatp),

    [CSR_MTVAL2] =              CSR_OP_RW(hmode, mtval2),
    [CSR_MTINST] =              CSR_OP_RW(hmode, mtinst),

#ifdef TARGET_CHERI
    // CHERI CSRs: For now we always report enabled and dirty and don't support
    // turning off CHERI.  sccsr contains global capability load generation bits
    // that can be written, but the other two are constant.
    [CSR_UCCSR] =               CSR_OP_FN_RW(umode, read_ccsr, write_ccsr, "uccsr"),
    [CSR_SCCSR] =               CSR_OP_FN_RW(smode, read_ccsr, write_ccsr, "sccsr"),
    [CSR_MCCSR] =               CSR_OP_FN_RW(any, read_ccsr, write_ccsr, "mccsr"),
#endif

    /* Physical Memory Protection */
    [CSR_PMPCFG0  ... CSR_PMPCFG3] =  CSR_OP_NOLOG_RW(pmp, pmpcfg),
    [CSR_PMPADDR0 ... CSR_PMPADDR15] = CSR_OP_NOLOG_RW(pmp, pmpaddr),

    /* Performance Counters */
    [CSR_HPMCOUNTER3   ... CSR_HPMCOUNTER31] =    CSR_OP_FN_R(ctr, read_zero, "hpmcounterN"),
    [CSR_MHPMCOUNTER3  ... CSR_MHPMCOUNTER31] =   CSR_OP_FN_R(any, read_zero, "mhpmcounterN"),
    [CSR_MHPMEVENT3    ... CSR_MHPMEVENT31] =     CSR_OP_FN_R(any, read_zero, "mhpmeventN"),
    [CSR_HPMCOUNTER3H  ... CSR_HPMCOUNTER31H] =   CSR_OP_FN_R(ctr32, read_zero, "hpmcounterNh"),
    [CSR_MHPMCOUNTER3H ... CSR_MHPMCOUNTER31H] =  CSR_OP_FN_R(any32, read_zero, "mhpmcounterNh"),
#endif /* !CONFIG_USER_ONLY */
};
