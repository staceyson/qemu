/*
 * MIPS internal definitions and helpers
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef MIPS_INTERNAL_H
#define MIPS_INTERNAL_H

#include "exec/memattrs.h"
#include "qemu/log.h"
#include "exec/log_instr.h"

/*
 * MMU types, the first four entries have the same layout as the
 * CP0C0_MT field.
 */
enum mips_mmu_types {
    MMU_TYPE_NONE       = 0,
    MMU_TYPE_R4000      = 1,    /* Standard TLB */
    MMU_TYPE_BAT        = 2,    /* Block Address Translation */
    MMU_TYPE_FMT        = 3,    /* Fixed Mapping */
    MMU_TYPE_DVF        = 4,    /* Dual VTLB and FTLB */
    MMU_TYPE_R3000,
    MMU_TYPE_R6000,
    MMU_TYPE_R8000
};

struct mips_def_t {
    const char *name;
    int32_t CP0_PRid;
    int32_t CP0_Config0;
    int32_t CP0_Config1;
    int32_t CP0_Config2;
    int32_t CP0_Config3;
    int32_t CP0_Config4;
    int32_t CP0_Config4_rw_bitmask;
    int32_t CP0_Config5;
    int32_t CP0_Config5_rw_bitmask;
    int32_t CP0_Config6;
    int32_t CP0_Config6_rw_bitmask;
    int32_t CP0_Config7;
    int32_t CP0_Config7_rw_bitmask;
    target_ulong CP0_LLAddr_rw_bitmask;
    int CP0_LLAddr_shift;
    int32_t SYNCI_Step;
    int32_t CCRes;
    int32_t CP0_Status_rw_bitmask;
    int32_t CP0_TCStatus_rw_bitmask;
    int32_t CP0_SRSCtl;
    int32_t CP1_fcr0;
    int32_t CP1_fcr31_rw_bitmask;
    int32_t CP1_fcr31;
    int32_t MSAIR;
    int32_t SEGBITS;
    int32_t PABITS;
    int32_t CP0_SRSConf0_rw_bitmask;
    int32_t CP0_SRSConf0;
    int32_t CP0_SRSConf1_rw_bitmask;
    int32_t CP0_SRSConf1;
    int32_t CP0_SRSConf2_rw_bitmask;
    int32_t CP0_SRSConf2;
    int32_t CP0_SRSConf3_rw_bitmask;
    int32_t CP0_SRSConf3;
    int32_t CP0_SRSConf4_rw_bitmask;
    int32_t CP0_SRSConf4;
    int32_t CP0_PageGrain_rw_bitmask;
    int32_t CP0_PageGrain;
    target_ulong CP0_EBaseWG_rw_bitmask;
    uint64_t insn_flags;
    enum mips_mmu_types mmu_type;
    int32_t SAARP;
};

extern const struct mips_def_t mips_defs[];
extern const int mips_defs_number;

#ifdef TARGET_CHERI
#include "cheri_utils.h"

int mips_gdb_get_cheri_reg(CPUMIPSState *env, GByteArray *buf, int n);
int mips_gdb_set_cheri_reg(CPUMIPSState *env, uint8_t *mem_buf, int n);
#endif
int mips_gdb_get_sys_reg(CPUMIPSState *env, GByteArray *buf, int n);
int mips_gdb_set_sys_reg(CPUMIPSState *env, uint8_t *mem_buf, int n);

void mips_cpu_do_interrupt(CPUState *cpu);
bool mips_cpu_exec_interrupt(CPUState *cpu, int int_req);
void mips_cpu_dump_state(CPUState *cpu, FILE *f, int flags);
hwaddr mips_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
int mips_cpu_gdb_read_register(CPUState *cpu, GByteArray *buf, int reg);
int mips_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);
void mips_cpu_do_unaligned_access(CPUState *cpu, vaddr addr,
                                  MMUAccessType access_type,
                                  int mmu_idx, uintptr_t retaddr);

#if !defined(CONFIG_USER_ONLY)

typedef struct r4k_tlb_t r4k_tlb_t;
struct r4k_tlb_t {
    target_ulong VPN;
    uint32_t PageMask;
    uint16_t ASID;
    uint32_t MMID;
    unsigned int G:1;
    unsigned int C0:3;
    unsigned int C1:3;
    unsigned int V0:1;
    unsigned int V1:1;
    unsigned int D0:1;
    unsigned int D1:1;
#if defined(TARGET_CHERI)
    unsigned int L0:1;
    unsigned int L1:1;
    unsigned int S0:1;
    unsigned int S1:1;
    unsigned int CLG0:1;
    unsigned int CLG1:1;
#else
    unsigned int XI0:1;
    unsigned int XI1:1;
    unsigned int RI0:1;
    unsigned int RI1:1;
#endif /* TARGET_CHERI */
    unsigned int EHINV:1;
    uint64_t PFN[2];
};

struct CPUMIPSTLBContext {
    uint32_t nb_tlb;
    uint32_t tlb_in_use;
    int (*map_address)(struct CPUMIPSState *env, hwaddr *physical, int *prot,
                       target_ulong address, MMUAccessType access_type);
    void (*helper_tlbwi)(struct CPUMIPSState *env, uintptr_t retpc);
    void (*helper_tlbwr)(struct CPUMIPSState *env, uintptr_t retpc);
    void (*helper_tlbp)(struct CPUMIPSState *env);
    void (*helper_tlbr)(struct CPUMIPSState *env);
    void (*helper_tlbinv)(struct CPUMIPSState *env);
    void (*helper_tlbinvf)(struct CPUMIPSState *env);
    union {
        struct {
            r4k_tlb_t tlb[MIPS_TLB_MAX];
        } r4k;
    } mmu;
};

int no_mmu_map_address(CPUMIPSState *env, hwaddr *physical, int *prot,
                       target_ulong address, MMUAccessType access_type);
int fixed_mmu_map_address(CPUMIPSState *env, hwaddr *physical, int *prot,
                          target_ulong address, MMUAccessType access_type);
int r4k_map_address(CPUMIPSState *env, hwaddr *physical, int *prot,
                    target_ulong address, MMUAccessType access_type);
void r4k_helper_tlbwi(CPUMIPSState *env, uintptr_t retpc);
void r4k_helper_tlbwr(CPUMIPSState *env, uintptr_t retpc);
void r4k_helper_tlbp(CPUMIPSState *env);
void r4k_helper_tlbr(CPUMIPSState *env);
void r4k_helper_tlbinv(CPUMIPSState *env);
void r4k_helper_tlbinvf(CPUMIPSState *env);
void r4k_invalidate_tlb(CPUMIPSState *env, int idx, int use_extra);
bool r4k_lookup_tlb(CPUMIPSState *env, int *matching, bool use_extra);
uint32_t cpu_mips_get_random(CPUMIPSState *env);

void mips_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr,
                                    vaddr addr, unsigned size,
                                    MMUAccessType access_type,
                                    int mmu_idx, MemTxAttrs attrs,
                                    MemTxResult response, uintptr_t retaddr);
hwaddr cpu_mips_translate_address(CPUMIPSState *env, target_ulong address,
                                  MMUAccessType access_type);
#endif

#define cpu_signal_handler cpu_mips_signal_handler

#ifndef CONFIG_USER_ONLY
extern const VMStateDescription vmstate_mips_cpu;
#endif

static inline bool cpu_mips_hw_interrupts_enabled(CPUMIPSState *env)
{
    return (env->CP0_Status & (1 << CP0St_IE)) &&
        !(env->CP0_Status & (1 << CP0St_EXL)) &&
        !(env->CP0_Status & (1 << CP0St_ERL)) &&
        !(env->hflags & MIPS_HFLAG_DM) &&
        /*
         * Note that the TCStatus IXMT field is initialized to zero,
         * and only MT capable cores can set it to one. So we don't
         * need to check for MT capabilities here.
         */
        !(env->active_tc.CP0_TCStatus & (1 << CP0TCSt_IXMT));
}

/* Check if there is pending and not masked out interrupt */
static inline bool cpu_mips_hw_interrupts_pending(CPUMIPSState *env)
{
    int32_t pending;
    int32_t status;
    bool r;

    pending = env->CP0_Cause & CP0Ca_IP_mask;
    status = env->CP0_Status & CP0Ca_IP_mask;

    if (env->CP0_Config3 & (1 << CP0C3_VEIC)) {
        /*
         * A MIPS configured with a vectorizing external interrupt controller
         * will feed a vector into the Cause pending lines. The core treats
         * the status lines as a vector level, not as individual masks.
         */
        r = pending > status;
    } else {
        /*
         * A MIPS configured with compatibility or VInt (Vectored Interrupts)
         * treats the pending lines as individual interrupt lines, the status
         * lines are individual masks.
         */
        r = (pending & status) != 0;
    }
    return r;
}

void mips_tcg_init(void);

void msa_reset(CPUMIPSState *env);

/* cp0_timer.c */
uint32_t cpu_mips_get_count(CPUMIPSState *env);
void cpu_mips_store_count(CPUMIPSState *env, uint32_t value);
void cpu_mips_store_compare(CPUMIPSState *env, uint32_t value);
void cpu_mips_start_count(CPUMIPSState *env);
void cpu_mips_stop_count(CPUMIPSState *env);

uint64_t cpu_mips_get_rtc64 (CPUMIPSState *env);
void cpu_mips_set_rtc64 (CPUMIPSState *env, uint64_t value);

/* helper.c */
void mmu_init(CPUMIPSState *env, const mips_def_t *def);
bool mips_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr);

/* op_helper.c */
void update_pagemask(CPUMIPSState *env, target_ulong arg1, int32_t *pagemask);

static inline void restore_pamask(CPUMIPSState *env)
{
    if (env->hflags & MIPS_HFLAG_ELPA) {
        env->PAMask = (1ULL << env->PABITS) - 1;
    } else {
        env->PAMask = PAMASK_BASE;
    }
}

static inline int mips_vpe_active(CPUMIPSState *env)
{
    int active = 1;

    /* Check that the VPE is enabled.  */
    if (!(env->mvp->CP0_MVPControl & (1 << CP0MVPCo_EVP))) {
        active = 0;
    }
    /* Check that the VPE is activated.  */
    if (!(env->CP0_VPEConf0 & (1 << CP0VPEC0_VPA))) {
        active = 0;
    }

    /*
     * Now verify that there are active thread contexts in the VPE.
     *
     * This assumes the CPU model will internally reschedule threads
     * if the active one goes to sleep. If there are no threads available
     * the active one will be in a sleeping state, and we can turn off
     * the entire VPE.
     */
    if (!(env->active_tc.CP0_TCStatus & (1 << CP0TCSt_A))) {
        /* TC is not activated.  */
        active = 0;
    }
    if (env->active_tc.CP0_TCHalt & 1) {
        /* TC is in halt state.  */
        active = 0;
    }

    return active;
}

static inline int mips_vp_active(CPUMIPSState *env)
{
    CPUState *other_cs = first_cpu;

    /* Check if the VP disabled other VPs (which means the VP is enabled) */
    if ((env->CP0_VPControl >> CP0VPCtl_DIS) & 1) {
        return 1;
    }

    /* Check if the virtual processor is disabled due to a DVP */
    CPU_FOREACH(other_cs) {
        MIPSCPU *other_cpu = MIPS_CPU(other_cs);
        if ((&other_cpu->env != env) &&
            ((other_cpu->env.CP0_VPControl >> CP0VPCtl_DIS) & 1)) {
            return 0;
        }
    }
    return 1;
}

static inline bool cheri_have_access_sysregs(CPUArchState *env);

static inline bool can_access_cp0(CPUMIPSState* env) {
    if (((env->CP0_Status & (1 << CP0St_CU0)) &&
        !(env->insn_flags & ISA_MIPS_R6)) ||
        !(env->hflags & MIPS_HFLAG_KSU)) {
#ifdef TARGET_CHERI
        // For CHERI we need to check PCC.perms before enabling access to cp0 features.
        // XXX: can't use cheri_have_access_sysregs() here due to cyclic deps
        if (!cheri_have_access_sysregs(env)) {
            /* qemu_log_mask(CPU_LOG_INSTR, "Kernel mode but no ASR!\n"); */
            return false;
        }
#endif
        return true; // plain MIPS can always access system registers.
    }
    return false;
}

static inline void update_cp0_access_for_pc(CPUMIPSState* env) {
    if (can_access_cp0(env)) {
        if ((env->hflags & MIPS_HFLAG_CP0) == 0) {
            qemu_maybe_log_instr_extra(env, "%s: restoring access to CP0 since "
                "$pcc has ASR permission\n", __func__);
            env->hflags |= MIPS_HFLAG_CP0;
        }
    } else {
        if ((env->hflags & MIPS_HFLAG_CP0)) {
            qemu_maybe_log_instr_extra(env, "%s: removing access to CP0 since "
                "$pcc does not have ASR permission\n", __func__);
            env->hflags &= ~MIPS_HFLAG_CP0;
        }
    }
}

static inline void compute_hflags(CPUMIPSState *env)
{
    env->hflags &= ~(MIPS_HFLAG_COP1X | MIPS_HFLAG_64 | MIPS_HFLAG_CP0 |
                     MIPS_HFLAG_F64 | MIPS_HFLAG_FPU | MIPS_HFLAG_KSU |
                     MIPS_HFLAG_AWRAP | MIPS_HFLAG_DSP | MIPS_HFLAG_DSP_R2 |
                     MIPS_HFLAG_DSP_R3 | MIPS_HFLAG_SBRI | MIPS_HFLAG_MSA |
                     MIPS_HFLAG_FRE | MIPS_HFLAG_ELPA |
#ifdef TARGET_CHERI
                     MIPS_HFLAG_COP2X |
#endif /* TARGET_CHERI */
                     MIPS_HFLAG_ERL);
    if (env->CP0_Status & (1 << CP0St_ERL)) {
        env->hflags |= MIPS_HFLAG_ERL;
    }
    if (!(env->CP0_Status & (1 << CP0St_EXL)) &&
        !(env->CP0_Status & (1 << CP0St_ERL)) &&
        !(env->hflags & MIPS_HFLAG_DM)) {
        env->hflags |= (env->CP0_Status >> CP0St_KSU) &
                       MIPS_HFLAG_KSU;
    }
#if defined(TARGET_MIPS64)
    if ((env->insn_flags & ISA_MIPS3) &&
        (((env->hflags & MIPS_HFLAG_KSU) != MIPS_HFLAG_UM) ||
         (env->CP0_Status & (1 << CP0St_PX)) ||
         (env->CP0_Status & (1 << CP0St_UX)))) {
        env->hflags |= MIPS_HFLAG_64;
    }

    if (!(env->insn_flags & ISA_MIPS3)) {
        env->hflags |= MIPS_HFLAG_AWRAP;
    } else if (((env->hflags & MIPS_HFLAG_KSU) == MIPS_HFLAG_UM) &&
               !(env->CP0_Status & (1 << CP0St_UX))) {
        env->hflags |= MIPS_HFLAG_AWRAP;
    } else if (env->insn_flags & ISA_MIPS_R6) {
        /* Address wrapping for Supervisor and Kernel is specified in R6 */
        if ((((env->hflags & MIPS_HFLAG_KSU) == MIPS_HFLAG_SM) &&
             !(env->CP0_Status & (1 << CP0St_SX))) ||
            (((env->hflags & MIPS_HFLAG_KSU) == MIPS_HFLAG_KM) &&
             !(env->CP0_Status & (1 << CP0St_KX)))) {
            env->hflags |= MIPS_HFLAG_AWRAP;
        }
    }
#endif
    if (can_access_cp0(env)) {
        env->hflags |= MIPS_HFLAG_CP0;
    }
    if (env->CP0_Status & (1 << CP0St_CU1)) {
        env->hflags |= MIPS_HFLAG_FPU;
    }
    if (env->CP0_Status & (1 << CP0St_FR)) {
        env->hflags |= MIPS_HFLAG_F64;
    }
#ifdef TARGET_CHERI
    if (env->CP0_Status & (1 << CP0St_CU2)) {
        env->hflags |= MIPS_HFLAG_COP2X;
    }
#endif /* TARGET_CHERI */
    if (((env->hflags & MIPS_HFLAG_KSU) != MIPS_HFLAG_KM) &&
        (env->CP0_Config5 & (1 << CP0C5_SBRI))) {
        env->hflags |= MIPS_HFLAG_SBRI;
    }
    if (env->insn_flags & ASE_DSP_R3) {
        /*
         * Our cpu supports DSP R3 ASE, so enable
         * access to DSP R3 resources.
         */
        if (env->CP0_Status & (1 << CP0St_MX)) {
            env->hflags |= MIPS_HFLAG_DSP | MIPS_HFLAG_DSP_R2 |
                           MIPS_HFLAG_DSP_R3;
        }
    } else if (env->insn_flags & ASE_DSP_R2) {
        /*
         * Our cpu supports DSP R2 ASE, so enable
         * access to DSP R2 resources.
         */
        if (env->CP0_Status & (1 << CP0St_MX)) {
            env->hflags |= MIPS_HFLAG_DSP | MIPS_HFLAG_DSP_R2;
        }

    } else if (env->insn_flags & ASE_DSP) {
        /*
         * Our cpu supports DSP ASE, so enable
         * access to DSP resources.
         */
        if (env->CP0_Status & (1 << CP0St_MX)) {
            env->hflags |= MIPS_HFLAG_DSP;
        }

    }
    if (env->insn_flags & ISA_MIPS_R2) {
#ifdef TARGET_CHERI
        /* COP1X enables CP1X instructions such as MADD.S, and is
           orthogonal to whether the FPU is in 64-bit mode. In MIPS32,
           the COP1Xto whether the FPU is in 64-bit mode. In MIPS32, the
           COP1X instructions are always available when the FPU is
           enabled. */
        env->hflags |= MIPS_HFLAG_COP1X;
#else /* ! TARGET_CHERI */
        if (env->active_fpu.fcr0 & (1 << FCR0_F64)) {
            env->hflags |= MIPS_HFLAG_COP1X;
        }
#endif /* ! TARGET_CHERI */
    } else if (env->insn_flags & ISA_MIPS_R1) {
        if (env->hflags & MIPS_HFLAG_64) {
            env->hflags |= MIPS_HFLAG_COP1X;
        }
    } else if (env->insn_flags & ISA_MIPS4) {
        /*
         * All supported MIPS IV CPUs use the XX (CU3) to enable
         * and disable the MIPS IV extensions to the MIPS III ISA.
         * Some other MIPS IV CPUs ignore the bit, so the check here
         * would be too restrictive for them.
         */
        if (env->CP0_Status & (1U << CP0St_CU3)) {
            env->hflags |= MIPS_HFLAG_COP1X;
        }
    }
    if (ase_msa_available(env)) {
        if (env->CP0_Config5 & (1 << CP0C5_MSAEn)) {
            env->hflags |= MIPS_HFLAG_MSA;
        }
    }
    if (env->active_fpu.fcr0 & (1 << FCR0_FREP)) {
        if (env->CP0_Config5 & (1 << CP0C5_FRE)) {
            env->hflags |= MIPS_HFLAG_FRE;
        }
    }
    if (env->CP0_Config3 & (1 << CP0C3_LPA)) {
        if (env->CP0_PageGrain & (1 << CP0PG_ELPA)) {
            env->hflags |= MIPS_HFLAG_ELPA;
        }
    }
}

void cpu_mips_tlb_flush(CPUMIPSState *env);
void sync_c0_status(CPUMIPSState *env, CPUMIPSState *cpu, int tc);
void cpu_mips_store_status(CPUMIPSState *env, target_ulong val);
void cpu_mips_store_cause(CPUMIPSState *env, target_ulong val);

const char *mips_exception_name(int32_t exception);

void QEMU_NORETURN do_raise_exception_err(CPUMIPSState *env, MipsExcp exception,
                                          int error_code, uintptr_t pc);

static inline void QEMU_NORETURN do_raise_exception(CPUMIPSState *env,
                                                    MipsExcp exception,
                                                    uintptr_t pc)
{
    /* NOTE: pc is a HOST program counter (from GETPC()) and not a MIPS guest pc */
    do_raise_exception_err(env, exception, env->error_code & EXCP_INST_NOTAVAIL, pc);
}

static inline void check_hwrena(CPUMIPSState *env, int reg, uintptr_t pc) {
    if ((env->hflags & MIPS_HFLAG_CP0) || (env->CP0_HWREna & (1 << reg))) {
        return;
    }
    do_raise_exception(env, EXCP_RI, pc);
}

#ifdef TARGET_CHERI
static inline void cpu_mips_store_capcause(CPUMIPSState *env, uint16_t reg_num,
        uint16_t exc_code)
{

    env->CP2_CapCause =
        (exc_code << 8) | (env->capcause_reg_already_set ? env->reg_if_exception
                                                         : (reg_num & 0xff));
    env->capcause_reg_already_set = false;
}

static inline void cpu_mips_store_capcause_reg(CPUMIPSState *env,
                                               uint16_t reg_num)
{
    env->reg_if_exception = reg_num & 0xff;
    env->capcause_reg_already_set = true;
}

static inline void cpu_mips_clear_capcause_reg(CPUMIPSState *env)
{
    env->capcause_reg_already_set = false;
}

static inline QEMU_NORETURN void do_raise_c0_exception_impl(CPUMIPSState *env,
        uint16_t cause, uint64_t badvaddr, uintptr_t pc)
{
    env->CP0_BadVAddr = badvaddr;
    do_raise_exception(env, cause, pc);
}

void cheri_dump_state(CPUState *cs, FILE *f, fprintf_function cpu_fprintf, int flags);

#define do_raise_c2_exception(env, cause, reg) \
  do_raise_c2_exception_impl(env, cause, reg, _host_return_address)
#define do_raise_c0_exception(env, cause, reg) \
  do_raise_c0_exception_impl(env, cause, reg, _host_return_address)

#endif /* TARGET_CHERI */

static inline target_ulong get_CP0_EPC(CPUMIPSState *env)
{
#ifdef TARGET_CHERI
    return (uint64_t)cap_get_offset(&env->active_tc.CHWR.EPCC);
#else
    return env->CP0_EPC;
#endif
}

static inline target_ulong get_CP0_ErrorEPC(CPUMIPSState *env)
{
#ifdef TARGET_CHERI
    return (uint64_t)cap_get_offset(&env->active_tc.CHWR.ErrorEPCC);
#else
    return env->CP0_ErrorEPC;
#endif
}

void set_CP0_EPC(CPUMIPSState *env, target_ulong value);
void set_CP0_ErrorEPC(CPUMIPSState *env, target_ulong value);
#ifdef CONFIG_TCG_LOG_INSTR
void r4k_dump_tlb(CPUMIPSState *env, int idx);
#endif
void do_hexdump(GString *strbuf, uint8_t* buffer, target_ulong length,
                target_ulong vaddr);
hwaddr do_translate_address(CPUMIPSState *env, target_ulong address,
                            MMUAccessType access_type, uintptr_t retaddr);

#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

#endif
