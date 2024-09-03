/*
 * QEMU RISC-V CPU
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
#include "qemu/qemu-print.h"
#include "qemu/ctype.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "exec/exec-all.h"
#include "exec/log_instr.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu-common.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "fpu/softfloat-helpers.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h"
#include "disas/disas.h"
#include "monitor/monitor.h"

#include "rvfi_dii.h"
#include "helper_utils.h"

#ifdef TARGET_CHERI
#include "cheri-lazy-capregs.h"
#endif

/* RISC-V CPU definitions */

static const char riscv_exts[26] = "IEMAFDQCLBJTPVNSUHKORWXYZG";

const char * const riscv_int_regnames[] = {
  "x0/zero", "x1/ra",  "x2/sp",  "x3/gp",  "x4/tp",  "x5/t0",   "x6/t1",
  "x7/t2",   "x8/s0",  "x9/s1",  "x10/a0", "x11/a1", "x12/a2",  "x13/a3",
  "x14/a4",  "x15/a5", "x16/a6", "x17/a7", "x18/s2", "x19/s3",  "x20/s4",
  "x21/s5",  "x22/s6", "x23/s7", "x24/s8", "x25/s9", "x26/s10", "x27/s11",
  "x28/t3",  "x29/t4", "x30/t5", "x31/t6"
};

const char * const cheri_gp_regnames[32] = {
    "c0/cnull", "c1/cra",  "c2/csp",  "c3/cgp",  "c4/ctp",  "c5/ct0",   "c6/ct1",
    "c7/ct2",   "c8/cs0",  "c9/cs1",  "c10/ca0", "c11/ca1", "c12/ca2",  "c13/ca3",
    "c14/ca4",  "c15/ca5", "c16/ca6", "c17/ca7", "c18/cs2", "c19/cs3",  "c20/cs4",
    "c21/cs5",  "c22/cs6", "c23/cs7", "c24/cs8", "c25/cs9", "c26/cs10", "c27/cs11",
    "c28/ct3",  "c29/ct4", "c30/ct5", "c31/ct6"
};

const char * const riscv_fpr_regnames[] = {
  "f0/ft0",   "f1/ft1",  "f2/ft2",   "f3/ft3",   "f4/ft4",  "f5/ft5",
  "f6/ft6",   "f7/ft7",  "f8/fs0",   "f9/fs1",   "f10/fa0", "f11/fa1",
  "f12/fa2",  "f13/fa3", "f14/fa4",  "f15/fa5",  "f16/fa6", "f17/fa7",
  "f18/fs2",  "f19/fs3", "f20/fs4",  "f21/fs5",  "f22/fs6", "f23/fs7",
  "f24/fs8",  "f25/fs9", "f26/fs10", "f27/fs11", "f28/ft8", "f29/ft9",
  "f30/ft10", "f31/ft11"
};

// See Table 3.6 In privileged ISA spec (20190608-Priv-MSU-Ratified)
const char * const riscv_excp_names[] = {
    "misaligned_fetch",
    "fault_fetch",
    "illegal_instruction",
    "breakpoint",
    "misaligned_load",
    "fault_load",
    "misaligned_store",
    "fault_store",
    "user_ecall",
    "supervisor_ecall",
    "hypervisor_ecall",
    "machine_ecall",
    "exec_page_fault",
    "load_page_fault",
    "reserved",         // 14 Reserved for future standard use
    "store_page_fault",
    // 16–23 Reserved for future standard use
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "guest_exec_page_fault",
    "guest_load_page_fault",
    "reserved",
    "guest_store_page_fault",
    // 24-31 Reserved for custom use
#ifdef TARGET_CHERI
#ifndef TARGET_RISCV32
    [RISCV_EXCP_LOAD_CAP_PAGE_FAULT] = "load_cap_page_fault",
    [RISCV_EXCP_STORE_AMO_CAP_PAGE_FAULT] = "store_cap_page_fault",
#endif
    [RISCV_EXCP_CHERI] = "cheri_fault"
#endif
    // 32–47 Reserved for future standard use
    // 48-63 Reserved for custom use
    // >64 Reserved for future standard use
};

const char * const riscv_intr_names[] = {
    "u_software",
    "s_software",
    "vs_software",
    "m_software",
    "u_timer",
    "s_timer",
    "vs_timer",
    "m_timer",
    "u_external",
    "vs_external",
    "h_external",
    "m_external",
    "reserved",
    "reserved",
    "reserved",
    "reserved"
};

#ifdef CONFIG_TCG_LOG_INSTR
const char * const riscv_cpu_mode_names[QEMU_LOG_INSTR_CPU_MODE_MAX] = {
    "User", "Supervisor", "Hypervisor", "<invalid>", "Machine",
};
#endif

const char *riscv_cpu_get_trap_name(target_ulong cause, bool async)
{
    if (async) {
        return (cause < ARRAY_SIZE(riscv_intr_names)) ?
               riscv_intr_names[cause] : "(unknown)";
    } else {
        // Not all entries are filled, need to check for NULL
        const char *ret = (cause < ARRAY_SIZE(riscv_excp_names))
                              ? riscv_excp_names[cause] : "(unknown)";
        return ret ? ret : "(unknown)";
    }
}

bool riscv_cpu_is_32bit(CPURISCVState *env)
{
    if (env->misa & RV64) {
        return false;
    }

    return true;
}

static void set_misa(CPURISCVState *env, target_ulong misa)
{
    env->misa_mask = env->misa = misa;
}

static void set_priv_version(CPURISCVState *env, int priv_ver)
{
    env->priv_ver = priv_ver;
}

static void set_vext_version(CPURISCVState *env, int vext_ver)
{
    env->vext_ver = vext_ver;
}

static void set_feature(CPURISCVState *env, int feature)
{
    env->features |= (1ULL << feature);
}

static void set_resetvec(CPURISCVState *env, int resetvec)
{
#ifndef CONFIG_USER_ONLY
    env->resetvec = resetvec;
#endif
}

static void riscv_any_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RVXLEN | RVI | RVM | RVA | RVF | RVD | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_11_0);
}

#if defined(TARGET_RISCV64)
static void rv64_base_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    /* We set this in the realise function */
    set_misa(env, RV64);
}

static void rv64_sifive_u_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
}

static void rv64_sifive_e_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    qdev_prop_set_bit(DEVICE(obj), "mmu", false);
}
#else
static void rv32_base_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    /* We set this in the realise function */
    set_misa(env, RV32);
}

static void rv32_sifive_u_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
}

static void rv32_sifive_e_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    qdev_prop_set_bit(DEVICE(obj), "mmu", false);
}

static void rv32_ibex_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    qdev_prop_set_bit(DEVICE(obj), "mmu", false);
}

static void rv32_imafcu_nommu_cpu_init(Object *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    qdev_prop_set_bit(DEVICE(obj), "mmu", false);
}
#endif

static ObjectClass *riscv_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;
    char **cpuname;

    cpuname = g_strsplit(cpu_model, ",", 1);
    typename = g_strdup_printf(RISCV_CPU_TYPE_NAME("%s"), cpuname[0]);
    oc = object_class_by_name(typename);
    g_strfreev(cpuname);
    g_free(typename);
    if (!oc || !object_class_dynamic_cast(oc, TYPE_RISCV_CPU) ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

static void riscv_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    int i;

#if !defined(CONFIG_USER_ONLY)
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s %d\n", "V      =  ", riscv_cpu_virt_enabled(env));
    }
#endif
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "pc      ", PC_ADDR(env));
#ifdef TARGET_CHERI
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "pc (offset) ", GET_SPECIAL_REG_ARCH(env, pc, pcc));
#endif
#ifndef CONFIG_USER_ONLY
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mhartid ", env->mhartid);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mstatus ", (target_ulong)env->mstatus);
    if (riscv_cpu_is_32bit(env)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mstatush ",
                     (target_ulong)(env->mstatus >> 32));
    }
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "hstatus ", env->hstatus);
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vsstatus ",
                     (target_ulong)env->vsstatus);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mip     ", env->mip);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mie     ", env->mie);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mideleg ", env->mideleg);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "hideleg ", env->hideleg);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "medeleg ", env->medeleg);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "hedeleg ", env->hedeleg);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtvec   ", GET_SPECIAL_REG_ARCH(env, mtvec, mtcc));
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "stvec   ", GET_SPECIAL_REG_ARCH(env, stvec, stcc));
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vstvec  ", GET_SPECIAL_REG_ARCH(env, vstvec, vstcc));
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mepc    ", GET_SPECIAL_REG_ARCH(env, mepc, mepcc));
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "sepc    ", GET_SPECIAL_REG_ARCH(env, sepc, sepcc));
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vsepc   ", GET_SPECIAL_REG_ARCH(env, vsepc, vsepcc));
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mcause  ", env->mcause);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "scause  ", env->scause);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vscause ", env->vscause);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtval ", env->mtval);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "stval ", env->sbadaddr);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "htval ", env->htval);
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtval2 ", env->mtval2);
    }
#endif

    for (i = 0; i < 32; i++) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx,
                     riscv_int_regnames[i], gpr_int_value(env, i));
        if ((i & 3) == 3) {
            qemu_fprintf(f, "\n");
        }
    }
    if (flags & CPU_DUMP_FPU) {
        for (i = 0; i < 32; i++) {
            qemu_fprintf(f, " %s %016" PRIx64,
                         riscv_fpr_regnames[i], env->fpr[i]);
            if ((i & 3) == 3) {
                qemu_fprintf(f, "\n");
            }
        }
    }
}

static void riscv_cpu_set_pc(CPUState *cs, vaddr value)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
#ifdef TARGET_CHERI
    cheri_update_pcc(&env->pcc, value, /*can_be_unrepresentable=*/true);
#else
    env->pc = value;
#endif
}

static void riscv_cpu_synchronize_from_tb(CPUState *cs,
                                          const TranslationBlock *tb)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    riscv_update_pc(env, tb->pc, /*can_be_unrepresentable=*/false);
#ifdef TARGET_CHERI
    cheri_debug_assert(tb_in_capmode(tb) == cheri_in_capmode(env));
#endif
#ifdef CONFIG_DEBUG_TCG
    env->_pc_is_current = true;
#endif
}

static bool riscv_cpu_has_work(CPUState *cs)
{
#ifndef CONFIG_USER_ONLY
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    /*
     * Definition of the WFI instruction requires it to ignore the privilege
     * mode and delegation registers, but respect individual enables
     */
    return (env->mip & env->mie) != 0;
#else
    return true;
#endif
}

void restore_state_to_opc(CPURISCVState *env, TranslationBlock *tb,
                          target_ulong *data)
{
#ifdef TARGET_CHERI
    assert(cap_is_in_bounds(&env->pcc, data[0], 1));
    if (unlikely(env->pcc._cr_cursor != data[0])) {
        qemu_log_instr_or_mask_msg(env, CPU_LOG_INT,
            "%s: Updating pc from TB: " TARGET_FMT_lx " -> " TARGET_FMT_lx "\n",
            __func__, (target_ulong)env->pcc._cr_cursor, data[0]);
    }
#endif
    riscv_update_pc(env, data[0], /*can_be_unrepresentable=*/false);
}


#ifdef CONFIG_RVFI_DII
extern int rvfi_client_fd;
extern bool rvfi_debug_output;

static void send_rvfi_dii_packet(const void *data, size_t len)
{
    if (rvfi_debug_output) {
        qemu_hexdump(stderr, "PACKET", data, len);
    }
    ssize_t nbytes = write(rvfi_client_fd, data, len);
    if (nbytes != len) {
        error_report("Failed to write packet to socket: %zd (%s)", nbytes,
                     strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void rvfi_dii_send_v1_trace(CPURISCVState* env)
{
    struct rvfi_dii_trace_v1 trace;
    // convert the state saved in env to a legacy v1 trace
    trace.rvfi_dii_order = env->rvfi_dii_trace.INST.rvfi_order;
    trace.rvfi_dii_pc_rdata = env->rvfi_dii_trace.PC.rvfi_pc_rdata;
    trace.rvfi_dii_pc_wdata = env->rvfi_dii_trace.PC.rvfi_pc_wdata;
    trace.rvfi_dii_insn = env->rvfi_dii_trace.INST.rvfi_insn;
    trace.rvfi_dii_rs1_data = env->rvfi_dii_trace.INTEGER.rvfi_rs1_rdata;
    trace.rvfi_dii_rs2_data = env->rvfi_dii_trace.INTEGER.rvfi_rs2_rdata;
    trace.rvfi_dii_rd_wdata = env->rvfi_dii_trace.INTEGER.rvfi_rd_wdata;
    trace.rvfi_dii_mem_addr = env->rvfi_dii_trace.MEM.rvfi_mem_addr;
    trace.rvfi_dii_mem_rdata = env->rvfi_dii_trace.MEM.rvfi_mem_rdata[0];
    trace.rvfi_dii_mem_wdata = env->rvfi_dii_trace.MEM.rvfi_mem_wdata[0];
    trace.rvfi_dii_mem_rmask = env->rvfi_dii_trace.MEM.rvfi_mem_rmask;
    trace.rvfi_dii_mem_wmask = env->rvfi_dii_trace.MEM.rvfi_mem_wmask;
    trace.rvfi_dii_rs1_addr = env->rvfi_dii_trace.INTEGER.rvfi_rs1_addr;
    trace.rvfi_dii_rs2_addr = env->rvfi_dii_trace.INTEGER.rvfi_rs2_addr;
    trace.rvfi_dii_rd_addr = env->rvfi_dii_trace.INTEGER.rvfi_rd_addr;
    trace.rvfi_dii_trap = env->rvfi_dii_trace.INST.rvfi_trap;
    trace.rvfi_dii_halt = env->rvfi_dii_trace.INST.rvfi_halt;
    trace.rvfi_dii_intr = env->rvfi_dii_trace.INST.rvfi_intr;

    if (rvfi_debug_output) {
        info_report("Sending %jd PCWD: 0x%08jx, RD: %02d, RWD: 0x%08jx, MA: "
                    "0x%08jx, MWD: 0x%08jx, MWM: 0x%08x, I: 0x%016jx H:%u\n",
                    (uintmax_t)trace.rvfi_dii_order,
                    (uintmax_t)trace.rvfi_dii_pc_wdata, trace.rvfi_dii_rd_addr,
                    (uintmax_t)trace.rvfi_dii_rd_wdata,
                    (uintmax_t)trace.rvfi_dii_mem_addr,
                    (uintmax_t)trace.rvfi_dii_mem_wdata,
                    trace.rvfi_dii_mem_wmask, (uintmax_t)trace.rvfi_dii_insn,
                    (unsigned)trace.rvfi_dii_halt);
    }
    send_rvfi_dii_packet(&trace, sizeof(trace));
}

static void rvfi_dii_send_v2_trace(CPURISCVState *env)
{

    struct rvfi_dii_trace_v2 trace = {
        .magic = "trace-v2",
        .available_fields = env->rvfi_dii_trace.available_fields,
        .pc_data = env->rvfi_dii_trace.PC,
        .basic_info = env->rvfi_dii_trace.INST,
    };
    GByteArray *buf = g_byte_array_new();
    g_byte_array_append(buf, (const guint8*)&trace, sizeof(trace));
    if (env->rvfi_dii_trace.available_fields & RVFI_INTEGER_DATA) {
        g_byte_array_append(buf, (const guint8 *)"int-data", 8);
        g_byte_array_append(buf, (const guint8 *)&env->rvfi_dii_trace.INTEGER,
                            sizeof(env->rvfi_dii_trace.INTEGER));
    }
    if (env->rvfi_dii_trace.available_fields & RVFI_MEM_DATA) {
        g_byte_array_append(buf, (const guint8 *)"mem-data", 8);
        g_byte_array_append(buf, (const guint8 *)&env->rvfi_dii_trace.MEM,
                            sizeof(env->rvfi_dii_trace.MEM));
    }
    // Now that we know the total size, we can update the trace header:
    ((struct rvfi_dii_trace_v2 *)buf->data)->trace_size = buf->len;
    if (rvfi_debug_output) {
        fprintf(stderr,
            "Sending %u bytes: %jd PCWD: 0x%08jx, RD: %02d, RWD: 0x%08jx, MA: "
            "0x%08jx, MWD: 0x%08jx, MWM: 0x%08x, I: 0x%016jx H:%u T:%u\n",
            buf->len, (uintmax_t)env->rvfi_dii_trace.INST.rvfi_order,
            (uintmax_t)env->rvfi_dii_trace.PC.rvfi_pc_wdata,
            env->rvfi_dii_trace.INTEGER.rvfi_rd_addr,
            (uintmax_t)env->rvfi_dii_trace.INTEGER.rvfi_rd_wdata,
            (uintmax_t)env->rvfi_dii_trace.MEM.rvfi_mem_addr,
            (uintmax_t)env->rvfi_dii_trace.MEM.rvfi_mem_wdata[0],
            env->rvfi_dii_trace.MEM.rvfi_mem_wmask,
            (uintmax_t)env->rvfi_dii_trace.INST.rvfi_insn,
            (unsigned)env->rvfi_dii_trace.INST.rvfi_halt,
            (unsigned)env->rvfi_dii_trace.INST.rvfi_trap);
    }
    send_rvfi_dii_packet(buf->data, buf->len);
    g_byte_array_free(buf, true);
}

static void rvfi_dii_send_trace(CPURISCVState *env, unsigned version)
{
    if (version == 1) {
        rvfi_dii_send_v1_trace(env);
    } else if (version == 2) {
        rvfi_dii_send_v2_trace(env);
    } else {
        error_report("Invalid trace version %d", version);
        exit(EXIT_FAILURE);
    }
}

void rvfi_dii_communicate(CPUState* cs, CPURISCVState* env, bool was_trap) {
    // needs to be global since this function is called for each instruction
    // that is executed.
    static bool rvfi_dii_started = false;
    static unsigned rvfi_dii_version = 1;
    // Single-step completed -> update PC in the trace buffer
    env->rvfi_dii_trace.PC.rvfi_pc_wdata = GET_SPECIAL_REG_ARCH(env, pc, pcc);
    env->rvfi_dii_trace.INST.rvfi_order++;

    // TestRIG expects a zero $pc after a trap:
    if (env->rvfi_dii_trace.INST.rvfi_trap && rvfi_debug_output) {
        info_report("Got trap at " TARGET_FMT_lx, PC_ADDR(env));
    }
    env->rvfi_dii_have_injected_insn = false;
    while (true) {
        assert(cs->singlestep_enabled);
        rvfi_dii_command_t cmd_buf;
        _Static_assert(sizeof(cmd_buf) == 8, "Expected 8 bytes of data");
#ifdef CONFIG_TCG_LOG_INSTR
        // Print the instruction now and skip the next commit() call that
        // happens when we return to the translator loop.
        qemu_log_instr_commit(env);
        qemu_log_instr_drop(env); // Avoid an invalid instruction log
#endif
        if (rvfi_dii_started) {
            // Send previous state
            rvfi_dii_send_trace(env, rvfi_dii_version);
            // Zero the output trace for the next test except for instret
            uint64_t old_instret = env->rvfi_dii_trace.INST.rvfi_order;
            memset(&env->rvfi_dii_trace, 0, sizeof(env->rvfi_dii_trace));
            env->rvfi_dii_trace.INST.rvfi_order = old_instret;
        }
        // Should be blocking, so we only read fewer bytes on EOF
        ssize_t nbytes = read(rvfi_client_fd, &cmd_buf, sizeof(cmd_buf));
        if (nbytes != sizeof(cmd_buf)) {
            error_report("GOT EOF/Error reading from socket: %zd (%s)", nbytes,
                         strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (rvfi_debug_output) {
            info_report("Handling RVFI-DII command %d", cmd_buf.rvfi_dii_cmd);
        }
        switch (cmd_buf.rvfi_dii_cmd) {
        case '\0': {
            rvfi_dii_started = false;
            if (cmd_buf.rvfi_dii_insn ==
                (('V' << 24) | ('E' << 16) | ('R' << 8) | 'S')) {
                // Version negotiation request -> send a v1 packet with halt=3
                // to indicate that we support the v2 protocol
                env->rvfi_dii_trace.INST.rvfi_halt = 3;
            } else {
                env->rvfi_dii_trace.INST.rvfi_halt = 1;
            }
            env->rvfi_dii_trace.INST.rvfi_order = 0;
            // Clear all fields that can be zeroes: we want a defined reset
            // state for TestRIG even if the RISC-V ISA does not guarantee it.
            memset(env, 0, offsetof(CPURISCVState, end_testrig_reset_fields));
            // Overwrite the processor's resetvec as otherwise reset()
            // writes PC with default RSTVECTOR (0x10000)
            env->resetvec = RVFI_DII_RAM_START;
            // Reset the processor (and ensure that it resets to 0x80000000)
            cpu_reset(cs);
            // FIXME: Hopefully this resets RAM?
            qemu_system_reset(SHUTDOWN_CAUSE_HOST_SIGNAL);
            cs->cflags_next_tb = (curr_cflags(cs) & ~CF_USE_ICOUNT) | 1;
            hwaddr system_ram_addr = cpu_get_phys_page_debug(cs, PC_ADDR(env));
            hwaddr system_ram_size = RVFI_DII_RAM_SIZE;
            void *ram_ptr = cpu_physical_memory_map(
                system_ram_addr, &system_ram_size, /*is_write=*/true);
            assert(system_ram_size == RVFI_DII_RAM_SIZE);
            // TODO: would be nice to do this lazily instead of writing 8 MiB
            // FIXME: is it safe to do a munmap/mmap? We could also MAP_FIXED over
            // the existing mapping. This should be faster since we rarely use more
            // than one page.
            memset(ram_ptr, 0, system_ram_size);
            // Unmap: this should invalidate all caches for that regio.
            cpu_physical_memory_unmap(ram_ptr, system_ram_size, /*is_write=*/true, system_ram_size);
            // Flush the TCG state:
            tb_flush(cs);
            tlb_flush(cs); // Flush the QEMU guest->host tlb

            // TestRIG expects all capability registers to be max perms
#ifdef TARGET_CHERI
            set_max_perms_capregs(env);
#endif
            rvfi_dii_send_trace(env, rvfi_dii_version);
            memset(&env->rvfi_dii_trace, 0, sizeof(env->rvfi_dii_trace));
            continue;
        }
        case 'v': { /* Set wire format version */
            if (cmd_buf.rvfi_dii_insn == 1) {
                fprintf(stderr, "Requested trace in legacy format!\n");
            } else if (cmd_buf.rvfi_dii_insn == 2) {
                fprintf(stderr, "Requested trace in v2 format!\n");
            } else {
                fprintf(stderr, "Requested trace in unsupported format %jd!\n",
                        (intmax_t)cmd_buf.rvfi_dii_insn);
                exit(EXIT_FAILURE);
            }
            // From now on send traces in the requested format
            rvfi_dii_version = cmd_buf.rvfi_dii_insn;
            struct {
                char msg[8];
                uint64_t version;
            } version_response = {"version=", rvfi_dii_version};
            send_rvfi_dii_packet(&version_response, sizeof(version_response));
            continue;
        }
        case 'B': {
            fprintf(stderr, "*BLINK*\n");
            info_report("*BLINK*\n");
            break;
        }
        case 'Q': {
            // The remote disconnected.
            fprintf(stderr, "Received a quit command. Quitting.\n");
            info_report("Received a quit command. Quitting.\n");
            close(rvfi_client_fd);
            rvfi_client_fd = 0;
            exit(EXIT_SUCCESS);
        }
        case 1: {
            // We send the resulting packet on the next call of this function.
            rvfi_dii_started = true;
            cpu_single_step(cs, SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER);
            if (rvfi_debug_output) {
                char buf[512];
                FILE *tmp = fmemopen(buf, sizeof(buf), "w+");
                target_disas_buf(tmp, cs, &cmd_buf.rvfi_dii_insn,
                                 sizeof(cmd_buf.rvfi_dii_insn), PC_ADDR(env),
                                 1);
                fclose(tmp);
                info_report("injecting instruction %d '0x%08x' at %s",
                            cmd_buf.rvfi_dii_time, cmd_buf.rvfi_dii_insn, buf);
            }
            // Ideally we would just completely disable caching of translated
            // blocks in RVFI-DII mode, but I can't figure out how to do this.
            // Instead let's just flush the entire TCG cache (which should have
            // the same effect).
            tb_flush(cs); // flush TCG state
            env->rvfi_dii_injected_insn = cmd_buf.rvfi_dii_insn;
            env->rvfi_dii_have_injected_insn = true;
            env->rvfi_dii_trace.PC.rvfi_pc_rdata = GET_SPECIAL_REG_ARCH(env, pc, pcc);
            env->rvfi_dii_trace.INST.rvfi_mode = env->priv;
            env->rvfi_dii_trace.INST.rvfi_ixl = get_field(env->misa, MISA_MXL);
            resume_all_vcpus();
            cpu_resume(cs);
            env->rvfi_dii_trace.PC.rvfi_pc_wdata = -1; // Will be set after single-step trap
            // Clear the EXCP_DEBUG flag to avoid dropping into GDB
            cs->exception_index = EXCP_NONE; // EXCP_INTERRUPT;
            cs->cflags_next_tb = (curr_cflags(cs) & ~CF_USE_ICOUNT) | 1;
            // Continue execution at env->pc
            cpu_loop_exit_noexc(cs); // noreturn -> jumps back to TCG
        }
        default:
            error_report("rvfi_dii got unsupported command '%c'\n",
                         cmd_buf.rvfi_dii_cmd);
            exit(EXIT_FAILURE);
        }
        rvfi_dii_started = true;
    }
}

#endif // CONFIG_RVFI_DII

static void riscv_debug_excp_handler(CPUState *cs)
{
    /*
     * Called by core code when a watchpoint or breakpoint fires;
     * Also happens for singlestep events
     */
#ifdef CONFIG_RVFI_DII
    struct RISCVCPU *cpu = RISCV_CPU(cs);
    struct CPURISCVState *env = &cpu->env;
    if (rvfi_client_fd && cs->singlestep_enabled) {
        rvfi_dii_communicate(cs, env, false);
        return;
    }
#endif
}

static void riscv_cpu_reset(DeviceState *dev)
{
    CPUState *cs = CPU(dev);
    RISCVCPU *cpu = RISCV_CPU(cs);
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cpu);
    CPURISCVState *env = &cpu->env;

    mcc->parent_reset(dev);
#ifndef CONFIG_USER_ONLY
    env->priv = PRV_M;
    env->mstatus &= ~(MSTATUS_MIE | MSTATUS_MPRV);
    env->mcause = 0;
    env->two_stage_lookup = false;
#if defined(TARGET_RISCV64)
    target_ulong mxl = get_field(env->misa, MISA_MXL);
    env->mstatus = set_field(env->mstatus, MSTATUS64_SXL, mxl);
    env->mstatus = set_field(env->mstatus, MSTATUS64_UXL, mxl);
#endif
#endif

    cs->exception_index = EXCP_NONE;
    env->load_res = -1;
    set_default_nan_mode(1, &env->fp_status);

#if !defined(TARGET_CHERI)
    env->pc = env->resetvec;
    // Also reset mepc/sepc to zero for predicatable behaviour
    env->mepc = 0;
    env->sepc = 0;
#else
    if (!cpu->cfg.ext_cheri) {
        error_report("CHERI extension can't be disabled yet!");
        exit(EXIT_FAILURE);
    }
    // All general purpose capability registers are reset to NULL:
    reset_capregs(env);
    /*
     * See Table 5.2: Special Capability Registers (SCRs) in the CHERI ISA spec
     */
    set_max_perms_capability(&env->pcc, env->resetvec);
    set_max_perms_capability(&env->ddc, 0);
    // User mode trap handling:
    set_max_perms_capability(&env->utcc, 0);
    null_capability(&env->utdc);
    null_capability(&env->uscratchc);
    set_max_perms_capability(&env->uepcc, 0);
    // Supervisor mode trap handling
    set_max_perms_capability(&env->stcc, 0);
    null_capability(&env->stdc);
    null_capability(&env->sscratchc);
    set_max_perms_capability(&env->sepcc, 0);
    // Machine mode trap handling
    set_max_perms_capability(&env->mtcc, 0);
    null_capability(&env->mtdc);
    null_capability(&env->mscratchc);
    set_max_perms_capability(&env->mepcc, 0);
#endif /* TARGET_CHERI */
#ifdef CONFIG_DEBUG_TCG
    env->_pc_is_current = true;
#endif
}

static void riscv_cpu_disas_set_info(CPUState *s, disassemble_info *info)
{
    RISCVCPU *cpu = RISCV_CPU(s);
    if (riscv_cpu_is_32bit(&cpu->env)) {
        info->print_insn = print_insn_riscv32;
    } else {
        info->print_insn = print_insn_riscv64;
    }
#ifdef TARGET_CHERI
    info->flags |= RISCV_DIS_FLAG_CHERI;
    if (cheri_in_capmode(&cpu->env)) {
        info->flags |= RISCV_DIS_FLAG_CAPMODE;
    }
#endif
}

static void riscv_cpu_realize(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    RISCVCPU *cpu = RISCV_CPU(dev);
    CPURISCVState *env = &cpu->env;
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(dev);
    int priv_version = PRIV_VERSION_1_11_0;
    int vext_version = VEXT_VERSION_0_07_1;
    target_ulong target_misa = env->misa;
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    if (cpu->cfg.priv_spec) {
        if (!g_strcmp0(cpu->cfg.priv_spec, "v1.11.0")) {
            priv_version = PRIV_VERSION_1_11_0;
        } else if (!g_strcmp0(cpu->cfg.priv_spec, "v1.10.0")) {
            priv_version = PRIV_VERSION_1_10_0;
        } else {
            error_setg(errp,
                       "Unsupported privilege spec version '%s'",
                       cpu->cfg.priv_spec);
            return;
        }
    }

    set_priv_version(env, priv_version);
    set_vext_version(env, vext_version);

    if (cpu->cfg.mmu) {
        set_feature(env, RISCV_FEATURE_MMU);
    }

    if (cpu->cfg.pmp) {
        set_feature(env, RISCV_FEATURE_PMP);
    }

    set_resetvec(env, cpu->cfg.resetvec);

    /* If only XLEN is set for misa, then set misa from properties */
    if (env->misa == RV32 || env->misa == RV64) {
        /* Do some ISA extension error checking */
        if (cpu->cfg.ext_i && cpu->cfg.ext_e) {
            error_setg(errp,
                       "I and E extensions are incompatible");
                       return;
       }

        if (!cpu->cfg.ext_i && !cpu->cfg.ext_e) {
            error_setg(errp,
                       "Either I or E extension must be set");
                       return;
       }

       if (cpu->cfg.ext_g && !(cpu->cfg.ext_i & cpu->cfg.ext_m &
                               cpu->cfg.ext_a & cpu->cfg.ext_f &
                               cpu->cfg.ext_d)) {
            warn_report("Setting G will also set IMAFD");
            cpu->cfg.ext_i = true;
            cpu->cfg.ext_m = true;
            cpu->cfg.ext_a = true;
            cpu->cfg.ext_f = true;
            cpu->cfg.ext_d = true;
        }

        /* Set the ISA extensions, checks should have happened above */
        if (cpu->cfg.ext_i) {
            target_misa |= RVI;
        }
        if (cpu->cfg.ext_e) {
            target_misa |= RVE;
        }
        if (cpu->cfg.ext_m) {
            target_misa |= RVM;
        }
        if (cpu->cfg.ext_a) {
            target_misa |= RVA;
        }
        if (cpu->cfg.ext_f) {
            target_misa |= RVF;
        }
        if (cpu->cfg.ext_d) {
            target_misa |= RVD;
        }
        if (cpu->cfg.ext_c) {
            target_misa |= RVC;
        }
        if (cpu->cfg.ext_s) {
            target_misa |= RVS;
        }
        if (cpu->cfg.ext_u) {
            target_misa |= RVU;
        }
        if (cpu->cfg.ext_h) {
            target_misa |= RVH;
        }
        if (cpu->cfg.ext_v) {
            target_misa |= RVV;
            if (!is_power_of_2(cpu->cfg.vlen)) {
                error_setg(errp,
                        "Vector extension VLEN must be power of 2");
                return;
            }
            if (cpu->cfg.vlen > RV_VLEN_MAX || cpu->cfg.vlen < 128) {
                error_setg(errp,
                        "Vector extension implementation only supports VLEN "
                        "in the range [128, %d]", RV_VLEN_MAX);
                return;
            }
            if (!is_power_of_2(cpu->cfg.elen)) {
                error_setg(errp,
                        "Vector extension ELEN must be power of 2");
                return;
            }
            if (cpu->cfg.elen > 64 || cpu->cfg.vlen < 8) {
                error_setg(errp,
                        "Vector extension implementation only supports ELEN "
                        "in the range [8, 64]");
                return;
            }
            if (cpu->cfg.vext_spec) {
                if (!g_strcmp0(cpu->cfg.vext_spec, "v0.7.1")) {
                    vext_version = VEXT_VERSION_0_07_1;
                } else {
                    error_setg(errp,
                           "Unsupported vector spec version '%s'",
                           cpu->cfg.vext_spec);
                    return;
                }
            } else {
                qemu_log("vector version is not specified, "
                        "use the default value v0.7.1\n");
            }
            set_vext_version(env, vext_version);
        }
#ifdef TARGET_CHERI
        if (cpu->cfg.ext_cheri) {
            // Non-standard extensions present
            target_misa |= RV('X');
        }
#endif

        set_misa(env, target_misa);
    }

    riscv_cpu_register_gdb_regs_for_features(cs);

    qemu_init_vcpu(cs);
#ifdef CONFIG_DEBUG_TCG
    env->_pc_is_current = true;
#endif
#ifdef CONFIG_RVFI_DII
    /* When waiting for RVFI packets, don't fetch the initial instruction */
    if (rvfi_client_fd && cs->singlestep_enabled) {
        env->rvfi_dii_have_injected_insn = true;
        env->rvfi_dii_injected_insn = 0; /* ILLEGAL */
    }
#endif
    cpu_reset(cs);

    mcc->parent_realize(dev, errp);
}

static void riscv_cpu_init(Object *obj)
{
    RISCVCPU *cpu = RISCV_CPU(obj);

    cpu_set_cpustate_pointers(cpu);
}

static Property riscv_cpu_properties[] = {
    DEFINE_PROP_BOOL("i", RISCVCPU, cfg.ext_i, true),
    DEFINE_PROP_BOOL("e", RISCVCPU, cfg.ext_e, false),
    DEFINE_PROP_BOOL("g", RISCVCPU, cfg.ext_g, true),
    DEFINE_PROP_BOOL("m", RISCVCPU, cfg.ext_m, true),
    DEFINE_PROP_BOOL("a", RISCVCPU, cfg.ext_a, true),
    DEFINE_PROP_BOOL("f", RISCVCPU, cfg.ext_f, true),
    DEFINE_PROP_BOOL("d", RISCVCPU, cfg.ext_d, true),
    DEFINE_PROP_BOOL("c", RISCVCPU, cfg.ext_c, true),
    DEFINE_PROP_BOOL("s", RISCVCPU, cfg.ext_s, true),
    DEFINE_PROP_BOOL("u", RISCVCPU, cfg.ext_u, true),
    /* This is experimental so mark with 'x-' */
    DEFINE_PROP_BOOL("x-h", RISCVCPU, cfg.ext_h, false),
    DEFINE_PROP_BOOL("x-v", RISCVCPU, cfg.ext_v, false),
    DEFINE_PROP_BOOL("Counters", RISCVCPU, cfg.ext_counters, true),
    DEFINE_PROP_BOOL("Zifencei", RISCVCPU, cfg.ext_ifencei, true),
    DEFINE_PROP_BOOL("Zicsr", RISCVCPU, cfg.ext_icsr, true),
#ifdef TARGET_CHERI
    DEFINE_PROP_BOOL("Xcheri", RISCVCPU, cfg.ext_cheri, true),
    DEFINE_PROP_BOOL("Xcheri_v9", RISCVCPU, cfg.ext_cheri_v9, false),
#endif
    DEFINE_PROP_STRING("priv_spec", RISCVCPU, cfg.priv_spec),
    DEFINE_PROP_STRING("vext_spec", RISCVCPU, cfg.vext_spec),
    DEFINE_PROP_UINT16("vlen", RISCVCPU, cfg.vlen, 128),
    DEFINE_PROP_UINT16("elen", RISCVCPU, cfg.elen, 64),
    DEFINE_PROP_BOOL("mmu", RISCVCPU, cfg.mmu, true),
    DEFINE_PROP_BOOL("pmp", RISCVCPU, cfg.pmp, true),
    DEFINE_PROP_UINT64("resetvec", RISCVCPU, cfg.resetvec, DEFAULT_RSTVEC),
    DEFINE_PROP_END_OF_LIST(),
};

static gchar *riscv_gdb_arch_name(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (riscv_cpu_is_32bit(env)) {
        return g_strdup("riscv:rv32");
    } else {
        return g_strdup("riscv:rv64");
    }
}

static const char *riscv_gdb_get_dynamic_xml(CPUState *cs, const char *xmlname)
{
    RISCVCPU *cpu = RISCV_CPU(cs);

    if (strcmp(xmlname, "riscv-csr.xml") == 0) {
        return cpu->dyn_csr_xml;
    }

    return NULL;
}

#include "hw/core/tcg-cpu-ops.h"

static struct TCGCPUOps riscv_tcg_ops = {
    .initialize = riscv_translate_init,
    .synchronize_from_tb = riscv_cpu_synchronize_from_tb,
    .cpu_exec_interrupt = riscv_cpu_exec_interrupt,
    .tlb_fill = riscv_cpu_tlb_fill,
    .debug_excp_handler = riscv_debug_excp_handler,

#ifndef CONFIG_USER_ONLY
    .do_interrupt = riscv_cpu_do_interrupt,
    .do_transaction_failed = riscv_cpu_do_transaction_failed,
    .do_unaligned_access = riscv_cpu_do_unaligned_access,
#endif /* !CONFIG_USER_ONLY */
};

static void riscv_cpu_class_init(ObjectClass *c, void *data)
{
    RISCVCPUClass *mcc = RISCV_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);
    DeviceClass *dc = DEVICE_CLASS(c);

    device_class_set_parent_realize(dc, riscv_cpu_realize,
                                    &mcc->parent_realize);

    device_class_set_parent_reset(dc, riscv_cpu_reset, &mcc->parent_reset);

    cc->class_by_name = riscv_cpu_class_by_name;
    cc->has_work = riscv_cpu_has_work;
    cc->dump_state = riscv_cpu_dump_state;
    cc->set_pc = riscv_cpu_set_pc;
    cc->gdb_read_register = riscv_cpu_gdb_read_register;
    cc->gdb_write_register = riscv_cpu_gdb_write_register;
    cc->gdb_num_core_regs = 33;
#if defined(TARGET_RISCV32)
    cc->gdb_core_xml_file = "riscv-32bit-cpu.xml";
#elif defined(TARGET_RISCV64)
    cc->gdb_core_xml_file = "riscv-64bit-cpu.xml";
#endif
    cc->gdb_stop_before_watchpoint = true;
    cc->disas_set_info = riscv_cpu_disas_set_info;
#ifndef CONFIG_USER_ONLY
    cc->get_phys_page_debug = riscv_cpu_get_phys_page_debug;
    /* For now, mark unmigratable: */
    cc->vmsd = &vmstate_riscv_cpu;
    cc->write_elf64_note = riscv_cpu_write_elf64_note;
    cc->write_elf32_note = riscv_cpu_write_elf32_note;
#endif
    cc->gdb_arch_name = riscv_gdb_arch_name;
    cc->gdb_get_dynamic_xml = riscv_gdb_get_dynamic_xml;
    cc->tcg_ops = &riscv_tcg_ops;

    device_class_set_props(dc, riscv_cpu_properties);
}

char *riscv_isa_string(RISCVCPU *cpu)
{
    int i;
    const size_t maxlen = sizeof("rv128") + sizeof(riscv_exts) + 1;
    char *isa_str = g_new(char, maxlen);
    char *p = isa_str + snprintf(isa_str, maxlen, "rv%d", TARGET_LONG_BITS);
    for (i = 0; i < sizeof(riscv_exts); i++) {
        if (cpu->env.misa & RV(riscv_exts[i])) {
            *p++ = qemu_tolower(riscv_exts[i]);
        }
    }
    *p = '\0';
    // TODO: add Xcheri?
    return isa_str;
}

static gint riscv_cpu_list_compare(gconstpointer a, gconstpointer b)
{
    ObjectClass *class_a = (ObjectClass *)a;
    ObjectClass *class_b = (ObjectClass *)b;
    const char *name_a, *name_b;

    name_a = object_class_get_name(class_a);
    name_b = object_class_get_name(class_b);
    return strcmp(name_a, name_b);
}

static void riscv_cpu_list_entry(gpointer data, gpointer user_data)
{
    const char *typename = object_class_get_name(OBJECT_CLASS(data));
    int len = strlen(typename) - strlen(RISCV_CPU_TYPE_SUFFIX);

    qemu_printf("%.*s\n", len, typename);
}

void riscv_cpu_list(void)
{
    GSList *list;

    list = object_class_get_list(TYPE_RISCV_CPU, false);
    list = g_slist_sort(list, riscv_cpu_list_compare);
    g_slist_foreach(list, riscv_cpu_list_entry, NULL);
    g_slist_free(list);
}

#define DEFINE_CPU(type_name, initfn)      \
    {                                      \
        .name = type_name,                 \
        .parent = TYPE_RISCV_CPU,          \
        .instance_init = initfn            \
    }

static const TypeInfo riscv_cpu_type_infos[] = {
    {
        .name = TYPE_RISCV_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(RISCVCPU),
        .instance_align = __alignof__(RISCVCPU),
        .instance_init = riscv_cpu_init,
        .abstract = true,
        .class_size = sizeof(RISCVCPUClass),
        .class_init = riscv_cpu_class_init,
    },
    DEFINE_CPU(TYPE_RISCV_CPU_ANY,              riscv_any_cpu_init),
#if defined(TARGET_RISCV32)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE32,           rv32_base_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_IBEX,             rv32_ibex_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E31,       rv32_sifive_e_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E34,       rv32_imafcu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U34,       rv32_sifive_u_cpu_init),
#elif defined(TARGET_RISCV64)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE64,           rv64_base_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E51,       rv64_sifive_e_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U54,       rv64_sifive_u_cpu_init),
#endif
};

DEFINE_TYPES(riscv_cpu_type_infos)
