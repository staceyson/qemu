/*
 * RISC-V GDB Server Stub
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
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
#include "exec/gdbstub.h"
#include "exec/log_instr.h"
#include "cpu.h"
#include "helper_utils.h"
#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

int riscv_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (n < 32) {
        return gdb_get_regl(mem_buf, gpr_int_value(env, n));
    } else if (n == 32) {
        return gdb_get_regl(mem_buf, GET_SPECIAL_REG_ARCH(env, pc, PCC));
    }
    return 0;
}

int riscv_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (n == 0) {
        /* discard writes to x0 */
        return sizeof(target_ulong);
    } else if (n < 32) {
        gpr_set_int_value(env, n, ldtul_p(mem_buf));
        return sizeof(target_ulong);
    } else if (n == 32) {
        /* TODO(am2419): arguably we don't want to log changes from gdb */
        SET_SPECIAL_REG(env, pc, PCC, ldtul_p(mem_buf));
        return sizeof(target_ulong);
    }
    return 0;
}

static int riscv_gdb_get_fpu(CPURISCVState *env, GByteArray *buf, int n)
{
    if (n < 32) {
        if (env->misa & RVD) {
            return gdb_get_reg64(buf, env->fpr[n]);
        }
        if (env->misa & RVF) {
            return gdb_get_reg32(buf, env->fpr[n]);
        }
    /* there is hole between ft11 and fflags in fpu.xml */
    } else if (n < 36 && n > 32) {
        target_ulong val = 0;
        int result;
        /*
         * CSR_FFLAGS is at index 1 in csr_register, and gdb says it is FP
         * register 33, so we recalculate the map index.
         * This also works for CSR_FRM and CSR_FCSR.
         */
        result = riscv_csrrw_debug(env, n - 32, &val,
                                   0, 0);
        if (result == 0) {
            return gdb_get_regl(buf, val);
        }
    }
    return 0;
}

static int riscv_gdb_set_fpu(CPURISCVState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        env->fpr[n] = ldq_p(mem_buf); /* always 64-bit */
        return sizeof(uint64_t);
    /* there is hole between ft11 and fflags in fpu.xml */
    } else if (n < 36 && n > 32) {
        target_ulong val = ldtul_p(mem_buf);
        int result;
        /*
         * CSR_FFLAGS is at index 1 in csr_register, and gdb says it is FP
         * register 33, so we recalculate the map index.
         * This also works for CSR_FRM and CSR_FCSR.
         */
        result = riscv_csrrw_debug(env, n - 32, NULL,
                                   val, -1);
        if (result == 0) {
            return sizeof(target_ulong);
        }
    }
    return 0;
}

static int riscv_gdb_get_csr(CPURISCVState *env, GByteArray *buf, int n)
{
    if (n < CSR_TABLE_SIZE) {
        target_ulong val = 0;
        int result;

        result = riscv_csrrw_debug(env, n, &val, 0, 0);
        if (result == 0) {
            return gdb_get_regl(buf, val);
        }
    }
    return 0;
}

static int riscv_gdb_set_csr(CPURISCVState *env, uint8_t *mem_buf, int n)
{
    if (n < CSR_TABLE_SIZE) {
        target_ulong val = ldtul_p(mem_buf);
        int result;

        result = riscv_csrrw_debug(env, n, NULL, val, -1);
        if (result == 0) {
            return sizeof(target_ulong);
        }
    }
    return 0;
}

static int riscv_gdb_get_virtual(CPURISCVState *cs, GByteArray *buf, int n)
{
    if (n == 0) {
#ifdef CONFIG_USER_ONLY
        return gdb_get_regl(buf, 0);
#else
        return gdb_get_regl(buf, cs->priv);
#endif
    }
    return 0;
}

static int riscv_gdb_set_virtual(CPURISCVState *cs, uint8_t *mem_buf, int n)
{
    if (n == 0) {
#ifndef CONFIG_USER_ONLY
        cs->priv = ldtul_p(mem_buf) & 0x3;
        if (cs->priv == PRV_H) {
            cs->priv = PRV_S;
        }
#endif
        return sizeof(target_ulong);
    }
    return 0;
}


#if defined(TARGET_CHERI)
#define CHERI_GDB_NUM_GP_CAPREGS 32
#define CHERI_GDB_NUM_SPECIAL_CAPREGS 2
#define CHERI_GDB_NUM_CAPREGS (CHERI_GDB_NUM_GP_CAPREGS + CHERI_GDB_NUM_SPECIAL_CAPREGS)
#define CHERI_GDB_NUM_REGS (CHERI_GDB_NUM_CAPREGS)

static int riscv_gdb_get_cheri_reg(CPURISCVState *env, GByteArray *buf, int n)
{
    if (n < 0)
        return 0;

    if (n < CHERI_GDB_NUM_GP_CAPREGS) {
        return gdb_get_general_purpose_capreg(buf, env, n);
    }
    switch (n) {
    case CHERI_GDB_NUM_GP_CAPREGS:
        return gdb_get_capreg(buf, cheri_get_current_pcc(env));
    case CHERI_GDB_NUM_GP_CAPREGS + 1:
        return gdb_get_capreg(buf, cheri_get_ddc(env));
    }
    return 0;
}

static int riscv_gdb_set_cheri_reg(CPURISCVState *env, uint8_t *mem_buf, int n)
{
    /* All CHERI registers are read-only currently.  */
    if (n <= CHERI_GDB_NUM_CAPREGS) {
        return CHERI_CAP_SIZE + 1;
    }

    return 0;
}
#endif

static int riscv_gen_dynamic_csr_xml(CPUState *cs, int base_reg)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    GString *s = g_string_new(NULL);
    riscv_csr_predicate_fn predicate;
    int bitsize = riscv_cpu_is_32bit(env) ? 32 : 64;
    int i;

    g_string_printf(s, "<?xml version=\"1.0\"?>");
    g_string_append_printf(s, "<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">");
    g_string_append_printf(s, "<feature name=\"org.gnu.gdb.riscv.csr\">");

    for (i = 0; i < CSR_TABLE_SIZE; i++) {
        predicate = csr_ops[i].predicate;
        if (predicate && !predicate(env, i)) {
            if (csr_ops[i].name) {
                g_string_append_printf(s, "<reg name=\"%s\"", csr_ops[i].name);
            } else {
                g_string_append_printf(s, "<reg name=\"csr%03x\"", i);
            }
            g_string_append_printf(s, " bitsize=\"%d\"", bitsize);
            g_string_append_printf(s, " regnum=\"%d\"/>", base_reg + i);
        }
    }

    g_string_append_printf(s, "</feature>");

    cpu->dyn_csr_xml = g_string_free(s, false);
    return CSR_TABLE_SIZE;
}

void riscv_cpu_register_gdb_regs_for_features(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    if (env->misa & RVD) {
        gdb_register_coprocessor(cs, riscv_gdb_get_fpu, riscv_gdb_set_fpu,
                                 36, "riscv-64bit-fpu.xml", 0);
    } else if (env->misa & RVF) {
        gdb_register_coprocessor(cs, riscv_gdb_get_fpu, riscv_gdb_set_fpu,
                                 36, "riscv-32bit-fpu.xml", 0);
    }
#if defined(TARGET_RISCV32)
    gdb_register_coprocessor(cs, riscv_gdb_get_virtual, riscv_gdb_set_virtual,
                             1, "riscv-32bit-virtual.xml", 0);
#elif defined(TARGET_RISCV64)
    gdb_register_coprocessor(cs, riscv_gdb_get_virtual, riscv_gdb_set_virtual,
                             1, "riscv-64bit-virtual.xml", 0);
#endif
#if defined(TARGET_CHERI)
    gdb_register_coprocessor(cs, riscv_gdb_get_cheri_reg,
                             riscv_gdb_set_cheri_reg, CHERI_GDB_NUM_REGS,
#if defined(TARGET_RISCV32)
                             "riscv-32bit-cheri.xml", 0);
#elif defined(TARGET_RISCV64)
                             "riscv-64bit-cheri.xml", 0);
#else
#error INVALID TARGET
#endif
#endif

    gdb_register_coprocessor(cs, riscv_gdb_get_csr, riscv_gdb_set_csr,
                             riscv_gen_dynamic_csr_xml(cs, cs->gdb_num_regs),
                             "riscv-csr.xml", 0);
}
