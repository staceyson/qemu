/*
 * RISC-V emulation for qemu: main translation routines.
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
#include "qemu/log.h"
#include "cpu.h"
#include "tcg/tcg-op.h"
#include "disas/disas.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "exec/translator.h"
#include "exec/log.h"
#include "exec/log_instr.h"

#include "instmap.h"


/* global register indices */
#ifdef TARGET_CHERI
#include "cheri-lazy-capregs.h"
static TCGv _cpu_cursors_do_not_access_directly[32];
static TCGv cpu_pc;  // Note: this is PCC.cursor
#else
static TCGv cpu_gpr[32], cpu_pc;
#endif
#ifdef CONFIG_RVFI_DII
TCGv_i32 cpu_rvfi_available_fields;
#endif
static TCGv cpu_vl;
static TCGv_i64 cpu_fpr[32]; /* assume F and D extensions */
static TCGv_cap_checked_ptr load_res;
static TCGv load_val;

#include "exec/gen-icount.h"

typedef struct DisasContext {
    DisasContextBase base;
    /* pc_succ_insn points to the instruction following base.pc_next */
    target_ulong pc_succ_insn;
    target_ulong priv_ver;
    bool virt_enabled;
    uint32_t opcode;
    uint32_t mstatus_fs;
    uint32_t misa;
    uint32_t mem_idx;
    /* Remember the rounding mode encoded in the previous fp instruction,
       which we have already installed into env->fp_status.  Or -1 for
       no previous fp instruction.  Note that we exit the TB when writing
       to any system register, which includes CSR_FRM, so we do not have
       to reset this known value.  */
    int frm;
    bool ext_ifencei;
    bool hlsx;
#ifdef TARGET_CHERI
    bool capmode;
    bool cheri_v9_semantics;
#endif
    /* vector extension */
    bool vill;
    uint8_t lmul;
    uint8_t sew;
    uint16_t vlen;
    uint16_t mlen;
    bool vl_eq_vlmax;
    CPUState *cs;
} DisasContext;

#ifdef TARGET_RISCV64
#define CASE_OP_32_64(X) case X: case glue(X, W)
#else
#define CASE_OP_32_64(X) case X
#endif

#ifdef CONFIG_DEBUG_TCG
#define gen_mark_pc_updated() tcg_gen_movi_tl(_pc_is_current, 1)
#else
#define gen_mark_pc_updated() ((void)0)
#endif


static inline void gen_update_cpu_pc(target_ulong new_pc)
{
    tcg_gen_movi_tl(cpu_pc, new_pc);
    gen_mark_pc_updated();
}

static inline bool has_ext(DisasContext *ctx, uint32_t ext)
{
    return ctx->misa & ext;
}

/*
 * RISC-V requires NaN-boxing of narrower width floating point values.
 * This applies when a 32-bit value is assigned to a 64-bit FP register.
 * For consistency and simplicity, we nanbox results even when the RVD
 * extension is not present.
 */
static void gen_nanbox_s(TCGv_i64 out, TCGv_i64 in)
{
    tcg_gen_ori_i64(out, in, MAKE_64BIT_MASK(32, 32));
}

/*
 * A narrow n-bit operation, where n < FLEN, checks that input operands
 * are correctly Nan-boxed, i.e., all upper FLEN - n bits are 1.
 * If so, the least-significant bits of the input are used, otherwise the
 * input value is treated as an n-bit canonical NaN (v2.2 section 9.2).
 *
 * Here, the result is always nan-boxed, even the canonical nan.
 */
static void gen_check_nanbox_s(TCGv_i64 out, TCGv_i64 in)
{
    TCGv_i64 t_max = tcg_const_i64(0xffffffff00000000ull);
    TCGv_i64 t_nan = tcg_const_i64(0xffffffff7fc00000ull);

    tcg_gen_movcond_i64(TCG_COND_GEU, out, in, t_max, in, t_nan);
    tcg_temp_free_i64(t_max);
    tcg_temp_free_i64(t_nan);
}

static void generate_exception(DisasContext *ctx, int excp)
{
    gen_update_cpu_pc(ctx->base.pc_next);
    TCGv_i32 helper_tmp = tcg_const_i32(excp);
    gen_helper_raise_exception(cpu_env, helper_tmp);
    tcg_temp_free_i32(helper_tmp);
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void generate_exception_mbadaddr(DisasContext *ctx, int excp)
{
    gen_update_cpu_pc(ctx->base.pc_next);
    tcg_gen_st_tl(cpu_pc, cpu_env, offsetof(CPURISCVState, badaddr));
    TCGv_i32 helper_tmp = tcg_const_i32(excp);
    gen_helper_raise_exception(cpu_env, helper_tmp);
    tcg_temp_free_i32(helper_tmp);
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_exception_debug(void)
{
    TCGv_i32 helper_tmp = tcg_const_i32(EXCP_DEBUG);
    gen_helper_raise_exception(cpu_env, helper_tmp);
    tcg_temp_free_i32(helper_tmp);
}

/* Wrapper around tcg_gen_exit_tb that handles single stepping */
static void exit_tb(DisasContext *ctx)
{
    if (ctx->base.singlestep_enabled) {
        gen_exception_debug();
    } else {
        tcg_gen_exit_tb(NULL, 0);
    }
}

/* Wrapper around tcg_gen_lookup_and_goto_ptr that handles single stepping */
static void lookup_and_goto_ptr(DisasContext *ctx)
{
    if (ctx->base.singlestep_enabled) {
        gen_exception_debug();
    } else {
        tcg_gen_lookup_and_goto_ptr();
    }
}

static void gen_exception_illegal(DisasContext *ctx)
{
    generate_exception(ctx, RISCV_EXCP_ILLEGAL_INST);
}

static void gen_exception_inst_addr_mis(DisasContext *ctx)
{
    generate_exception_mbadaddr(ctx, RISCV_EXCP_INST_ADDR_MIS);
}

static inline bool use_goto_tb(DisasContext *ctx, target_ulong dest)
{
    if (unlikely(ctx->base.singlestep_enabled)) {
        return false;
    }

#ifndef CONFIG_USER_ONLY
    return (ctx->base.tb->pc & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK);
#else
    return true;
#endif
}

/* Wrapper for getting reg values - need to check of reg is zero since
 * cpu_gpr[0] is not actually allocated
 */
static inline void _gen_get_gpr(TCGv t, int reg_num)
{
    if (reg_num == 0) {
        tcg_gen_movi_tl(t, 0);
    } else {
#ifdef TARGET_CHERI
        tcg_gen_mov_tl(t, _cpu_cursors_do_not_access_directly[reg_num]);
#else
        tcg_gen_mov_tl(t, cpu_gpr[reg_num]);
#endif
    }
}

#ifdef CONFIG_RVFI_DII
//#define gen_get_gpr(t, reg_num, field_prefix)                                  \
//    do {                                                                       \
//        _gen_get_gpr(t, reg_num);                                              \
//        gen_rvfi_dii_set_field(field_prefix##_data, t);                        \
//        gen_rvfi_dii_set_field_const(field_prefix##_addr, reg_num);            \
//    } while (0)
#else
// #define gen_get_gpr(t, reg_num, field) _gen_get_gpr(t, reg_num)
#endif
#define gen_get_gpr(t, reg_num) _gen_get_gpr(t, reg_num)

#include "cheri-translate-utils.h"

/* Wrapper for setting reg values - need to check of reg is zero since
 * cpu_gpr[0] is not actually allocated. this is more for safety purposes,
 * since we usually avoid calling the OP_TYPE_gen function if we see a write to
 * $zero
 */
static inline void _gen_set_gpr(DisasContext *ctx, int reg_num_dst, TCGv t,
                                bool clear_pesbt)
{
    if (reg_num_dst != 0) {
#ifdef TARGET_CHERI
        if (clear_pesbt)
            gen_lazy_cap_set_int(
                ctx, reg_num_dst); // Reset the register type to int.
        tcg_gen_mov_tl(_cpu_cursors_do_not_access_directly[reg_num_dst], t);
#else
        tcg_gen_mov_tl(cpu_gpr[reg_num_dst], t);
#endif
        gen_rvfi_dii_set_field_const_i8(INTEGER, rd_addr, reg_num_dst);
        gen_rvfi_dii_set_field_zext_tl(INTEGER, rd_wdata, t);
#ifdef CONFIG_TCG_LOG_INSTR
        // Log GPR writes here
        if (unlikely(ctx->base.log_instr_enabled)) {
            TCGv_i32 tregnum = tcg_const_i32(reg_num_dst);
            gen_helper_riscv_log_gpr_write(cpu_env, tregnum, t);
            tcg_temp_free_i32(tregnum);
        }
#endif
    }
}

static inline void _gen_set_gpr_const(DisasContext *ctx, int reg_num_dst,
                                      target_ulong value)
{
    if (reg_num_dst != 0) {
#ifdef TARGET_CHERI
        gen_lazy_cap_set_int(ctx,
                             reg_num_dst); // Reset the register type to int.
        tcg_gen_movi_tl(_cpu_cursors_do_not_access_directly[reg_num_dst], value);
#else
        tcg_gen_movi_tl(cpu_gpr[reg_num_dst], value);
#endif
        gen_rvfi_dii_set_field_const_i8(INTEGER, rd_addr, reg_num_dst);
        gen_rvfi_dii_set_field_const_i64(INTEGER, rd_wdata, value);
#ifdef CONFIG_TCG_LOG_INSTR
        // Log GPR writes here
        if (unlikely(ctx->base.log_instr_enabled)) {
            TCGv_i32 tregnum = tcg_const_i32(reg_num_dst);
            TCGv tval = tcg_const_tl(value);
            gen_helper_riscv_log_gpr_write(cpu_env, tregnum, tval);
            tcg_temp_free(tval);
            tcg_temp_free_i32(tregnum);
        }
#endif
    }
}

#define gen_set_gpr(reg_num_dst, t) _gen_set_gpr(ctx, reg_num_dst, t, true)
#define gen_set_gpr_const(reg_num_dst, t) _gen_set_gpr_const(ctx, reg_num_dst, t)

#ifdef CONFIG_TCG_LOG_INSTR
static inline void gen_riscv_log_instr(DisasContext *ctx, uint32_t opcode,
                                       int width)
{
    if (unlikely(ctx->base.log_instr_enabled)) {
        TCGv tpc = tcg_const_tl(ctx->base.pc_next);
        TCGv_i32 topc = tcg_const_i32(opcode);
        TCGv_i32 twidth = tcg_const_i32(width);
        // TODO(am2419): bswap opcode if target byte-order != host byte-order
        gen_helper_riscv_log_instr(cpu_env, tpc, topc, twidth);
        tcg_temp_free(tpc);
        tcg_temp_free_i32(topc);
        tcg_temp_free_i32(twidth);
    }
}

#else /* ! CONFIG_TCG_LOG_INSTR */
#define gen_riscv_log_instr(ctx, opcode, width) ((void)0)
#endif /* ! CONFIG_TCG_LOG_INSTR */

#define gen_riscv_log_instr16(ctx, opcode)              \
    gen_riscv_log_instr(ctx, opcode, sizeof(uint16_t))
#define gen_riscv_log_instr32(ctx, opcode)              \
    gen_riscv_log_instr(ctx, opcode, sizeof(uint32_t))

void cheri_tcg_save_pc(DisasContextBase *db) { gen_update_cpu_pc(db->pc_next); }
// We have to call gen_update_cpu_pc() before setting DISAS_NORETURN (see
// generate_exception())
void cheri_tcg_prepare_for_unconditional_exception(DisasContextBase *db)
{
    cheri_tcg_save_pc(db);
    db->is_jmp = DISAS_NORETURN;
}

static void gen_goto_tb(DisasContext *ctx, int n, target_ulong dest,
                        bool bounds_check)
{
    if (bounds_check)
        gen_check_branch_target(ctx, dest);

    if (use_goto_tb(ctx, dest)) {
        /* chaining is only allowed when the jump is to the same page */
        tcg_gen_goto_tb(n);
        gen_update_cpu_pc(dest);

        /* No need to check for single stepping here as use_goto_tb() will
         * return false in case of single stepping.
         */
        tcg_gen_exit_tb(ctx->base.tb, n);
    } else {
        gen_update_cpu_pc(dest);
        lookup_and_goto_ptr(ctx);
    }
}

static void gen_mulhsu(TCGv ret, TCGv arg1, TCGv arg2)
{
    TCGv rl = tcg_temp_new();
    TCGv rh = tcg_temp_new();

    tcg_gen_mulu2_tl(rl, rh, arg1, arg2);
    /* fix up for one negative */
    tcg_gen_sari_tl(rl, arg1, TARGET_LONG_BITS - 1);
    tcg_gen_and_tl(rl, rl, arg2);
    tcg_gen_sub_tl(ret, rh, rl);

    tcg_temp_free(rl);
    tcg_temp_free(rh);
}

static void gen_div(TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, cond2, zeroreg, resultopt1;
    /*
     * Handle by altering args to tcg_gen_div to produce req'd results:
     * For overflow: want source1 in source1 and 1 in source2
     * For div by zero: want -1 in source1 and 1 in source2 -> -1 result
     */
    cond1 = tcg_temp_new();
    cond2 = tcg_temp_new();
    zeroreg = tcg_const_tl(0);
    resultopt1 = tcg_temp_new();

    tcg_gen_movi_tl(resultopt1, (target_ulong)-1);
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond2, source2, (target_ulong)(~0L));
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond1, source1,
                        ((target_ulong)1) << (TARGET_LONG_BITS - 1));
    tcg_gen_and_tl(cond1, cond1, cond2); /* cond1 = overflow */
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond2, source2, 0); /* cond2 = div 0 */
    /* if div by zero, set source1 to -1, otherwise don't change */
    tcg_gen_movcond_tl(TCG_COND_EQ, source1, cond2, zeroreg, source1,
            resultopt1);
    /* if overflow or div by zero, set source2 to 1, else don't change */
    tcg_gen_or_tl(cond1, cond1, cond2);
    tcg_gen_movi_tl(resultopt1, (target_ulong)1);
    tcg_gen_movcond_tl(TCG_COND_EQ, source2, cond1, zeroreg, source2,
            resultopt1);
    tcg_gen_div_tl(ret, source1, source2);

    tcg_temp_free(cond1);
    tcg_temp_free(cond2);
    tcg_temp_free(zeroreg);
    tcg_temp_free(resultopt1);
}

static void gen_divu(TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, zeroreg, resultopt1;
    cond1 = tcg_temp_new();

    zeroreg = tcg_const_tl(0);
    resultopt1 = tcg_temp_new();

    tcg_gen_setcondi_tl(TCG_COND_EQ, cond1, source2, 0);
    tcg_gen_movi_tl(resultopt1, (target_ulong)-1);
    tcg_gen_movcond_tl(TCG_COND_EQ, source1, cond1, zeroreg, source1,
            resultopt1);
    tcg_gen_movi_tl(resultopt1, (target_ulong)1);
    tcg_gen_movcond_tl(TCG_COND_EQ, source2, cond1, zeroreg, source2,
            resultopt1);
    tcg_gen_divu_tl(ret, source1, source2);

    tcg_temp_free(cond1);
    tcg_temp_free(zeroreg);
    tcg_temp_free(resultopt1);
}

static void gen_rem(TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, cond2, zeroreg, resultopt1;

    cond1 = tcg_temp_new();
    cond2 = tcg_temp_new();
    zeroreg = tcg_const_tl(0);
    resultopt1 = tcg_temp_new();

    tcg_gen_movi_tl(resultopt1, 1L);
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond2, source2, (target_ulong)-1);
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond1, source1,
                        (target_ulong)1 << (TARGET_LONG_BITS - 1));
    tcg_gen_and_tl(cond2, cond1, cond2); /* cond1 = overflow */
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond1, source2, 0); /* cond2 = div 0 */
    /* if overflow or div by zero, set source2 to 1, else don't change */
    tcg_gen_or_tl(cond2, cond1, cond2);
    tcg_gen_movcond_tl(TCG_COND_EQ, source2, cond2, zeroreg, source2,
            resultopt1);
    tcg_gen_rem_tl(resultopt1, source1, source2);
    /* if div by zero, just return the original dividend */
    tcg_gen_movcond_tl(TCG_COND_EQ, ret, cond1, zeroreg, resultopt1,
            source1);

    tcg_temp_free(cond1);
    tcg_temp_free(cond2);
    tcg_temp_free(zeroreg);
    tcg_temp_free(resultopt1);
}

static void gen_remu(TCGv ret, TCGv source1, TCGv source2)
{
    TCGv cond1, zeroreg, resultopt1;
    cond1 = tcg_temp_new();
    zeroreg = tcg_const_tl(0);
    resultopt1 = tcg_temp_new();

    tcg_gen_movi_tl(resultopt1, (target_ulong)1);
    tcg_gen_setcondi_tl(TCG_COND_EQ, cond1, source2, 0);
    tcg_gen_movcond_tl(TCG_COND_EQ, source2, cond1, zeroreg, source2,
            resultopt1);
    tcg_gen_remu_tl(resultopt1, source1, source2);
    /* if div by zero, just return the original dividend */
    tcg_gen_movcond_tl(TCG_COND_EQ, ret, cond1, zeroreg, resultopt1,
            source1);

    tcg_temp_free(cond1);
    tcg_temp_free(zeroreg);
    tcg_temp_free(resultopt1);
}

static void gen_jal(DisasContext *ctx, int rd, target_ulong imm)
{
    target_ulong next_pc;

    /* check misaligned: */
    next_pc = ctx->base.pc_next + imm;
    gen_check_branch_target(ctx, next_pc);

    if (!has_ext(ctx, RVC)) {
        if ((next_pc & 0x3) != 0) {
            gen_exception_inst_addr_mis(ctx);
            return;
        }
    }
    /* For CHERI ISAv8 the result is an offset relative to PCC.base */
    gen_set_gpr_const(rd, ctx->pc_succ_insn - pcc_reloc(ctx));

    gen_goto_tb(ctx, 0, ctx->base.pc_next + imm, /*bounds_check=*/true); /* must use this for safety */
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_jalr(DisasContext *ctx, int rd, int rs1, target_ulong imm)
{
    /* no chaining with JALR */
    TCGLabel *misaligned = NULL;
    // Note: We need to use tcg_temp_local_new() for t0 since
    // gen_check_branch_target_dynamic() inserts branches.
    TCGv t0 = tcg_temp_local_new();

    gen_get_gpr(t0, rs1);
    /* For CHERI ISAv8 the destination is an offset relative to PCC.base. */
    tcg_gen_addi_tl(t0, t0, imm + pcc_reloc(ctx));
    tcg_gen_andi_tl(t0, t0, (target_ulong)-2);
    gen_check_branch_target_dynamic(ctx, t0);
    // Note: Only update cpu_pc after a successful bounds check to avoid
    // representability issues caused by directly modifying PCC.cursor.
    tcg_gen_mov_tl(cpu_pc, t0);
    gen_mark_pc_updated();

    if (!has_ext(ctx, RVC)) {
        misaligned = gen_new_label();
        tcg_gen_andi_tl(t0, cpu_pc, 0x2);
        tcg_gen_brcondi_tl(TCG_COND_NE, t0, 0x0, misaligned);
    }

    /* For CHERI ISAv8 the result is an offset relative to PCC.base */
    gen_set_gpr_const(rd, ctx->pc_succ_insn - pcc_reloc(ctx));
    lookup_and_goto_ptr(ctx);

    if (misaligned) {
        gen_set_label(misaligned);
        gen_exception_inst_addr_mis(ctx);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(t0);
}

#ifndef CONFIG_USER_ONLY
/* The states of mstatus_fs are:
 * 0 = disabled, 1 = initial, 2 = clean, 3 = dirty
 * We will have already diagnosed disabled state,
 * and need to turn initial/clean into dirty.
 */
static void mark_fs_dirty(DisasContext *ctx)
{
    TCGv tmp;
    if (ctx->mstatus_fs == MSTATUS_FS) {
        return;
    }
    /* Remember the state change for the rest of the TB.  */
    ctx->mstatus_fs = MSTATUS_FS;

    tmp = tcg_temp_new();
    tcg_gen_ld_tl(tmp, cpu_env, offsetof(CPURISCVState, mstatus));
    tcg_gen_ori_tl(tmp, tmp, MSTATUS_FS | MSTATUS_SD);
    tcg_gen_st_tl(tmp, cpu_env, offsetof(CPURISCVState, mstatus));

    if (ctx->virt_enabled) {
        tcg_gen_ld_tl(tmp, cpu_env, offsetof(CPURISCVState, mstatus_hs));
        tcg_gen_ori_tl(tmp, tmp, MSTATUS_FS | MSTATUS_SD);
        tcg_gen_st_tl(tmp, cpu_env, offsetof(CPURISCVState, mstatus_hs));
    }
    tcg_temp_free(tmp);
}
#else
static inline void mark_fs_dirty(DisasContext *ctx) { }
#endif

static void gen_set_rm(DisasContext *ctx, int rm)
{
    TCGv_i32 t0;

    if (ctx->frm == rm) {
        return;
    }
    ctx->frm = rm;
    t0 = tcg_const_i32(rm);
    gen_helper_set_rounding_mode(cpu_env, t0);
    tcg_temp_free_i32(t0);
}

static int ex_plus_1(DisasContext *ctx, int nf)
{
    return nf + 1;
}

#define EX_SH(amount) \
    static int ex_shift_##amount(DisasContext *ctx, int imm) \
    {                                         \
        return imm << amount;                 \
    }
EX_SH(1)
EX_SH(2)
EX_SH(3)
EX_SH(4)
EX_SH(12)

#define REQUIRE_EXT(ctx, ext) do { \
    if (!has_ext(ctx, ext)) {      \
        return false;              \
    }                              \
} while (0)

static int ex_rvc_register(DisasContext *ctx, int reg)
{
    return 8 + reg;
}

static int ex_rvc_shifti(DisasContext *ctx, int imm)
{
    /* For RV128 a shamt of 0 means a shift by 64. */
    return imm ? imm : 64;
}

static bool pred_capmode(DisasContext *ctx)
{
#ifdef TARGET_CHERI
    return ctx->capmode;
#else
    return false;
#endif
}

/* Include the auto-generated decoder for 32 bit insn */
#include "decode-insn32.c.inc"

static bool gen_arith_imm_fn(DisasContext *ctx, arg_i *a,
                             void (*func)(TCGv, TCGv, target_long))
{
    TCGv source1;
    source1 = tcg_temp_new();

    gen_get_gpr(source1, a->rs1);

    (*func)(source1, source1, a->imm);

    gen_set_gpr(a->rd, source1);
    tcg_temp_free(source1);
    return true;
}

static bool gen_arith_imm_tl(DisasContext *ctx, arg_i *a,
                             void (*func)(TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new();
    source2 = tcg_temp_new();

    gen_get_gpr(source1, a->rs1);
    tcg_gen_movi_tl(source2, a->imm);

    (*func)(source1, source1, source2);

    gen_set_gpr(a->rd, source1);
    tcg_temp_free(source1);
    tcg_temp_free(source2);
    return true;
}

#ifdef TARGET_RISCV64
static void gen_addw(TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_add_tl(ret, arg1, arg2);
    tcg_gen_ext32s_tl(ret, ret);
}

static void gen_subw(TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_sub_tl(ret, arg1, arg2);
    tcg_gen_ext32s_tl(ret, ret);
}

static void gen_mulw(TCGv ret, TCGv arg1, TCGv arg2)
{
    tcg_gen_mul_tl(ret, arg1, arg2);
    tcg_gen_ext32s_tl(ret, ret);
}

static bool gen_arith_div_w(DisasContext *ctx, arg_r *a,
                            void(*func)(TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new();
    source2 = tcg_temp_new();

    gen_get_gpr(source1, a->rs1);
    gen_get_gpr(source2, a->rs2);
    tcg_gen_ext32s_tl(source1, source1);
    tcg_gen_ext32s_tl(source2, source2);

    (*func)(source1, source1, source2);

    tcg_gen_ext32s_tl(source1, source1);
    gen_set_gpr(a->rd, source1);
    tcg_temp_free(source1);
    tcg_temp_free(source2);
    return true;
}

static bool gen_arith_div_uw(DisasContext *ctx, arg_r *a,
                            void(*func)(TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new();
    source2 = tcg_temp_new();

    gen_get_gpr(source1, a->rs1);
    gen_get_gpr(source2, a->rs2);
    tcg_gen_ext32u_tl(source1, source1);
    tcg_gen_ext32u_tl(source2, source2);

    (*func)(source1, source1, source2);

    tcg_gen_ext32s_tl(source1, source1);
    gen_set_gpr(a->rd, source1);
    tcg_temp_free(source1);
    tcg_temp_free(source2);
    return true;
}

#endif

static bool gen_arith(DisasContext *ctx, arg_r *a,
                      void(*func)(TCGv, TCGv, TCGv))
{
    TCGv source1, source2;
    source1 = tcg_temp_new();
    source2 = tcg_temp_new();

    gen_get_gpr(source1, a->rs1);
    gen_get_gpr(source2, a->rs2);

    (*func)(source1, source1, source2);

    gen_set_gpr(a->rd, source1);
    tcg_temp_free(source1);
    tcg_temp_free(source2);
    return true;
}

static bool gen_shift(DisasContext *ctx, arg_r *a,
                        void(*func)(TCGv, TCGv, TCGv))
{
    TCGv source1 = tcg_temp_new();
    TCGv source2 = tcg_temp_new();

    gen_get_gpr(source1, a->rs1);
    gen_get_gpr(source2, a->rs2);

    tcg_gen_andi_tl(source2, source2, TARGET_LONG_BITS - 1);
    (*func)(source1, source1, source2);

    gen_set_gpr(a->rd, source1);
    tcg_temp_free(source1);
    tcg_temp_free(source2);
    return true;
}

static uint32_t opcode_at(DisasContextBase *dcbase, target_ulong pc)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPUState *cpu = ctx->cs;
    CPURISCVState *env = cpu->env_ptr;

    return cpu_ldl_code(env, pc);
}

/* Include insn module translation function */
#ifdef TARGET_CHERI
/* Must be included first since the helpers are used by trans_rvi.c.inc */
#include "insn_trans/trans_cheri.c.inc"
#else
/* Stubs needed for mode-dependent compressed instructions */

typedef arg_i arg_lc;
static inline bool trans_lc(DisasContext *ctx, arg_lc *a)
{
    g_assert_not_reached();
    return false;
}

typedef arg_s arg_sc;
static inline bool trans_sc(DisasContext *ctx, arg_sc *a)
{
    g_assert_not_reached();
    return false;
}

typedef arg_i arg_cincoffsetimm;
static inline bool trans_cincoffsetimm(DisasContext *ctx, arg_cincoffsetimm *a)
{
    g_assert_not_reached();
    return false;
}
#endif
// Helpers to generate a virtual address that has been checked by the CHERI
// capability helpers: If ctx->capmode is set, the register number will be
// a capability and we check that capability, otherwise we treat the register
// as an offset relative to $ddc and check if that is in bounds.
// Note: the return value must be freed with tcg_temp_free_cap_checked()
static inline TCGv_cap_checked_ptr _get_capmode_dependent_addr(
    DisasContext *ctx, int reg_num, target_long regoffs,
#ifdef TARGET_CHERI
    void (*gen_check_cap)(TCGv_cap_checked_ptr, uint32_t, target_long, MemOp),
    void (*check_ddc)(TCGv_cap_checked_ptr, DisasContext *, TCGv, target_ulong),
#endif
    MemOp mop)

{
    TCGv_cap_checked_ptr result = tcg_temp_new_cap_checked();
#ifdef TARGET_CHERI
    if (ctx->capmode) {
        gen_check_cap(result, reg_num, regoffs, mop);
    } else {
        generate_get_ddc_checked_gpr_plus_offset(result, ctx, reg_num, regoffs,
                                                 mop, check_ddc);
    }
#else
    gen_get_gpr(result, reg_num);
    if (!__builtin_constant_p(regoffs) || regoffs != 0) {
        tcg_gen_addi_tl(result, result, regoffs);
    }
#endif
    return result;
}

static inline TCGv_cap_checked_ptr
get_capmode_dependent_load_addr(DisasContext *ctx, int reg_num,
                               target_long regoffs, MemOp mop)
{
    return _get_capmode_dependent_addr(ctx, reg_num, regoffs,
#ifdef TARGET_CHERI
                                       &generate_cap_load_check_imm,
                                       &generate_ddc_checked_load_ptr,
#endif
                                       mop);
}

static inline TCGv_cap_checked_ptr
get_capmode_dependent_store_addr(DisasContext *ctx, int reg_num,
                                target_long regoffs, MemOp mop)
{
    return _get_capmode_dependent_addr(ctx, reg_num, regoffs,
#ifdef TARGET_CHERI
                                       &generate_cap_store_check_imm,
                                       &generate_ddc_checked_store_ptr,
#endif
                                       mop);
}

static inline TCGv_cap_checked_ptr
get_capmode_dependent_rmw_addr(DisasContext *ctx, int reg_num,
                               target_long regoffs, MemOp mop)
{
    return _get_capmode_dependent_addr(ctx, reg_num, regoffs,
#ifdef TARGET_CHERI
                                       &generate_cap_rmw_check_imm,
                                       &generate_ddc_checked_rmw_ptr,
#endif
                                       mop);
}

#include "insn_trans/trans_rvi.c.inc"
#include "insn_trans/trans_rvm.c.inc"
#include "insn_trans/trans_rva.c.inc"
#include "insn_trans/trans_rvf.c.inc"
#include "insn_trans/trans_rvd.c.inc"
#include "insn_trans/trans_rvh.c.inc"
#include "insn_trans/trans_rvv.c.inc"
#include "insn_trans/trans_privileged.c.inc"

/* Include the auto-generated decoder for 16 bit insn */
#include "decode-insn16.c.inc"

static bool trans_c_hint(DisasContext *ctx, arg_c_hint *a)
{
    return true;
}

static void decode_opc(CPURISCVState *env, DisasContext *ctx)
{
#ifdef CONFIG_RVFI_DII
    // We have to avoid memory accesses for injected instructions since
    // the PC could point somewhere invalid.
    uint16_t opcode = env->rvfi_dii_have_injected_insn
                          ? env->rvfi_dii_injected_insn
                          : translator_lduw(env, ctx->base.pc_next);
    gen_rvfi_dii_set_field_const_i64(PC, pc_rdata, ctx->base.pc_next);
#else
    uint16_t opcode = translator_lduw(env, ctx->base.pc_next);
#endif
    /* check for compressed insn */
    if (extract16(opcode, 0, 2) != 3) {
        gen_riscv_log_instr16(ctx, opcode);
        gen_check_pcc_bounds_next_inst(ctx, 2);
        gen_rvfi_dii_set_field_const_i64(INST, insn, opcode);
        if (!has_ext(ctx, RVC)) {
            gen_exception_illegal(ctx);
        } else {
            ctx->pc_succ_insn = ctx->base.pc_next + 2;
            if (!decode_insn16(ctx, opcode)) {
                gen_exception_illegal(ctx);
            }
        }
    } else {
#ifdef CONFIG_RVFI_DII
        // We have to avoid memory accesses for injected instructions since
        // the PC could point somewhere invalid.
        uint16_t next_16 = env->rvfi_dii_have_injected_insn
                          ? (env->rvfi_dii_injected_insn >> 16)
                          : translator_lduw(env, ctx->base.pc_next + 2);
#else
        uint16_t next_16 = translator_lduw(env, ctx->base.pc_next + 2);
#endif
        uint32_t opcode32 = opcode;
        opcode32 = deposit32(opcode32, 16, 16, next_16);
        gen_riscv_log_instr32(ctx, opcode32);
        gen_check_pcc_bounds_next_inst(ctx, 4);
        ctx->pc_succ_insn = ctx->base.pc_next + 4;
        gen_rvfi_dii_set_field_const_i64(INST, insn, opcode32);
        if (!decode_insn32(ctx, opcode32)) {
            gen_exception_illegal(ctx);
        }
    }
}

static void riscv_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPURISCVState *env = cs->env_ptr;
    RISCVCPU *cpu = RISCV_CPU(cs);
    uint32_t tb_flags = ctx->base.tb->flags;

    ctx->pc_succ_insn = ctx->base.pc_first;
    ctx->mem_idx = tb_flags & TB_FLAGS_MMU_MASK;
    ctx->mstatus_fs = tb_flags & TB_FLAGS_MSTATUS_FS;
#ifdef TARGET_CHERI
    ctx->capmode = tb_in_capmode(ctx->base.tb);
    ctx->cheri_v9_semantics = cpu->cfg.ext_cheri_v9;
#endif
    ctx->priv_ver = env->priv_ver;
#if !defined(CONFIG_USER_ONLY)
    if (riscv_has_ext(env, RVH)) {
        ctx->virt_enabled = riscv_cpu_virt_enabled(env);
    } else {
        ctx->virt_enabled = false;
    }
#else
    ctx->virt_enabled = false;
#endif
    ctx->misa = env->misa;
    ctx->frm = -1;  /* unknown rounding mode */
    ctx->ext_ifencei = cpu->cfg.ext_ifencei;
    ctx->vlen = cpu->cfg.vlen;
    ctx->hlsx = FIELD_EX32(tb_flags, TB_FLAGS, HLSX);
    ctx->vill = FIELD_EX32(tb_flags, TB_FLAGS, VILL);
    ctx->sew = FIELD_EX32(tb_flags, TB_FLAGS, SEW);
    ctx->lmul = FIELD_EX32(tb_flags, TB_FLAGS, LMUL);
    ctx->mlen = 1 << (ctx->sew  + 3 - ctx->lmul);
    ctx->vl_eq_vlmax = FIELD_EX32(tb_flags, TB_FLAGS, VL_EQ_VLMAX);
    ctx->cs = cs;
}

static void riscv_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void riscv_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    tcg_gen_insn_start(ctx->base.pc_next);
}

static bool riscv_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                      const CPUBreakpoint *bp)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    gen_update_cpu_pc(ctx->base.pc_next);
    ctx->base.is_jmp = DISAS_NORETURN;
    gen_exception_debug();
    /* The address covered by the breakpoint must be included in
       [tb->pc, tb->pc + tb->size) in order to for it to be
       properly cleared -- thus we increment the PC here so that
       the logic setting tb->size below does the right thing.  */
    ctx->base.pc_next += 4;
    return true;
}

static void riscv_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPURISCVState *env = cpu->env_ptr;

    decode_opc(env, ctx);
    ctx->base.pc_next = ctx->pc_succ_insn;
    gen_rvfi_dii_set_field_const_i64(PC, pc_wdata, ctx->base.pc_next);

    if (ctx->base.is_jmp == DISAS_NEXT) {
        target_ulong page_start;

        page_start = ctx->base.pc_first & TARGET_PAGE_MASK;
        if (ctx->base.pc_next - page_start >= TARGET_PAGE_SIZE) {
            ctx->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static void riscv_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_TOO_MANY:
        /* CHERI PCC bounds check done on next ifetch. */
        gen_goto_tb(ctx, 0, ctx->base.pc_next, /*bounds_check=*/false);
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static void riscv_tr_disas_log(const DisasContextBase *dcbase, CPUState *cpu)
{
#ifndef CONFIG_USER_ONLY
    RISCVCPU *rvcpu = RISCV_CPU(cpu);
    CPURISCVState *env = &rvcpu->env;
#endif

#ifdef CONFIG_RVFI_DII
    if (env->rvfi_dii_have_injected_insn) {
        assert(dcbase->num_insns == 1);
        FILE *logfile = qemu_log_lock();
        uint32_t insn = env->rvfi_dii_injected_insn;
        if (logfile) {
            fprintf(logfile, "IN: %s\n", lookup_symbol(dcbase->pc_first));
            target_disas_buf(stderr, cpu, &insn, sizeof(insn), dcbase->pc_first, 1);
        }
        qemu_log_unlock(logfile);
    }
#else
    qemu_log("IN: %s\n", lookup_symbol(dcbase->pc_first));
#ifndef CONFIG_USER_ONLY
    qemu_log("Priv: "TARGET_FMT_ld"; Virt: "TARGET_FMT_ld"\n", env->priv, env->virt);
#endif
    log_target_disas(cpu, dcbase->pc_first, dcbase->tb->size);
#endif
}

static const TranslatorOps riscv_tr_ops = {
    .init_disas_context = riscv_tr_init_disas_context,
    .tb_start           = riscv_tr_tb_start,
    .insn_start         = riscv_tr_insn_start,
    .breakpoint_check   = riscv_tr_breakpoint_check,
    .translate_insn     = riscv_tr_translate_insn,
    .tb_stop            = riscv_tr_tb_stop,
    .disas_log          = riscv_tr_disas_log,
};

void gen_intermediate_code(CPUState *cs, TranslationBlock *tb, int max_insns)
{
    DisasContext ctx;

    translator_loop(&riscv_tr_ops, &ctx.base, cs, tb, max_insns);
}

void riscv_translate_init(void)
{
    int i;


    /* cpu_gpr[0] is a placeholder for the zero register. Do not use it. */
    /* Use the gen_set_gpr and gen_get_gpr helper functions when accessing */
    /* registers, unless you specifically block reads/writes to reg 0 */
#ifndef TARGET_CHERI
    cpu_gpr[0] = NULL;
    for (i = 1; i < 32; i++) {
        cpu_gpr[i] = tcg_global_mem_new(cpu_env,
            offsetof(CPURISCVState, gpr[i]), riscv_int_regnames[i]);
    }
#else
    /* CNULL cursor should never be written! */
    _cpu_cursors_do_not_access_directly[0] = NULL;
    /*
     * Provide fast access to integer part of capability registers using
     * gen_get_gpr() and get_set_gpr(). But don't expose the cpu_gprs TCGv
     * directly to avoid errors.
     */
    for (i = 1; i < 32; i++) {
        _cpu_cursors_do_not_access_directly[i] = tcg_global_mem_new(
            cpu_env,
            offsetof(CPURISCVState, gpcapregs.decompressed[i].cap._cr_cursor),
            riscv_int_regnames[i]);
    }
#endif
#ifdef CONFIG_RVFI_DII
    cpu_rvfi_available_fields = tcg_global_mem_new_i32(
        cpu_env, offsetof(CPURISCVState, rvfi_dii_trace.available_fields),
        "rvfi_available_fields");
#endif

    for (i = 0; i < 32; i++) {
        cpu_fpr[i] = tcg_global_mem_new_i64(cpu_env,
            offsetof(CPURISCVState, fpr[i]), riscv_fpr_regnames[i]);
    }

#ifdef TARGET_CHERI
    cpu_pc = tcg_global_mem_new(cpu_env,
                                offsetof(CPURISCVState, PCC._cr_cursor), "pc");
    /// XXXAR: We currently interpose using DDC.cursor and not DDC.base!
    ddc_interposition = tcg_global_mem_new(
        cpu_env, offsetof(CPURISCVState, DDC._cr_cursor), "ddc_interpose");
#else
    cpu_pc = tcg_global_mem_new(cpu_env, offsetof(CPURISCVState, pc), "pc");
#endif
    cpu_vl = tcg_global_mem_new(cpu_env, offsetof(CPURISCVState, vl), "vl");
#ifdef CONFIG_DEBUG_TCG
    _pc_is_current = tcg_global_mem_new(
        cpu_env, offsetof(CPURISCVState, _pc_is_current), "_pc_is_current");
#endif
    load_res = (TCGv_cap_checked_ptr)tcg_global_mem_new(
        cpu_env, offsetof(CPURISCVState, load_res), "load_res");
    load_val = tcg_global_mem_new(cpu_env, offsetof(CPURISCVState, load_val),
                             "load_val");
}

void gen_cheri_break_loadlink(TCGv_cap_checked_ptr out_addr)
{
    // The SC implementation uses load_res directly, and apparently this helper
    // can be called from inside the addr==load_res check and the cmpxchg being
    // executed.
    // Until this is fixed, comment out the invalidation
    // tcg_gen_movi_tl((TCGv)load_res, -1);
}
