/*
 *  MIPS translation routines.
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef TARGET_MIPS_TRANSLATE_H
#define TARGET_MIPS_TRANSLATE_H

#include "exec/translator.h"
#include "tcg/tcg-op.h"

#define MIPS_DEBUG_DISAS 0

typedef struct DisasContext {
    DisasContextBase base;
    target_ulong saved_pc;
    target_ulong page_start;
    uint32_t opcode;
    uint64_t insn_flags;
    int32_t CP0_Config1;
    int32_t CP0_Config2;
    int32_t CP0_Config3;
    int32_t CP0_Config5;
    /* Routine used to access memory */
    int mem_idx;
    MemOp default_tcg_memop_mask;
    uint32_t hflags, saved_hflags;
    target_ulong btarget;
    bool ulri;
    int kscrexist;
    bool rxi;
    int ie;
    bool bi;
    bool bp;
    uint64_t PAMask;
    bool mvh;
    bool eva;
    bool sc;
    int CP0_LLAddr_shift;
    bool ps;
    bool vp;
    bool cmgcr;
    bool mrp;
    bool nan2008;
    bool abs2008;
#ifndef TARGET_CHERI
    bool saar; /* This conflicts with the cheri RTC mfc/mtc */
#endif /* TARGET_CHERI */
    bool mi;
    int gi;
} DisasContext;

/* MIPS major opcodes */
#define MASK_OP_MAJOR(op)   (op & (0x3F << 26))

#define OPC_CP1 (0x11 << 26)

/* Coprocessor 1 (rs field) */
#define MASK_CP1(op)                (MASK_OP_MAJOR(op) | (op & (0x1F << 21)))

/* Values for the fmt field in FP instructions */
enum {
    /* 0 - 15 are reserved */
    FMT_S = 16,          /* single fp */
    FMT_D = 17,          /* double fp */
    FMT_E = 18,          /* extended fp */
    FMT_Q = 19,          /* quad fp */
    FMT_W = 20,          /* 32-bit fixed */
    FMT_L = 21,          /* 64-bit fixed */
    FMT_PS = 22,         /* paired single fp */
    /* 23 - 31 are reserved */
};

enum {
    OPC_MFC1     = (0x00 << 21) | OPC_CP1,
    OPC_DMFC1    = (0x01 << 21) | OPC_CP1,
    OPC_CFC1     = (0x02 << 21) | OPC_CP1,
    OPC_MFHC1    = (0x03 << 21) | OPC_CP1,
    OPC_MTC1     = (0x04 << 21) | OPC_CP1,
    OPC_DMTC1    = (0x05 << 21) | OPC_CP1,
    OPC_CTC1     = (0x06 << 21) | OPC_CP1,
    OPC_MTHC1    = (0x07 << 21) | OPC_CP1,
    OPC_BC1      = (0x08 << 21) | OPC_CP1, /* bc */
    OPC_BC1ANY2  = (0x09 << 21) | OPC_CP1,
    OPC_BC1ANY4  = (0x0A << 21) | OPC_CP1,
    OPC_S_FMT    = (FMT_S << 21) | OPC_CP1,
    OPC_D_FMT    = (FMT_D << 21) | OPC_CP1,
    OPC_E_FMT    = (FMT_E << 21) | OPC_CP1,
    OPC_Q_FMT    = (FMT_Q << 21) | OPC_CP1,
    OPC_W_FMT    = (FMT_W << 21) | OPC_CP1,
    OPC_L_FMT    = (FMT_L << 21) | OPC_CP1,
    OPC_PS_FMT   = (FMT_PS << 21) | OPC_CP1,
    OPC_BC1EQZ   = (0x09 << 21) | OPC_CP1,
    OPC_BC1NEZ   = (0x0D << 21) | OPC_CP1,
};

#define MASK_CP1_FUNC(op)           (MASK_CP1(op) | (op & 0x3F))
#define MASK_BC1(op)                (MASK_CP1(op) | (op & (0x3 << 16)))

enum {
    OPC_BC1F     = (0x00 << 16) | OPC_BC1,
    OPC_BC1T     = (0x01 << 16) | OPC_BC1,
    OPC_BC1FL    = (0x02 << 16) | OPC_BC1,
    OPC_BC1TL    = (0x03 << 16) | OPC_BC1,
};

enum {
    OPC_BC1FANY2     = (0x00 << 16) | OPC_BC1ANY2,
    OPC_BC1TANY2     = (0x01 << 16) | OPC_BC1ANY2,
};

enum {
    OPC_BC1FANY4     = (0x00 << 16) | OPC_BC1ANY4,
    OPC_BC1TANY4     = (0x01 << 16) | OPC_BC1ANY4,
};

void generate_exception(DisasContext *ctx, int excp);
void generate_exception_err(DisasContext *ctx, int excp, int err);
void generate_exception_end(DisasContext *ctx, int excp);
void gen_reserved_instruction(DisasContext *ctx);

void check_insn(DisasContext *ctx, uint64_t flags);
void check_mips_64(DisasContext *ctx);
void check_cp0_enabled(DisasContext *ctx);
void check_cp1_enabled(DisasContext *ctx);
void check_cp1_64bitmode(DisasContext *ctx);
void check_cp1_registers(DisasContext *ctx, int regs);
void check_cop1x(DisasContext *ctx);

void gen_base_offset_addr(DisasContext *ctx, TCGv addr, int base, int offset);
void gen_move_low32(TCGv ret, TCGv_i64 arg);
void gen_move_high32(TCGv ret, TCGv_i64 arg);
void gen_load_gpr(TCGv t, int reg);
/*
 * Hack to forward extra arguments to _gen_store_gpr without changing
 * existing calls. This assumes that the DisasContext ctx argument is
 * present at call sites.
 */
#define gen_store_gpr(t, reg) _gen_store_gpr(ctx, t, reg)
void _gen_store_gpr(DisasContext *ctx, TCGv t, int reg);
#if defined(TARGET_MIPS64)
void gen_load_gpr_hi(TCGv_i64 t, int reg);
void gen_store_gpr_hi(TCGv_i64 t, int reg);
#endif /* TARGET_MIPS64 */
void gen_load_fpr32(DisasContext *ctx, TCGv_i32 t, int reg);
void gen_load_fpr64(DisasContext *ctx, TCGv_i64 t, int reg);
void gen_store_fpr32(DisasContext *ctx, TCGv_i32 t, int reg);
void gen_store_fpr64(DisasContext *ctx, TCGv_i64 t, int reg);
int get_fp_bit(int cc);

/*
 * Address Computation and Large Constant Instructions
 */
void gen_op_addr_add(DisasContext *ctx, TCGv ret, TCGv arg0, TCGv arg1);
bool gen_lsa(DisasContext *ctx, int rd, int rt, int rs, int sa);
bool gen_dlsa(DisasContext *ctx, int rd, int rt, int rs, int sa);

void gen_rdhwr(DisasContext *ctx, int rt, int rd, int sel);

extern TCGv cpu_gpr[32], cpu_PC;
#if defined(TARGET_MIPS64)
extern TCGv_i64 cpu_gpr_hi[32];
#endif
extern TCGv cpu_HI[MIPS_DSP_ACC], cpu_LO[MIPS_DSP_ACC];
extern TCGv_i32 fpu_fcr0, fpu_fcr31;
extern TCGv_i64 fpu_f64[32];
extern TCGv bcond;

#define LOG_DISAS(...)                                                        \
    do {                                                                      \
        if (MIPS_DEBUG_DISAS) {                                               \
            qemu_log_mask(CPU_LOG_TB_IN_ASM, ## __VA_ARGS__);                 \
        }                                                                     \
    } while (0)

#define MIPS_INVAL(op)                                                        \
    do {                                                                      \
        if (MIPS_DEBUG_DISAS) {                                               \
            qemu_log_mask(CPU_LOG_TB_IN_ASM,                                  \
                          TARGET_FMT_lx ": %08x Invalid %s %03x %03x %03x\n", \
                          ctx->base.pc_next, ctx->opcode, op,                 \
                          ctx->opcode >> 26, ctx->opcode & 0x3F,              \
                          ((ctx->opcode >> 16) & 0x1F));                      \
        }                                                                     \
    } while (0)

#ifdef CONFIG_TCG_LOG_INSTR
/*
 * Generate helper to log general purpose register update by the
 * instruction.
 */
static inline void gen_log_instr_gpr_update(DisasContext *ctx, int reg)
{
    if (unlikely(ctx->base.log_instr_enabled)) {
        TCGv_i32 regnum = tcg_const_i32(reg);
        gen_helper_mips_log_instr_gpr(cpu_env, regnum, cpu_gpr[reg]);
        tcg_temp_free_i32(regnum);
    }
}

/*
 * Generate helper to log Cop0 register updates.
 * This handles updates that do not go through helpers.
 */
static inline void gen_log_instr_cop0_update(DisasContext *ctx, int reg,
                                             int sel, target_ulong offset)
{
    if (unlikely(ctx->base.log_instr_enabled)) {
        TCGv_i32 treg = tcg_const_i32(reg);
        TCGv_i32 tsel = tcg_const_i32(sel);
        TCGv tv = tcg_temp_new();
        tcg_gen_ld_tl(tv, cpu_env, offset);
        gen_helper_mips_log_instr_cop0(cpu_env, treg, tsel, tv);
        tcg_temp_free(tv);
        tcg_temp_free_i32(treg);
        tcg_temp_free_i32(tsel);
    }
}

/*
 * Generate helper to log HI/LO register updates.
 */
static inline void gen_log_instr_hilo_update(DisasContext *ctx, int hiLO,
                                             int index, int reg)
{
    if (likely(!ctx->base.log_instr_enabled))
        return;

    TCGv_i32 thilo = tcg_const_i32(hiLO);
    TCGv_i32 tindex = tcg_const_i32(index);
    if (reg == 0) {
        //  cpu_gpr[0] is NULL and should not be used.
        TCGv tzero = tcg_const_tl(0);
        gen_helper_mips_log_instr_hilo(cpu_env, thilo, tindex, tzero);
        tcg_temp_free(tzero);
    } else {
        gen_helper_mips_log_instr_hilo(cpu_env, thilo, tindex, cpu_gpr[reg]);
    }
    tcg_temp_free_i32(thilo);
    tcg_temp_free_i32(tindex);
}

ATTRIBUTE_UNUSED static void _debug_value(TCGv value, const char* msg) {
    TCGv_ptr dbg_msg = tcg_const_ptr(msg);
    gen_helper_log_value(cpu_env, dbg_msg, value);
    tcg_temp_free_ptr(dbg_msg);
}
#define DEBUG_VALUE(value) _debug_value(value, #value)

#else
#define DEBUG_VALUE(value) ((void)0)
#define gen_log_instr_gpr_update(ctx, reg) ((void)0)
#define gen_log_instr_cop0_update(ctx, reg, sel, off) ((void)0)
#define gen_log_instr_hilo_update(ctx, hiLO, index, reg) ((void)0)
#endif

/* MSA */
void msa_translate_init(void);

/* MXU */
void mxu_translate_init(void);
bool decode_ase_mxu(DisasContext *ctx, uint32_t insn);

/* decodetree generated */
bool decode_isa_rel6(DisasContext *ctx, uint32_t insn);
bool decode_ase_msa(DisasContext *ctx, uint32_t insn);
bool decode_ext_txx9(DisasContext *ctx, uint32_t insn);
#if defined(TARGET_MIPS64)
bool decode_ext_tx79(DisasContext *ctx, uint32_t insn);
#endif

#endif
