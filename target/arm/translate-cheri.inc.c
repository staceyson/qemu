/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Lawrence Esswood
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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

// Included from translate-a64.c

#include "decode-cheri.c.inc"

#define TRACE_MEMOP_TRANSLATION 0

// For the most part, new morello instructions seem to use the variant where 31
// is SP, and X regs varies a lot

#define SE_64(Val, Width) (uint64_t) sextract64(Val, 0, Width)
#define SE_32(Val, Width) (int32_t) sextract32(Val, 0, Width)

#define ONES(X) ((1ULL << (X)) - 1)

#define TRANS_F(NAME) static bool trans_##NAME(DisasContext *ctx, arg_##NAME *a)

typedef void(cheri_cap_cap_imm_helper)(TCGv_env, TCGv_i32, TCGv_i32, TCGv);
static inline bool gen_cheri_cap_cap_imm(DisasContext *ctx, int cd, int cn,
                                         target_long imm,
                                         cheri_cap_cap_imm_helper *gen_func)
{
    TCGv_i32 dest_regnum = tcg_const_i32(cd);
    TCGv_i32 source_regnum = tcg_const_i32(cn);
    TCGv imm_value = tcg_const_tl(imm);
    disas_capreg_state_set_unknown(ctx, cd);
    disas_capreg_state_set_unknown(ctx, cn);
    gen_func(cpu_env, dest_regnum, source_regnum, imm_value);
    tcg_temp_free(imm_value);
    tcg_temp_free_i32(source_regnum);
    tcg_temp_free_i32(dest_regnum);
    return true;
}

typedef void(cheri_cap_cap_cap_helper)(TCGv_env, TCGv_i32, TCGv_i32, TCGv_i32);
static inline bool gen_cheri_cap_cap_cap(DisasContext *ctx, int cd, int cn,
                                         int cm,
                                         cheri_cap_cap_cap_helper *gen_func)
{
    TCGv_i32 dest_regnum = tcg_const_i32(cd);
    TCGv_i32 source_regnum1 = tcg_const_i32(cn);
    TCGv_i32 source_regnum2 = tcg_const_i32(cm);
    disas_capreg_state_set_unknown(ctx, cd);
    disas_capreg_state_set_unknown(ctx, cn);
    disas_capreg_state_set_unknown(ctx, cm);
    gen_func(cpu_env, dest_regnum, source_regnum1, source_regnum2);
    tcg_temp_free_i32(source_regnum2);
    tcg_temp_free_i32(source_regnum1);
    tcg_temp_free_i32(dest_regnum);
    return true;
}

typedef void(cheri_cap_cap_int_helper)(TCGv_env, TCGv_i32, TCGv_i32, TCGv);
static inline bool gen_cheri_cap_cap_int_imm(DisasContext *ctx, int cd, int cn,
                                             int rm, target_long imm,
                                             cheri_cap_cap_int_helper *gen_func)
{
    TCGv_i32 dest_regnum = tcg_const_i32(cd);
    TCGv_i32 source_regnum = tcg_const_i32(cn);
    TCGv gpr_value = read_cpu_reg(ctx, rm, 1);
    if (imm != 0) {
        tcg_gen_addi_tl(gpr_value, gpr_value, imm);
    }
    disas_capreg_state_set_unknown(ctx, cd);
    disas_capreg_state_set_unknown(ctx, cn);
    gen_func(cpu_env, dest_regnum, source_regnum, gpr_value);
    tcg_temp_free_i32(source_regnum);
    tcg_temp_free_i32(dest_regnum);
    return true;
}
static inline bool gen_cheri_cap_cap_int(DisasContext *ctx, int cd, int cn,
                                         int rm,
                                         cheri_cap_cap_int_helper *gen_func)
{
    return gen_cheri_cap_cap_int_imm(ctx, cd, cn, rm, 0, gen_func);
}

enum ADDR_OPS {
    OP_ALIGN_DOWN = 0,
    OP_OR = 1,
    OP_EOR = 2,
    OP_ALIGN_UP,
    OP_SET,
};

#define OP_AND_NOT OP_ALIGN_DOWN

static inline bool gen_cheri_addr_op_imm(DisasContext *ctx, int cd,
                                         uint64_t val, enum ADDR_OPS op,
                                         bool flags_only)
{

    TCGv_i64 result = read_cpu_reg_sp(ctx, cd, 1);

    switch (op) {
    case OP_OR:
        tcg_gen_ori_i64(result, result, val);
        break;
    case OP_EOR:
        tcg_gen_xori_i64(result, result, val);
        break;
    case OP_ALIGN_UP:
        tcg_gen_addi_i64(result, result, val);
    case OP_ALIGN_DOWN:
        tcg_gen_andi_i64(result, result, ~val);
        break;
    default:
        assert(0);
    }

    gen_cap_set_cursor(ctx, cd, result, flags_only);
    gen_reg_modified_cap(ctx, cd);
    return true;
}

static inline bool gen_cheri_addr_op_tcgval(DisasContext *ctx, int cd,
                                            TCGv_i64 val, enum ADDR_OPS op,
                                            bool flags_only)
{

    TCGv_i64 result = read_cpu_reg_sp(ctx, cd, 1);

    switch (op) {
    case OP_SET:
        tcg_gen_andi_i64(result, result, ~(0xFFULL << 56));
    case OP_OR:
        tcg_gen_or_i64(result, result, val);
        break;
    case OP_EOR:
        tcg_gen_xor_i64(result, result, val);
        break;
    case OP_ALIGN_UP:
        tcg_gen_add_i64(result, result, val);
    case OP_ALIGN_DOWN:
        tcg_gen_andc_i64(result, result, val);
        break;
    default:
        assert(0);
    }

    gen_cap_set_cursor(ctx, cd, result, flags_only);
    gen_reg_modified_cap(ctx, cd);
    return true;
}

#define TRANSLATE_UNDEF(MORELLO_NAME)                                          \
    TRANS_F(MORELLO_NAME)                                                      \
    {                                                                          \
        assert(0 && #MORELLO_NAME " not implemented");                         \
    }

#define TRANSLATE_REDUNDANT(MORELLO_NAME)                                      \
    TRANS_F(MORELLO_NAME)                                                      \
    {                                                                          \
        return false;                                                          \
    }

static void set_flag(TCGv_i32 dest, TCGv_i32 source, int shift,
                     int default_value)
{
    if (source) {
        if (shift == 0) {
            tcg_gen_mov_i32(dest, source);
        } else {
            tcg_gen_shli_i32(dest, source, shift);
        }
    } else {
        tcg_gen_movi_i32(dest, default_value);
    }
}

// Set N,Z,C,V with either null (constant 0), or a TCGv containing only a 0
// or 1.
static void set_NZCV(DisasContext *ctx, TCGv_i32 N, TCGv_i32 Z, TCGv_i32 C,
                     TCGv_i32 V)
{

    qemu_log_gen_printf(&ctx->base, "wwww",
                        "Modified NZCV: N=%d, Z=%d, C=%d, V=%d.\n", N, Z, C, V);

    if (Z) {
        tcg_gen_setcondi_i32(TCG_COND_EQ, Z, Z, 0);
    }
    set_flag(cpu_NF, N, 31, 0);
    set_flag(cpu_ZF, Z, 0, 1);
    set_flag(cpu_CF, C, 0, 0);
    set_flag(cpu_VF, V, 31, 0);
}

#define OPTION_NONE 0xff

static inline TCGv_i64 cpu_reg_maybe_0(DisasContext *ctx, int regnum)
{
    if (regnum == NULL_CAPREG_INDEX) {
        return cpu_reg(ctx, 31);
    } else {
        return cpu_reg_sp(ctx, regnum);
    }
}

static inline TCGv_i64 read_cpu_reg_maybe_0(DisasContext *ctx, int regnum)
{
    if (regnum == NULL_CAPREG_INDEX) {
        return read_cpu_reg(ctx, 31, 1);
    } else {
        return read_cpu_reg_sp(ctx, regnum, 1);
    }
}


/**
 * Load/store common code. Most of these options should optimise away.
 *
 * @rd: first register to load/store
 * @rd2: second register to load/store
 * @rn: base register
 * @rm: offset register (extended by option and shift). Also the result register
 *      for an exclusive operation.
 * @imm: immediate offset
 * @size: log2 of number of bytes to load/store
 * @extend_size: extend the result to this size after load (also log2)
 * @pre_inc: pre-increment base register
 * @post_inc: post-increment base register
 * @alternate_base: swaps use of capability / DDC base reg in C64 / non-C64 mode
 * @exclusive: perform an exclusive operation (arm version of load-link
 *             store-conditional)
 * @pcc_base: enforce use of PCC, regardless of C64 / alternate_base
 * @acquire_release: will do either an load-acquire / store-release, or both
 *                   if set to 2
 * @swap: indicates the operation is a swap, not a pair load/store. swap = 2
 *        performs a CAS
 * @unpriv: Perform an unprivileged load/store (i.e. as EL0)
 */
static inline __attribute__((always_inline)) bool load_store_implementation(
    DisasContext *ctx, bool is_load, bool vector, uint32_t rd, uint32_t rd2,
    uint8_t size, uint8_t extend_size, uint32_t rn, uint32_t rm,
    target_ulong imm, bool pre_inc, bool post_inc, bool non_temporal_hint,
    bool alternate_base, bool pcc_base, bool exclusive, int acquire_release,
    int swap, int option, unsigned int shift, bool unpriv)
{
    // base on capability rn, otherwise ddc (or maybe even pcc) with rn as
    // value/offset In C64 base is the cap provided, or DDC/PCC otherwise.
    // Alternate is the opposite.
    bool capability_base = !pcc_base && (IS_C64(ctx) != alternate_base);

    assert(size <= 4);

#if (TRACE_MEMOP_TRANSLATION)
    printf("CTX pc cur: %lx\n", ctx->pc_curr);
    printf(
        "Memop: %s vec:%d rd:%d rd2:%d size:%d extend:%d rn:%d rm:%d imm:%ld. "
        "AB? %d. CB? %d. pcc_base? %d. pre %d. post %d. opt: %d. shift %d.\n",
        is_load ? "load" : "store", vector, rd, rd2, size, extend_size, rn, rm,
        imm, alternate_base, capability_base, pcc_base, pre_inc, post_inc,
        option, shift);
    if (rn != REG_NONE)
        gen_cap_debug(ctx, rn);
    if (rm != REG_NONE)
        gen_cap_debug(ctx, rm);
#endif

    // Some combinations not implemented
    assert(!(exclusive && vector));
    assert(!swap || (size == 4 && !vector));

    if (vector) {
        if (!fp_access_check(ctx)) {
            return true;
        }
    }

    if (rn == 31)
        gen_check_sp_alignment(ctx);

    TCGv_i64 addr;

    // Get integer component of base
    if (rn == REG_NONE) {
        // For PCC/DDC relative things there is no base rn
        int64_t addr_imm = imm;
        if (pcc_base) {
            // So this is really only to support LDR (literal).
            // PCC Base offset is ignored, everything is relative to PCC cursor,
            // rounded to a cap.
            addr_imm = (ctx->pc_curr + imm) & ~(CHERI_CAP_SIZE - 1);
        }
        addr = tcg_const_i64(addr_imm);
    } else {
        // Things with a base (still unchecked)
        addr = read_cpu_reg_maybe_0(ctx, rn);
        if (imm != 0 && !post_inc) {
            tcg_gen_addi_i64(addr, addr, imm);
        }
    }

    TCGv_i64 wb;
    // There are too many places we might accidentally add DDC base, so if we
    // are going to store back, take a copy
    if ((pre_inc || post_inc)) {
        wb = tcg_temp_local_new_i64();
        tcg_gen_mov_i64(wb, addr);
    }

    // Now add register offset if any
    if (rm != REG_NONE && !exclusive) {
        TCGv_i64 tcg_rm = read_cpu_reg_maybe_0(ctx, rm);
        if (option != OPTION_NONE) {
            ext_and_shift_reg(tcg_rm, tcg_rm, option, shift);
        }
        tcg_gen_add_i64(addr, addr, tcg_rm);
    }

    // Just special casing capabilities for now until we get better TCG handling
    // for caps
    if (size == 4 && !vector) {
        uint32_t base_reg = capability_base ? rn
                                            : (pcc_base ? CHERI_EXC_REGNUM_PCC
                                                        : CHERI_EXC_REGNUM_DDC);

        TCGv_i32 tcg_base_reg = tcg_const_i32(base_reg);
        TCGv_i32 tcg_rd = tcg_const_i32(rd);

        TCGv_i32 tcg_rd2 = NULL;

        // Only one helper for exclusive, we just pass REG_NONE
        if (rd2 != REG_NONE || exclusive) {
            tcg_rd2 = tcg_const_i32(rd2);
        }

        if (!capability_base) {
            // might have to add base of ppc / ddc
            if (!pcc_base && cctlr_set(ctx, CCTLR_DDCBO)) {
                tcg_gen_add_i64(addr, addr, ddc_interposition);
            }
        }

        if (is_load || swap) {

            disas_capreg_state_set_unknown(ctx, rd);

            if (rd2 != REG_NONE) {
                disas_capreg_state_set_unknown(ctx, rd2);
            }
        }

        if (exclusive) {
            tcg_debug_assert(!unpriv);
            if (is_load) {
                gen_helper_load_exclusive_cap_via_cap(cpu_env, tcg_rd, tcg_rd2,
                                                      tcg_base_reg, addr);
            } else {
                TCGv_i32 tcg_rm = tcg_const_i32(rm);
                disas_capreg_state_set(ctx, rm, CREG_INTEGER);
                gen_helper_store_exclusive_cap_via_cap(
                    cpu_env, tcg_rm, tcg_rd, tcg_rd2, tcg_base_reg, addr);
                tcg_temp_free_i32(tcg_rm);
            }
        } else if (rd2 == REG_NONE) {
            if (unpriv) {
                TCGv_i32 tcg_idx = tcg_const_i32(get_a64_user_mem_index(ctx));
                (is_load ? gen_helper_load_cap_via_cap_mmu_idx
                         : gen_helper_store_cap_via_cap_mmu_idx)(
                    cpu_env, tcg_rd, tcg_base_reg, addr, tcg_idx);
                tcg_temp_free_i32(tcg_idx);
            } else {
                (is_load ? gen_helper_load_cap_via_cap
                         : gen_helper_store_cap_via_cap)(cpu_env, tcg_rd, addr,
                                                         tcg_base_reg);
            }

        } else {
            tcg_debug_assert(!unpriv);
            void (*helper_fn)(TCGv_ptr, TCGv_i32, TCGv_i32, TCGv_i32, TCGv);

            if (swap == 2)
                helper_fn = &gen_helper_compare_swap_cap_via_cap;
            else if (swap == 1)
                helper_fn = &gen_helper_swap_cap_via_cap;
            else if (is_load)
                helper_fn = &gen_helper_load_cap_pair_via_cap;
            else
                helper_fn = &gen_helper_store_cap_pair_via_cap;

            helper_fn(cpu_env, tcg_rd, tcg_rd2, tcg_base_reg, addr);
        }

        tcg_temp_free_i32(tcg_base_reg);
        tcg_temp_free_i32(tcg_rd);

        if (tcg_rd2 != NULL || exclusive) {
            tcg_temp_free_i32(tcg_rd2);
        }

    } else {
        // Calculate src/dst registers and base
        assert(rd != REG_NONE);

        // Perform bounds checks and do load / stores
        int memidx = unpriv ? get_a64_user_mem_index(ctx) : get_mem_index(ctx);

        TCGv_cap_checked_ptr checked =
            gen_mte_and_cheri_check1(ctx, addr, is_load, !is_load, false,
                                     (rd2 == REG_NONE) ? size : (size + 1), rn,
                                     alternate_base, !pcc_base);

        if (exclusive) {
            uint32_t rd_0 = STANDARD_ZERO(rd);
            uint32_t rd2_0 = STANDARD_ZERO(rd2);

            if (is_load) {
                gen_load_exclusive(ctx, rd_0, rd2_0, checked, size,
                                   rd2 != REG_NONE);
            } else {
                gen_store_exclusive(ctx, STANDARD_ZERO(rm), rd_0, rd2_0,
                                    checked, size, rd2 != REG_NONE);
            }
        } else if (!vector) {
            MemOp memop = ctx->be_data + size;

            bool fault_unaligned = exclusive || acquire_release;
            if (fault_unaligned || memop_align_sctlr(ctx))
                memop |= MO_ALIGN;

            TCGv_i64 tcg_rd = cpu_reg_maybe_0(ctx, rd);
            TCGv_i64 tcg_rd2;

            if (rd2 != REG_NONE) {
                tcg_rd2 = cpu_reg_maybe_0(ctx, rd2);
            }

            // Do the actual load / stores
            TCGv_i64 load_tmp = tcg_rd;

            // If loading two things we have to not make any modifications until
            // the second has succeeded
            if (is_load && (rd2 != REG_NONE)) {
                load_tmp = tcg_temp_new_i64();
            }

            void (*mem_op_fn)(TCGv_i64, TCGv_cap_checked_ptr, TCGArg, MemOp);

            mem_op_fn = is_load ? &tcg_gen_qemu_ld_i64_with_checked_addr
                                : &tcg_gen_qemu_st_i64_with_checked_addr;

            mem_op_fn(tcg_rd, checked, memidx, memop);

            if (is_load)
                gen_lazy_cap_set_int(ctx, rd);

            if (rd2 != REG_NONE) {
                // already checked, just coerce
                tcg_gen_addi_i64((TCGv_i64)checked, (TCGv_i64)checked,
                                 1 << size);
                mem_op_fn(tcg_rd2, checked, memidx, memop);
                if (is_load) {
                    gen_lazy_cap_set_int(ctx, rd2);
                    // Now the second load has finished we can store the first
                    // one back
                    tcg_gen_mov_i64(tcg_rd, load_tmp);
                    tcg_temp_free_i64(load_tmp);
                }
            }

            // Sign extend
            if (extend_size > size) {
                assert(rd2 == REG_NONE);
                assert(is_load);
                assert(extend_size == 3 || extend_size == 2);
                switch (size) {
                case 0:
                    tcg_gen_ext8s_i64(tcg_rd, tcg_rd);
                    break;
                case 1:
                    tcg_gen_ext16s_i64(tcg_rd, tcg_rd);
                    break;
                case 2:
                    tcg_gen_ext32s_i64(tcg_rd, tcg_rd);
                    break;
                default:
                    assert(0);
                }
                if (extend_size == 2) {
                    tcg_gen_andi_i64(tcg_rd, tcg_rd, 0xFFFFFFFF);
                }
            }
        } else {
            if (is_load) {
                do_fp_ld(ctx, rd, checked, size);
            } else {
                do_fp_st(ctx, rd, checked, size);
            }
        }
    }

    if (acquire_release) {
        TCGBar bar = TCG_MO_ALL;
        if ((acquire_release == 2) || is_load)
            bar |= TCG_BAR_LDAQ;
        if ((acquire_release == 2) || !is_load)
            bar |= TCG_BAR_STRL;
        tcg_gen_mb(bar);
    }

    // Add immediate afterwards if post incrementing
    if (post_inc && imm != 0) {
        tcg_gen_addi_i64(wb, wb, imm);
    }

    if (post_inc || pre_inc) {
        assert(!exclusive); // otherwise this temp will have died
        set_gpr_reg_addr_base(ctx, rn, wb, capability_base);
        tcg_temp_free_i64(wb);
    }

    if (rn == REG_NONE) {
        tcg_temp_free_i64(addr);
    }

    return true;
}

// All the instructions

TRANS_F(ADR)
{
    if (a->Rd == 31)
        return true;

    // The lack of a capabilities enabled check here is intentional

    bool c64 = IS_C64(ctx);
    bool P_in_immediate = (!a->op) || !c64;
    bool page_align = a->op;
    bool sign_extend = !(c64 && a->op && !a->P);
    bool pcc = !c64 || !a->op || a->P;
    bool adrdpb = cctlr_set(ctx, CCTLR_ADRDPB);

    // Concat bits together for immediate
    int width = 18 + 2;
    uint64_t im = P_in_immediate ? a->P << 18 : 0;
    if (P_in_immediate)
        width++;
    im = (((im | a->immhi) << 2) | a->immlo);

    // Shift if page aligning
    if (page_align) {
        im <<= 12;
        width += 12;
    }

    // Sign extend
    if (sign_extend) {
        im = SE_64(im, width);
    }

    // Do this early as it contains a branch
    if (!pcc && adrdpb)
        gen_ensure_cap_decompressed(ctx, 28);

    TCGv_i64 new_addr = tcg_temp_new_i64();

    // First get the address
    if (pcc) {
        // Can just work this out as a constant
        uint64_t result = im + ctx->pc_curr;
        if (!c64) {
            result -= pcc_reloc(ctx);
        }
        if (page_align) {
            result &= ~((1 << 12) - 1);
        }
        tcg_gen_movi_i64(new_addr, result);
    } else {
        if (adrdpb) {
            gen_cap_get_cursor(ctx, 28, new_addr);
        } else {
            tcg_gen_ld_i64(new_addr, cpu_env,
                           offsetof(CPUARMState, DDC_current) +
                               offsetof(cap_register_t, _cr_cursor));
        }
        tcg_gen_addi_i64(new_addr, new_addr, im);
        tcg_gen_andi_i64(new_addr, new_addr, ~((1 << 12) - 1));
    }

    if (c64) {
        // Derive a capability

        if (pcc || !adrdpb) {
            if (!pcc)
                tcg_gen_sync_i64(ddc_interposition);
            gen_move_cap_gp_sp(ctx, a->Rd,
                               pcc ? offsetof(CPUARMState, pc)
                                   : offsetof(CPUARMState, DDC_current));
        } else {
            gen_move_cap_gp_gp(ctx, a->Rd, 28);
        }

        gen_cap_set_cursor_fast(ctx, a->Rd, new_addr);
        gen_reg_modified_cap(ctx, a->Rd);

    } else {
        // Derive an integer
        tcg_gen_mov_i64(cpu_reg(ctx, a->Rd), new_addr);
        gen_lazy_cap_set_int(ctx, a->Rd);
    }

    tcg_temp_free_i64(new_addr);

    return true;
}

TRANS_F(ADD_SUB)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    uint64_t imm = a->imm12;
    if (a->sh)
        imm <<= 12;
    if (a->A)
        imm = -imm;

    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);

    TCGv_i64 increment = tcg_const_i64(imm);

    gen_cap_add_fast(ctx, a->Cd, increment);

    tcg_temp_free_i64(increment);
    gen_reg_modified_cap(ctx, a->Cd);
    return true;
}

// This covers all the pairs
TRANS_F(LDP_STP)
{
    bool load = a->L;

    if (a->op1 == 0 && a->op2 != 0b11) {
        bool op = a->imm7 >> 6;
        uint32_t rs = (a->imm7 >> 1) & 0b11111;
        bool o2 = a->imm7 & 1;

        if (a->op2 == 1) {
            // Load / Store exclusive family
            // o2: acquire/release
            // CT all 1's when only single register
            // Rs (status) all 1's for loads
            bool pair = op;
            if (load && rs != 0b11111)
                return false;

            if (!pair && a->Ct2 != 0b11111)
                return false;

            if (capabilities_enabled_exception(ctx))
                return true;

            return load_store_implementation(ctx, load, false, AS_ZERO(a->Ct),
                                             pair ? AS_ZERO(a->Ct2) : REG_NONE,
                                             4, 4, a->Rn, AS_ZERO(rs), 0, false,
                                             false, false, false, false, true,
                                             o2, 0, OPTION_NONE, 0, false);
        } else if (a->op2 == 2) {
            // acquire/release
            if (rs != 0b11111)
                return false;
            if (a->Ct2 != 0b11111)
                return false;

            if (capabilities_enabled_exception(ctx))
                return true;

            bool alternate_base = op || !o2;
            uint64_t size = op == 0 ? 4 : (o2 ? 2 : 0);
            return load_store_implementation(
                ctx, load, false, AS_ZERO(a->Ct), REG_NONE, size, size, a->Rn,
                REG_NONE, 0, false, false, false, alternate_base, false, false,
                true, 0, OPTION_NONE, 0, false);
        } else
            return false;
    } else if (a->op1 == 0b00 || a->op1 == 0b01) {
        // 01 01 post-index
        // 11 01 pre-index
        // 11 00 non-temporal
        // 10 01 signed

        bool non_temporal_hint = a->op1 == 0b00;
        if (non_temporal_hint)
            if (a->op2 != 0b11)
                return false;

        if (capabilities_enabled_exception(ctx))
            return true;

        bool pre_inc = !non_temporal_hint && (a->op2 == 0b11);
        bool post_inc = !non_temporal_hint && (a->op2 == 0b01);
        uint64_t imm = SE_64((a->imm7 << 4), 11);
        return load_store_implementation(
            ctx, a->L, false, AS_ZERO(a->Ct), AS_ZERO(a->Ct2), 4, 4, a->Rn,
            REG_NONE, imm, pre_inc, post_inc, non_temporal_hint, false, false,
            false, false, 0, OPTION_NONE, 0, false);
    } else
        return false;
}

TRANS_F(ADD1)
{
    if (a->imm3 > 4)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    gen_ensure_cap_decompressed(ctx, a->Cn);
    TCGv_i64 extended = read_cpu_reg(ctx, a->Rm, 1);
    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);

    // extended int
    ext_and_shift_reg(extended, extended, a->option_name, a->imm3);

    gen_cap_add_fast(ctx, a->Cd, extended);
    gen_reg_modified_cap(ctx, a->Cd);
    return true;
}

// Load/Store unscaled immediate via alternate base
TRANS_F(AUR)
{
    int size, extend_size;
    bool is_load;

    if (a->V && a->op1 && (a->op2 > 1))
        return false;

    if ((a->op1 == 0b11) && (!a->V) && (a->op2 == 0b10))
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    if (!a->V) {
        size = ((a->op2 == 0b11) && (a->op1 >= 0b10)) ? 4 : a->op1;
        is_load = !((a->op2 == 0b00) || ((a->op2 == 0b11) && (a->op1 == 0b10)));
        extend_size = (a->op2 == 0b10) ? 3 : ((a->op2 == 0b11) ? 2 : 0);
        if (extend_size < size)
            extend_size = size;
    } else {
        is_load = a->op2 & 1;
        size = ((a->op1) == 0 && (a->op2 & 2)) ? 4 : a->op1;
        extend_size = size;
    }
    return load_store_implementation(
        ctx, is_load, a->V, a->V ? a->Rt : AS_ZERO(a->Rt), REG_NONE, size,
        extend_size, a->Rn, REG_NONE, SE_64(a->imm9, 9), false, false, false,
        true, false, false, false, 0, OPTION_NONE, 0, false);
}

TRANS_F(ALIGN)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    return gen_cheri_addr_op_imm(ctx, a->Cd, ONES(a->imm6),
                                 a->U ? OP_ALIGN_UP : OP_ALIGN_DOWN, false);
}

TRANS_F(FLGS)
{
    if (a->op == 0b11)
        return false;
    if (capabilities_enabled_exception(ctx))
        return true;

    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    return gen_cheri_addr_op_imm(ctx, a->Cd, (uint64_t)a->imm8 << 56ULL,
                                 (enum ADDR_OPS)a->op, true);
}

static bool cvt_impl_ptr_to_cap(DisasContext *ctx, uint32_t cd, uint32_t cn,
                                uint32_t rm, bool zero_is_null, bool pcc_bo)
{

    bool base_off = (pcc_bo && cctlr_set(ctx, CCTLR_PCCBO)) ||
                    (!pcc_bo && cctlr_set(ctx, CCTLR_DDCBO));

    if (cd == NULL_CAPREG_INDEX)
        return true;

    bool special_move =
        cn == CHERI_EXC_REGNUM_DDC || cn == CHERI_EXC_REGNUM_PCC;

    if (!special_move)
        gen_ensure_cap_decompressed(ctx, cn);

    TCGv_i64 tcg_rm = cd == rm ? read_cpu_reg(ctx, rm, 1) : cpu_reg(ctx, rm);

    // Move cap
    if (special_move) {
        if (cn == CHERI_EXC_REGNUM_DDC)
            tcg_gen_sync_i64(ddc_interposition);
        gen_move_cap_gp_sp(ctx, cd,
                           (cn == CHERI_EXC_REGNUM_DDC)
                               ? offsetof(CPUARMState, DDC_current)
                               : offsetof(CPUARMState, pc));
    } else {
        gen_move_cap_gp_gp(ctx, cd, cn);
    }

    TCGv_i64 new_cursor = tcg_temp_local_new_i64();

    TCGv_i64 temp = tcg_temp_new_i64();

    // TODO PCC/DDC base known at translate time. Could do a better job.
    if (base_off) {
        gen_cap_get_base(ctx, cd, temp);
        tcg_gen_add_i64(new_cursor, tcg_rm, temp);
    } else {
        tcg_gen_mov_i64(new_cursor, tcg_rm);
    }

    TCGLabel *l1;

    if (zero_is_null) {
        l1 = gen_new_label();
        tcg_gen_movi_i64(temp, 0);
        // If rm != 0
        tcg_gen_brcond_i64(TCG_COND_EQ, tcg_rm, temp, l1);
    }

    // Set cursor
    gen_cap_set_cursor(ctx, cd, new_cursor, false);

    if (zero_is_null) {
        TCGLabel *l2 = gen_new_label();
        tcg_gen_br(l2);
        gen_set_label(l1);
        // else ...
        tcg_gen_movi_i64(cpu_reg(ctx, cd), 0);    // cursor = 0
        gen_lazy_cap_set_int_cond(ctx, cd, true); // set int
        gen_set_label(l2);
    }

    tcg_temp_free_i64(new_cursor);
    tcg_temp_free_i64(temp);

    gen_reg_modified_cap(ctx, cd);

    return true;
}

static bool cvt_impl_cap_to_ptr(DisasContext *ctx, uint32_t rd, uint32_t cn,
                                uint32_t cm, bool pcc_bo)
{
    bool base_off = (pcc_bo && cctlr_set(ctx, CCTLR_PCCBO)) ||
                    (!pcc_bo && cctlr_set(ctx, CCTLR_DDCBO));

    TCGv_i64 temp = tcg_temp_new_i64();
    TCGv_i64 base;

    if (base_off) {
        if (cm == CHERI_EXC_REGNUM_DDC) {
            base = ddc_interposition;
        } else {
            base = temp;
            if (cm == CHERI_EXC_REGNUM_PCC) {
                // FIXME: PCC base is know at translate time
                tcg_gen_ld_i64(base, cpu_env,
                               offsetof(CPUARMState, pc) +
                                   offsetof(cap_register_t, cr_base));
            } else {
                gen_cap_get_base(ctx, cm, base);
            }
        }
    }

    TCGv_i64 result = read_cpu_reg(ctx, rd, 1);

    gen_cap_get_cursor(ctx, cn, result);

    // subtract base
    if (base_off)
        tcg_gen_sub_i64(result, result, base);

    // Is also always flag setting.

    TCGv_i32 tag32 = tcg_temp_new_i32();
    gen_cap_get_tag_i32(ctx, cn, tag32);

    tcg_gen_extu_i32_i64(temp, tag32);
    tcg_gen_neg_i64(temp, temp);
    // result = cn_tagged ? result : 0
    tcg_gen_and_i64(result, result, temp);

    tcg_gen_movi_i64(temp, 0);
    // temp = result == 0
    tcg_gen_setcond_i64(TCG_COND_EQ, temp, result, temp);

    TCGv_i32 z = tcg_temp_new_i32();
    tcg_gen_extrl_i64_i32(z, temp);

    // z = (result == 0) && cn_tagged
    tcg_gen_and_i32(z, z, tag32);
    // c == cn_tagged
    set_NZCV(ctx, NULL, z, tag32, NULL);

    tcg_gen_mov_i64(cpu_reg(ctx, rd), result);

    gen_lazy_cap_set_int(ctx, rd);

    tcg_temp_free_i64(temp);
    tcg_temp_free_i32(tag32);
    tcg_temp_free_i32(z);

    return true;
}

TRANS_F(CVT)
{
    if (capabilities_enabled_exception(ctx))
        return true;
    return cvt_impl_ptr_to_cap(ctx, AS_ZERO(a->Cd), a->Cn, a->Rm, false, false);
}
TRANS_F(CVT1)
{
    if (capabilities_enabled_exception(ctx))
        return true;
    return cvt_impl_ptr_to_cap(ctx, AS_ZERO(a->Cd), a->Cn, a->Rm, true, false);
}

TRANS_F(SUBS)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    // We want to use the same add with carry logic regardless of whether
    // comparing tags or value gen_adc_CC expects a 64-bit value to add.
    // Comparing tags use two 2-bit values, so we can shift them up 62 places,
    // do a gen_adc, then shift down 62 places.

    TCGv_i64 tag1 = tcg_temp_new_i64();
    TCGv_i64 tag2 = tcg_temp_new_i64();
    gen_cap_get_tag(ctx, AS_ZERO(a->Cn), tag1);
    gen_cap_get_tag(ctx, AS_ZERO(a->Cm), tag2);
    tcg_gen_shli_i64(tag1, tag1, 62);
    tcg_gen_shli_i64(tag2, tag2, 62);

    TCGv_i64 shift = tcg_temp_new_i64();
    TCGv_i64 value1 = tcg_const_i64(0);
    TCGv_i64 value2 = tcg_const_i64(62);

    // shift = tag1 == tag2 ? 0 : 62
    tcg_gen_movcond_i64(TCG_COND_EQ, shift, tag1, tag2, value1, value2);
    // valuex = tag1 == tag2 ? (cursorx : tagx)
    tcg_gen_movcond_i64(TCG_COND_EQ, value1, tag1, tag2, cpu_reg(ctx, a->Cn),
                        tag1);
    tcg_gen_movcond_i64(TCG_COND_EQ, value2, tag1, tag2, cpu_reg(ctx, a->Cm),
                        tag2);

    tcg_temp_free_i64(tag1);
    tcg_temp_free_i64(tag2);

    TCGv_i64 result = cpu_reg(ctx, a->Rd);

    // negate value 2 and set carry in to one
    tcg_gen_not_i64(value2, value2);
    tcg_gen_movi_i32(cpu_CF, 1);
    gen_adc_CC(1, result, value1, value2);

    // Shift result down again (if we were comparing tags)
    tcg_gen_shr_i64(result, result, shift);

    gen_lazy_cap_set_int(ctx, AS_ZERO(a->Rd));

    tcg_temp_free_i64(shift);
    tcg_temp_free_i64(value1);
    tcg_temp_free_i64(value2);

    return true;
}

TRANS_F(FLGS_CTHI)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    int cn = a->opc == 0b11 ? AS_ZERO(a->Cn) : a->Cn;
    gen_ensure_cap_decompressed(ctx, cn);
    TCGv_i64 rm = read_cpu_reg(ctx, a->Rm, 1);
    gen_move_cap_gp_gp(ctx, a->Cd, cn);

    if (a->opc == 0b11) { // cn/cm as zero
        gen_cap_set_pesbt(ctx, a->Cd, rm);
        gen_reg_modified_cap(ctx, a->Cd);
        return true;
    } else { // cm as zero
        tcg_gen_andi_i64(rm, rm, 0xFFULL << 56);
        return gen_cheri_addr_op_tcgval(ctx, a->Cd, rm, a->opc, true);
    }
}

static TCGv get_link_addr(DisasContext *ctx)
{
    return tcg_const_tl(ctx->base.pc_next);
}

static TCGv_i32 get_link_reg(DisasContext *ctx, bool link)
{
    if (link)
        disas_capreg_state_set(ctx, 30, CREG_FULLY_DECOMPRESSED);
    return tcg_const_i32(link ? 30 : NULL_CAPREG_INDEX);
}

static bool should_be_executive(DisasContext *ctx)
{
    if (!GET_FLAG(ctx, EXECUTIVE)) {
        unallocated_encoding(ctx);
        return true;
    }
    return false;
}

static TCGv_i32 get_branch_flags(DisasContext *ctx, bool can_branch_restricted)
{
    uint32_t flags = 0;
    if (!cctlr_set(ctx, CCTLR_SBL))
        flags |= CJALR_DONT_MAKE_SENTRY;
    if (can_branch_restricted) {
        flags |= CJALR_CAN_BRANCH_RESTRICTED;
        should_be_executive(ctx);
    }

    return tcg_const_i32(flags);
}

TRANS_F(BLR_BR_RET_CHKD)
{
    // Some instructions are undef due in restricted mode _before_ caps enabled
    // is checked:
    // RETR, BRR, BLRR
    // Others this is reversed.

    // op:
    //  00 is branch indirect
    //  01 are checks
    //  10 is branch sealed (slightly diffrent behavior if unsealed)
    //  11 is branch restricted (same behavior as sealed basically)
    // opc:
    //  00: BR
    //  01: BLR
    //  10: RET
    //  11: BX (requires CN = 0b11111, op == 0b00)

    if (a->op == 0b01) {
        if (a->opc > 0b01)
            return false;
        if (capabilities_enabled_exception(ctx))
            return true;

        TCGv_i32 tag = NULL;
        TCGv_i32 sealed = NULL;
        switch (a->opc) {
        case 0b00: // CHKSLD
            sealed = tcg_temp_new_i32();
            gen_cap_get_sealed_i32(ctx, a->Cn, sealed);
            break;
        case 0b01: // CHKTGD
            tag = tcg_temp_new_i32();
            gen_cap_get_tag_i32(ctx, a->Cn, tag);
            break;
        default:
            g_assert_not_reached();
        }
        set_NZCV(ctx, NULL, NULL, tag, sealed);
        if (tag)
            tcg_temp_free_i32(tag);
        if (sealed)
            tcg_temp_free_i32(sealed);
        return true;
    }

    if (a->op == 0b11) {
        should_be_executive(ctx);
    }

    if (a->opc == 0b11 && a->Cn != 0b11111)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    if (a->opc == 0b11) {
        // BX is not _really_ a branch, just a mode switch.
        // Flip pstate.C64
        TCGv_i32 pstate = tcg_temp_new_i32();
        tcg_gen_ld_i32(pstate, cpu_env, offsetof(CPUARMState, pstate));
        tcg_gen_xori_i32(pstate, pstate, PSTATE_C64);
        tcg_gen_st_i32(pstate, cpu_env, offsetof(CPUARMState, pstate));
        // update hflags because we know that a bit will have changed
        TCGv_i32 tcg_el = tcg_const_i32(ctx->current_el);
        gen_helper_rebuild_hflags_a64(cpu_env, tcg_el);
        // Also exit the translation block
        ctx->base.is_jmp = DISAS_UPDATE_EXIT;
        tcg_temp_free_i32(tcg_el);
        tcg_temp_free_i32(pstate);

    } else {
        uint32_t source = AS_ZERO(a->Cn);
        // Sealed / restricted branches must branch to sentries if SBL set
        int sbl = cctlr_set(ctx, CCTLR_SBL);
        if (sbl && (a->op >= 0b10))
            source |= CJALR_MUST_BE_SENTRY;
        // Can only go into restricted mode if this branch is used
        if (a->op == 0b11)
            source |= CJALR_CAN_BRANCH_RESTRICTED;
        // Only make sentries in sbl mode
        if (!sbl)
            source |= CJALR_DONT_MAKE_SENTRY;

        TCGv_i32 target_regnum = tcg_const_i32(source);

        TCGv_i32 link_regnum = get_link_reg(ctx, a->opc == 0b01);

        TCGv link_addr = get_link_addr(ctx);
        TCGv cjalr_imm = tcg_const_tl(0);

        disas_capreg_state_set_unknown(ctx, AS_ZERO(a->Cn));
        gen_helper_cjalr(cpu_env, link_regnum, target_regnum, cjalr_imm,
                         link_addr);

        tcg_temp_free(cjalr_imm);
        tcg_temp_free(link_addr);
        tcg_temp_free_i32(target_regnum);
        tcg_temp_free_i32(link_regnum);

        ctx->base.is_jmp = DISAS_JUMP;
    }

    return true;
}

// Unseal load branches
TRANS_F(BR_BLR)
{

    if (capabilities_enabled_exception(ctx))
        return true;

    TCGv_i32 cn = tcg_const_i32(a->Cn);
    TCGv_i32 offset = tcg_const_i32(SE_32(a->imm7 << 4, 11));
    TCGv_i32 link = get_link_reg(ctx, a->link);
    TCGv link_addr = get_link_addr(ctx);
    TCGv_i32 flags = get_branch_flags(ctx, false);

    disas_capreg_state_set(ctx, a->Cn, CREG_FULLY_DECOMPRESSED);
    gen_helper_load_and_branch_and_link(cpu_env, cn, offset, link, link_addr,
                                        flags);

    tcg_temp_free_i32(cn);
    tcg_temp_free_i32(offset);
    tcg_temp_free_i32(link);
    tcg_temp_free(link_addr);
    tcg_temp_free_i32(flags);

    ctx->base.is_jmp = DISAS_JUMP;

    return true;
}

// Branch sealed pair
TRANS_F(BRS)
{

    if (a->opc == 0b11)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    TCGv_i32 flags = get_branch_flags(ctx, false);

    // Branch and link sealed
    bool link = a->opc == 0b01;
    TCGv_i32 cn = tcg_const_i32(AS_ZERO(a->Cn));
    TCGv_i32 cm = tcg_const_i32(AS_ZERO(a->Cm));
    TCGv_i32 linkreg = get_link_reg(ctx, link);
    TCGv link_addr = get_link_addr(ctx);

    disas_capreg_state_set(ctx, AS_ZERO(a->Cn), CREG_FULLY_DECOMPRESSED);
    disas_capreg_state_set(ctx, AS_ZERO(a->Cm), CREG_FULLY_DECOMPRESSED);
    disas_capreg_state_set(ctx, 29, CREG_FULLY_DECOMPRESSED);

    gen_helper_branch_sealed_pair(cpu_env, cn, cm, linkreg, link_addr, flags);

    tcg_temp_free_i32(cn);
    tcg_temp_free_i32(cm);
    tcg_temp_free_i32(flags);
    tcg_temp_free_i32(linkreg);
    tcg_temp_free_i64(link_addr);

    ctx->base.is_jmp = DISAS_JUMP;

    return true;
}

TRANS_F(CHK)
{
    if (a->opc > 0b01)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    TCGv_i32 n = NULL;
    TCGv_i32 z = NULL;
    switch (a->opc) {
    case 0b00: // CHKSS
    {
        TCGv_i64 ss_and_tagged = tcg_temp_new_i64();
        gen_cap_is_subset_and_tag_eq(ctx, a->Cn, a->Cm, ss_and_tagged);
        n = tcg_temp_new_i32();
        tcg_gen_extrl_i64_i32(n, ss_and_tagged);
        tcg_temp_free_i64(ss_and_tagged);
        break;
    }
    case 0b01: // CHKEQ
        z = tcg_temp_new_i32();
        gen_cap_get_eq_i32(ctx, a->Cn, AS_ZERO(a->Cm), z);
        break;
    default:
        g_assert_not_reached();
    }

    set_NZCV(ctx, n, z, NULL, NULL);
    if (n)
        tcg_temp_free_i32(n);
    if (z)
        tcg_temp_free_i32(z);

    return true;
}

TRANS_F(CAS)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    return load_store_implementation(ctx, a->L, false, AS_ZERO(a->Ct),
                                     AS_ZERO(a->Cs), 4, 4, a->Rn, REG_NONE, 0,
                                     false, false, false, false, false, false,
                                     a->L + a->R, 2, OPTION_NONE, 0, false);
}

TRANS_F(BUILD_CSEAL_CPYE)
{

    if (capabilities_enabled_exception(ctx))
        return true;

    uint32_t cn = a->Cn;
    uint32_t cm = a->Cm;
    uint32_t cd = a->Cd;

    if (a->opc & 1) {
        // cpytype / cpyvalue treat reg 31 as zero reg.
        cn = AS_ZERO(cn);
        cm = AS_ZERO(cm);
        cd = AS_ZERO(cd);
    }

    // Might need to move to a temp so cm is not clobbered
    uint32_t cd_temp = cd == cm ? SCRATCH_REG_NUM : cd;

    gen_move_cap_gp_gp(ctx, cd_temp, cn);

    switch (a->opc) {
    case 0b00: // BUILD
    {
        gen_ensure_cap_decompressed(ctx, cm);
        // new_tag = (old_tag && !sealed) || (cm tagged && !cm sealed &&
        // subset(d, cm) && !above_limit(data))
        TCGv_i64 result = tcg_temp_new_i64();
        TCGv_i64 temp0 = tcg_const_i64(0);
        TCGv_i64 temp1 = tcg_temp_new_i64();

        gen_cap_get_unsealed(ctx, cd_temp, result);
        // Set type to unsealed
        gen_cap_set_type_unchecked(ctx, cd_temp, temp0);

        gen_cap_get_tag(ctx, cd_temp, temp0);
        tcg_gen_and_i64(result, result, temp0);

        gen_cap_get_tag(ctx, cm, temp1);

        gen_cap_get_unsealed(ctx, cm, temp0);
        tcg_gen_and_i64(temp1, temp1, temp0);

        gen_cap_is_subset(ctx, cd_temp, cm, temp0);
        tcg_gen_and_i64(temp1, temp1, temp0);

        gen_cap_get_base_below_top(ctx, cd_temp, temp0);
        tcg_gen_and_i64(temp1, temp1, temp0);
        tcg_gen_or_i64(result, result, temp1);

        gen_cap_set_tag(ctx, cd_temp, result, false);

        tcg_temp_free_i64(result);
        tcg_temp_free_i64(temp0);
        tcg_temp_free_i64(temp1);
        break;
    }

    case 0b01: // CPYTYPE
    {
        TCGv_i64 type = tcg_temp_new_i64();
        gen_cap_get_type_for_copytype(ctx, cm, type);
        gen_cap_set_cursor(ctx, cd_temp, type, false);
        tcg_temp_free_i64(type);
        break;
    }
    case 0b10: // CSEAL
    {
        TCGv_i64 success = tcg_temp_new_i64();
        gen_cap_seal(ctx, cd_temp, cm, true, success);
        TCGv_i32 v = tcg_temp_new_i32();
        tcg_gen_extrl_i64_i32(v, success);
        set_NZCV(ctx, NULL, NULL, NULL, v);
        tcg_temp_free_i32(v);
        tcg_temp_free_i64(success);
        break;
    }
    case 0b11: // CPYVALUE
        gen_cap_set_cursor(ctx, cd_temp, read_cpu_reg(ctx, a->Cm, 1), false);
        break;
    }

    if (cd == cm) {
        gen_move_cap_gp_gp(ctx, cd, cd_temp);
    }

    gen_reg_modified_cap(ctx, cd);

    return true;
}

TRANS_F(CLRPERM)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    gen_ensure_cap_decompressed(ctx, a->Cn);
    TCGv_i64 rmv = read_cpu_reg(ctx, a->Rm, 1);
    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    gen_cap_clear_perms(ctx, a->Cd, rmv, true);
    gen_cap_untag_if_sealed(ctx, a->Cd);
    gen_reg_modified_cap(ctx, a->Cd);
    return true;
}

static bool isTagSettingDisabled(DisasContext *ctx)
{
    // This flag is maps to the correct CSR for the current exception level
    return GET_FLAG(ctx, SETTAG) ? true : false;
}

// Set capability tag. Got weirdly named by script
TRANS_F(SCG)
{

    if (ctx->current_el == 0)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    gen_ensure_cap_decompressed(ctx, a->Cn);
    TCGv_i64 tcgrm = read_cpu_reg(ctx, a->Rm, 1);

    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);

    // Then set state
    if (!isTagSettingDisabled(ctx) && cheri_is_system_ctx(ctx)) {
        gen_cap_set_tag(ctx, a->Cd, tcgrm, true);
    } else {
        gen_lazy_cap_set_state(ctx, a->Cd, CREG_UNTAGGED_CAP);
    }

    gen_reg_modified_cap(ctx, a->Cd);

    return true;
}

// SCFLGS. Also weird named, likely because SCTAGS and SCFLGS looked too
// similar.
TRANS_F(SCG1)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    gen_ensure_cap_decompressed(ctx, a->Cn);
    TCGv_i64 flag_bits = read_cpu_reg(ctx, a->Rm, 1);
    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    tcg_gen_andi_i64(flag_bits, flag_bits, 0xFFULL << 56);

    gen_cheri_addr_op_tcgval(ctx, a->Cd, flag_bits, OP_SET, true);

    gen_reg_modified_cap(ctx, a->Cd);

    return true;
}

TRANS_F(CLRTAG_CPY)
{
    // 10 is cpy, 00 is clr tag
    if (a->opc & 1)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    if (!(a->opc))
        gen_cap_clear_tag(ctx, a->Cd);

    gen_reg_modified_cap(ctx, a->Cd);

    return true;
}

// Seal (immediate, for special types)
TRANS_F(SEAL)
{
    if (a->form == 0)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    target_ulong types[] = {0, CAP_OTYPE_SENTRY, CAP_OTYPE_LOAD_PAIR_BRANCH,
                            CAP_OTYPE_LOAD_BRANCH};
    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    gen_cap_set_type_const(ctx, a->Cd, types[a->form], true);
    gen_reg_modified_cap(ctx, a->Cd);
    return true;
}

TRANS_F(SEAL_CHKSSU)
{

    if (a->opc == 0b11)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    int cd = AS_ZERO(a->Cd);

    // These instructions may actually need a temp unlike the rest
    bool need_scratch = (a->Cd == a->Cm) || (cd == NULL_CAPREG_INDEX);

    int cd_temp = need_scratch ? SCRATCH_REG_NUM : cd;

    gen_move_cap_gp_gp(ctx, cd_temp, a->opc == 0b10 ? a->Cn : AS_ZERO(a->Cn));

    switch (a->opc) {
    case 0b00: // SEAL
        gen_cap_seal(ctx, cd_temp, AS_ZERO(a->Cm), false, NULL);
        break;
    case 0b01: // UNSEAL
        gen_cap_unseal(ctx, cd_temp, AS_ZERO(a->Cm));
        break;
    case 0b10: // CHKSSU
    {
        int cm = a->Cm;
        TCGv_i64 ss_and_tagged = tcg_temp_new_i64();
        gen_cap_is_subset_and_tag_eq(ctx, cd_temp, cm, ss_and_tagged);
        TCGv_i32 n = tcg_temp_new_i32();
        tcg_gen_extrl_i64_i32(n, ss_and_tagged);
        set_NZCV(ctx, n, NULL, NULL, NULL);
        tcg_temp_free_i32(n);

        // type = ss_and_tagged && cm tagged && !cm sealed ? unsealed : type
        TCGv_i64 temp = tcg_temp_new_i64();
        gen_cap_get_tag(ctx, cm, temp);
        tcg_gen_and_i64(ss_and_tagged, ss_and_tagged, temp);
        gen_cap_get_unsealed(ctx, cm, temp);
        tcg_gen_and_i64(ss_and_tagged, ss_and_tagged, temp);
        _Static_assert(CAP_OTYPE_UNSEALED == 0, "");
        tcg_gen_movi_i64(temp, 1);
        tcg_gen_sub_i64(ss_and_tagged, ss_and_tagged, temp);
        gen_cap_get_type(ctx, cd_temp, temp);
        tcg_gen_and_i64(temp, temp, ss_and_tagged);
        gen_cap_set_type_unchecked(ctx, cd_temp, temp);

        tcg_temp_free_i64(temp);
        tcg_temp_free_i64(ss_and_tagged);

        break;
    }
    default:
        g_assert_not_reached();
    }

    if (need_scratch)
        gen_move_cap_gp_gp(ctx, cd, cd_temp);

    gen_reg_modified_cap(ctx, cd);

    return true;
}

TRANS_F(CSEL)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    gen_ensure_cap_decompressed(ctx, AS_ZERO(a->Cn));
    gen_ensure_cap_decompressed(ctx, AS_ZERO(a->Cm));
    DisasCompare cmp;
    arm_test_cc(&cmp, a->cond);
    gen_move_cap_gp_select_gp(ctx, AS_ZERO(a->Cd), AS_ZERO(a->Cn),
                              AS_ZERO(a->Cm), cmp.cond, cmp.value);
    arm_free_cc(&cmp);
    return true;
}

TRANS_F(CFHI)
{
    if (a->opc == 0b11)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    TCGv_i64 dst = cpu_reg(ctx, a->Rd);

    switch (a->opc) {
    case 0b00: // GCLIM
        gen_cap_get_top_clamped(ctx, a->Cn, dst);
        break;
    case 0b01: // GCFLGS
        gen_cap_get_flags(ctx, a->Cn, dst);
        break;
    case 0b10: // CFHI
        gen_cap_get_hi(ctx, a->Cn, dst);
        break;
    default:
        g_assert_not_reached();
    }

    gen_lazy_cap_set_int(ctx, AS_ZERO(a->Rd));
    return true;
}
// CVT with PCC / DDC as a base, cap -> ptr
TRANS_F(CVT2)
{
    if (a->opc > 0b01)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    bool pcc = (a->opc & 1) != 0;
    return cvt_impl_cap_to_ptr(
        ctx, a->Rd, a->Cn, pcc ? CHERI_EXC_REGNUM_PCC : CHERI_EXC_REGNUM_DDC,
        pcc);
}

TRANS_F(GC)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    int regnum = a->Cn;
    TCGv_i64 result = cpu_reg(ctx, a->Rd);

    switch (a->opc) {
    case 0b000: // base
        gen_cap_get_base(ctx, regnum, result);
        break;
    case 0b001: // len
        gen_cap_get_length(ctx, regnum, result);
        break;
    case 0b010: // value
        gen_cap_get_cursor(ctx, regnum, result);
        break;
    case 0b011: // off
        gen_cap_get_offset(ctx, regnum, result);
        break;
    case 0b100: // tag
        gen_cap_get_tag(ctx, regnum, result);
        break;
    case 0b101: // seal
        gen_cap_get_sealed(ctx, regnum, result);
        break;
    case 0b110: // perm
        gen_cap_get_perms(ctx, regnum, result);
        break;
    case 0b111: // type
        gen_cap_get_type(ctx, regnum, result);
        break;
    }

    gen_lazy_cap_set_int(ctx, AS_ZERO(a->Rd));
    return true;
}

TRANS_F(LDPBR)
{
    if (a->opc >= 2)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    bool link = a->opc == 0b01;
    TCGv_i32 link_regnum = get_link_reg(ctx, link);
    TCGv_i32 pair_regnum = tcg_const_i32(a->Cn);
    TCGv_i32 data_regnum = tcg_const_i32(AS_ZERO(a->Ct));
    TCGv_i32 flag_tcg = get_branch_flags(ctx, false);
    TCGv link_addr = get_link_addr(ctx);

    disas_capreg_state_set_unknown(ctx, AS_ZERO(a->Ct));
    disas_capreg_state_set(ctx, a->Cn, CREG_FULLY_DECOMPRESSED);
    gen_helper_load_pair_and_branch_and_link(cpu_env, pair_regnum, data_regnum,
                                             link_regnum, link_addr, flag_tcg);

    tcg_temp_free(link_addr);
    tcg_temp_free_i32(flag_tcg);
    tcg_temp_free_i32(data_regnum);
    tcg_temp_free_i32(pair_regnum);
    tcg_temp_free_i32(link_regnum);

    ctx->base.is_jmp = DISAS_JUMP;

    return true;
}

TRANS_F(LDR)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    return load_store_implementation(
        ctx, true, false, AS_ZERO(a->Ct), REG_NONE, 4, 4, REG_NONE, REG_NONE,
        SE_64(a->imm17 << 4, 21), false, false, false, false, true, false,
        false, 0, OPTION_NONE, 0, false);
}

// op:  00 capsized
//      01 byte
//      10 word
//      11 dw
static uint64_t size_log(uint64_t op)
{
    return (op & 2) ? op : (op == 0 ? 4 : 0);
}

// imm9 with op for different sizes
TRANS_F(LDR_STR)
{
    // op:      01 post increment
    //          11 pre increment
    //          10 immediate translated
    //          00 unscaled immediate

    // opc:     0L
    if (a->opc & 2)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    bool pre = (a->op == 0b11);
    bool post = (a->op == 0b01);
    bool unpriv = (a->op == 0b10);
    bool scale = (a->op != 0b00);

    uint64_t imm = a->imm9;
    if (scale)
        imm <<= 4;
    imm = SE_64(imm, scale ? 13 : 9);

    return load_store_implementation(ctx, a->opc & 1, false, AS_ZERO(a->Ct),
                                     REG_NONE, 4, 4, a->Rn, REG_NONE, imm, pre,
                                     post, false, false, false, false, false, 0,
                                     OPTION_NONE, 0, unpriv);
}

// imm12
TRANS_F(LDR_STR1)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    return load_store_implementation(ctx, a->L, false, AS_ZERO(a->Ct), REG_NONE,
                                     4, 4, a->Rn, REG_NONE, a->imm12 << 4,
                                     false, false, false, false, false, false,
                                     false, 0, OPTION_NONE, 0, false);
}

TRANS_F(LDR_STR2)
{
    if (!(a->option_name & 0b10))
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    return load_store_implementation(
        ctx, a->opc == 0b01, false, AS_ZERO(a->Ct), REG_NONE, 4, 4, a->Rn,
        AS_ZERO(a->Rm), 0, false, false, false, false, false, false, false, 0,
        a->option_name, a->S ? 4 : 0, false);
}

TRANS_F(MRS_MSR)
{
    // MRS/MSR might touch the backing memory of DDC, which has its base as a
    // global SYNC before the operation, and discard after.
    // FIXME: Bit of a hack doing this here
    tcg_gen_sync_i64(ddc_interposition);
    handle_sys(ctx, 0x1 << 25, a->L, a->o0 + 2, a->op1, a->op2, a->CRn, a->CRm,
               a->Ct);
    tcg_gen_discard_i64(ddc_interposition);
    return true;
}

TRANS_F(RR)
{
    if (a->opc > 0b01)
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    void (*helper)(TCGv, TCGv_env, TCGv);

    switch (a->opc) {
    case 0: // RRLEN
        helper = &gen_helper_crap;
        break;
    case 1: // RRMASK
        helper = &gen_helper_cram;
        break;
    default:
        g_assert_not_reached();
    }

    helper(cpu_reg(ctx, a->Rd), cpu_env, cpu_reg(ctx, a->Rn));
    gen_lazy_cap_set_int(ctx, AS_ZERO(a->Rd));

    return true;
}

TRANS_F(SCBNDS)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    uint64_t length = a->S ? (a->imm6 << 4) : a->imm6;
    gen_cheri_cap_cap_imm(ctx, a->Cd, a->Cn, length,
                          &gen_helper_csetboundsexact);
    return true;
}

TRANS_F(SC)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    if (!(a->opc & 2)) {
        cheri_cap_cap_int_helper *helper = NULL;
        if (a->opc == 0) {
            helper = &gen_helper_csetbounds;
        } else if (a->opc == 1) {
            helper = &gen_helper_csetboundsexact;
        }
        return gen_cheri_cap_cap_int(ctx, a->Cd, a->Cn, a->Rm, helper);
    } else {
        // opc 2 is set addr, opc 3 is setoffset

        gen_ensure_cap_decompressed(ctx, a->Cn);
        TCGv_i64 new_cursor = read_cpu_reg(ctx, a->Rm, 1);
        gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);


        if (a->opc == 3) {
            TCGv_i64 base = tcg_temp_new_i64();
            gen_cap_get_base(ctx, a->Cd, base);
            tcg_gen_add_i64(new_cursor, new_cursor, base);
            tcg_temp_free_i64(base);
        }

        gen_cap_set_cursor(ctx, a->Cd, new_cursor, false);
    }

    gen_reg_modified_cap(ctx, a->Cd);
    return true;
}

// CVT cap -> ptr
TRANS_F(CVT3)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    return cvt_impl_cap_to_ptr(ctx, a->Rd, a->Cn, AS_ZERO(a->Cm), false);
}

TRANS_F(SWP)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    return load_store_implementation(ctx, a->A, false, AS_ZERO(a->Ct),
                                     AS_ZERO(a->Cs), 4, 4, a->Rn, REG_NONE, 0,
                                     false, false, false, false, false, false,
                                     a->A + a->R, 1, OPTION_NONE, 0, false);
}

// CVT with PCC / DDC as a base, ptr -> cap
TRANS_F(CVT4)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    bool pcc = (a->opc & 1) == 1;
    bool zero_is_null = (a->opc & 2) == 2;
    uint32_t reg = pcc ? CHERI_EXC_REGNUM_PCC : CHERI_EXC_REGNUM_DDC;
    return cvt_impl_ptr_to_cap(ctx, AS_ZERO(a->Cd), reg, a->Rn, zero_is_null,
                               pcc);
}

TRANS_F(CLRPERM1)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    gen_move_cap_gp_gp(ctx, a->Cd, a->Cn);
    int64_t perms = 0;
    if (a->perm & 1)
        perms |= CAP_PERM_EXECUTE;
    if (a->perm & 2)
        perms |= CAP_PERM_STORE;
    if (a->perm & 4)
        perms |= CAP_PERM_LOAD;

    TCGv_i64 mask = tcg_const_i64(perms);
    gen_cap_clear_perms(ctx, a->Cd, mask, false);
    gen_cap_untag_if_sealed(ctx, a->Cd);
    tcg_temp_free_i64(mask);

    gen_reg_modified_cap(ctx, a->Cd);
    return true;
}

// Load store via alternate base
TRANS_F(ARB_ALDR)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    uint64_t log = size_log(a->op);
    return load_store_implementation(ctx, a->L, false, AS_ZERO(a->Rt), REG_NONE,
                                     log, log, a->Rn, REG_NONE, a->imm9 << log,
                                     false, false, false, true, false, false,
                                     false, 0, OPTION_NONE, 0, false);
}

// Load store via alternate base register offset
TRANS_F(ASTR_ALDR1)
{
    if (!(a->option_name & 0b10))
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    bool is_load = a->L || (!a->op && (a->opc == 0b01 || a->opc == 0b10));
    // op,opc   0 00 byte
    //          0 01 signed byte (extend to word if L, otherwise double)
    //          0 10 signed half (extend to word if L, otherwise double)
    //          0 11 half
    //          1 00 word
    //          1 01 doubleword
    //          1 10 simd&fp
    //          1 11 simd&fp

    size_t size;
    size_t extend_size;
    bool vector = false;

    switch (a->opc | (a->op << 2)) {
    case 0b000:
        size = 0;
        extend_size = 0;
        break;
    case 0b001:
        size = 0;
        extend_size = a->L ? 2 : 3;
        break;
    case 0b010:
        size = 1;
        extend_size = a->L ? 2 : 3;
        break;
    case 0b011:
        size = 1;
        extend_size = 1;
        break;
    case 0b100:
        size = 2;
        extend_size = 2;
        break;
    case 0b110:
        size = 3;
        extend_size = 3;
        vector = true;
        break;
    case 0b111:
        size = 2;
        extend_size = 2;
        vector = true;
        break;
    case 0b101:
        size = 3;
        extend_size = 3;
        break;
    default:
        g_assert_not_reached();
    }
    return load_store_implementation(
        ctx, is_load, vector, vector ? a->Rt : AS_ZERO(a->Rt), REG_NONE, size,
        extend_size, a->Rn, AS_ZERO(a->Rm), 0, false, false, false, true, false,
        false, false, 0, a->option_name, a->S ? size : 0, false);
}

// Load store capability via alternate base
TRANS_F(ASTR_ALDR)
{
    if (!(a->option_name & 0b10))
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    return load_store_implementation(ctx, a->L, false, AS_ZERO(a->Ct), REG_NONE,
                                     4, 4, a->Rn, AS_ZERO(a->Rm), 0, false,
                                     false, false, true, false, false, false, 0,
                                     a->option_name, a->S ? 4 : 0, false);
}

TRANS_F(CT)
{
    if (a->opc > 1)
        return false;
    if (!a->opc && (ctx->current_el == 0))
        return false;

    if (capabilities_enabled_exception(ctx))
        return true;

    uint32_t reg = IS_C64(ctx) ? a->Rn : CHERI_EXC_REGNUM_DDC;

    if (a->Rn == 31)
        gen_check_sp_alignment(ctx);

    TCGv_i64 addr = read_cpu_reg_sp(ctx, a->Rn, 1);

    if (!IS_C64(ctx) && cctlr_set(ctx, CCTLR_DDCBO)) {
        tcg_gen_add_i64(addr, addr, ddc_interposition);
    }

    TCGv_i32 tcg_reg = tcg_const_i32(reg);

    if (a->opc) {
        gen_helper_load_tags(cpu_reg(ctx, a->Rt), cpu_env, tcg_reg, addr);
        gen_lazy_cap_set_int(ctx, AS_ZERO(a->Rt));
    } else {
        TCGv_i64 v = cpu_reg(
            ctx, (!isTagSettingDisabled(ctx) && cheri_is_system_ctx(ctx))
                     ? a->Rt
                     : 31);
        gen_helper_store_tags(cpu_env, v, tcg_reg, addr);
    }

    tcg_temp_free_i32(tcg_reg);

    return true;
}

TRANS_F(LDAPR)
{
    if (capabilities_enabled_exception(ctx))
        return true;

    // LDAPR is slightly weaker than LDAR, so we can just make LDAPR into LDAR.
    return load_store_implementation(ctx, true, false, AS_ZERO(a->Ct), REG_NONE,
                                     4, 4, a->Rn, REG_NONE, 0, false, false,
                                     false, false, false, false, true, false,
                                     OPTION_NONE, 0, false);
}
