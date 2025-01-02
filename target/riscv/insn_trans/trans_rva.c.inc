/*
 * RISC-V translation routines for the RV64A Standard Extension.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2018 Peer Adelt, peer.adelt@hni.uni-paderborn.de
 *                    Bastian Koppelmann, kbastian@mail.uni-paderborn.de
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

static inline bool gen_lr_impl(DisasContext *ctx, TCGv_cap_checked_ptr addr,
                               arg_atomic *a, MemOp mop)
{
    /* Put addr in load_res, data in load_val.  */
    if (a->rl) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }
    cheri_debug_assert((mop & MO_ALIGN) && "load-reserved must be aligned");
    tcg_gen_qemu_ld_tl_with_checked_addr(load_val, addr, ctx->mem_idx, mop);
    if (a->aq) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }
    tcg_gen_mov_cap_checked(load_res, addr);
    gen_set_gpr(a->rd, load_val);

    return true;
}

static inline bool gen_lr(DisasContext *ctx, arg_atomic *a, MemOp mop)
{
    TCGv_cap_checked_ptr addr =
        get_capmode_dependent_load_addr(ctx, a->rs1, 0, mop);
    bool result = gen_lr_impl(ctx, addr, a, mop);
    tcg_temp_free_cap_checked(addr);
    return result;
}

static inline bool gen_sc_impl(DisasContext *ctx, TCGv_cap_checked_ptr addr,
                               arg_atomic *a, MemOp mop)
{
    TCGv src1 = tcg_temp_new();
    TCGv src2 = tcg_temp_new();
    TCGv dat = tcg_temp_new();
    TCGLabel *l1 = gen_new_label();
    TCGLabel *l2 = gen_new_label();

    /*
     * Alignment must always be checked (even on reservation address mismatch):
     * "If the address is not naturally aligned, an address-misaligned
     * exception or an access-fault exception will be generated".
     * We have to do the alignment check unconditionally (instead of only in the
     * mismatch case) since the implicit alignment check as part of
     * tcg_gen_atomic_cmpxchg_tl_with_checked_addr() can result in a load being
     * emitted before a store in which case we would end up with a load fault
     * rather than an AMO fault.
     */
    cheri_debug_assert((mop & MO_ALIGN) && "store-conditional must be aligned");
    if (memop_size(mop) > 1) {
        TCGv_i32 tmop = tcg_const_i32(mop);
        TCGv_i32 tcode = tcg_const_i32(RISCV_EXCP_STORE_AMO_ADDR_MIS);
        gen_helper_check_alignment(cpu_env, (TCGv)addr, tmop, tcode);
        tcg_temp_free_i32(tcode);
        tcg_temp_free_i32(tmop);
    }

    tcg_gen_brcond_cap_checked(TCG_COND_NE, load_res, addr, l1);
    gen_get_gpr(src2, a->rs2);
    /*
     * Note that the TCG atomic primitives are SC,
     * so we can ignore AQ/RL along this path.
     */
    tcg_gen_atomic_cmpxchg_tl_with_checked_addr(src1, load_res, load_val, src2,
                                                ctx->mem_idx, mop);
    /*
     * cmpxchg will perform a read and therefore update mem_rmask, but to match
     * sail we should report that this was just a store.
     */
    gen_rvfi_dii_set_field_const_i32(MEM, mem_rmask, 0);
    tcg_gen_setcond_tl(TCG_COND_NE, dat, src1, load_val);
    gen_set_gpr(a->rd, dat);
    tcg_gen_br(l2);

    gen_set_label(l1);
    /*
     * Address comparison failure.  However, we still need to
     * provide the memory barrier implied by AQ/RL.
     */
    tcg_gen_mb(TCG_MO_ALL + a->aq * TCG_BAR_LDAQ + a->rl * TCG_BAR_STRL);
    tcg_gen_movi_tl(dat, 1);
    gen_set_gpr(a->rd, dat);

    gen_set_label(l2);
    /*
     * Clear the load reservation, since an SC must fail if there is
     * an SC to any address, in between an LR and SC pair.
     */
    tcg_gen_movi_tl((TCGv)load_res, -1);

    tcg_temp_free(dat);
    tcg_temp_free(src1);
    tcg_temp_free(src2);
    return true;
}

static inline bool gen_sc(DisasContext *ctx, arg_atomic *a, MemOp mop)
{
    TCGv_cap_checked_ptr addr =
        get_capmode_dependent_load_addr(ctx, a->rs1, 0, mop);
    cheri_debug_assert((mop & MO_ALIGN) && "store-conditional must be aligned");
    bool result = gen_sc_impl(ctx, addr, a, mop);
    tcg_temp_free_cap_checked(addr);
    return result;
}

static bool gen_amo(DisasContext *ctx, arg_atomic *a,
                    void(*func)(TCGv, TCGv_cap_checked_ptr, TCGv, TCGArg, MemOp),
                    MemOp mop)
{
    TCGv_cap_checked_ptr src1 = get_capmode_dependent_rmw_addr(ctx, a->rs1, 0, mop);
    cheri_debug_assert((mop & MO_ALIGN) && "RMW AMOs must be aligned");
    /*
     * We have to check the alignment explicitly before the tcg_gen_atomic_*
     * as those can end up in do_nonatomic_op_i64() which will lower them to
     * a load+op+store sequence and if that faults due to alignment we will
     * get a load fault rather than the spec-mandated store/amo fault.
     */
    if (memop_size(mop) > 1) {
        TCGv_i32 tmop = tcg_const_i32(mop);
        TCGv_i32 tcode = tcg_const_i32(RISCV_EXCP_STORE_AMO_ADDR_MIS);
        gen_helper_check_alignment(cpu_env, (TCGv)src1, tmop, tcode);
        tcg_temp_free_i32(tcode);
        tcg_temp_free_i32(tmop);
    }
    TCGv src2 = tcg_temp_new();
    gen_get_gpr(src2, a->rs2);

    (*func)(src2, src1, src2, ctx->mem_idx, mop);

    gen_set_gpr(a->rd, src2);
    tcg_temp_free_cap_checked(src1);
    tcg_temp_free(src2);
    return true;
}

static bool trans_lr_w(DisasContext *ctx, arg_lr_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_lr(ctx, a, (MO_ALIGN | MO_TESL));
}

static bool trans_sc_w(DisasContext *ctx, arg_sc_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_sc(ctx, a, (MO_ALIGN | MO_TESL));
}

/// Note: LR/SC.{B,H} is a CHERI extension but we allow them everywhere
static bool trans_lr_h(DisasContext *ctx, arg_lr_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_lr(ctx, a, (MO_ALIGN | MO_TESW));
}

static bool trans_sc_h(DisasContext *ctx, arg_sc_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_sc(ctx, a, (MO_ALIGN | MO_TESW));
}

static bool trans_lr_b(DisasContext *ctx, arg_lr_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_lr(ctx, a, (MO_ALIGN | MO_SB));
}

static bool trans_sc_b(DisasContext *ctx, arg_sc_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_sc(ctx, a, (MO_ALIGN | MO_SB));
}

static bool trans_amoswap_w(DisasContext *ctx, arg_amoswap_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_xchg_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoadd_w(DisasContext *ctx, arg_amoadd_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_add_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoxor_w(DisasContext *ctx, arg_amoxor_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_xor_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoand_w(DisasContext *ctx, arg_amoand_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_and_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoor_w(DisasContext *ctx, arg_amoor_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_or_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomin_w(DisasContext *ctx, arg_amomin_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smin_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomax_w(DisasContext *ctx, arg_amomax_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smax_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amominu_w(DisasContext *ctx, arg_amominu_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umin_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomaxu_w(DisasContext *ctx, arg_amomaxu_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umax_tl, (MO_ALIGN | MO_TESL));
}

#ifdef TARGET_RISCV64

static bool trans_lr_d(DisasContext *ctx, arg_lr_d *a)
{
    return gen_lr(ctx, a, MO_ALIGN | MO_TEQ);
}

static bool trans_sc_d(DisasContext *ctx, arg_sc_d *a)
{
    return gen_sc(ctx, a, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoswap_d(DisasContext *ctx, arg_amoswap_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_xchg_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoadd_d(DisasContext *ctx, arg_amoadd_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_add_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoxor_d(DisasContext *ctx, arg_amoxor_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_xor_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoand_d(DisasContext *ctx, arg_amoand_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_and_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amoor_d(DisasContext *ctx, arg_amoor_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_or_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amomin_d(DisasContext *ctx, arg_amomin_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smin_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amomax_d(DisasContext *ctx, arg_amomax_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smax_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amominu_d(DisasContext *ctx, arg_amominu_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umin_tl, (MO_ALIGN | MO_TEQ));
}

static bool trans_amomaxu_d(DisasContext *ctx, arg_amomaxu_d *a)
{
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umax_tl, (MO_ALIGN | MO_TEQ));
}
#endif
