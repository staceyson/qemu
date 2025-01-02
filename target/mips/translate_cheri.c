/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2016 Stacey Son <sson@FreeBSD.org>
 * Copyright (c) 2016-2018 Alfredo Mazzinghi <am2419@cl.cam.ac.uk>
 * Copyright (c) 2016-2018 Alex Richardson <Alexander.Richardson@cl.cam.ac.uk>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

/* Note: this is included in translate.c */

#if defined(TARGET_CHERI) && defined(TARGET_MIPS)
/* Verify that the processor is running with CHERI instructions enabled. */
static inline void check_cop2x(DisasContext *ctx)
{

    if (unlikely(!(ctx->hflags & MIPS_HFLAG_COP2X))) {
        generate_exception_err(ctx, EXCP_CpU, 2);
    }
    // Pretty much every CHERI instruction can throw an exception so we need to
    // save the hflags if we are in a branch. If we don't do this we mess up
    // state on trap (e.g. the BDELAY flag will not be set in CP0_Cause)
    // It also causes BadInstrP to not be updated (and we depend on that in CheriBSD)
    if (unlikely(ctx->hflags & MIPS_HFLAG_BMASK))
        save_cpu_state(ctx, 0);
}

/* generic sign extension helper */
static inline int32_t sign_extend(int32_t x, int offset)
{
    int32_t const mask = 1U << (offset - 1);

    x = x & ((1U << offset) - 1);
    return (x ^ mask) - mask;
}

/*
static inline bool is_cop2x_enabled(DisasContext *ctx)
{

    return (likely(ctx->hflags & MIPS_HFLAG_COP2X));
}
*/

static inline void generate_ccall(int32_t cs, int32_t cb)
{
    /*
     * XXXAM can a ccall be in a delay slot?
     */
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv_i32 tcb = tcg_const_i32(cb);

    gen_helper_ccall(cpu_env, tcs, tcb);

    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tcs);
}

static inline void generate_ccall_notrap(DisasContext *ctx, int32_t cs, int32_t cb, int32_t select)
{
    /*
     * This version of ccall does not have a delay slot
     * and also can not be used in a delay slot.
     */
    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x"
                  TARGET_FMT_lx "\n", ctx->base.pc_next);
#endif
        generate_exception(ctx, EXCP_RI);
    } else {
        TCGv_i32 tcs = tcg_const_i32(cs);
        TCGv_i32 tcb = tcg_const_i32(cb);

        if (select == CCALL_SELECTOR_1)
            gen_helper_cinvoke(cpu_env, tcs, tcb);
        else if(select == CCALL_SELECTOR_2)
            gen_helper_ccall_notrap2(btarget, cpu_env, tcs, tcb);
        else
            tcg_debug_assert(0 && "Invalid CCall Selector");
        /* Set ccall branch flags */
        ctx->hflags |= (MIPS_HFLAG_BRCCALL);
        save_cpu_state(ctx, 0);

        tcg_temp_free_i32(tcb);
        tcg_temp_free_i32(tcs);
    }
}

typedef void(cheri_cap_cap_int_helper)(TCGv_ptr, TCGv_i32, TCGv_i32, TCGv);
static inline void gen_cheri_cap_cap_int(DisasContext *ctx, int cd, int cb,
                                         int rt,
                                         cheri_cap_cap_int_helper *gen_func)
{
    check_cop2x(ctx);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_func(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

typedef void (cheri_branch_helper)(TCGv, TCGv_ptr, TCGv_i32, TCGv_i32);
static inline void gen_compute_cheri_branch(DisasContext *ctx, int32_t cb,
                                         int32_t offset, cheri_branch_helper* gen_func)
{
    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x"
                TARGET_FMT_lx "\n", ctx->base.pc_next);
#endif
        generate_exception(ctx, EXCP_RI);
    } else {
        TCGv_i32 tcb = tcg_const_i32(cb);
        TCGv_i32 toffset = tcg_const_i32(offset);

        gen_func(bcond, cpu_env, tcb, toffset);
        ctx->btarget = ctx->base.pc_next + 4 * offset + 4;
        /* Set conditional branch and branch delay slot flags */
        ctx->hflags |= (MIPS_HFLAG_BC | MIPS_HFLAG_BDS32);

        // Check that the branch isn't out-of-bounds of PCC before executing the delay slot
        // Check that the conditional branch target is in range (but only if the branch is taken)
        gen_check_cond_branch_target(ctx, bcond, ctx->btarget);

        tcg_temp_free_i32(toffset);
        tcg_temp_free_i32(tcb);
    }
}

static inline void generate_cbez(DisasContext *ctx, int32_t cb, int32_t offset)
{
    gen_compute_cheri_branch(ctx, cb, offset, &gen_helper_cbez);
}

static inline void generate_cbnz(DisasContext *ctx, int32_t cb, int32_t offset)
{
    gen_compute_cheri_branch(ctx, cb, offset, &gen_helper_cbnz);
}

static inline void generate_cbts(DisasContext *ctx, int32_t cb, int32_t offset)
{
    gen_compute_cheri_branch(ctx, cb, offset, &gen_helper_cbts);
}

static inline void generate_cbtu(DisasContext *ctx, int32_t cb, int32_t offset)
{
    gen_compute_cheri_branch(ctx, cb, offset, &gen_helper_cbtu);
}

static inline void generate_cjalr(DisasContext *ctx, int32_t cd, int32_t cb)
{

    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x"
                TARGET_FMT_lx "\n", ctx->base.pc_next);
#endif
        generate_exception(ctx, EXCP_RI);
    } else {
        TCGv_i32 tcd = tcg_const_i32(cd);
        TCGv_i32 tcb = tcg_const_i32(cb);
        TCGv toff = tcg_const_tl(0);
        /* Instruction size is always four bytes and so is the delay slot */
        TCGv link_addr = tcg_const_tl(ctx->base.pc_next + 8);
        gen_helper_cjalr(cpu_env, tcd, tcb, toff, link_addr);
        /* Set branch and delay slot flags */
        ctx->hflags |= (MIPS_HFLAG_BRC | MIPS_HFLAG_BDS32);
        /* Save capability register index that is new PCC */
        // ctx->btcr = cb;
        save_cpu_state(ctx, 0);

        tcg_temp_free(link_addr);
        tcg_temp_free(toff);
        tcg_temp_free_i32(tcb);
        tcg_temp_free_i32(tcd);
    }
}

static inline void generate_cjr(DisasContext *ctx, int32_t cb)
{
    if (ctx->hflags & MIPS_HFLAG_BMASK) {
#ifdef MIPS_DEBUG_DISAS
        LOG_DISAS("Branch in delay / forbidden slot at PC 0x"
                TARGET_FMT_lx "\n", ctx->base.pc_next);
#endif
        generate_exception(ctx, EXCP_RI);
    } else {
        TCGv_i32 tcb = tcg_const_i32(cb);

        gen_helper_cjr(btarget, cpu_env, tcb);
        /* Set branch and delay slot flags */
        ctx->hflags |= (MIPS_HFLAG_BRC | MIPS_HFLAG_BDS32);
        /* Save capability register index that is new PCC */
        // ctx->btcr = cb;
        save_cpu_state(ctx, 0);

        tcg_temp_free_i32(tcb);
    }
}

static inline void generate_ccheckperm(int32_t cs, int32_t rt)
{
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_ccheckperm(cpu_env, tcs, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cchecktype(int32_t cs, int32_t cb)
{
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv_i32 tcb = tcg_const_i32(cb);

    gen_helper_cchecktype(cpu_env, tcs, tcb);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tcs);
}

static inline void generate_ccleartag(int32_t cd, int32_t cb)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);

    gen_helper_ccleartag(cpu_env, tcd, tcb);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cfromptr(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_cfromptr(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

typedef void (cheri_cget_helper)(TCGv, TCGv_ptr, TCGv_i32);
static inline void generate_cheri_cget(DisasContext *ctx, int rd, int cs,
                                       cheri_cget_helper *gen_func)
{
    check_cop2x(ctx);
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv t0 = tcg_temp_new();

    gen_func(t0, cpu_env, tcs);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cloadtags(DisasContext *ctx, int32_t rd, int32_t cb)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_cap_checked_ptr tcbc  = tcg_temp_new_cap_checked();
    TCGv ttags = tcg_temp_new();

    tcg_gen_mb(TCG_MO_LD_LD | TCG_MO_ST_LD | TCG_BAR_SC);

    gen_helper_cloadtags(ttags, cpu_env, tcb);
    tcg_gen_movi_i32(tcb, MO_TEQ);
#ifdef CONFIG_TCG_LOG_INSTR
    gen_helper_qemu_log_instr_load64(cpu_env, tcbc, ttags, tcb); // FIXME: not really correct
#endif
    gen_store_gpr(ttags, rd);

    tcg_temp_free_cap_checked(tcbc);
    tcg_temp_free(ttags);
    tcg_temp_free_i32(tcb);
}


static inline void generate_cgetcause(DisasContext *ctx, int32_t rd)
{
    TCGv t0 = tcg_temp_new();

    gen_helper_cgetcause(t0, cpu_env);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
}

static inline void generate_cgetpcc(DisasContext *ctx, int32_t cd)
{
    TCGv_i32 tcd = tcg_const_i32(cd);

    save_cpu_state(ctx, 1); // save pcc.cursor for the helper call
    gen_helper_cgetpcc(cpu_env, tcd);
    tcg_temp_free_i32(tcd);
}

static inline void
generate_helper_cap_regnum_gpr_val(int32_t cd, int32_t rs,
                                   void (*gen_helper)(TCGv_env, TCGv_i32, TCGv)) {
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rs);
    gen_helper(cpu_env, tcd, t0);
    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
}

static inline void generate_cincoffset(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();
    gen_load_gpr(t0, rt);
    gen_helper_cincoffset(cpu_env, tcd, tcb, t0);
    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cincoffset_imm(int32_t cd, int32_t cs, int32_t increment)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv t0 = tcg_temp_new();

    tcg_gen_movi_tl(t0, sign_extend(increment, 11));
    gen_helper_cincoffset(cpu_env, tcd, tcs, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cmove(int32_t cd, int32_t cs)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcs = tcg_const_i32(cs);

    gen_helper_cmove(cpu_env, tcd, tcs);

    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cmovz(int32_t cd, int32_t cs, int32_t rs)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rs);
    gen_helper_cmovz(cpu_env, tcd, tcs, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cmovn(int32_t cd, int32_t cs, int32_t rs)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rs);
    gen_helper_cmovn(cpu_env, tcd, tcs, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cbuildcap(int32_t cd, int32_t cb, int32_t ct)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);

    gen_helper_cbuildcap(cpu_env, tcd, tcb, tct);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tct);
}

static inline void generate_ccseal(int32_t cd, int32_t cs, int32_t ct)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv_i32 tct = tcg_const_i32(ct);

    gen_helper_ccseal(cpu_env, tcd, tcs, tct);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcs);
    tcg_temp_free_i32(tct);
}

static inline void generate_ccopytype(int32_t cd, int32_t cb, int32_t ct)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);

    gen_helper_ccopytype(cpu_env, tcd, tcb, tct);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tct);
}

static inline void generate_ctestsubset(DisasContext *ctx, int32_t rd,
                                        int32_t cb, int32_t ct)
{
    TCGv t0 = tcg_temp_new();
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);

    gen_helper_ctestsubset(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tct);
}

static inline void generate_creturn(void)
{
    gen_helper_creturn(cpu_env);
}

static inline void generate_cseal(int32_t cd, int32_t cb, int32_t ct)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);

    gen_helper_cseal(cpu_env, tcd, tcb, tct);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tcd);
}

static inline void generate_csetbounds(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_csetbounds(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_candaddr(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_candaddr(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_csetaddr(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_csetaddr(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cgetandaddr(DisasContext *ctx, int32_t rd,
                                        int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv t0 = tcg_temp_new();
    TCGv t1 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_cgetandaddr(t1, cpu_env, tcb, t0);
    gen_store_gpr(t1, rd);

    tcg_temp_free(t1);
    tcg_temp_free(t0);
    tcg_temp_free_i32(tcb);
}

static inline void generate_csetboundsexact(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_csetboundsexact(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_csetbounds_imm(int32_t cd, int32_t cb, int32_t length)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv t0 = tcg_temp_new();

    tcg_debug_assert(length >= 0 && "CSetBoundsImm decoding broken (should be unsigned)?");
    tcg_gen_movi_tl(t0, length);
    gen_helper_csetbounds(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_csub(DisasContext *ctx, int32_t rd, int32_t cb,
                                 int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_csub(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_csetcause(int32_t rd)
{
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rd);
    gen_helper_csetcause(cpu_env, t0);
    tcg_temp_free(t0);
}

static inline void generate_csetoffset(int32_t cd, int32_t cb, int32_t rt)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);
    gen_helper_csetoffset(cpu_env, tcd, tcb, t0);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tcd);
    tcg_temp_free_i32(tcb);
}

static inline void generate_ctoptr(DisasContext *ctx, int32_t rd, int32_t cb,
                                   int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_ctoptr(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cunseal(int32_t cd, int32_t cb, int32_t ct)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);

    gen_helper_cunseal(cpu_env, tcd, tcb, tct);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tcd);
}

static inline int generate_cclearregs(DisasContext *ctx, int32_t regset, int32_t mask)
{
    int i;
    TCGv t0;
    TCGv_i32 tcr0;

    switch(regset) {
    case 0: /* ClearLO */
        if (!mask)
            return 0;
        t0 = tcg_temp_new();
        tcg_gen_movi_tl(t0, 0);
        mask = mask >> 1; /* Skip R0, the zero register */
        for(i = 1; i < 16; i++) {
            if (mask & 0x1)
                gen_store_gpr(t0, i);
            mask = mask >> 1;
        }
        tcg_temp_free(t0);
        break;
    case 1: /* ClearHi */
        if (!mask)
            return 0;
        t0 = tcg_temp_new();
        tcg_gen_movi_tl(t0, 0);
        for(i = 16; i < 32; i++) {
            if (mask & 0x1)
                gen_store_gpr(t0, i);
            mask = mask >> 1;
        }
        tcg_temp_free(t0);
        break;
    case 2: /* CClearLO */
        if (!mask)
            return 0;
        tcr0 = tcg_const_i32(mask);
        gen_helper_cclearreg(cpu_env, tcr0);
        tcg_temp_free_i32(tcr0);
        break;
    case 3: /* CClearHi */
        if (!mask)
            return 0;
        tcr0 = tcg_const_i32(mask << 16);
        gen_helper_cclearreg(cpu_env, tcr0);
        tcg_temp_free_i32(tcr0);
        break;
    default:
        return 1; /* Invalid */
    }
    return 0;
}

static inline void generate_ceq(DisasContext *ctx, int32_t rd, int32_t cb,
                                int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_ceq(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cne(DisasContext *ctx, int32_t rd, int32_t cb,
                                int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_cne(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_clt(DisasContext *ctx, int32_t rd, int32_t cb,
                                int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_clt(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cle(DisasContext *ctx, int32_t rd, int32_t cb,
                                int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_cle(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cltu(DisasContext *ctx, int32_t rd, int32_t cb,
                                 int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_cltu(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cleu(DisasContext *ctx, int32_t rd, int32_t cb,
                                 int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_cleu(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cexeq(DisasContext *ctx, int32_t rd, int32_t cb,
                                  int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_cseqx(t0, cpu_env, tcb, tct);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline void generate_cnexeq(DisasContext *ctx, int32_t rd, int32_t cb,
                                   int32_t ct)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tct = tcg_const_i32(ct);
    TCGv t0 = tcg_temp_new();

    gen_helper_cseqx(t0, cpu_env, tcb, tct);
    tcg_gen_xori_i64(t0, t0, 1);
    gen_store_gpr(t0, rd);

    tcg_temp_free(t0);
    tcg_temp_free_i32(tct);
    tcg_temp_free_i32(tcb);
}

static inline target_long cload_sign_extend(target_long x)
{
    target_long const mask = 1U << (8 - 1);

    x = x & ((1U << 8) - 1);
    return (x ^ mask) - mask;
}

/* Load Via Capability Register */
static inline void generate_cap_load(DisasContext *ctx, int32_t rd, int32_t cb,
        int32_t rt, int32_t offset, MemOp op, int opcode)
{
    // FIXME: just do everything in the helper
    TCGv_cap_checked_ptr vaddr = tcg_temp_new_cap_checked();
    TCGv t1 = tcg_temp_new();
    gen_load_gpr(t1, rt);
    tcg_gen_addi_tl(t1, t1, cload_sign_extend(offset) * memop_size(op));

    generate_cap_load_check(vaddr, cb, t1, op);
    tcg_gen_qemu_ld_tl_with_checked_addr(t1, vaddr, ctx->mem_idx, op);
    gen_store_gpr(t1, rd);

    tcg_temp_free(t1);
    tcg_temp_free_cap_checked(vaddr);
}

static inline void generate_cloadlinked_int(DisasContext *ctx, int32_t rd, int32_t cb, MemOp op, int opcode)
{
    check_cop2x(ctx);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv t0 = tcg_temp_new();
    TCGv_cap_checked_ptr taddr = tcg_temp_new_cap_checked();
    TCGv_i32 tlen = tcg_const_i32(memop_size(op));

    gen_helper_cloadlinked(taddr, cpu_env, tcb, tlen);
    tcg_gen_qemu_ld_tl_with_checked_addr(t0, taddr, ctx->mem_idx, op);
    gen_store_gpr(t0, rd);

    tcg_temp_free_i32(tlen);
    tcg_temp_free_cap_checked(taddr);
    tcg_temp_free(t0);
    tcg_temp_free_i32(tcb);
}

/*
 * Compute the address for a CSC[BHWD]
 *
 * XXX There's nothing very CSC-specific about this, other than logging...
 */
static inline void generate_cstorecond(TCGv_cap_checked_ptr taddr, int32_t cb, int32_t len)
{
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv_i32 tlen = tcg_const_i32(len);

    gen_helper_cstorecond(taddr, cpu_env, tcb, tlen);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tlen);
}

static inline void generate_cstorecond_int(DisasContext *ctx, int32_t rs,
                                           int32_t cb, int32_t rd, MemOp op,
                                           int opcode) {
    check_cop2x(ctx);
    const int size = memop_size(op);
    TCGv_cap_checked_ptr taddr = tcg_temp_local_new_cap_checked();
    TCGv t0 = tcg_temp_new();
    TCGv tlf = tcg_temp_local_new();
    TCGLabel *l1 = gen_new_label();

    generate_cstorecond(taddr, cb, size);

    /* Verify that the store matches the load link address */
    tcg_gen_movi_tl(tlf, 0); // prepare to return failure
    tcg_gen_brcond_tl(TCG_COND_NE, (TCGv)taddr, cpu_lladdr, l1);

    tcg_gen_movi_tl(tlf, 1); // return success when we get there

    /* Write rs to memory. */
    gen_load_gpr(t0, rs);
    tcg_gen_qemu_st_tl_with_checked_addr(t0, taddr, ctx->mem_idx, op);

    tcg_temp_free_cap_checked(taddr);
    tcg_temp_free(t0);

    gen_set_label(l1);
    gen_store_gpr(tlf, rd);
    tcg_temp_free(tlf);
}


static inline void generate_cstore(DisasContext *ctx, int32_t rs, int32_t cb,
        int32_t rt, int32_t offset, MemOp op, int opcode)
{
    const int size = memop_size(op);
    TCGv_cap_checked_ptr taddr = tcg_temp_local_new_cap_checked();
    TCGv t0 = tcg_temp_new();

    gen_load_gpr(t0, rt);  // t0 <- register offset
    tcg_gen_addi_tl(t0, t0, cload_sign_extend(offset) * size);

    generate_cap_store_check(taddr, cb, t0, op);

    gen_load_gpr(t0, rs); // t0 <- load value to store
    tcg_gen_qemu_st_tl_with_checked_addr(t0, taddr, ctx->mem_idx, op);

    tcg_temp_free(t0);
    tcg_temp_free_cap_checked(taddr);
}

static inline target_long clc_sign_extend(target_long x, bool big_imm)
{
    const target_long bits = big_imm ? 16 : 11;
    target_long const mask = 1U << (bits - 1);

    x = x & ((1U << bits) - 1);
    return (x ^ mask) - mask;
}

static inline void generate_clc(DisasContext *ctx, int32_t cd, int32_t cb,
        int32_t rt, int32_t offset, bool big_imm)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv toffset = tcg_temp_new();
    gen_load_gpr(toffset, rt);
    tcg_gen_addi_tl(toffset, toffset, clc_sign_extend(offset, big_imm) * 16);
    if (cb == 0) {
        gen_helper_load_cap_via_ddc(cpu_env, tcd, toffset);
    } else {
        TCGv_i32 tcb = tcg_const_i32(cb);
        TCGv taddr = tcg_temp_new();
        gen_cap_get_cursor(ctx, cb, taddr);
        tcg_gen_add_tl(taddr, taddr, toffset);
        gen_helper_load_cap_via_cap(cpu_env, tcd, taddr, tcb);
        tcg_temp_free(taddr);
        tcg_temp_free_i32(tcb);
    }
    tcg_temp_free(toffset);
    tcg_temp_free_i32(tcd);
}

static inline void generate_cllc(DisasContext *ctx, int32_t cd, int32_t cb)
{
    TCGv_i32 tcd = tcg_const_i32(cd);
    TCGv_i32 tcb = tcg_const_i32(cb);
    gen_helper_cllc_without_tcg(cpu_env, tcd, tcb);
    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tcd);
}

static inline void generate_csc(DisasContext *ctx, int32_t cs, int32_t cb,
        int32_t rt, int32_t offset, bool big_imm)
{
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv toffset = tcg_temp_new();
    gen_load_gpr(toffset, rt);
    tcg_gen_addi_tl(toffset, toffset, clc_sign_extend(offset, big_imm) * 16);
    /*
     * CSC traps on cbp == NULL, so we use reg0 as $ddc to save encoding
     * space and increase code density since storing relative to $ddc is common
     * in the hybrid ABI (and also for backwards compat with old binaries).
     */
    if (cb == 0) {
        gen_helper_store_cap_via_ddc(cpu_env, tcs, toffset);
    } else {
        TCGv_i32 tcb = tcg_const_i32(cb);
        TCGv taddr = tcg_temp_new();
        gen_cap_get_cursor(ctx, cb, taddr);
        tcg_gen_add_tl(taddr, taddr, toffset);
        gen_helper_store_cap_via_cap(cpu_env, tcs, taddr, tcb);
        tcg_temp_free(taddr);
        tcg_temp_free_i32(tcb);
    }
    tcg_gen_movi_tl(cpu_lladdr, 1);
    tcg_temp_free(toffset);
    tcg_temp_free_i32(tcs);
}

static inline void generate_cscc(DisasContext *ctx, int32_t cs, int32_t cb,
        int32_t rd)
{
    TCGv_i32 tcs = tcg_const_i32(cs);
    TCGv_i32 tcb = tcg_const_i32(cb);
    TCGv t0 = tcg_temp_local_new();

    /* Check the cap registers and compute the address. */
    gen_helper_cscc_without_tcg(t0, cpu_env, tcs, tcb);
    gen_store_gpr(t0, rd);

    tcg_temp_free_i32(tcb);
    tcg_temp_free_i32(tcs);
    tcg_temp_free(t0);
}

#define GEN_CAP_CHECK_STORE(addr, offset, len) \
    generate_ccheck_store(addr, offset, len)

static inline void generate_ccheck_load_right(TCGv_cap_checked_ptr addr, TCGv offset, int32_t len)
{
    TCGv_i32 tlen = tcg_const_i32(len);

    gen_helper_ccheck_load_right(addr, cpu_env, offset, tlen);
    tcg_temp_free_i32(tlen);
}
static inline void generate_ccheck_load_pcrel(TCGv addr, int32_t len)
{
    TCGv_i32 tlen = tcg_const_i32(len);
    gen_helper_ccheck_load_pcrel(cpu_env, addr, tlen);
    tcg_temp_free_i32(tlen);
}

static void gen_mtc2(DisasContext *ctx, TCGv arg, int reg, int sel)
{
    const char *rn = "invalid";

    switch (reg) {
    case 0:
        switch (sel) {
        case 6:
            save_cpu_state(ctx, 1); // Need to sync PC
            gen_helper_mtc2_dumpcstate(cpu_env, arg);
            rn = "capdump";
            goto out;
        default:
            goto cp2_unimplemented;
        }
    default:
        goto cp2_unimplemented;
    }
out:
    (void)rn; /* avoid a compiler warning */
    LOG_DISAS("mtc2 %s (reg %d sel %d)\n", rn, reg, sel);
    /* For simplicity assume that all writes can cause interrupts.  */
    if (ctx->base.tb->cflags & CF_USE_ICOUNT) {
        gen_io_end();
        ctx->base.is_jmp = DISAS_EXIT;
    }
    return;

cp2_unimplemented:
    LOG_DISAS("mtc2 %s (reg %d sel %d)\n", rn, reg, sel);
}


#else /* ! TARGET_CHERI */
#define generate_ccheck_load_right(addr, offset, len) tcg_gen_mov_tl(addr, offset);
#define generate_ccheck_load_pcrel(addr, len)
#endif /* ! TARGET_CHERI */

static inline TCGv_cap_checked_ptr PCC_CHECKED(TCGv addr) {
    return (TCGv_cap_checked_ptr)addr;
}

// instruction decoding for CHERI insns:
#if defined(TARGET_CHERI)

static void gen_cp2 (DisasContext *ctx, uint32_t opc, int r16, int r11, int r6)
{
    const char *opn = "cp2inst";

    /*
     * r16 = (ctx->opcode >> 16) & 0x1f;
     * r11 = (ctx->opcode >> 11) & 0x1f;
     * r6  = (ctx->opcode >> 6) & 0x1f;
     */

    /*
     * Every instruction checks whether cp2 is enabled and if
     * it can be in a delay slot, checks if the delay slot is a ccall
     * delay slot and is accessing IDC.
     */

    switch (MASK_CP2(opc)) {
    case OPC_CGET:  /* same as OPC_CAP_NI, 0x00 */
        switch(MASK_CAP6(opc)) {
        case OPC_CGETPERM:          /* 0x00 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetperm);
            opn = "cgetperm";
            break;
        case OPC_CGETTYPE:          /* 0x01 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgettype);
            opn = "cgettype";
            break;
        case OPC_CGETBASE:          /* 0x02 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetbase);
            opn = "cgetbase";
            break;
        case OPC_CGETLEN:           /* 0x03 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetlen);
            opn = "cgetlen";
            break;
        case OPC_CGETCAUSE:         /* 0x04 */
            check_cop2x(ctx);
            generate_cgetcause(ctx, r16);
            opn = "cgetcause";
            break;
        case OPC_CGETTAG:           /* 0x05 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgettag);
            opn = "cgettag";
            break;
        case OPC_CGETSEALED:        /* 0x06 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetsealed);
            opn = "cgetsealed";
            break;
        case OPC_CGETPCC:           /* 0x07 */
            check_cop2x(ctx);
            generate_cgetpcc(ctx, r11);
            opn = "cgetpcc";
            break;
                                    /* 0x08 */
        case OPC_CSETBOUNDSEXACT:   /* 0x09 */
            check_cop2x(ctx);
            generate_csetboundsexact(r16, r11, r6);
            opn = "csetboundsexact";
            break;
        case OPC_CSUB:              /* 0x0a */
            check_cop2x(ctx);
            generate_csub(ctx, r16, r11, r6);
            opn = "csub";
            break;
        case OPC_CSEAL_NI: /* 0x0b */
            check_cop2x(ctx);
            generate_cseal(r16, r11, r6);
            opn = "cseal";
            break;
        case OPC_CUNSEAL_NI: /* 0x0c */
            check_cop2x(ctx);
            generate_cunseal(r16, r11, r6);
            opn = "cunseal";
            break;
        case OPC_CANDPERM_NI: /* 0x0d */
            gen_cheri_cap_cap_int(ctx, r16, r11, r6, &gen_helper_candperm);
            opn = "candperm";
            break;
        case OPC_CSETFLAGS_NI: /* 0x0e */
            gen_cheri_cap_cap_int(ctx, r16, r11, r6, &gen_helper_csetflags);
            opn = "csetflags";
            break;
        case OPC_CSETOFFSET_NI: /* 0x0f */
            check_cop2x(ctx);
            generate_csetoffset(r16, r11, r6);
            opn = "csetoffset";
            break;
        case OPC_CSETBOUNDS_NI: /* 0x10 */
            check_cop2x(ctx);
            generate_csetbounds(r16, r11, r6);
            opn = "csetbounds";
            break;
        case OPC_CINCOFFSET_NI: /* 0x11 */
            check_cop2x(ctx);
            generate_cincoffset(r16, r11, r6);
            opn = "cincoffset";
            break;
        case OPC_CTOPTR_NI: /* 0x12 */
            check_cop2x(ctx);
            generate_ctoptr(ctx, r16, r11, r6);
            opn = "ctoptr";
            break;
        case OPC_CFROMPTR_NI: /* 0x13 */
            check_cop2x(ctx);
            generate_cfromptr(r16, r11, r6);
            opn = "cfromptr";
            break;
        case OPC_CEQ_NI: /* 0x14 */
            check_cop2x(ctx);
            generate_ceq(ctx, r16, r11, r6);
            opn = "ceq";
            break;
        case OPC_CNE_NI: /* 0x15 */
            check_cop2x(ctx);
            generate_cne(ctx, r16, r11, r6);
            opn = "cne";
            break;
        case OPC_CLT_NI: /* 0x16 */
            check_cop2x(ctx);
            generate_clt(ctx, r16, r11, r6);
            opn = "clt";
            break;
        case OPC_CLE_NI: /* 0x17 */
            check_cop2x(ctx);
            generate_cle(ctx, r16, r11, r6);
            opn = "cle";
            break;
        case OPC_CLTU_NI: /* 0x18 */
            check_cop2x(ctx);
            generate_cltu(ctx, r16, r11, r6);
            opn = "cltu";
            break;
        case OPC_CLEU_NI: /* 0x19 */
            check_cop2x(ctx);
            generate_cleu(ctx, r16, r11, r6);
            opn = "cleu";
            break;
        case OPC_CEXEQ_NI: /* 0x1a */
            check_cop2x(ctx);
            generate_cexeq(ctx, r16, r11, r6);
            opn = "cexeq";
            break;
        case OPC_CMOVZ_NI: /* 0x1b */
            check_cop2x(ctx);
            generate_cmovz(r16, r11, r6);
            opn = "cmovz";
            break;
        case OPC_CMOVN_NI: /* 0x1c */
            check_cop2x(ctx);
            generate_cmovn(r16, r11, r6);
            opn = "cmovn";
            break;
        case OPC_CBUILDCAP_NI: /* 0x1d */
            check_cop2x(ctx);
            generate_cbuildcap(r16, r11, r6);
            opn = "cbuildcap";
            break;
        case OPC_CCOPYTYPE_NI: /* 0x1e */
            check_cop2x(ctx);
            generate_ccopytype(r16, r11, r6);
            opn = "ccopytype";
            break;
        case OPC_CCSEAL_NI: /* 0x1f */
            check_cop2x(ctx);
            generate_ccseal(r16, r11, r6);
        case OPC_CTESTSUBSET_NI: /* 0x20 */
            check_cop2x(ctx);
            generate_ctestsubset(ctx, r16, r11, r6);
            opn = "ctestsubset";
            break;
        case OPC_CNEXEQ_NI: /* 0x21 */
            check_cop2x(ctx);
            generate_cnexeq(ctx, r16, r11, r6);
            opn = "cnexeq";
            break;
        case OPC_CSETADDR_NI: /* 0x22 */
            check_cop2x(ctx);
            generate_csetaddr(r16, r11, r6);
            opn = "csetaddr";
            break;
        case OPC_CGETANDADDR_NI: /* 0x23 */
            check_cop2x(ctx);
            generate_cgetandaddr(ctx, r16, r11, r6);
            opn = "cgetaddrmasked";
            break;
        case OPC_CANDADDR_NI: /* 0x24 */
            check_cop2x(ctx);
            generate_candaddr(r16, r11, r6);
            opn = "candaddr";
            break;
        /* Two-operand cap instructions. */
        case OPC_C2OPERAND_NI:         /* 0x3f */
            switch(MASK_CAP7(opc)) {
            case OPC_CGETPERM_NI:   /* 0x00 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetperm);
                opn = "cgetperm";
                break;
            case OPC_CGETTYPE_NI:   /* 0x01 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgettype);
                opn = "cgettype";
                break;
            case OPC_CGETBASE_NI:   /* 0x02 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetbase);
                opn = "cgetbase";
                break;
            case OPC_CGETLEN_NI:    /* 0x03 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetlen);
                opn = "cgetlen";
                break;
            case OPC_CGETTAG_NI:    /* 0x04 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgettag);
                opn = "cgettag";
                break;
            case OPC_CGETSEALED_NI: /* 0x05 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetsealed);
                opn = "cgetsealed";
                break;
            case OPC_CGETOFFSET_NI: /* 0x06 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetoffset);
                opn = "cgetoffset";
                break;
            case OPC_CGETPCCSETOFF_NI: /* 0x07 << 6 */
                check_cop2x(ctx);
                generate_helper_cap_regnum_gpr_val(r16, r11, &gen_helper_cgetpccsetoffset);
                opn = "cgetpccsetoffset";
                break;
            case OPC_CGETPCCINCOFF_NI: /* 0x013 << 6 */
                check_cop2x(ctx);
                save_cpu_state(ctx, 1); // save pcc.cursor for the helper call
                generate_helper_cap_regnum_gpr_val(r16, r11, &gen_helper_cgetpccincoffset);
                opn = "cgetpccincoffset";
                break;
            case OPC_CGETPCCSETADDR_NI: /* 0x014 << 6 */
                check_cop2x(ctx);
                generate_helper_cap_regnum_gpr_val(r16, r11, &gen_helper_cgetpccsetaddr);
                opn = "cgetpccsetaddr";
                break;
            case OPC_CCHECKPERM_NI:    /* 0x08 << 6 */
                check_cop2x(ctx);
                generate_ccheckperm(r16, r11);
                opn = "ccheckperm";
                break;
            case OPC_CCHECKTYPE_NI:    /* 0x09 << 6 */
                check_cop2x(ctx);
                generate_cchecktype(r16, r11);
                opn = "cchecktype";
                break;
            case OPC_CMOVE_NI:      /* 0x0a << 6 */
                check_cop2x(ctx);
                generate_cmove(r16, r11);
                opn = "cmove";
                break;
            case OPC_CCLEARTAG_NI:  /* 0x0b << 6 */
                check_cop2x(ctx);
                generate_ccleartag(r16, r11);
                opn = "ccleartag";
                break;
            case OPC_CJALR_NI:      /* 0x0c << 6 */
                check_cop2x(ctx);
                generate_cjalr(ctx, r16, r11);
                opn = "cjalr";
                break;
            case OPC_CREADHWR_NI:   /* 0x0d << 6 */
                check_cop2x(ctx);
                gen_helper_2_consti32(creadhwr, r16, r11);
                opn = "creadhwr";
                break;
            case OPC_CWRITEHWR_NI:  /* 0x0e << 6 */
                check_cop2x(ctx);
                gen_helper_2_consti32(cwritehwr, r16, r11);
                if (r11 == CP2HWR_DDC) {
                    // When DDC changes we have to exit the current translation
                    // block since we cache DDC properties in the flags to
                    // optimize out bounds/permission checks.
                    // XXXAR: DISAS_STOP seems to be enough?
                    // gen_save_pc(ctx->base.pc_next + 4);
                    // ctx->base.is_jmp = DISAS_EXIT;
                    ctx->base.is_jmp = DISAS_STOP;
                }
                opn = "cwritehwr";
                break;
            case OPC_CGETADDR_NI:   /* 0x0f << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetaddr);
                opn = "cgetaddr";
                break;
            case OPC_CRAP_NI:   /* 0x10 << 6 */
            {
                check_cop2x(ctx);
                TCGv t0 = tcg_temp_new();
                TCGv t1 = tcg_temp_new();
                gen_load_gpr(t0, r11);
                gen_helper_crap(t1, cpu_env, t0);
                gen_store_gpr(t1, r16);
                tcg_temp_free(t1);
                tcg_temp_free(t0);
                opn = "croundrepresetablelength";
                break;
            }
            case OPC_CRAM_NI:   /* 0x11 << 6 */
            {
                check_cop2x(ctx);
                TCGv t0 = tcg_temp_new();
                TCGv t1 = tcg_temp_new();
                gen_load_gpr(t0, r11);
                gen_helper_cram(t1, cpu_env, t0);
                gen_store_gpr(t1, r16);
                tcg_temp_free(t1);
                tcg_temp_free(t0);
                opn = "crepresentablealignmentmask";
                break;
            }
            case OPC_CGETFLAGS_NI:   /* 0x12 << 6 */
                generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetflags);
                opn = "cgetflags";
                break;
            case OPC_CSEALENTRY_NI:   /* 0x1d << 6 */
                check_cop2x(ctx);
                gen_helper_2_consti32(csealentry, r16, r11);
                opn = "csealentry";
                break;
            case OPC_CLOADTAGS_NI:   /* 0x1e << 6 */
                check_cop2x(ctx);
                generate_cloadtags(ctx, r16, r11);
                opn = "cloadtags";
                break;

            /* One-operand cap instructions. */
            case OPC_C1OPERAND_NI:     /* 0x1f << 6 */
                switch(MASK_CAP8(opc)) {
                case OPC_CGETPCC_NI:    /* 0x00 << 11 */
                    check_cop2x(ctx);
                    generate_cgetpcc(ctx, r16);
                    opn = "cgetpcc";
                    break;
                case OPC_CGETCAUSE_NI:  /* 0x01 << 11 */
                    check_cop2x(ctx);
                    generate_cgetcause(ctx, r16);
                    opn = "cgetcause";
                    break;
                case OPC_CSETCAUSE_NI:  /* 0x02 << 11 */
                    check_cop2x(ctx);
                    generate_csetcause(r16);
                    opn = "csetcause";
                    break;
                case OPC_CJR_NI:        /* 0x03 << 11 */
                    check_cop2x(ctx);
                    generate_cjr(ctx, r16);
                    opn = "cjr";
                    break;

                default:
                    opn = "c1operand";
                    goto invalid;
                }
                break;

            default:
                opn = "c2operand";
                goto invalid;
            }
            break;

        default:
            opn = "cget";
            goto invalid;
        }
        break;
    case OPC_CSETBOUNDS: /* 0x01 */
        check_cop2x(ctx);
        generate_csetbounds(r16, r11, r6);
        opn = "csetbounds";
        break;
    case OPC_CSEAL:  /* 0x02 */
        check_cop2x(ctx);
        generate_cseal(r16, r11, r6);
        opn = "cseal";
        break;
    case OPC_CUNSEAL: /* 0x03 */
        check_cop2x(ctx);
        generate_cunseal(r16, r11, r6);
        opn = "cunseal";
        break;
    case OPC_CMISC: /* 0x04 */
        switch(MASK_CAP3(opc)) {
        case OPC_CANDPERM: /* 0x0 */
            gen_cheri_cap_cap_int(ctx, r16, r11, r6, &gen_helper_candperm);
            opn = "candperm";
            break;

        case OPC_CSETCAUSE: /* 0x4 */
            check_cop2x(ctx);
            generate_csetcause(r6);
            opn = "csetcause";
            break;
        case OPC_CCLEARTAG: /* 0x5 */
            check_cop2x(ctx);
            generate_ccleartag(r16, r11);
            opn = "ccleartag";
            break;
        case OPC_MTC2SEL6: /* 0x6 */
            {
                TCGv t0 = tcg_temp_new();

                gen_load_gpr(t0, r16);
                gen_mtc2(ctx, t0, r11, ctx->opcode & 0x7);
                tcg_temp_free(t0);
            }
            opn = "mtc2";
            break;
        case OPC_CFROMPTR: /* 0x7 */
            check_cop2x(ctx);
            generate_cfromptr(r16, r11, r6);
            opn = "cfromptr";
            break;
        default:
            opn = "cmisc";
            goto invalid;
        }
        break;
    case OPC_CCALL: /* 0x05 */
        switch(MASK_CCALL_SEL(opc)) {
        case CCALL_SELECTOR_CRETURN: /* 0x7ff */
            check_cop2x(ctx);
            opn = "creturn";
            generate_creturn();
            break;
        case CCALL_SELECTOR_0: /* 0x000 */
            check_cop2x(ctx);
            generate_ccall(r16, r11);
            opn = "ccall";
            break;
        case CCALL_SELECTOR_1: /* 0x001 */
        case CCALL_SELECTOR_2: /* 0x002 */
            check_cop2x(ctx);
            generate_ccall_notrap(ctx, r16, r11, MASK_CCALL_SEL(opc));
            opn = "ccall";
            break;
        default:
            opn = "ccall";
            goto invalid;
        }
        break;
    case OPC_CRETURN: /* 0x06 */
        check_cop2x(ctx);
        generate_creturn();
        opn = "creturn";
        break;
    case OPC_CJALR: /* 0x07 */
        check_cop2x(ctx);
        generate_cjalr(ctx, r16, r11);
        opn = "cjalr";
        break;
    case OPC_CJR: /* 0x08 */
        check_cop2x(ctx);
        generate_cjr(ctx, r11);
        opn = "cjr";
        break;
    case OPC_CBTU: /* 0x09 */
        opn = "cbtu";
        check_cop2x(ctx);
        generate_cbtu(ctx, r16, (int16_t)(ctx->opcode));
        break;
    case OPC_CBTS: /* 0x0a */
        opn = "cbts";
        check_cop2x(ctx);
        generate_cbts(ctx, r16, (int16_t)(ctx->opcode));
        break;
    case OPC_CCHECK: /* 0x0b */
        switch(MASK_CAP3(opc)) {
        case OPC_CCHECKPERM: /* 0x0 */
            check_cop2x(ctx);
            generate_ccheckperm(r16, r6);
            opn = "ccheckperm";
            break;
        case OPC_CCHECKTYPE: /* 0x1 */
            check_cop2x(ctx);
            generate_cchecktype(r16, r11);
            opn = "cchecktype";
            break;
        default:
            opn = "ccheck";
            goto invalid;
        }
        break;
    case OPC_CTOPTR: /* 0x0c */
        check_cop2x(ctx);
        generate_ctoptr(ctx, r16, r11, r6);
        opn = "ctoptr";
        break;
    case OPC_COFFSET: /* 0x0d */
        switch(MASK_CAP3(opc)) {
        case OPC_CINCOFFSET: /* 0x0 */
            check_cop2x(ctx);
            generate_cincoffset(r16, r11, r6);
            opn = "cincoffset";
            break;
        case OPC_CSETOFFSET: /* 0x1 */
            check_cop2x(ctx);
            generate_csetoffset(r16, r11, r6);
            opn = "csetoffset";
            break;
        case OPC_CGETOFFSET: /* 0x2 */
            generate_cheri_cget(ctx, r16, r11, &gen_helper_cgetoffset);
            opn = "cgetoffset";
            break;
        default:
            opn = "coffset";
            goto invalid;
        }
        break;
    case OPC_CPTRCMP: /* 0x0e */
        switch(MASK_CAP3(opc)) {
        case OPC_CEQ:  /* 0x0 */
            check_cop2x(ctx);
            generate_ceq(ctx, r16, r11, r6);
            opn = "ceq";
            break;
        case OPC_CNE:  /* 0x1 */
            check_cop2x(ctx);
            generate_cne(ctx, r16, r11, r6);
            opn = "cne";
            break;
        case OPC_CLT:  /* 0x2 */
            check_cop2x(ctx);
            generate_clt(ctx, r16, r11, r6);
            opn = "clt";
            break;
        case OPC_CLE:  /* 0x3 */
            check_cop2x(ctx);
            generate_cle(ctx, r16, r11, r6);
            opn = "cle";
            break;
        case OPC_CLTU: /* 0x4 */
            check_cop2x(ctx);
            generate_cltu(ctx, r16, r11, r6);
            opn = "cltu";
            break;
        case OPC_CLEU: /* 0x5 */
            check_cop2x(ctx);
            generate_cleu(ctx, r16, r11, r6);
            opn = "cleu";
            break;
        case OPC_CEXEQ: /* 0x6 */
            check_cop2x(ctx);
            generate_cexeq(ctx, r16, r11, r6);
            opn = "cexeq";
            break;
        case OPC_CNEXEQ: /* 0x7 */
            check_cop2x(ctx);
            generate_cnexeq(ctx, r16, r11, r6);
            opn = "cnexeq";
            break;
        default: /* Can't happen, because all possible values are allocated */
            opn = "cptrcmp";
            goto invalid;
        }
        break;
    case OPC_CCLEARREGS: /* 0x0f */
        opn = "cclearregs";
        check_cop2x(ctx);
        if (generate_cclearregs(ctx, r16, opc & 0xffff) != 0)
            goto invalid;
        break;
    case OPC_CLL:   /* 0x10 */
        /*
         * check_cop2x(ctx);
         */
        switch(MASK_CAP4(opc)) {
        case OPC_CSCB: /* 0x0 */
            generate_cstorecond_int(ctx, r16, r11, r6, MO_8, MASK_CAP4(opc));
            opn = "cscb";
            break;
        case OPC_CSCH: /* 0x1 */
            generate_cstorecond_int(ctx, r16, r11, r6,
                                    MO_TEUW | ctx->default_tcg_memop_mask,
                                    MASK_CAP4(opc));
            opn = "csch";
            break;
        case OPC_CSCW: /* 0x2 */
            generate_cstorecond_int(ctx, r16, r11, r6,
                                    MO_TEUL | ctx->default_tcg_memop_mask,
                                    MASK_CAP4(opc));
            opn = "cscw";
            break;
        case OPC_CSCD: /* 0x3 */
            generate_cstorecond_int(ctx, r16, r11, r6,
                                    MO_TEQ | ctx->default_tcg_memop_mask,
                                    MASK_CAP4(opc));
            opn = "cscd";
            break;

        case OPC_CSCC: /* 0x7 */
            check_cop2x(ctx);
            generate_cscc(ctx, r16, r11, r6);
            opn = "cscc";
            break;

        case OPC_CLLB: /* 0xc */
            generate_cloadlinked_int(ctx, r16, r11, MO_SB,MASK_CAP4(opc));
            opn = "cllb";
            break;
        case OPC_CLLH: /* 0xd */
            generate_cloadlinked_int(ctx, r16, r11,
                                     MO_TESW | ctx->default_tcg_memop_mask,
                                     MASK_CAP4(opc));

            opn = "cllh";
            break;
        case OPC_CLLW: /* 0xe */
            generate_cloadlinked_int(ctx, r16, r11,
                                     MO_TESL | ctx->default_tcg_memop_mask,
                                     MASK_CAP4(opc));
            opn = "cllw";
            break;
        case OPC_CLLD: /* 0xb */
            generate_cloadlinked_int(ctx, r16, r11,
                                     MO_TEQ | ctx->default_tcg_memop_mask,
                                     MASK_CAP4(opc));
            opn = "clld";
            break;
        case OPC_CLLBU: /* 0x8 */
            generate_cloadlinked_int(ctx, r16, r11,
                                     MO_UB | ctx->default_tcg_memop_mask,
                                     MASK_CAP4(opc));
            opn = "cllbu";
            break;
        case OPC_CLLHU: /* 0x9 */
            generate_cloadlinked_int(ctx, r16, r11,
                                     MO_TEUW | ctx->default_tcg_memop_mask,
                                     MASK_CAP4(opc));
            opn = "cllhu";
            break;
        case OPC_CLLWU: /* 0xa */
            generate_cloadlinked_int(ctx, r16, r11,
                                     MO_TEUL | ctx->default_tcg_memop_mask,
                                     MASK_CAP4(opc));
            opn = "cllwu";
            break;
        case OPC_CLLC: /* 0xf */
            check_cop2x(ctx);
            generate_cllc(ctx, r16, r11);
            opn = "cllc";
            break;

        default:
            opn = "cll";
            goto invalid;
        }
        break;
    case OPC_CBEZ_NI: /* 0x11 */
        check_cop2x(ctx);
        generate_cbez(ctx, r16, (int16_t)opc);
        opn = "cbez";
        break;
    case OPC_CBNZ_NI: /* 0x12 */
        check_cop2x(ctx);
        generate_cbnz(ctx, r16, (int16_t)opc);
        opn = "cbnz";
        break;
    case OPC_CINCOFFSETIMM_NI: /* 0x13 */
        check_cop2x(ctx);
        generate_cincoffset_imm(r16, r11, (opc & 0x7ff));
        opn = "cincoffsetimmediate";
        break;
    case OPC_CSETBOUNDSIMM_NI: /* 0x14 */
        check_cop2x(ctx);
        generate_csetbounds_imm(r16, r11, (opc & 0x7ff));
        opn = "csetboundsimmediate";
        break;

    default:
        goto invalid;
    }
    // FIXME: we can remove opn
    (void)opn; /* avoid a compiler warning */
    return;

invalid:
    MIPS_INVAL(opn);
    generate_exception (ctx, EXCP_RI);
    return;
}

#endif /* TARGET_CHERI */
