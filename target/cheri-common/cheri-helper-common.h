/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Alex Richardson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

/* All helpers shared between RISCV and MIPS are defined here.
 * Helpers are grouped by instruction kind and sorted alphabetically within
 * each group.
 *
 * Most are implemented in op_helper_cheri_common.c, but some have
 * target-dependent implementations and are defined in
 * target/mips/op_helper_cheri.c or target/riscv/op_helper_cheri.c.
 */

// Lazy capreg state is a global, and so anything that might
// cause a decompression can write global.

// PCC bounds checks:
// Use these for instruction fetch faults
DEF_HELPER_1(raise_exception_pcc_perms, noreturn, env)
DEF_HELPER_3(raise_exception_pcc_bounds, noreturn, env, tl, i32)
// And these for loads/stores
DEF_HELPER_3(raise_exception_pcc_perms_not_if, noreturn, env, tl, i32)
DEF_HELPER_3(raise_exception_ddc_perms, noreturn, env, tl, i32)
DEF_HELPER_3(raise_exception_ddc_bounds, noreturn, env, tl, i32)

// Two-operand capability inspection
DEF_HELPER_FLAGS_2(cgetaddr, TCG_CALL_NO_WG, tl, env, i32)
DEF_HELPER_FLAGS_2(cgetbase, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgetflags, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgethigh, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgetlen, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgetperm, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgetoffset, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgetsealed, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgettag, 0, tl, env, i32)
DEF_HELPER_FLAGS_2(cgettype, 0, tl, env, i32)

// Two operands (cap cap)
DEF_HELPER_3(ccleartag, void, env, i32, i32)
DEF_HELPER_3(cmove, void, env, i32, i32)
DEF_HELPER_3(cchecktype, void, env, i32, i32)
DEF_HELPER_3(csealentry, void, env, i32, i32)
DEF_HELPER_3(cinvoke, void, env, i32, i32)

// Two operands (cap int)
DEF_HELPER_3(ccheckperm, void, env, i32, tl)
DEF_HELPER_3(cgetpccsetoffset, void, env, i32, tl)
DEF_HELPER_3(cgetpccincoffset, void, env, i32, tl)
DEF_HELPER_3(cgetpccsetaddr, void, env, i32, tl)

// Two operands (int int)
DEF_HELPER_FLAGS_2(crap, TCG_CALL_NO_RWG_SE, tl, env, tl)
DEF_HELPER_FLAGS_2(cram, TCG_CALL_NO_RWG_SE, tl, env, tl)

// Three operands (cap cap cap)
DEF_HELPER_4(cbuildcap, void, env, i32, i32, i32)
DEF_HELPER_4(ccopytype, void, env, i32, i32, i32)
DEF_HELPER_4(ccseal, void, env, i32, i32, i32)
DEF_HELPER_4(cseal, void, env, i32, i32, i32)
DEF_HELPER_4(cunseal, void, env, i32, i32, i32)

// Three operands (cap cap int)
DEF_HELPER_4(candaddr, void, env, i32, i32, tl)
DEF_HELPER_4(candperm, void, env, i32, i32, tl)
DEF_HELPER_4(cfromptr, void, env, i32, i32, tl)
DEF_HELPER_4(cincoffset, void, env, i32, i32, tl)

// Rather than waste TCG vals on a few bits of flags, they can be placed in the
// 32-bit register numbers. Also has the benefit of optimising away when defined
// to 0 for targets that do not support them.
#define HELPER_REG_MASK 0xFF
#ifdef TARGET_AARCH64
#define CJALR_MUST_BE_SENTRY (1 << 8)
#define CJALR_CAN_BRANCH_RESTRICTED (1 << 9)
#define CJALR_DONT_MAKE_SENTRY (1 << 10)
#else
#define CJALR_MUST_BE_SENTRY 0
#define CJALR_CAN_BRANCH_RESTRICTED 0
#define CJALR_DONT_MAKE_SENTRY 0
#endif
DEF_HELPER_5(cjalr, void, env, i32, i32, tl, tl)
DEF_HELPER_4(csetaddr, void, env, i32, i32, tl)
DEF_HELPER_4(csethigh, void, env, i32, i32, tl)
DEF_HELPER_4(csetbounds, void, env, i32, i32, tl)
DEF_HELPER_4(csetboundsexact, void, env, i32, i32, tl)
#ifndef TARGET_AARCH64
DEF_HELPER_4(csetflags, void, env, i32, i32, tl)
#endif
DEF_HELPER_4(csetoffset, void, env, i32, i32, tl)

// Three operands (int cap cap)
DEF_HELPER_FLAGS_3(csub, 0, tl, env, i32, i32)
DEF_HELPER_FLAGS_3(ctestsubset, 0, tl, env, i32, i32)
DEF_HELPER_FLAGS_3(cseqx, 0, tl, env, i32, i32)
DEF_HELPER_FLAGS_3(ctoptr, 0, tl, env, i32, i32)

// Loads+Stores
/*
 * These perform cap+offset checks which are not compatible with the assumption
 * of the AArch64 tcg usage that makes use addresses everywhere.
 * FIXME: these helpers should probably be deprecated in favour of a single one.
 */
DEF_HELPER_4(cap_load_check, cap_checked_ptr, env, i32, tl, i32)
DEF_HELPER_4(cap_store_check, cap_checked_ptr, env, i32, tl, i32)
DEF_HELPER_4(cap_rmw_check, cap_checked_ptr, env, i32, tl, i32)
DEF_HELPER_5(cap_check_addr, cap_checked_ptr, env, i32, tl, i32, i32)
DEF_HELPER_4(load_cap_via_cap, void, env, i32, tl, i32)
DEF_HELPER_3(load_cap_via_ddc, void, env, i32, tl)
DEF_HELPER_4(store_cap_via_cap, void, env, i32, tl, i32)
DEF_HELPER_3(store_cap_via_ddc, void, env, i32, tl)

// Misc
DEF_HELPER_2(decompress_cap, void, env, i32)
DEF_HELPER_2(cloadtags, tl, env, i32)
// Slightly different from normal tracing as it will not trigger decompression.
// This is helpful if there is a TCG bug that would go away with tracing.
DEF_HELPER_2(debug_cap, void, env, i32)

// Check that static optimisation is correct
DEF_HELPER_4(capreg_state_debug, void, env, i32, i64, i64)
