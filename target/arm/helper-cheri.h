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

DEF_HELPER_5(load_cap_pair_via_cap, void, env, i32, i32, i32, tl)
DEF_HELPER_5(store_cap_pair_via_cap, void, env, i32, i32, i32, tl)

DEF_HELPER_5(load_exclusive_cap_via_cap, void, env, i32, i32, i32, tl)
DEF_HELPER_6(store_exclusive_cap_via_cap, void, env, i32, i32, i32, i32, tl)

DEF_HELPER_5(swap_cap_via_cap, void, env, i32, i32, i32, tl)
DEF_HELPER_5(compare_swap_cap_via_cap, void, env, i32, i32, i32, tl)

DEF_HELPER_5(load_cap_via_cap_mmu_idx, void, env, i32, i32, tl, i32)
DEF_HELPER_5(store_cap_via_cap_mmu_idx, void, env, i32, i32, tl, i32)

DEF_HELPER_6(load_pair_and_branch_and_link, void, env, i32, i32, i32, tl, i32)
DEF_HELPER_6(load_and_branch_and_link, void, env, i32, i32, i32, tl, i32)
DEF_HELPER_6(branch_sealed_pair, void, env, i32, i32, i32, tl, i32)

DEF_HELPER_3(load_tags, i64, env, i32, tl)
DEF_HELPER_4(store_tags, void, env, i64, i32, tl)

DEF_HELPER_FLAGS_1(check_capabilities_enabled_exception, TCG_CALL_NO_RETURN,
                   void, env)
DEF_HELPER_FLAGS_2(sys_not_accessible_exception, TCG_CALL_NO_RETURN, void, env,
                   i32)

DEF_HELPER_2(set_pcc, void, env, tl)
