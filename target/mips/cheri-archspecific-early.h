/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2016 Stacey Son <sson@FreeBSD.org>
 * Copyright (c) 2016-2018 Alfredo Mazzinghi <am2419@cl.cam.ac.uk>
 * Copyright (c) 2016-2020 Alex Richardson <Alexander.Richardson@cl.cam.ac.uk>
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
#pragma once

#include "cheri_defs.h"
#include "cheri-archspecific-earlier.h"

// This needs a refactor. It is helpful to give special purpose registers
// numbers as then common code paths can be used for both general purpose and
// special purpose registers. For RISCV, the exception number was used for this
// purpose, and so arm followed suit in using CHERI_EXC_REGNUM_DDC. However, on
// mips, the actual exception number for DDC is 0. This is not helpful, as 0 is
// the zero register in some contexts. We should really have a DDC_REGNUM
// distinct from NULL_CAPREG_INDEX (which is what CHERI_EXC_REGNUM_DDC currently
// is) and CHERI_EXC_REGNUM_DDC which is only used for exceptions and nothing
// else.
#define CHERI_EXC_REGNUM_DDC 32
#define CHERI_TRUE_EXC_REGNUM_DDC 0
#define CHERI_EXC_REGNUM_PCC 0xff
#define CHERI_REGNUM_IDC  26  /* Invoked Data Capability */
#define CINVOKE_DATA_REGNUM CHERI_REGNUM_IDC
#define CHERI_CONTROLFLOW_CHECK_AT_TARGET 0
#define CHERI_TAG_CLEAR_ON_INVALID(env)   0
#define CHERI_TRANSLATE_DDC_RELOCATION(ctx) 1
#define CHERI_TRANSLATE_PCC_RELOCATION(ctx) 1

/*
 * QEMU currently tells the kernel that there are no caches installed
 * (xref target/mips/translate_init.inc.c MIPS_CONFIG1 definition)
 * so we're kind of free to make up a line size here.  For simplicity,
 * we pretend that our cache lines always contain 8 capabilities.
 */
#define CAP_TAG_GET_MANY_SHFT 3

typedef enum CheriCapExc {
    CapEx_None                          = 0x0,  /* None */
    CapEx_LengthViolation               = 0x1,  /* Length Violation */
    CapEx_TagViolation                  = 0x2,  /* Tag Violation */
    CapEx_SealViolation                 = 0x3,  /* Seal Violation */
    CapEx_TypeViolation                 = 0x4,  /* Type Violation */
    CapEx_CallTrap                      = 0x5,  /* Call Trap */
    CapEx_ReturnTrap                    = 0x6,  /* Return Trap */
    CapEx_TSSUnderFlow                  = 0x7,  /* Underflow of trusted system stack */
    CapEx_UserDefViolation              = 0x8,  /* User-defined Permission Violation */
    CapEx_TLBNoStoreCap                 = 0x9,  /* TLB prohibits store capability */
    CapEx_InexactBounds                 = 0xA,  /* Bounds cannot be represented exactly */
    CapEx_UnalignedBase                 = 0xB,
    CapEx_CapLoadGen                    = 0xC,
    // 0x0D-0x0F Reserved
    CapEx_GlobalViolation               = 0x10,  /* Global Violation */
    CapEx_PermitExecuteViolation        = 0x11,  /* Permit_Execute Violation */
    CapEx_PermitLoadViolation           = 0x12,  /* Permit_Load Violation */
    CapEx_PermitStoreViolation          = 0x13,  /* Permit_Store Violation */
    CapEx_PermitLoadCapViolation        = 0x14,  /* Permit_Load_Capability Violation */
    CapEx_PermitStoreCapViolation       = 0x15,  /* Permit_Store_Capability Violation */
    CapEx_PermitStoreLocalCapViolation  = 0x16,  /* Permit_Store_Local_Capability Violation */
    CapEx_PermitSealViolation           = 0x17,  /* Permit_Seal Violation */
    CapEx_AccessSystemRegsViolation     = 0x18,  /* Access System Registers Violation */
    CapEx_PermitCCallViolation          = 0x19,  /* Permit_CCall Violation */
    CapEx_AccessCCallIDCViolation       = 0x1A,  /* Access IDC in a CCall delay slot */
    CapEx_PermitUnsealViolation         = 0x1B,  /* Permit_Unseal violation */
    CapEx_PermitSetCIDViolation         = 0x1C,  /* Permit_SetCID violation */
    // 0x1d-0x1f Reserved
} CheriCapExcCause;

static inline const cap_register_t *cheri_get_ddc(CPUMIPSState *env) {
    cheri_debug_assert(env->active_tc.CHWR.DDC.cr_extra ==
                       CREG_FULLY_DECOMPRESSED);
    return &env->active_tc.CHWR.DDC;
}

static inline const cap_register_t *_cheri_get_pcc_unchecked(CPUMIPSState *env)
{
    cheri_debug_assert(env->active_tc.PCC.cr_extra == CREG_FULLY_DECOMPRESSED);
    return &env->active_tc.PCC;
}

static inline GPCapRegs *cheri_get_gpcrs(CPUArchState *env) {
    return &env->active_tc.gpcapregs;
}

#define CHERI_GPCAPREGS_MEMBER active_tc.gpcapregs
