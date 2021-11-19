/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Alfredo Mazzinghi
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

/*
 * C Glue code to bridge TCG instruction logging to the C++ perfetto interface.
 */

#include "qemu/osdep.h"
#include "qemu/log_instr.h"
#include "cpu.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/log_instr_perfetto.h"

/*
 * Initialize perfetto tracing.
 *
 * Start tracing thread when first called.
 */
void init_perfetto_backend(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    int cpu_id = env_cpu(env)->cpu_index;

    perfetto_init_cpu(cpu_id, &cpulog->backend_data);
}

/* Syncronize buffers on this CPU. */
void sync_perfetto_backend(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    perfetto_sync_cpu(cpulog->backend_data);
}

void emit_perfetto_entry(CPUArchState *env, cpu_log_entry_t *entry)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    perfetto_emit_instr(cpulog->backend_data, entry);
}

log_event_t *perfetto_log_event(cpu_log_entry_handle handle, int idx)
{
    return &g_array_index(handle->events, log_event_t, idx);
}

/* Helpers to access cpu_log_entry_t fields */
CPU_LOG_ENTRY_GETTER(uint16_t, asid)
CPU_LOG_ENTRY_GETTER(int, flags)
CPU_LOG_ENTRY_GETTER(qemu_log_instr_cpu_mode_t, next_cpu_mode)
CPU_LOG_ENTRY_GETTER(uint32_t, intr_code)
CPU_LOG_ENTRY_GETTER(uint64_t, intr_vector)
CPU_LOG_ENTRY_GETTER(uint64_t, intr_faultaddr)
CPU_LOG_ENTRY_GETTER(uint64_t, pc)
CPU_LOG_ENTRY_GETTER_DECL(const char *, insn_bytes)
{
    return &handle->insn_bytes[0];
}
CPU_LOG_ENTRY_GETTER(int, insn_size)
CPU_LOG_ENTRY_GETTER_DECL(int, mem)
{
    return handle->mem->len;
}
CPU_LOG_ENTRY_GETTER_DECL(int, regs)
{
    return handle->regs->len;
}
CPU_LOG_ENTRY_GETTER_DECL(int, events)
{
    return handle->events->len;
}
CPU_LOG_ENTRY_GETTER_DECL(const char *, txt_buffer)
{
    return handle->txt_buffer->str;
}

REG_INFO_GETTER(uint16_t, flags)
REG_INFO_GETTER(const char *, name)
REG_INFO_GETTER(uint64_t, gpr)
REG_INFO_GETTER_DECL(cap_register_handle, cap)
{
#ifdef TARGET_CHERI
    log_reginfo_t *r = &g_array_index(handle->regs, log_reginfo_t, idx);
    return (cap_register_handle)(&r->cap);
#else
    return NULL;
#endif
}

MEM_INFO_GETTER(uint8_t, flags)
MEM_INFO_GETTER(int, op)
MEM_INFO_GETTER(uint64_t, addr)
MEM_INFO_GETTER(uint64_t, value)
MEM_INFO_GETTER_DECL(cap_register_handle, cap)
{
#ifdef TARGET_CHERI
    log_meminfo_t *m = &g_array_index(handle->mem, log_meminfo_t, idx);
    return (cap_register_handle)(&m->cap);
#else
    return NULL;
#endif
}

CAPREG_GETTER_DECL(bool, tag)
{
#ifdef TARGET_CHERI
    return ((cap_register_t *)handle)->cr_tag;
#else
    /*
     * XXX-AM Error instead? these must be defined for non-CHERI
     * targets but will never be called.
     */
    return 0;
#endif
}

CAPREG_GETTER_DECL(bool, sealed)
{
#ifdef TARGET_CHERI
    return !cap_is_unsealed((cap_register_t *)handle);
#else
    return 0;
#endif
}

CAPREG_GETTER_DECL(uint64_t, base)
{
#ifdef TARGET_CHERI
    return cap_get_base((cap_register_t *)handle);
#else
    return 0;
#endif
}

CAPREG_GETTER_DECL(uint64_t, cursor)
{
#ifdef TARGET_CHERI
    return cap_get_cursor((cap_register_t *)handle);
#else
    return 0;
#endif
}

CAPREG_GETTER_DECL(uint64_t, length)
{
#ifdef TARGET_CHERI
    return cap_get_length_full((cap_register_t *)handle);
#else
    return 0;
#endif
}

CAPREG_GETTER_DECL(uint32_t, perms)
{
#ifdef TARGET_CHERI
    return cap_get_perms((cap_register_t *)handle);
#else
    return 0;
#endif
}

CAPREG_GETTER_DECL(uint32_t, otype)
{
#ifdef TARGET_CHERI
    return cap_get_otype_unsigned((cap_register_t *)handle);
#else
    return 0;
#endif
}
