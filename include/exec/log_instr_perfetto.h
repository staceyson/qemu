/*-
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
 * Note: This is internal to the C++ perfetto tracing glue code.
 */

#pragma once

#ifdef __cplusplus
#include <cstdint>
#include <perfetto.h>

/*
 * For each CPU we have the following tracks:
 * CPU N: track for generic CPU events, contains the following categories:
 *   - instructions: events related to the instruction stream
 *   - sched: scheduling events on the CPU or on context-track
 *   - trap: Contains interrupt and trap events with help from OS-driven events
 *   - ctrl: Tracing control events (e.g. when tracing is started and stopped)
 * Process/Thread/Compartment tracks:
 *   these are dynamic tracks that are created in response to OS-driven events,
 *   we rely on the OS to pass the pid/tid/cid triple when relevant.
 *   Each of these tracks is used to accumulate per-thread and per-compartment
 *   information.
 */
PERFETTO_DEFINE_CATEGORIES(
    perfetto::Category("instructions")
        .SetDescription("CPU instructions executed"),
    perfetto::Category("memory").SetDescription("Tag and memory load/store"),
    perfetto::Category("stats").SetDescription("High-level statistics data"),
    perfetto::Category("ctrl").SetDescription("Tracing control events"),
    perfetto::Category("trap").SetDescription("CPU trap events"),
    perfetto::Category("sched").SetDescription("Scheduling events"));
#endif

/*
 * XXX-AM: We can not import directly exec/log_instr_internal.h This is sad as
 * we need to generate wrappers to fetch cpu_log_entry fields to fill the trace
 * entry protobufs. For now this is somewhat hacky :(
 */
#ifdef __cplusplus
extern "C" {
#endif
/* Opaque handles for cpu_log_entry_t */
struct cpu_log_entry;
typedef struct cpu_log_entry *cpu_log_entry_handle;
struct log_reginfo;
typedef struct log_reginfo *reg_info_handle;
struct log_meminfo;
typedef struct log_meminfo *mem_info_handle;
typedef void *cap_register_handle;

void perfetto_init_cpu(int cpu_index, void **backend_data);
void perfetto_sync_cpu(void *backend_data);
void perfetto_emit_instr(void *backend_data, cpu_log_entry_handle entry_handle);

/*
 * cpu_log_entry getters implemented by the perfetto backend glue code.
 * Note: Sadly, the type must be manually be kept in sync with
 * log_instr_internal.h
 */
#define CPU_LOG_ENTRY_GETTER_DECL(type, field)                                 \
    type perfetto_log_entry_##field(cpu_log_entry_handle handle)
#define REG_INFO_GETTER_DECL(type, field)                                      \
    type perfetto_reg_info_##field(cpu_log_entry_handle handle, int idx)
#define MEM_INFO_GETTER_DECL(type, field)                                      \
    type perfetto_mem_info_##field(cpu_log_entry_handle handle, int idx)
#define CAPREG_GETTER_DECL(type, field)                                        \
    type perfetto_cap_##field(cap_register_handle handle)

#define CPU_LOG_ENTRY_GETTER(type, field)                                      \
    CPU_LOG_ENTRY_GETTER_DECL(type, field)                                     \
    {                                                                          \
        return (type)(handle->field);                                          \
    }
#define REG_INFO_GETTER(type, field)                                           \
    REG_INFO_GETTER_DECL(type, field)                                          \
    {                                                                          \
        log_reginfo_t *r = &g_array_index(handle->regs, log_reginfo_t, idx);   \
        return (type)(r->field);                                               \
    }
#define MEM_INFO_GETTER(type, field)                                           \
    MEM_INFO_GETTER_DECL(type, field)                                          \
    {                                                                          \
        log_meminfo_t *m = &g_array_index(handle->mem, log_meminfo_t, idx);    \
        return (type)(m->field);                                               \
    }

CPU_LOG_ENTRY_GETTER_DECL(uint16_t, asid);
CPU_LOG_ENTRY_GETTER_DECL(int, flags);
CPU_LOG_ENTRY_GETTER_DECL(qemu_log_instr_cpu_mode_t, next_cpu_mode);
CPU_LOG_ENTRY_GETTER_DECL(uint32_t, intr_code);
CPU_LOG_ENTRY_GETTER_DECL(uint64_t, intr_vector);
CPU_LOG_ENTRY_GETTER_DECL(uint64_t, intr_faultaddr);
CPU_LOG_ENTRY_GETTER_DECL(uint64_t, pc);
CPU_LOG_ENTRY_GETTER_DECL(int, insn_size);
CPU_LOG_ENTRY_GETTER_DECL(const char *, insn_bytes);
CPU_LOG_ENTRY_GETTER_DECL(int, mem);
CPU_LOG_ENTRY_GETTER_DECL(int, regs);
CPU_LOG_ENTRY_GETTER_DECL(int, events);
CPU_LOG_ENTRY_GETTER_DECL(const char *, txt_buffer);

log_event_t *perfetto_log_event(cpu_log_entry_handle handle, int idx);

REG_INFO_GETTER_DECL(uint16_t, flags);
REG_INFO_GETTER_DECL(const char *, name);
REG_INFO_GETTER_DECL(uint64_t, gpr);
REG_INFO_GETTER_DECL(cap_register_handle, cap);

MEM_INFO_GETTER_DECL(uint8_t, flags);
MEM_INFO_GETTER_DECL(int, op);
MEM_INFO_GETTER_DECL(uint64_t, addr);
MEM_INFO_GETTER_DECL(uint64_t, value);
MEM_INFO_GETTER_DECL(cap_register_handle, cap);

CAPREG_GETTER_DECL(bool, tag);
CAPREG_GETTER_DECL(bool, sealed);
CAPREG_GETTER_DECL(uint64_t, base);
CAPREG_GETTER_DECL(uint64_t, cursor);
CAPREG_GETTER_DECL(uint64_t, length);
CAPREG_GETTER_DECL(uint32_t, perms);
CAPREG_GETTER_DECL(uint32_t, otype);

#ifdef __cplusplus
}
#endif
