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
 * Internal TCG instruction logging macros and types.
 * This should only be included by the instruction logging backend
 * implementation and not from the qemu targets.
 */

#pragma once

/* cpu_log_entry flags */
/* Entry contains a synchronous exception */
#define LI_FLAG_INTR_TRAP (1 << 0)
/* Entry contains an asynchronous exception */
#define LI_FLAG_INTR_ASYNC (1 << 1)
#define LI_FLAG_INTR_MASK  (LI_FLAG_INTR_TRAP | LI_FLAG_INTR_ASYNC)
/* Entry contains a CPU mode-switch and associated code */
#define LI_FLAG_MODE_SWITCH (1 << 2)
/* Entry contains instruction data or just events */
#define LI_FLAG_HAS_INSTR_DATA (1 << 3)

/* register info flags */
#define LRI_CAP_REG   1
#define LRI_HOLDS_CAP 2

/* memory op info flags */
#define LMI_LD  1
#define LMI_ST  2
#define LMI_CAP 4

#ifndef __cplusplus
/*
 * Temporary argument to the log-level switching callbacks.
 * This is passed internally to async_run_on_cpu()
 */
typedef struct {
    bool global;
    qemu_log_instr_loglevel_t next_level;
    target_ulong pc;
} qemu_log_next_level_arg_t;

/*
 * Instruction log info associated with each committed log entry.
 * This is stored in the per-cpu log cpustate.
 */
typedef struct cpu_log_entry {
#define cpu_log_entry_startzero asid
    uint16_t asid;
    int flags;
    qemu_log_instr_cpu_mode_t next_cpu_mode;
    uint32_t intr_code;
    target_ulong intr_vector;
    target_ulong intr_faultaddr;

    target_ulong pc;
    /* Generic instruction opcode buffer */
    int insn_size;
    char insn_bytes[TARGET_MAX_INSN_SIZE];
#define cpu_log_entry_endzero mem
    /*
     * Array of log_meminfo_t.
     * For now we allow multiple accesses to be tied to one instruction.
     * Some architectures may have multiple memory accesses
     * in the same instruction (e.g. x86-64 pop r/m64,
     * vector/matrix instructions, load/store pair). It is unclear
     * whether we would treat these as multiple trace "entities".
     */
    GArray *mem;
    /* Register modifications - array of log_reginfo_t */
    GArray *regs;
    /*
     * Events associated with the instruction - array of log_event_t.
     * Note that events may be present even if the entry does not contain
     * valid instruction state. This allows the flexibility of only
     * instrumenting a subset of the instructions/events.
     */
    GArray *events;
    /* Extra text-only log */
    GString *txt_buffer;
} cpu_log_entry_t;

/*
 * Register update info.
 * This records a CPU register update occurred during an instruction.
 */
typedef struct log_reginfo {
    uint16_t flags;
    const char *name;
    union {
        target_ulong gpr;
#ifdef TARGET_CHERI
        cap_register_t cap;
#endif
    };
} log_reginfo_t;

#define reginfo_is_cap(ri)  (ri->flags & LRI_CAP_REG)
#define reginfo_has_cap(ri) (reginfo_is_cap(ri) && (ri->flags & LRI_HOLDS_CAP))

/*
 * Memory access info.
 * This records a memory access occurred during an instruction.
 */
typedef struct log_meminfo {
    uint8_t flags;
    MemOp op;
    target_ulong addr;
    union {
        uint64_t value;
#ifdef TARGET_CHERI
        cap_register_t cap;
#endif
    };
} log_meminfo_t;

/*
 * Callbacks defined by a trace backend implementation.
 * These are called to covert instruction tracing events to the corresponding
 * binary or text format.
 */
struct trace_backend_hooks {
    void (*init)(CPUArchState *env);
    void (*sync)(CPUArchState *env);
    void (*emit_header)(CPUArchState *env);
    void (*emit_instr)(CPUArchState *env, cpu_log_entry_t *entry);
};
typedef struct trace_backend_hooks trace_backend_hooks_t;

/*
 * Instruction entry filter function.
 * Return false if the entry should be dropped, true otherwise.
 */
typedef bool (*cpu_log_instr_filter_fn_t)(struct cpu_log_entry *entry);

/* Text backend */
void emit_text_instr(CPUArchState *env, cpu_log_entry_t *entry);
/* CVTrace backend */
void emit_cvtrace_header(CPUArchState *env);
void emit_cvtrace_entry(CPUArchState *env, cpu_log_entry_t *entry);
#ifdef CONFIG_TRACE_PERFETTO
/* Perfetto backend */
void init_perfetto_backend(CPUArchState *env);
void sync_perfetto_backend(CPUArchState *env);
void emit_perfetto_entry(CPUArchState *env, cpu_log_entry_t *entry);
#endif
#ifdef CONFIG_TRACE_PROTOBUF
void init_protobuf_backend(CPUArchState *env);
void sync_protobuf_backend(CPUArchState *env);
void emit_protobuf_entry(CPUArchState *env, cpu_log_entry_t *entry);
#endif

#ifdef CONFIG_DEBUG_TCG
#define log_assert(x) assert((x))
#else
#define log_assert(x)
#endif

/*
 * Fetch the log state for a cpu.
 */
static inline cpu_log_instr_state_t *get_cpu_log_state(CPUArchState *env)
{
    return &env_cpu(env)->log_state;
}

/*
 * Fetch the given cpu current instruction info
 */
static inline cpu_log_entry_t *get_cpu_log_entry(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    return &g_array_index(cpulog->instr_info, cpu_log_entry_t,
                          cpulog->ring_head);
}
#endif /* __cplusplus */
