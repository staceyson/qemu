/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Alfredo Mazzinghi
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
#include <glib.h>

/*
 * CPU-independant instruction logging configuration helpers.
 * These are generally used during initialization to setup
 * logging.
 */

#ifdef CONFIG_TCG_LOG_INSTR

/* Max printf args. */
#define QEMU_LOG_PRINTF_ARG_MAX 8
/* Max printf's before flush. */
#define QEMU_LOG_PRINTF_BUF_DEPTH 32
/* Early flush if buffer gets this full. */
#define QEMU_LOG_PRINTF_FLUSH_BARRIER 32
/* Max name size for qemu counters and other events */
#define QEMU_LOG_EVENT_MAX_NAMELEN 64

/*
 * Instruction logging format
 */
typedef enum {
    QEMU_LOG_INSTR_BACKEND_TEXT = 0,
    QEMU_LOG_INSTR_BACKEND_CVTRACE = 1,
    QEMU_LOG_INSTR_BACKEND_NOP = 2,
#ifdef CONFIG_TRACE_PERFETTO
    QEMU_LOG_INSTR_BACKEND_PERFETTO = 3,
#endif
#ifdef CONFIG_TRACE_PROTOBUF
    QEMU_LOG_INSTR_BACKEND_PROTOBUF = 4,
#endif
#ifdef CONFIG_TRACE_JSON
    QEMU_LOG_INSTR_BACKEND_JSON = 5,
#endif
} qemu_log_instr_backend_t;

extern qemu_log_instr_backend_t qemu_log_instr_backend;

/*
 * CPU mode. This unifies the logging codes for CPU mode switches.
 * we take the same approach as with TCG DisasJumpType, where target
 * specific modes are supported by using one of the TARGET* values.
 * These values are meant to be usable for array indexing.
 */
typedef enum {
    QEMU_LOG_INSTR_CPU_USER = 0,
    QEMU_LOG_INSTR_CPU_SUPERVISOR = 1,
    QEMU_LOG_INSTR_CPU_HYPERVISOR = 2,
    QEMU_LOG_INSTR_CPU_DEBUG = 3,
    QEMU_LOG_INSTR_CPU_TARGET1 = 4,
    QEMU_LOG_INSTR_CPU_TARGET2 = 5,
    QEMU_LOG_INSTR_CPU_TARGET3 = 6,
    QEMU_LOG_INSTR_CPU_TARGET4 = 7,
    QEMU_LOG_INSTR_CPU_MODE_MAX
} qemu_log_instr_cpu_mode_t;

/*
 * XXX-AM: Consider using protobufs for log events so that they
 * are already in a serialized format when they reach the
 * perfetto backend.
 * How this would affect other formats?
 */

/*
 * Instruction logging per-CPU log level
 */
typedef enum {
    /* No logging for this CPU */
    QEMU_LOG_INSTR_LOGLEVEL_NONE = 0,
    /* Log all instructions */
    QEMU_LOG_INSTR_LOGLEVEL_ALL = 1,
    /* Only log when running in user-mode */
    QEMU_LOG_INSTR_LOGLEVEL_USER = 2,
} qemu_log_instr_loglevel_t;

/*
 * Trace event identifiers.
 */
typedef enum {
    LOG_EVENT_STATE = 0,
    LOG_EVENT_CTX_UPDATE = 1,
    LOG_EVENT_MARKER = 2,
    LOG_EVENT_REGDUMP = 3,
    LOG_EVENT_COUNTER = 4,
} log_event_id_t;

/*
 * Tracing status changed (e.g. trace start/stop)
 */
typedef enum {
    LOG_EVENT_STATE_START = 0,
    LOG_EVENT_STATE_STOP = 1,
    LOG_EVENT_STATE_FLUSH = 2
} log_event_trace_state_t;

typedef struct {
    log_event_trace_state_t next_state;
    uint64_t pc;
} log_event_trace_state_update_t;

typedef enum {
    /*
     * Switch context from the current to the new (proc, thread, compartment) ID
     */
    LOG_EVENT_CTX_OP_SWITCH = 0
} log_event_ctx_update_op_t;

/*
 * Context update event.
 */
typedef struct {
    log_event_ctx_update_op_t op;   /* What changed */
    uint64_t pid;                   /* Process ID */
    uint64_t tid;                   /* Thread ID */
    uint64_t cid;                   /* Compartment ID */
    qemu_log_instr_cpu_mode_t mode; /* CPU mode */
} log_event_ctx_update_t;

/*
 * Register dump event.
 * This is used to emit guest register dumps. The main use case is to
 * recover lost state due to pause/unpause of the trace.
 */
typedef struct {
    /*
     * Register info - array of log_reginfo_t
     * Use the qemu_log_instr_event_rdump_* interface to add entries.
     */
    GArray *gpr;
} log_event_regdump_t;

/*
 * Counter event.
 * This represents an arbitrary named counter. Generally driven from the
 * guest OS via NOPs, but can also be generated internally.
 */
typedef struct {
    char name[QEMU_LOG_EVENT_MAX_NAMELEN];
    int64_t value;
    uint64_t flags;
} log_event_counter_t;

#define log_event_counter_slot(flags)        (flags & 0xffff)
#define log_event_counter_incremental(flags) ((flags >> 32) & 0x01)

/*
 * Trace event.
 * This records arbitrary higher-level events associated with instruction
 * entries.
 * Currently, in order to reduce complexity, the event definitions are
 * target-agnostic, and we assume that all targets interested in emitting
 * the events will need to implement some logic to fill the data structures
 * taking care of any casting necessary.
 * This is at the cost of wasting some space for architectures that do not
 * have 64bit words. An additional burden is put on the target to perform
 * some dynamic allocation for some events. This is sub-optimal but the
 * alternative requires extra time to implement and this is good enough
 * for now.
 */
typedef struct {
    log_event_id_t id;
    union {
        log_event_trace_state_update_t state;
        log_event_ctx_update_t ctx_update;
        log_event_regdump_t reg_dump;
        uint64_t marker;
        log_event_counter_t counter;
    };
} log_event_t;

#ifdef CONFIG_TRACE_PERFETTO
/* Perfetto backend configuration hooks */
#ifdef __cplusplus
extern "C" {
#endif
void qemu_log_instr_perfetto_conf_logfile(const char *name);
int qemu_log_instr_perfetto_conf_categories(const char *category_list);
#ifdef __cplusplus
}
#endif
#endif /* CONFIG_TRACE_PERFETTO */

#ifdef CONFIG_TRACE_PROTOBUF
void qemu_log_instr_protobuf_conf_logfile(const char *name);
#endif /* CONFIG_TRACE_PROTOBUF  */

#ifndef __cplusplus
/* No visibility in the perfetto tracing backend */

static inline void qemu_log_instr_set_backend(qemu_log_instr_backend_t id)
{
    qemu_log_instr_backend = id;
}

static inline qemu_log_instr_backend_t qemu_log_instr_get_backend(void)
{
    return qemu_log_instr_backend;
}

struct cpu_log_instr_info;

typedef union {
    char charv;
    short shortv;
    unsigned short ushortv;
    int intv;
    unsigned int uintv;
    long longv;
    unsigned long ulongv;
    long long longlongv;
    unsigned long long ulonglongv;
    float floatv;
    double doublev;
    void *ptrv;
} qemu_log_arg_t;

typedef struct {
    /* arguments to printf calls */
    qemu_log_arg_t args[QEMU_LOG_PRINTF_ARG_MAX * QEMU_LOG_PRINTF_BUF_DEPTH];
    const char *fmts[QEMU_LOG_PRINTF_BUF_DEPTH]; /* the printf fmts */
    uint64_t valid_entries; /* bitmap of which entries are valid */
} qemu_log_printf_buf_t;

/*
 * Per-CPU tracing statistics.
 */
typedef struct qemu_log_instr_stats {
    uint64_t entries_emitted;
    uint64_t trace_start;
    uint64_t trace_stop;
} qemu_log_instr_stats_t;

#define QEMU_LOG_INSTR_INC_STAT(cpu_state, stat)                               \
    do {                                                                       \
        cpu_state->stats.stat++;                                               \
    } while (0)

/*
 * Per-cpu logging state.
 */
typedef struct {
    /* Per-CPU instruction log level */
    qemu_log_instr_loglevel_t loglevel;
    /* Is the current log level active or paused? */
    bool loglevel_active;
    /* Force skipping of the current instruction being logged */
    bool force_drop;
    /* We are starting to log at the next commit */
    bool starting;
    /* Per-CPU flags */
    int flags;
#define QEMU_LOG_INSTR_FLAG_BUFFERED 1
    /* Trace entry filter functions */
    GArray *filters;
    /* Ring buffer of log_instr_info */
    GArray *instr_info;
    /* Ring buffer index of the next entry to write */
    size_t ring_head;
    /* Ring buffer index of the first entry to dump */
    size_t ring_tail;
    /* Accumulated debug printf buffer */
    qemu_log_printf_buf_t qemu_log_printf_buf;
    /* Private trace backend state */
    void *backend_data;
    /* Statistics for debugging */
    qemu_log_instr_stats_t stats;
} cpu_log_instr_state_t;

/*
 * Handles for instruction filters/callbacks.
 * These are used to identify and attach/detach instruction log entry filters,
 * the rationale for this is that the filters require access to the private
 * instruction log entry record structure and can only be defined within the
 * instruction logging core implementation. This solution mimics the trace
 * backend handling.
 */
typedef enum {
    LOG_INSTR_FILTER_MEM_RANGE = 0,
    LOG_FILTER_EVENTS = 1,
    LOG_INSTR_FILTER_MAX
} cpu_log_instr_filter_t;

/*
 * Initialize instruction logging for a cpu.
 */
void qemu_log_instr_init(CPUState *env);

/*
 * Hook to make sure all tracing buffers are synced on qemu shutdown.
 */
void qemu_log_instr_sync_buffers(void);

/*
 * Global instruction logging hook from qemu tracing commands.
 */
int qemu_log_instr_global_switch(int log_flags);

/*
 * Update the ring buffer size.
 * Note that this does not guarantee that the existing buffered
 * entries will be retained.
 */
void qemu_log_instr_set_buffer_size(unsigned long buffer_size);

/*
 * Set filters to activate from string names.
 * This is safe to call during startup as if no CPU exists, we
 * will set the filters when the CPU startup occurs.
 */
void qemu_log_instr_set_cli_filters(const char *filter_spec, Error **errp);

/*
 * Add a trace filter during startup. This will be activated on all the CPUs
 * that are initialized after the call.
 * After the CPUs have been initialized, this will set the filters on all
 * existing CPUs.
 */
void qemu_log_instr_add_startup_filter(cpu_log_instr_filter_t filter);

/*
 * Trigger update of the instruction entry filter reusing
 * the -dfilter qemu option to limit tracing to only interesting
 * memory ranges..
 */
void qemu_log_instr_mem_filter_update(void);

/*
 * Enable debug statistics recording.
 */
void qemu_log_instr_enable_trace_debug(void);
#endif /* ! __cplusplus */

#else /* ! CONFIG_TCG_LOG_INSTR */
#define qemu_log_instr_set_backend(id) ((void)0)
#endif /* ! CONFIG_TCG_LOG_INSTR */
