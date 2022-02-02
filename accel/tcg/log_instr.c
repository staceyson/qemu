/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020,2021 Alfredo Mazzinghi
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

#include <stdint.h>

#include "qemu/osdep.h"
#include "qemu/range.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu-param.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "exec/helper-proto.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"
#include "exec/translator.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"

/*
 * CHERI common instruction logging.
 *
 * This is the central implementation of the CPU_LOG_INSTR tracing.
 * The same functions can be used by CHERI targets to append to the instruction
 * log buffer. Once the instruction is fully processed, the target commits the
 * log buffer and depending on the instruction operations and -dfilter options
 * we either flush the buffer or drop it.
 * A central desing goal is to reliably log multiple register updates and memory
 * accesses performed by an instruction. We also want to allow to log arbitary
 * events via special no-op instructions. Extra text debug output can also be
 * appended to the instruction log info.
 *
 * The output trace format can be easily changed by implementing a new set of
 * trace_fmt_hooks.
 *
 * The CPU_LOG_INSTR flag is used as a global enable to signal that logging is
 * active. Each CPU holds a private logging state, that can be controlled
 * individually.
 *
 * TODO(am2419): how do we deal with orderding in case multiple registers are
 * updated? This is critical to recognize which value goes in which register,
 * and also how to tie multiple memory accesses to the respective
 * value/register. We could add an explicit target-specific register ID handle
 * in place of the register name. This could be used also to fetch the register
 * name and would provide an identifier to external parsers. Memory updates are
 * harder to deal with, at least in the current format, perhaps the semantic of
 * the instruction is enough to recover the ordering from a trace.
 */

#ifdef CONFIG_TCG_LOG_INSTR

// #define CONFIG_DEBUG_TCG

#ifndef TARGET_MAX_INSN_SIZE
#error "Target does not define TARGET_MAX_INSN_SIZE in cpu-param.h"
#endif

/*
 * -dfilter ranges in common logging implementation.
 */
extern GArray *debug_regions;

/* Global trace format selector. Defaults to text tracing */
qemu_log_instr_backend_t qemu_log_instr_backend = QEMU_LOG_INSTR_BACKEND_TEXT;

/* Current format callbacks. */
static trace_backend_hooks_t *trace_backend;

static void emit_nop_entry(CPUArchState *env, cpu_log_entry_t *entry);

/*
 * Existing format callbacks list, indexed by qemu_log_instr_backend_t.
 */
static trace_backend_hooks_t trace_backends[] = {
    { .init = NULL,
      .sync = NULL,
      .emit_header = NULL,
      .emit_instr = emit_text_instr },
    { .init = NULL,
      .sync = NULL,
      .emit_header = emit_cvtrace_header,
      .emit_instr = emit_cvtrace_entry },
    { .init = NULL,
      .sync = NULL,
      .emit_header = NULL,
      .emit_instr = emit_nop_entry },
#ifdef CONFIG_TRACE_PERFETTO
    { .init = init_perfetto_backend,
      .sync = sync_perfetto_backend,
      .emit_header = NULL,
      .emit_instr = emit_perfetto_entry },
#endif
#ifdef CONFIG_TRACE_PROTOBUF
    { .init = init_protobuf_backend,
      .sync = sync_protobuf_backend,
      .emit_header = NULL,
      .emit_instr = emit_protobuf_entry },
#endif
#ifdef CONFIG_TRACE_JSON
    { .init = init_json_backend,
      .sync = sync_json_backend,
      .emit_header = NULL,
      .emit_instr = emit_json_entry },
#endif
};

/* Existing trace filters list, indexed by cpu_log_instr_filter_t */
static cpu_log_instr_filter_fn_t trace_filters[];

/* Trace filters to activate when a new CPU is seen */
static GArray *reset_filters;

/* Number of per-cpu ring buffer entries for ring-buffer tracing mode */
#define MIN_ENTRY_BUFFER_SIZE (1 << 16)

static unsigned long reset_entry_buffer_size = MIN_ENTRY_BUFFER_SIZE;

static bool trace_debug;

static void emit_nop_entry(CPUArchState *env, cpu_log_entry_t *entry)
{
    return;
}

static void dump_debug_stats(CPUState *cpu)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(cpu->env_ptr);
    qemu_log_instr_stats_t *stats = &cpulog->stats;

    if (!trace_debug) {
        return;
    }

    fprintf(stderr, "TCG Instruction tracing statistics: CPU #%d\n",
            cpu->cpu_index);
    fprintf(stderr, "entries emitted: %lu\n", stats->entries_emitted);
    fprintf(stderr, "trace slices: %lu\n", stats->trace_start);
    if (stats->trace_start != stats->trace_stop) {
        fprintf(stderr, "Unbalanced trace stop: %lu\n", stats->trace_stop);
    }
}

void qemu_log_instr_enable_trace_debug()
{
    trace_debug = true;
}

static void emit_regdump_event(CPUArchState *env, cpu_log_entry_t *entry)
{
    log_event_t event;

    event.id = LOG_EVENT_REGDUMP;
    if (cpu_log_instr_event_regdump(env, &event)) {
        return;
    }
    g_array_append_val(entry->events, event);
}

static inline void emit_start_event(cpu_log_entry_t *entry, target_ulong pc)
{
    log_event_t event;

    event.id = LOG_EVENT_STATE;
    event.state.next_state = LOG_EVENT_STATE_START;
    event.state.pc = pc;
    /* Start events always have incomplete instruction data */
    entry->flags &= ~LI_FLAG_HAS_INSTR_DATA;
    /*
     * Also update PC to the one given in the start event.
     * This ensures that the pc field is always correct, even on the first
     * incomplete entry of the trace, where the start trigger occurs.
     * XXX-AM: Does this mean that we can do away with the state.pc field?
     */
    entry->pc = pc;

    g_array_append_val(entry->events, event);
}

static inline void emit_stop_event(cpu_log_entry_t *entry, target_ulong pc)
{
    log_event_t event;

    event.id = LOG_EVENT_STATE;
    event.state.next_state = LOG_EVENT_STATE_STOP;
    event.state.pc = pc;

    g_array_append_val(entry->events, event);
}

/* Reset instruction info buffer for next instruction */
static void reset_log_buffer(cpu_log_instr_state_t *cpulog,
                             cpu_log_entry_t *entry)
{
    log_event_t *evt;
    int i;

    memset(&entry->cpu_log_entry_startzero, 0,
           ((char *)&entry->cpu_log_entry_endzero -
            (char *)&entry->cpu_log_entry_startzero));
    g_array_remove_range(entry->regs, 0, entry->regs->len);
    g_array_remove_range(entry->mem, 0, entry->mem->len);
    /*
     * Need to free any dynamic allocation in the event structures to
     * avoid leaking memory. This is called before the log entry is
     * reused, so the memory might be reclaimed much later than the allocation
     * time.
     */
    for (i = 0; i < entry->events->len; i++) {
        evt = &g_array_index(entry->events, log_event_t, i);
        if (evt->id == LOG_EVENT_REGDUMP) {
            g_array_free(evt->reg_dump.gpr, true);
        }
    }
    g_array_remove_range(entry->events, 0, entry->events->len);
    g_string_erase(entry->txt_buffer, 0, -1);
    cpulog->force_drop = false;
    cpulog->starting = false;
}

/* Common instruction commit implementation */

static void do_instr_commit(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    cpu_log_instr_filter_fn_t filter;
    int i;

    log_assert(cpulog != NULL && "Invalid log state");
    log_assert(entry != NULL && "Invalid log buffer");

    if (cpulog->force_drop)
        return;

    for (i = 0; i < cpulog->filters->len; i++) {
        filter = g_array_index(cpulog->filters, cpu_log_instr_filter_fn_t, i);
        if (!filter(entry)) {
            return;
        }
    }

    if (cpulog->flags & QEMU_LOG_INSTR_FLAG_BUFFERED) {
        cpulog->ring_head = (cpulog->ring_head + 1) % cpulog->instr_info->len;
        if (cpulog->ring_tail == cpulog->ring_head)
            cpulog->ring_tail =
                (cpulog->ring_tail + 1) % cpulog->instr_info->len;
    } else {
        trace_backend->emit_instr(env, entry);
        QEMU_LOG_INSTR_INC_STAT(cpulog, entries_emitted);
    }
}

/*
 * Perform the actual work to change per-CPU log level.
 * This runs in the CPU exclusive context.
 *
 * Note:
 * If we start logging, we delay emitting the start event until the next commit.
 * This is because on the path from the exclusive context to the translation
 * loop we may get an interrupt/exception causing a switch in CPU mode, causing
 * to stop logging. This would result in a pointless start/stop sequence with
 * no instructions executed in beteween.
 */
static void do_cpu_loglevel_switch(CPUState *cpu, run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    tcg_debug_assert(env != NULL && "Called to early?");
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    qemu_log_instr_loglevel_t prev_level = cpulog->loglevel;
    bool prev_level_active = cpulog->loglevel_active;
    qemu_log_next_level_arg_t *arg = data.host_ptr;
    target_ulong pc = (arg->global) ? cpu_get_recent_pc(env) : arg->pc;
    bool next_level_active;

    log_assert(qemu_loglevel_mask(CPU_LOG_INSTR));

    /* Decide whether we have to pause/resume logging */
    switch (arg->next_level) {
    case QEMU_LOG_INSTR_LOGLEVEL_NONE:
        next_level_active = false;
        break;
    case QEMU_LOG_INSTR_LOGLEVEL_ALL:
        next_level_active = true;
        break;
    case QEMU_LOG_INSTR_LOGLEVEL_USER:
        /*
         * Assume entry holds the mode switch that caused cpu_loglevel_switch
         * to be called
         */
        if (entry->flags & LI_FLAG_MODE_SWITCH)
            next_level_active =
                (entry->next_cpu_mode == QEMU_LOG_INSTR_CPU_USER);
        else
            next_level_active = cpu_in_user_mode(env);
        break;
    default:
        log_assert(false && "Invalid cpu instruction log level");
        warn_report("Invalid cpu %d instruction log level\r", cpu->cpu_index);
    }

    /* Update level */
    cpulog->loglevel = arg->next_level;
    cpulog->loglevel_active = next_level_active;

    /* Check if this was a no-op */
    if (arg->next_level == prev_level &&
        prev_level_active == next_level_active) {
        goto done;
    }
    tb_flush(cpu);
    /* Emit start/stop events */
    if (prev_level_active) {
        if (cpulog->starting) {
            reset_log_buffer(cpulog, entry);
            goto done;
        }
        emit_stop_event(entry, pc);
        QEMU_LOG_INSTR_INC_STAT(cpulog, trace_stop);
        do_instr_commit(env);
        /* Instruction commit may have advanced to the next entry buffer slot */
        entry = get_cpu_log_entry(env);
        reset_log_buffer(cpulog, entry);
    }
    if (next_level_active) {
        cpulog->starting = true;
        /*
         * Note: the start event is emitted by the first instruction being
         * traced
         */
        emit_start_event(entry, pc);
        emit_regdump_event(env, entry);
        QEMU_LOG_INSTR_INC_STAT(cpulog, trace_start);
    }

done:
    g_free(arg);
}

static void cpu_loglevel_switch(CPUArchState *env, target_ulong pc,
                                qemu_log_instr_loglevel_t level, bool global)
{
    qemu_log_next_level_arg_t *arg = g_new(qemu_log_next_level_arg_t, 1);

    arg->next_level = level;
    arg->pc = pc;
    arg->global = global;
    async_safe_run_on_cpu(env_cpu(env), do_cpu_loglevel_switch,
                          RUN_ON_CPU_HOST_PTR(arg));
}

/* Start global logging flag if it was disabled */
static void global_loglevel_enable(void)
{
    if (!qemu_loglevel_mask(CPU_LOG_INSTR))
        qemu_set_log_internal(qemu_loglevel | CPU_LOG_INSTR);
}

/*
 * Handle global logging switch, triggered by the qemu monitor or
 * other external events.
 * This runs in the CPU exclusive context.
 */
static void do_global_loglevel_switch(CPUState *cpu, run_on_cpu_data data)
{
    qemu_log_next_level_arg_t *arg = data.host_ptr;

    if (arg->next_level != QEMU_LOG_INSTR_LOGLEVEL_NONE) {
        global_loglevel_enable();
    }
    /*
     * TODO(am2419): To do things cleanly, we should clear the CPU_LOG_INSTR
     * flag when stopping, however to do this we would need to keep track
     * of the number of CPUs that we have disabled so far, so that we only
     * clear the flag on the last CPU.
     * qemu_set_log_internal(qemu_loglevel & (~CPU_LOG_INSTR));
     */
    do_cpu_loglevel_switch(cpu, data);
}

/*
 * Interface for the monitor to start and stop tracing on all CPUs.
 * Note: It is critical that when stopping we delay the stop until
 * all the CPUs have exited their TCG exec loop. This will happen when
 * the current TB is finished. If we clear the global flag immediately
 * we will end up emitting stale instructions.
 */
int qemu_log_instr_global_switch(int log_flags)
{
    CPUState *cpu;
    qemu_log_next_level_arg_t *arg;

    CPU_FOREACH(cpu)
    {
        arg = g_new(qemu_log_next_level_arg_t, 1);

        if (log_flags & CPU_LOG_INSTR_U) {
            arg->next_level = QEMU_LOG_INSTR_LOGLEVEL_USER;
            log_flags |= CPU_LOG_INSTR;
        } else if (log_flags & CPU_LOG_INSTR) {
            arg->next_level = QEMU_LOG_INSTR_LOGLEVEL_ALL;
        } else {
            arg->next_level = QEMU_LOG_INSTR_LOGLEVEL_NONE;
        }
        arg->global = true;

        /* arg ownership transferred to do_global_loglevel_switch */
        async_safe_run_on_cpu(cpu, do_global_loglevel_switch,
                              RUN_ON_CPU_HOST_PTR(arg));
    }

    return log_flags;
}

/*
 * Initialize instruction info entry from the ring buffer.
 */
static void qemu_log_entry_init(cpu_log_entry_t *entry)
{
    if (entry->txt_buffer == NULL) {
        entry->txt_buffer = g_string_new(NULL);
    }
    if (entry->regs == NULL) {
        entry->regs = g_array_new(false, true, sizeof(log_reginfo_t));
    }
    if (entry->mem == NULL) {
        entry->mem = g_array_new(false, true, sizeof(log_meminfo_t));
    }
    if (entry->events == NULL) {
        entry->events = g_array_new(false, true, sizeof(log_event_t));
    }
}

/*
 * Clear an instruction info entry from the ring buffer.
 */
static void qemu_log_entry_destroy(gpointer data)
{
    cpu_log_entry_t *entry = data;
    log_event_t *evt;
    int i;

    g_string_free(entry->txt_buffer, true);
    g_array_free(entry->regs, true);
    g_array_free(entry->mem, true);
    for (i = 0; i < entry->events->len; i++) {
        evt = &g_array_index(entry->events, log_event_t, i);
        if (evt->id == LOG_EVENT_REGDUMP) {
            /* Need to free the register dump array */
            g_array_free(evt->reg_dump.gpr, true);
        }
    }
    g_array_free(entry->events, true);
}

/*
 * This must be called upon cpu creation.
 * Initializes the per-CPU logging state and data structures.
 *
 * Currently the instruction info ring buffer size is fixed and can not
 * be changed at runtime.
 */
void qemu_log_instr_init(CPUState *cpu)
{
    cpu_log_instr_state_t *cpulog = &cpu->log_state;
    GArray *entry_ring = g_array_sized_new(false, true, sizeof(cpu_log_entry_t),
                                           reset_entry_buffer_size);
    qemu_log_next_level_arg_t *start_level;
    cpu_log_entry_t *entry;
    int i;

    g_array_set_size(entry_ring, reset_entry_buffer_size);
    g_array_set_clear_func(entry_ring, qemu_log_entry_destroy);

    for (i = 0; i < entry_ring->len; i++) {
        entry = &g_array_index(entry_ring, cpu_log_entry_t, i);
        qemu_log_entry_init(entry);
    }

    cpulog->loglevel = QEMU_LOG_INSTR_LOGLEVEL_NONE;
    cpulog->loglevel_active = false;
    cpulog->filters = g_array_sized_new(
        false, true, sizeof(cpu_log_instr_filter_fn_t), LOG_INSTR_FILTER_MAX);
    cpulog->instr_info = entry_ring;
    cpulog->ring_head = 0;
    cpulog->ring_tail = 0;
    reset_log_buffer(cpulog, entry);

    /* Make sure we are using the correct trace format. */
    if (trace_backend == NULL) {
        trace_backend = &trace_backends[qemu_log_instr_backend];
        /* Only emit header on first init */
        if (trace_backend->emit_header) {
            /* XXX this can probably go away and just use init() */
            trace_backend->emit_header(cpu->env_ptr);
        }
    }
    /* Initialize backend state on this CPU */
    if (trace_backend->init) {
        trace_backend->init(cpu->env_ptr);
    }

    /* If we are starting with instruction logging enabled, switch it on now */
    if (qemu_loglevel_mask(CPU_LOG_INSTR | CPU_LOG_INSTR_U)) {
        start_level = g_new(qemu_log_next_level_arg_t, 1);
        if (qemu_loglevel_mask(CPU_LOG_INSTR_U)) {
            assert(qemu_loglevel_mask(CPU_LOG_INSTR) &&
                   "CPU_LOG_INSTR_U implies CPU_LOG_INSTR broken");
            start_level->next_level = QEMU_LOG_INSTR_LOGLEVEL_USER;
        } else {
            start_level->next_level = QEMU_LOG_INSTR_LOGLEVEL_ALL;
        }
        start_level->global = true;
        do_cpu_loglevel_switch(cpu, RUN_ON_CPU_HOST_PTR(start_level));
    }

    if (reset_filters != NULL) {
        for (i = 0; i < reset_filters->len; i++) {
            qemu_log_instr_add_filter(
                cpu, g_array_index(reset_filters, cpu_log_instr_filter_t, i));
        }
    }

    memset(&cpulog->stats, 0, sizeof(cpulog->stats));
}

static void do_log_backend_sync(CPUState *cpu, run_on_cpu_data _unused)
{
    if (trace_backend->sync != NULL) {
        trace_backend->sync(cpu->env_ptr);
    }
    dump_debug_stats(cpu);
}

/*
 * Attempt to syncronize buffers in the tracing backend for each CPU.
 * NOTE: This is a blocking operation that may delay the exit path.
 */
void qemu_log_instr_sync_buffers()
{
    CPUState *cpu;

    CPU_FOREACH(cpu)
    {
        run_on_cpu(cpu, do_log_backend_sync, RUN_ON_CPU_NULL);
    }
}

static void do_log_buffer_resize(CPUState *cpu, run_on_cpu_data data)
{
    unsigned long new_size = data.host_ulong;
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(cpu->env_ptr);
    cpu_log_entry_t *entry;
    int i;

    g_array_set_size(cpulog->instr_info, new_size);
    cpulog->ring_head = 0;
    cpulog->ring_tail = 0;
    for (i = 0; i < cpulog->instr_info->len; i++) {
        /*
         * Clear and reinitialize all the entries,
         * a bit overkill but should not be a frequent operation.
         */
        entry = &g_array_index(cpulog->instr_info, cpu_log_entry_t, i);
        qemu_log_entry_init(entry);
        reset_log_buffer(cpulog, entry);
    }
}

void qemu_log_instr_set_buffer_size(unsigned long new_size)
{
    CPUState *cpu;

    if (new_size < MIN_ENTRY_BUFFER_SIZE) {
        warn_report(
            "New trace entry buffer size is too small < %zu, ignored.",
            (size_t)MIN_ENTRY_BUFFER_SIZE);
        return;
    }

    /* Set this in case this is called from qemu option parsing */
    reset_entry_buffer_size = new_size;
    CPU_FOREACH(cpu)
    {
        async_safe_run_on_cpu(cpu, do_log_buffer_resize,
                              RUN_ON_CPU_HOST_ULONG(new_size));
    }
}

/*
 * Check whether instruction logging is enabled on this CPU.
 */
bool qemu_log_instr_check_enabled(CPUArchState *env)
{
    return (qemu_loglevel_mask(CPU_LOG_INSTR) &&
            get_cpu_log_state(env)->loglevel_active);
}

/*
 * Record a change in CPU mode.
 * Any instruction calling this should exit the TB.
 * This will also trigger pause and resume of user-only logging activity.
 *
 * We flush the TCG buffer when we have to change logging level, this
 * will cause an exit from the cpu_exec() loop, the bulk of the log level
 * switching is performed in exclusive context during the TCG flush
 * initiated here.
 */
void qemu_log_instr_mode_switch(CPUArchState *env,
                                qemu_log_instr_cpu_mode_t mode, target_ulong pc)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    log_assert(cpulog != NULL && "Invalid log state");
    log_assert(entry != NULL && "Invalid log info");

    entry->flags |= LI_FLAG_MODE_SWITCH;
    entry->next_cpu_mode = mode;

    /* If we are not logging in user-only mode, bail */
    if (!qemu_loglevel_mask(CPU_LOG_INSTR) ||
        cpulog->loglevel != QEMU_LOG_INSTR_LOGLEVEL_USER) {
        return;
    }

    /* Check if we are switching to an interesting mode */
    if ((mode == QEMU_LOG_INSTR_CPU_USER) != cpulog->loglevel_active) {
        cpu_loglevel_switch(env, pc, cpulog->loglevel, false);
    }
}

void qemu_log_instr_drop(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    log_assert(cpulog != NULL && "Invalid log state");

    cpulog->force_drop = true;
}

void qemu_log_instr_commit(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    log_assert(cpulog != NULL && "Invalid log state");
    log_assert(entry != NULL && "Invalid log info");

    do_instr_commit(env);
    /* commit may have advanced to the next entry buffer slot */
    entry = get_cpu_log_entry(env);
    reset_log_buffer(cpulog, entry);
}

void qemu_log_instr_reg(CPUArchState *env, const char *reg_name,
                        target_ulong value)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    log_reginfo_t r;

    r.flags = 0;
    r.name = reg_name;
    r.gpr = value;
    g_array_append_val(entry->regs, r);
}

void helper_qemu_log_instr_reg(CPUArchState *env, const void *reg_name,
                               target_ulong value)
{
    if (qemu_log_instr_check_enabled(env))
        qemu_log_instr_reg(env, (const char *)reg_name, value);
}

#ifdef TARGET_CHERI
void qemu_log_instr_cap(CPUArchState *env, const char *reg_name,
                        const cap_register_t *cr)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    log_reginfo_t r;

    r.flags = LRI_CAP_REG | LRI_HOLDS_CAP;
    r.name = reg_name;
    r.cap = *cr;
    g_array_append_val(entry->regs, r);
}

void helper_qemu_log_instr_cap(CPUArchState *env, const void *reg_name,
                               const void *cr)
{
    if (qemu_log_instr_check_enabled(env))
        qemu_log_instr_cap(env, reg_name, cr);
}

void qemu_log_instr_cap_int(CPUArchState *env, const char *reg_name,
                            target_ulong value)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    log_reginfo_t r;

    r.flags = LRI_CAP_REG;
    r.name = reg_name;
    r.gpr = value;
    g_array_append_val(entry->regs, r);
}
#endif

static inline void qemu_log_instr_mem_int(CPUArchState *env, target_ulong addr,
                                          int flags, TCGMemOpIdx oi,
                                          target_ulong value)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    log_meminfo_t m;

    m.flags = flags;
    m.op = get_memop(oi);
    m.addr = addr;
    m.value = value;
    g_array_append_val(entry->mem, m);
}

void qemu_log_instr_ld_int(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
                           target_ulong value)
{
    qemu_log_instr_mem_int(env, addr, LMI_LD, oi, value);
}

void qemu_log_instr_st_int(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
                           target_ulong value)
{
    qemu_log_instr_mem_int(env, addr, LMI_ST, oi, value);
}

#ifdef TARGET_CHERI
/*
 * Note: logging the value here may be redundant as the capability is
 * generally loaded to a register and we get the value in the reginfo
 * as well. Need to think whether there is value to keep logging what
 * was loaded directly.
 */
static inline void qemu_log_instr_mem_cap(CPUArchState *env, target_ulong addr,
                                          int flags,
                                          const cap_register_t *value)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    log_meminfo_t m;

    m.flags = flags;
    m.op = 0;
    m.addr = addr;
    m.cap = *value;
    g_array_append_val(entry->mem, m);
}

void qemu_log_instr_ld_cap(CPUArchState *env, target_ulong addr,
                           const cap_register_t *value)
{
    qemu_log_instr_mem_cap(env, addr, LMI_LD | LMI_CAP, value);
}
void qemu_log_instr_st_cap(CPUArchState *env, target_ulong addr,
                           const cap_register_t *value)
{
    qemu_log_instr_mem_cap(env, addr, LMI_ST | LMI_CAP, value);
}
#endif

void qemu_log_instr(CPUArchState *env, target_ulong pc, const char *insn,
                    uint32_t size)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    entry->pc = pc;
    entry->insn_size = size;
    entry->flags |= LI_FLAG_HAS_INSTR_DATA;
    memcpy(entry->insn_bytes, insn, size);
}

void qemu_log_instr_asid(CPUArchState *env, uint16_t asid)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    entry->asid = asid;
}

void qemu_log_instr_exception(CPUArchState *env, uint32_t code,
                              target_ulong vector, target_ulong faultaddr)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    entry->flags |= LI_FLAG_INTR_TRAP;
    entry->intr_code = code;
    entry->intr_vector = vector;
    entry->intr_faultaddr = faultaddr;
}

void qemu_log_instr_interrupt(CPUArchState *env, uint32_t code,
                              target_ulong vector)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    entry->flags |= LI_FLAG_INTR_ASYNC;
    entry->intr_code = code;
    entry->intr_vector = vector;
}

void qemu_log_instr_event(CPUArchState *env, log_event_t *evt)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);

    /* Note: transfer ownership of dynamically allocated data in evt */
    g_array_append_val(entry->events, *evt);
}

void qemu_log_instr_event_create_regdump(log_event_t *evt, int nregs)
{
    evt->reg_dump.gpr = g_array_sized_new(false, false, sizeof(log_reginfo_t),
                                          nregs * sizeof(log_reginfo_t));
}

void qemu_log_instr_event_dump_reg(log_event_t *evt, const char *reg_name,
                                   target_ulong value)
{
    log_reginfo_t r;

    r.flags = 0;
    r.name = reg_name;
    r.gpr = value;
    /*
     * Assume that the reg_dump array has been initialized,
     * should put an assertion in here.
     */
    g_array_append_val(evt->reg_dump.gpr, r);
}

#ifdef TARGET_CHERI
void qemu_log_instr_event_dump_cap(log_event_t *evt, const char *reg_name,
                                   const cap_register_t *value)
{
    log_reginfo_t r;

    r.flags = LRI_CAP_REG | LRI_HOLDS_CAP;
    r.name = reg_name;
    r.cap = *value;
    g_array_append_val(evt->reg_dump.gpr, r);
}

void qemu_log_instr_event_dump_cap_int(log_event_t *evt, const char *reg_name,
                                       target_ulong value)
{
    log_reginfo_t r;

    r.flags = LRI_CAP_REG;
    r.name = reg_name;
    r.gpr = value;
    g_array_append_val(evt->reg_dump.gpr, r);
}
#endif

void qemu_log_instr_extra(CPUArchState *env, const char *msg, ...)
{
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    va_list va;

    va_start(va, msg);
    g_string_append_vprintf(entry->txt_buffer, msg, va);
    va_end(va);
}

/*
 *  A printf that takes an array of argments unioned of all possible argument
 * types. Because we cant edit a VA_LIST, and we don't want the exponential blow
 * up of handling all combinations of types, we will bounce individual string
 * sections split in the fmt string to another buffer, then switch on all
 * possible types.
 */
static void g_string_append_printf_union_args(GString *string, const char *fmt,
                                              qemu_log_arg_t *args)
{

/* So Clang will not complain about the non-literal format. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"

    char bounce_buf[256];

    size_t i = 0;
    bool format = false;
    char c;
    bool is_short, is_long, is_long_long;
    while ((c = bounce_buf[i++] = *fmt++)) {
        assert(i != sizeof(bounce_buf));
        if (!format) {
            /*
             * A safe amount under the maximum size. An (illegally) wrong format
             * will cause the assert to be hit, but is a bug on the caller's
             * part.
             */
            if (i >= (sizeof(bounce_buf) - 10)) {
                bounce_buf[i] = '\0';
                g_string_append_printf(string, bounce_buf);
                i = 0;
            }
            format = c == '%';
            is_short = is_long = is_long_long = false;
            continue;
        }
        bounce_buf[i] = '\0';
        switch (c) {
        case 'c':
            g_string_append_printf(string, bounce_buf, (args++)->charv);
            format = false;
            i = 0;
            break;
        case 'd':
        case 'i':
            if (is_long_long) {
                g_string_append_printf(string, bounce_buf, (args++)->longlongv);
            } else if (is_long) {
                g_string_append_printf(string, bounce_buf, (args++)->longv);
            } else if (is_short) {
                g_string_append_printf(string, bounce_buf, (args++)->shortv);
            } else {
                g_string_append_printf(string, bounce_buf, (args++)->intv);
            }
            format = false;
            i = 0;
            break;
        case 'u':
        case 'x':
        case 'X':
        case 'o':
            if (is_long_long) {
                g_string_append_printf(string, bounce_buf,
                                       (args++)->ulonglongv);
            } else if (is_long) {
                g_string_append_printf(string, bounce_buf, (args++)->ulongv);
            } else if (is_short) {
                g_string_append_printf(string, bounce_buf, (args++)->ushortv);
            } else {
                g_string_append_printf(string, bounce_buf, (args++)->uintv);
            }
            format = false;
            i = 0;
            break;
        case 'e':
        case 'E':
        case 'f':
        case 'g':
        case 'G':
            if (is_long) {
                g_string_append_printf(string, bounce_buf, (args++)->doublev);
            } else {
                g_string_append_printf(string, bounce_buf, (args++)->floatv);
            }
            format = false;
            i = 0;
            break;
        case 's':
        case 'p':
            g_string_append_printf(string, bounce_buf, (args++)->ptrv);
            format = false;
            i = 0;
            break;
        case '%':
            format = false;
            break;
        case 'h':
            is_short = true;
            break;
        case 'l':
            if (is_long) {
                is_long_long = true;
            }
            is_long = true;
            break;
        default:
            break;
        }
    }

    g_string_append_printf(string, bounce_buf);

#pragma clang diagnostic pop
}

static TCGv_i64 qemu_log_printf_valid_entries;

#define QEMU_PRINTF_LOG_OFFSET                                                 \
    ((offsetof(ArchCPU, parent_obj) - offsetof(ArchCPU, env)) +                \
     offsetof(struct CPUState, log_state.qemu_log_printf_buf))

void qemu_log_printf_create_globals(void)
{
    qemu_log_printf_valid_entries = tcg_global_mem_new_i64(
        cpu_env,
        QEMU_PRINTF_LOG_OFFSET + offsetof(qemu_log_printf_buf_t, valid_entries),
        "log_valids");
}

void qemu_log_gen_printf(DisasContextBase *base, const char *qemu_format,
                         const char *fmt, ...)
{

    if (!qemu_base_logging_enabled(base)) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    size_t ndx = base->printf_used_ptr++;
    assert(
        ndx < QEMU_LOG_PRINTF_BUF_DEPTH &&
        "Increase QEMU_LOG_PRINTF_FLUSH_BARRIER or QEMU_LOG_PRINTF_BUF_DEPTH");

    size_t offset = QEMU_PRINTF_LOG_OFFSET +
                    (sizeof(qemu_log_arg_t) * (QEMU_LOG_PRINTF_ARG_MAX * ndx));

    int nargs = 0;
    char t;

    TCGv_i64 temp64 = tcg_temp_new_i64();
    TCGv_i32 temp32 = tcg_temp_new_i32();

    /* Store the format string out. */
    size_t fmt_offset = QEMU_PRINTF_LOG_OFFSET +
                        offsetof(qemu_log_printf_buf_t, fmts) +
                        (sizeof(const char *) * ndx);

#if UINTPTR_MAX == UINT32_MAX
    tcg_gen_movi_i32(temp32, (uintptr_t)fmt);
    tcg_gen_st_i32(temp32, cpu_env, fmt_offset);
#else
    tcg_gen_movi_i64(temp64, (uintptr_t)fmt);
    tcg_gen_st_i64(temp64, cpu_env, fmt_offset);
#endif

    /* Mark this entry as valid. */
    tcg_gen_movi_i64(temp64, (1ULL << ndx));
    tcg_gen_or_i64(qemu_log_printf_valid_entries, qemu_log_printf_valid_entries,
                   temp64);

    /*
     * Now process the qemu_format string and fmt string to generate tcg loads
     * and stores.
     */
    while ((t = *qemu_format++)) {
        assert(nargs != QEMU_LOG_PRINTF_ARG_MAX);
        /*
         * va_arg arguments are promoted according to standard promotion rules.
         * floats promote to doubles, types shorter than int promote to int.
         * Accessing va_arg with the wrong sign (but correct size) for
         * everything else is dancing with UB. The spec says its is OK if both
         * types could represent the value passed at runtime. However, as I am
         * only going to _store_ the value, I'm 99% certain I am still fine just
         * doing everything with one sign even when large magnitude values as
         * passed.
         */
        char c;
        bool format = false;
        bool is_short, is_long, is_long_long, is_signed;

        while ((c = *fmt++)) {
            if (!format) {
                format = c == '%';
                if (format) {
                    is_short = is_long = is_long_long = is_signed = false;
                }
                continue;
            }
            size_t arg_size = 0;
            uint64_t arg_const;
            switch (c) {
            case 'c':
                arg_size = sizeof(char);
                if (t == 'c') {
                    arg_const = (uint64_t)va_arg(args, int);
                }
                break;
            case 'd':
            case 'i':
                is_signed = true;
            case 'u':
            case 'x':
            case 'X':
            case 'o':
                if (is_long_long) {
                    arg_size = sizeof(long long);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, long long);
                    }
                } else if (is_long) {
                    arg_size = sizeof(long);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, long);
                    }
                } else if (is_short) {
                    arg_size = sizeof(short);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, int);
                    }
                } else {
                    arg_size = sizeof(int);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, int);
                    }
                }
                format = false;
                break;
            case 'e':
            case 'E':
            case 'f':
            case 'g':
            case 'G':
                if (is_long) {
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, double);
                    }
                    arg_size = sizeof(double);
                } else {
                    if (t == 'c') {
                        arg_const = (uint64_t)(float)va_arg(args, double);
                    }
                    arg_size = sizeof(float);
                }
                format = false;
                break;
            case 's':
            case 'p':
                arg_size = sizeof(void *);
                /*
                 * This does not break strict aliasing as long as only void*
                 * and char* is passed.
                 */
                if (t == 'c') {
                    arg_const = (uint64_t)va_arg(args, void *);
                }
            case '%':
                format = false;
                break;
            case 'h':
                is_short = true;
                break;
            case 'l':
                if (is_long) {
                    is_long_long = true;
                }
                is_long = true;
                break;
            default:
                break;
            }
            if (arg_size != 0) {
                /* Use 32-bit ops. */
                if (arg_size <= 4) {
                    TCGv_i32 t32;
                    if (t == 'c') {
                        t32 = temp32;
                        tcg_gen_movi_i32(t32, (uint32_t)arg_const);
                    } else if (t == 'w') {
                        t32 = va_arg(args, TCGv_i32);
                    } else {
                        assert((t == 'd') && "bad QEMU format string");
                        t32 = temp32;
                        tcg_gen_extrl_i64_i32(t32, va_arg(args, TCGv_i64));
                    }
                    if (!t32) {
                        t32 = temp32;
                        tcg_gen_movi_i32(t32, 0);
                    }
                    switch (arg_size) {
                    case 1:
                        tcg_gen_st8_i32(t32, cpu_env, offset);
                        break;
                    case 2:
                        tcg_gen_st16_i32(t32, cpu_env, offset);
                        break;
                    case 4:
                        tcg_gen_st_i32(t32, cpu_env, offset);
                        break;
                    default:
                        g_assert_not_reached();
                    }
                } else {
                    assert(arg_size <= 8);
                    /* Use 64-bit ops. */
                    TCGv_i64 t64;
                    if (t == 'c') {
                        t64 = temp64;
                        tcg_gen_movi_i64(t64, arg_const);
                    } else if (t == 'w') {
                        t64 = temp64;
                        if (is_signed) {
                            tcg_gen_ext_i32_i64(t64, va_arg(args, TCGv_i32));
                        } else {
                            tcg_gen_extu_i32_i64(t64, va_arg(args, TCGv_i32));
                        }
                    } else {
                        assert((t == 'd') && "bad QEMU format string");
                        t64 = va_arg(args, TCGv_i64);
                    }
                    if (!t64) {
                        t64 = temp64;
                        tcg_gen_movi_i64(t64, 0);
                    }
                    tcg_gen_st_i64(t64, cpu_env, offset);
                }
                offset += sizeof(qemu_log_arg_t);
                break;
            }
        }
        assert(c != 0 && "Format strings do not match");
    }

    va_end(args);

    tcg_temp_free_i64(temp64);
    tcg_temp_free_i32(temp32);
}

void qemu_log_gen_printf_flush(DisasContextBase *base, bool flush_early,
                               bool force_flush)
{
    if (force_flush || ((base->printf_used_ptr != 0) &&
                        (flush_early || (base->printf_used_ptr >=
                                         (QEMU_LOG_PRINTF_FLUSH_BARRIER))))) {
        gen_helper_qemu_log_printf_dump(cpu_env);
        base->printf_used_ptr = 0;
    }
}

void qemu_log_instr_flush(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    size_t curr = cpulog->ring_tail;
    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    log_event_t event;

    /* Emit FLUSH event so that it can be picked up by backends */
    event.id = LOG_EVENT_STATE;
    event.state.next_state = LOG_EVENT_STATE_FLUSH;
    event.state.pc = entry->pc;
    qemu_log_instr_event(env, &event);

    /*
     * If tracing is disabled, force the commit of events in this
     * trace entry.
     */
    if (!qemu_log_instr_check_enabled(env)) {
        qemu_log_instr_commit(env);
    }
    if ((cpulog->flags & QEMU_LOG_INSTR_FLAG_BUFFERED) == 0) {
        return;
    }

    while (curr != cpulog->ring_head) {
        entry = &g_array_index(cpulog->instr_info, cpu_log_entry_t, curr);
        trace_backend->emit_instr(env, entry);
        QEMU_LOG_INSTR_INC_STAT(cpulog, entries_emitted);
        curr = (curr + 1) % cpulog->instr_info->len;
    }
    cpulog->ring_tail = cpulog->ring_head;
}

/* Instruction logging helpers */

/* Dump out all the accumalated printf's */
void helper_qemu_log_printf_dump(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    tcg_debug_assert((QEMU_PRINTF_LOG_OFFSET + ((uintptr_t)env)) ==
                     (uintptr_t)(&cpulog->qemu_log_printf_buf));

    uint64_t valid = cpulog->qemu_log_printf_buf.valid_entries;
    cpulog->qemu_log_printf_buf.valid_entries = 0;

    if (!qemu_log_instr_enabled(env)) {
        return;
    }

    cpu_log_entry_t *entry = get_cpu_log_entry(env);
    while (valid) {
        size_t ndx = ctz64(valid);
        valid ^= (1 << ndx);
        qemu_log_arg_t *args =
            cpulog->qemu_log_printf_buf.args +
            (ndx * QEMU_LOG_PRINTF_ARG_MAX);
        const char *fmt = cpulog->qemu_log_printf_buf.fmts[ndx];
        g_string_append_printf_union_args(entry->txt_buffer, fmt, args);
    }
}

/*
 * Enable or disable buffered logging that is triggered by the target
 * via qemu_log_instr_flush().
 */
void helper_qemu_log_instr_buffered_mode(CPUArchState *env, uint32_t enable)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (enable) {
        cpulog->flags |= QEMU_LOG_INSTR_FLAG_BUFFERED;
    } else {
        cpulog->flags &= ~QEMU_LOG_INSTR_FLAG_BUFFERED;
    }
}

/* Helper version of qemu_log_instr_flush */
void helper_qemu_log_instr_buffer_flush(CPUArchState *env)
{
    qemu_log_instr_flush(env);
}

static void do_qemu_log_instr_start(CPUArchState *env, target_ulong pc,
                                    qemu_log_instr_loglevel_t level,
                                    bool global)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    log_assert(cpulog != NULL && "Invalid log state");
    global_loglevel_enable();

    /* If we are already started in the correct mode, bail */
    if (cpulog->loglevel == level && cpulog->loglevel_active) {
        return;
    }

    cpu_loglevel_switch(env, pc, level, global);
}

static void do_qemu_log_instr_stop(CPUArchState *env, target_ulong pc,
                                   bool global)
{
    cpu_loglevel_switch(env, pc, QEMU_LOG_INSTR_LOGLEVEL_NONE, global);
}

/* Start logging all instructions on the current CPU */
void helper_qemu_log_instr_start(CPUArchState *env, target_ulong pc)
{
    do_qemu_log_instr_start(env, pc, QEMU_LOG_INSTR_LOGLEVEL_ALL, false);
}

/* Start logging user-only instructions on the current CPU */
void helper_qemu_log_instr_user_start(CPUArchState *env, target_ulong pc)
{
    do_qemu_log_instr_start(env, pc, QEMU_LOG_INSTR_LOGLEVEL_USER, false);
}

/* Stop logging on the current CPU */
void helper_qemu_log_instr_stop(CPUArchState *env, target_ulong pc)
{
    do_qemu_log_instr_stop(env, pc, false);
}

/* Start logging all instructions on all CPUs */
void helper_qemu_log_instr_allcpu_start(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu)
    {
        do_qemu_log_instr_start(cpu->env_ptr, 0, QEMU_LOG_INSTR_LOGLEVEL_ALL,
                                true);
    }
}

/* Start logging user-only instructions on all CPUs */
void helper_qemu_log_instr_allcpu_user_start(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu)
    {
        do_qemu_log_instr_start(cpu->env_ptr, 0, QEMU_LOG_INSTR_LOGLEVEL_USER,
                                true);
    }
}

/* Stop logging instructions on all CPUs */
void helper_qemu_log_instr_allcpu_stop(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu)
    {
        do_qemu_log_instr_stop(cpu->env_ptr, 0, true);
    }
}

void helper_qemu_log_instr_commit(CPUArchState *env)
{
    qemu_log_instr_commit(env);
}

void helper_qemu_log_instr_load64(CPUArchState *env, target_ulong addr,
                                  uint64_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_LD, oi, value);
}

void helper_qemu_log_instr_store64(CPUArchState *env, target_ulong addr,
                                   uint64_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_ST, oi, value);
}

void helper_qemu_log_instr_load32(CPUArchState *env, target_ulong addr,
                                  uint32_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_LD, oi, (uint64_t)value);
}

void helper_qemu_log_instr_store32(CPUArchState *env, target_ulong addr,
                                   uint32_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_ST, oi, (uint64_t)value);
}

void helper_log_value(CPUArchState *env, const void *ptr, uint64_t value)
{
    qemu_maybe_log_instr_extra(env, "%s: " TARGET_FMT_plx "\n", ptr, value);
}

/*
 * Instruction stream filtering
 */

void qemu_log_instr_add_filter(CPUState *cpu, cpu_log_instr_filter_t filter)
{
    cpu_log_instr_state_t *cpulog = &cpu->log_state;
    cpu_log_instr_filter_fn_t new_fn, fn;
    int i;

    if (filter >= LOG_INSTR_FILTER_MAX) {
        warn_report("Instruction trace filter index is invalid");
        return;
    }
    new_fn = trace_filters[filter];
    /* Check for duplicates */
    for (i = 0; i < cpulog->filters->len; i++) {
        fn = g_array_index(cpulog->filters, cpu_log_instr_filter_fn_t, i);
        if (new_fn == fn) {
            return;
        }
    }
    g_array_append_val(cpulog->filters, new_fn);
}

void qemu_log_instr_allcpu_add_filter(cpu_log_instr_filter_t filter)
{
    CPUState *cpu;

    CPU_FOREACH(cpu)
    {
        qemu_log_instr_add_filter(cpu, filter);
    }
}

void qemu_log_instr_remove_filter(CPUState *cpu, cpu_log_instr_filter_t filter)
{
    cpu_log_instr_state_t *cpulog = &cpu->log_state;
    cpu_log_instr_filter_fn_t curr;
    int i;

    if (filter >= LOG_INSTR_FILTER_MAX) {
        warn_report("Instruction trace filter index is invalid");
        return;
    }

    for (i = 0; i < cpulog->filters->len; i++) {
        curr = g_array_index(cpulog->filters, cpu_log_instr_filter_fn_t, i);
        if (curr == trace_filters[filter]) {
            g_array_remove_index_fast(cpulog->filters, i);
            break;
        }
    }
}

void qemu_log_instr_allcpu_remove_filter(cpu_log_instr_filter_t filter)
{
    CPUState *cpu;

    CPU_FOREACH(cpu)
    {
        qemu_log_instr_remove_filter(cpu, filter);
    }
}

void qemu_log_instr_add_startup_filter(cpu_log_instr_filter_t filter)
{
    if (reset_filters == NULL) {
        reset_filters =
            g_array_new(false, true, sizeof(cpu_log_instr_filter_t));
    }

    if (first_cpu == NULL) {
        g_array_append_val(reset_filters, filter);
    } else {
        qemu_log_instr_allcpu_add_filter(filter);
    }
}

void qemu_log_instr_set_cli_filters(const char *filter_spec, Error **errp)
{
    gchar **names = g_strsplit(filter_spec, ",", 0);
    int i;

    for (i = 0; names[i]; i++) {
        if (strcmp(names[i], "events") == 0) {
            qemu_log_instr_add_startup_filter(LOG_FILTER_EVENTS);
        } else {
            error_setg(errp, "Invalid trace filter name");
            break;
        }
    }
}

/*
 * Log entry filter reusing the qemu -dfilter infrastructure to
 * filter instructions that run from or access given address ranges.
 */
static bool entry_mem_regions_filter(cpu_log_entry_t *entry)
{
    int i, j;
    bool match = false;

    if (debug_regions == NULL) {
        return true;
    }

    /* Check for dfilter matches in this instruction */
    for (i = 0; !match && i < debug_regions->len; i++) {
        Range *range = &g_array_index(debug_regions, Range, i);
        match = range_contains(range, entry->pc);
        if (match) {
            break;
        }

        for (j = 0; j < entry->mem->len; j++) {
            log_meminfo_t *minfo = &g_array_index(entry->mem, log_meminfo_t, j);
            match = range_contains(range, minfo->addr);
            if (match) {
                break;
            }
        }
    }
    return match;
}

/*
 * Log entry filter to retain only entries with events attached.
 */
static bool entry_event_filter(cpu_log_entry_t *entry)
{
    if (entry->events->len > 0) {
        return true;
    }
    return false;
}

/*
 * Trace filters mapping. Note that indices must match the
 * cpu_log_instr_filter_t enum values.
 */
static cpu_log_instr_filter_fn_t trace_filters[] = {
    entry_mem_regions_filter,
    entry_event_filter,
};
#endif /* CONFIG_TCG_LOG_INSTR */
