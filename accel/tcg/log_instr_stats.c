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
 * Statistic-gathering instruction logging backend
 */

#include <stdint.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/log_instr_stats.h"

struct cpu_stats {
    qemu_cpu_stats_t qstats;
    target_ulong last_pc;
    target_ulong pc_range_start;
};

static struct cpu_stats *get_cpu_stats(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    return (struct cpu_stats *)cpulog->backend_data;
}

/*
 * Initialize the backend.
 */
void init_stats_backend(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    struct cpu_stats *stats;

    stats = malloc(sizeof(struct cpu_stats));
    stats->qstats = qemu_cpu_stats_create(env_cpu(env)->cpu_index);
    stats->last_pc = 0;
    stats->pc_range_start = 0;
    cpulog->backend_data = stats;
}

/*
 * Emit a textual representation of events recorded by the given trace entry.
 */
void emit_stats_events(CPUArchState *env, cpu_log_entry_t *entry)
{
    struct cpu_stats *stats = get_cpu_stats(env);
    QemuLogFile *logfile;
    const log_event_t *event;
    bool header = false;
    int i;

    log_assert(stats != NULL && "Missing stats backend data");

    for (i = 0; i < entry->events->len; i++) {
        event = &g_array_index(entry->events, const log_event_t, i);
        if (event->id == LOG_EVENT_STATE) {
            if (event->state.next_state == LOG_EVENT_STATE_FLUSH) {
                rcu_read_lock();
                logfile = qatomic_rcu_read(&qemu_logfile);
                if (logfile) {
                    if (ftell(logfile->fd) == 0) {
                        header = true;
                    }
                    qemu_cpu_stats_dump(stats->qstats, fileno(logfile->fd),
                                        header);
                    fflush(logfile->fd);
                }
                rcu_read_unlock();
                break;
            }
        }
    }
}

/*
 * Emit textual representation of the instruction in the given
 * trace entry to the log.
 */
void emit_stats_entry(CPUArchState *env, cpu_log_entry_t *entry)
{
    struct cpu_stats *stats = get_cpu_stats(env);

    log_assert(stats != NULL && "Missing stats backend data");

    if (entry->pc - stats->last_pc > entry->insn_size) {
        qemu_cpu_stats_record_bb_hit(stats->qstats, stats->pc_range_start,
                                     stats->last_pc);
        stats->pc_range_start = entry->pc;
    }
    stats->last_pc = entry->pc;
}
