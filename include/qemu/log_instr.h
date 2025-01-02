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

/*
 * Instruction logging format
 */
typedef enum {
    QLI_FMT_TEXT = 0,
    QLI_FMT_CVTRACE = 1,
    QLI_FMT_NOP = 2
} qemu_log_instr_fmt_t;

extern qemu_log_instr_fmt_t qemu_log_instr_format;

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

static inline void qemu_log_instr_set_format(qemu_log_instr_fmt_t fmt)
{
    qemu_log_instr_format = fmt;
}

static inline qemu_log_instr_fmt_t qemu_log_instr_get_format(void)
{
    return qemu_log_instr_format;
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

    /* Ring buffer of log_instr_info */
    GArray *instr_info;
    /* Ring buffer index of the next entry to write */
    size_t ring_head;
    /* Ring buffer index of the first entry to dump */
    size_t ring_tail;

    qemu_log_printf_buf_t qemu_log_printf_buf;
} cpu_log_instr_state_t;

/*
 * Initialize instruction logging for a cpu.
 */
void qemu_log_instr_init(CPUState *cpu);
int qemu_log_instr_global_switch(int log_flags);

/*
 * Update the ring buffer size.
 * Note that this does not guarantee that the existing buffered 
 * entries will be retained.
 */
void qemu_log_instr_set_buffer_size(unsigned long buffer_size);

#else /* ! CONFIG_TCG_LOG_INSTR */
#define qemu_log_instr_set_format(fmt) ((void)0)
#endif /* ! CONFIG_TCG_LOG_INSTR */
