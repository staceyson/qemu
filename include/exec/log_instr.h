/*-
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

#include "hw/core/cpu.h"
#include "qemu/log_instr.h"
#include "cpu.h"

/*
 * Instruction logging interface for targets.
 *
 * # Adding a new target
 * The following functions must be defined by the target and declared in cpu.h:
 * - bool cpu_in_user_mode(env)
 *   return whether the cpu is in user mode
 * - uint16_t cpu_get_asid(env, pc)
 *   return the hardware address space identifier for a particular address
 * - const char *cpu_get_mode_name(mode)
 *   return the mode name associated with a qemu_log_instr_cpu_mode_t for
 * printing.
 * - bool cpu_log_instr_event_regdump(env, event)
 *   Builds a register dump for the target, returns true if the register dump
 *   was not produced and the event should be cancelled.
 *
 * - Each target should implement their own register update logging helpers that
 *   call into qemu_log_instr_gpr(), qemu_log_instr_cap() and similar interface
 *   functions.
 *   Note that the target is responsible for producing a register name to use.
 * - It is recommended to use the helper_<target>_log_instr_{gpr,cap..}() naming
 *   convention to distinguish target-specific and generic qemu_log_instr
 *   interfaces.
 * - The discipline for checking whether instruction logging is enabled is
 *   the following:
 *   + TCG helpers should be emitted after checking the cached value
 *     of DisasContextBase::log_instr_enabled.
 *   + TCG logging helpers internally must check whether logging is enabled,
 *     this is because sometimes the DisasContext is not available to check
 *     the condition above.
 *   + qemu_log_instr_* functions do not internally check whether logging is
 *     enabled. This must be done by the caller or via a macro.
 *   + Use the macro qemu_log_instr_enabled to check whether instruction logging
 *     is enabled. This can be used in `if (...)` statements without adding
 *     `unlikely(...)` built-ins.
 *
 * TODO(am2419): decide whether to inline some of these.
 */

#define _glue_args(...) , ## __VA_ARGS__

#ifdef CONFIG_TCG_LOG_INSTR
#define qemu_ctx_logging_enabled(ctx)   unlikely(ctx->base.log_instr_enabled)
#define qemu_base_logging_enabled(base) unlikely(base->log_instr_enabled)
#else
#define qemu_ctx_logging_enabled(ctx)   false
#define qemu_base_logging_enabled(base) false
#endif

/*
 * Helper to simplify checking for either instruction logging or
 * another loglevel enabled
 */
#define qemu_log_instr_or_mask_enabled(env, mask)                              \
    ((unlikely(qemu_loglevel_mask(mask)) || qemu_log_instr_enabled(env))       \
         ? true                                                                \
         : false)

/*
 * Helper to simplify emitting a message either to instruction
 * logging extra text buffer or when another loglevel is enabled
 */
#define qemu_log_instr_or_mask_msg(env, mask, msg, ...)                        \
    do {                                                                       \
        if (qemu_loglevel_mask(mask)) {                                        \
            qemu_log(msg _glue_args(__VA_ARGS__));                             \
        } else if (qemu_log_instr_enabled(env)) {                              \
            qemu_log_instr_extra(env, msg _glue_args(__VA_ARGS__));            \
        }                                                                      \
    } while (0)

/*
 * Helper version of qemu_log_instr_extra that checks whether logging is
 * enabled.
 */
#define qemu_maybe_log_instr_extra(env, msg, ...)                              \
    do {                                                                       \
        if (qemu_log_instr_enabled(env))                                       \
            qemu_log_instr_extra(env, msg _glue_args(__VA_ARGS__));            \
    } while (0)

/*
 * Helper to append a changed register content to the extra debug info
 * for the current instruction.
 * Note that this can be ignored by the output trace format.
 */
#define qemu_log_instr_dbg_reg(env, name, value)                               \
    do {                                                                       \
        if (qemu_log_instr_enabled(env))                                       \
            qemu_log_instr_extra(env, "    Write %s = " TARGET_FMT_lx "\n",    \
                                 name, value);                                 \
    } while (0)

/*
 * Helper to append a changed capability register content to the extra debug
 * info for the current instruction.
 * Note that this can be ignored by the output trace format.
 */
#define qemu_log_instr_dbg_cap(env, name, value)                               \
    do {                                                                       \
        if (qemu_log_instr_enabled(env))                                       \
            qemu_log_instr_extra(env,                                          \
                                 "    Write %s|" PRINT_CAP_FMTSTR_L1 "\n"      \
                                 "             |" PRINT_CAP_FMTSTR_L2 "\n",    \
                                 name, PRINT_CAP_ARGS_L1(value),               \
                                 PRINT_CAP_ARGS_L2(value));                    \
    } while (0)

#ifdef CONFIG_TCG_LOG_INSTR

/* Format specifiers for TCGv and TCGv_ptr */
#if TARGET_LONG_BITS == 64
#define QLP_TCGV "d"
#else
#define QLP_TCGV "w"
#endif
#if UINTPTR_MAX == UINT32_MAX
#define QLP_TCGP "w"
#else
#define QLP_TCGP "d"
#endif

/*
 * Will generate TCG that will perform a printf to the extra logging info.
 * Prints are batched until the end of an instruction
 * TODO: This was actually designed to batch for an entire basic block, but
 * sadly the string this would append to is cleared at the end of every
 * instruction.
 *
 * The qemu_format is a string of the format ([c|w|d])*, The letter specifies
 * whether the provided arguments are constant, words (TCGv_i32) or doubles
 * (TCGv_i64). You should use provided macros QLP_ to deal with TCGv/TCGv_ptr.
 * A NULL passed to a TCGv_* argument is interpreted as a constant 0.
 * example usage: qemu_log_printf(ctx, QLP_TCGP QLP_TCGV "c", "%s, %c, %d\n",
 * myTCGv_ptr, myTCGv, 7)
 *
 * WARN: Passed pointers MUST be const and live for the duration of the
 * compiled basic block, as they are read when the prints are batched.
 *
 * WARN: This TCG should be reached either 0 or 1 times total for each
 * invocation of the guest instruction. That is, you may have a TCG branch skip
 * this generated TCG, but cannot have this in a TCG loop (although it may be
 * part of a loop written in guest instructions, in which case you will get
 * multiple prints as expected)
 */

struct DisasContextBase;
void qemu_log_gen_printf(struct DisasContextBase *ctx, const char *qemu_format,
                         const char *fmt, ...);
/* Should only be called in a place it cannot be skipped by a branch! */
void qemu_log_gen_printf_flush(struct DisasContextBase *base, bool flush_early,
                               bool force_flush);
void qemu_log_printf_create_globals(void);

struct cpu_log_entry;

/*
 * Check whether instruction tracing is enabled.
 * Note: changes to the instruction logging flags result in a call to
 * tb_flush so we can do the logging checks at translate time as well.
 */
bool qemu_log_instr_check_enabled(CPUArchState *env);

/* Helper macro to check for instruction logging enabled */
#define qemu_log_instr_enabled(env)                                            \
    unlikely(qemu_log_instr_check_enabled((env)))

/*
 * Register a trace filter for a given CPU.
 */
void qemu_log_instr_add_filter(CPUState *env, cpu_log_instr_filter_t filter);

/*
 * Register a trace filter for a given CPU.
 */
void qemu_log_instr_allcpu_add_filter(cpu_log_instr_filter_t filter);

/*
 * Unregister a trace filter for a given CPU.
 */
void qemu_log_instr_remove_filter(CPUState *env, cpu_log_instr_filter_t filter);

/*
 * Unregister a trace filter for a given CPU.
 */
void qemu_log_instr_allcpu_remove_filter(cpu_log_instr_filter_t filter);

/*
 * Log a switch inc CPU modes.
 * This will also trigger pause and resume of user-only logging activity,
 * depending whether the mode parameter is QEMU_LOG_INSTR_CPU_USER or not.
 */
void qemu_log_instr_mode_switch(CPUArchState *env,
                                qemu_log_instr_cpu_mode_t mode,
                                target_ulong pc);

/*
 * Emit all buffered instruction logs.
 * This is only relevant when tracing in buffered mode.
 */
void qemu_log_instr_flush(CPUArchState *env);

/*
 * Drop the current buffered entry and ignore logging until next commit.
 */
void qemu_log_instr_drop(CPUArchState *env);

/*
 * Notify that we are done with this instruction and the buffer
 * can be sent to the output.
 */
void qemu_log_instr_commit(CPUArchState *env);

/*
 * Log changed general purpose register.
 */
void qemu_log_instr_reg(CPUArchState *env, const char *reg_name,
                        target_ulong value);

/*
 * Log integer memory load.
 */
void qemu_log_instr_ld_int(CPUArchState *env, target_ulong addr, MemOp op,
                           target_ulong value);

/*
 * Log integer memory store.
 */
void qemu_log_instr_st_int(CPUArchState *env, target_ulong addr, MemOp op,
                           target_ulong value);

#ifdef TARGET_CHERI
/*
 * Log changed capability register.
 */
void qemu_log_instr_cap(CPUArchState *env, const char *reg_name,
                        const cap_register_t *cr);

/*
 * Log changed capability register with integer value.
 */
void qemu_log_instr_cap_int(CPUArchState *env, const char *reg_name,
                            target_ulong value);

/*
 * Log capability memory load.
 */
void qemu_log_instr_ld_cap(CPUArchState *env, target_ulong addr,
                           const cap_register_t *value);

/*
 * Log capability memory store.
 */
void qemu_log_instr_st_cap(CPUArchState *env, target_ulong addr,
                           const cap_register_t *value);
#endif

/*
 * Log instruction pc and opcode.
 * Note that the insn buffer is expected to be in target byte-order.
 */
void qemu_log_instr(CPUArchState *env, target_ulong pc, const char *insn,
                    uint32_t size);

/*
 * Log Address Space IDentifier (also known as PCID).
 */
void qemu_log_instr_asid(CPUArchState *env, uint16_t asid);

/*
 * Log exception event.
 */
void qemu_log_instr_exception(CPUArchState *env, uint32_t code,
                              target_ulong vector, target_ulong faultaddr);

/*
 * Log interrupt event.
 */
void qemu_log_instr_interrupt(CPUArchState *env, uint32_t code,
                              target_ulong vector);

/*
 * Log extra events.
 * XXX we can avoid a copy if we make this return a newly allocated
 * log_event_t instead.
 */
void qemu_log_instr_event(CPUArchState *env, log_event_t *evt);

/*
 * Each target must define this function to implement
 * register dump events.
 */
bool cpu_log_instr_event_regdump(CPUArchState *env, log_event_t *evt);

/*
 * Interface to fill register dump log_event_t entries.
 * This mirrors the qemu_log_instr_reg/cap/cap_int functions.
 */
void qemu_log_instr_event_create_regdump(log_event_t *evt, int nregs);
void qemu_log_instr_event_dump_reg(log_event_t *evt, const char *reg_name,
                                   target_ulong value);
#ifdef TARGET_CHERI
void qemu_log_instr_event_dump_cap(log_event_t *evt, const char *reg_name,
                                   const cap_register_t *value);
void qemu_log_instr_event_dump_cap_int(log_event_t *evt, const char *reg_name,
                                       target_ulong value);
#endif

/*
 * Log extra information as a string. Some logging formats may
 * ignore this.
 */
void qemu_log_instr_extra(CPUArchState *env, const char *msg, ...);

/*
 * Tracepoint for qemu internals.
 * This should not be used for guest events.
 */
void qemu_log_instr_counter(CPUState *cpu, QEMUDebugCounter name, long value);

#else /* ! CONFIG_TCG_LOG_INSTR */
#define qemu_log_instr_enabled(cpu) false
#define qemu_log_instr_start(env, mode, pc)
#define qemu_log_instr_stop(env, mode, pc)
#define qemu_log_instr_mode_switch(...)
#define qemu_log_instr_flush(env)
#define qemu_log_instr_reg(...)
#define qemu_log_instr_cap(...)
#define qemu_log_instr_cap_int(...)
#define qemu_log_instr_mem(...)
#define qemu_log_instr_instr(...)
#define qemu_log_instr_hwtid(...)
#define qemu_log_instr_asid(...)
#define qemu_log_instr_exception(...)
#define qemu_log_instr_interrupt(...)
#define qemu_log_instr_env(...)
#define qemu_log_instr_extra(...)
#define qemu_log_instr_event(...)
#define qemu_log_instr_commit(...)
#define qemu_log_gen_printf(...)
#define qemu_log_gen_printf_flush(base, flush_early, force_flush)
#define qemu_log_printf_create_globals(...)
#endif /* ! CONFIG_TCG_LOG_INSTR */
