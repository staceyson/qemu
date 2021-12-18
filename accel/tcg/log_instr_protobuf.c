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
 * Similar functionality as the text backend but with a more stable format.
 */

#include <assert.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"

#include "protobuf_backend_entry.pb-c.h"

static FILE *protobuf_logfile;

#ifdef TARGET_CHERI
static QEMULogInstrCapability *emit_protobuf_capability(cap_register_t *cap)
{
    QEMULogInstrCapability *pb_cap = g_malloc(sizeof(QEMULogInstrCapability));

    qemulog_instr_capability__init(pb_cap);
    pb_cap->valid = cap->cr_tag;
    pb_cap->sealed = cap_is_sealed_with_type(cap);
    pb_cap->perms = COMBINED_PERMS_VALUE(cap);
    /* pb_cap->flags = cap_get_flags(cap); */
    pb_cap->otype = cap_get_otype_unsigned(cap);
    pb_cap->cap_base = cap_get_base(cap);
    pb_cap->cap_cursor = cap_get_cursor(cap);
    pb_cap->cap_length = cap_get_length_sat(cap);
    return pb_cap;
}
#endif

static void emit_protobuf_meminfo(log_meminfo_t *minfo,
                                  QEMULogInstrMem **pb_mem)
{
    QEMULogInstrMem *mem = g_malloc(sizeof(QEMULogInstrMem));

    qemulog_instr_mem__init(mem);
    mem->is_load = (minfo->flags & LMI_LD) != 0;
    mem->size = memop_size(minfo->op);
    mem->addr = minfo->addr;
#ifndef TARGET_CHERI
    assert((minfo->flags & LMI_CAP) == 0 &&
           "Capability memory access without CHERI support");
#else
    if (minfo->flags & LMI_CAP) {
        mem->value_case = QEMULOG_INSTR_MEM__VALUE_CAP_VALUE;
        mem->cap_value = emit_protobuf_capability(&minfo->cap);
    } else
#endif
    {
        mem->value_case = QEMULOG_INSTR_MEM__VALUE_INT_VALUE;
        mem->int_value = minfo->value;
    }
    *pb_mem = mem;
}

static void release_protobuf_meminfo(QEMULogInstrMem *pb_mem)
{
    if (pb_mem->value_case == QEMULOG_INSTR_MEM__VALUE_CAP_VALUE) {
        g_free(pb_mem->cap_value);
    }
    g_free(pb_mem);
}

static void emit_protobuf_reginfo(log_reginfo_t *rinfo,
                                  QEMULogInstrReg **pb_reg)
{
    QEMULogInstrReg *reg = g_malloc(sizeof(QEMULogInstrReg));

    qemulog_instr_reg__init(reg);
    /* Safe to de-const cast as the pointer is only used during packing */
    reg->name = (char *)rinfo->name;

#ifndef TARGET_CHERI
    assert(!reginfo_is_cap(rinfo) && "Register marked as capability "
                                     "register whitout CHERI support");
#else
    if (reginfo_is_cap(rinfo)) {
        if (reginfo_has_cap(rinfo)) {
            reg->value_case = QEMULOG_INSTR_REG__VALUE_CAP_VALUE;
            reg->cap_value = emit_protobuf_capability(&rinfo->cap);
        } else {
            reg->value_case = QEMULOG_INSTR_REG__VALUE_INT_VALUE;
            reg->int_value = rinfo->gpr;
        }
    } else
#endif
    {
        reg->value_case = QEMULOG_INSTR_REG__VALUE_INT_VALUE;
        reg->int_value = rinfo->gpr;
    }
    *pb_reg = reg;
}

static void release_protobuf_reginfo(QEMULogInstrReg *pb_reg)
{
    if (pb_reg->value_case == QEMULOG_INSTR_REG__VALUE_CAP_VALUE) {
        g_free(pb_reg->cap_value);
    }
    g_free(pb_reg);
}

static void emit_protobuf_event(log_event_t *evtinfo, QEMULogInstrEvt **pb_evt)
{
    QEMULogInstrEvt *evt = g_malloc(sizeof(QEMULogInstrEvt));

    qemulog_instr_evt__init(evt);
    switch (evtinfo->id) {
    case LOG_EVENT_STATE:
        evt->event_case = QEMULOG_INSTR_EVT__EVENT_STATE;
        evt->state = g_malloc(sizeof(QEMULogInstrEvtTraceState));
        qemulog_instr_evt_trace_state__init(evt->state);
        evt->state->next_state = (LogEventTraceState)evtinfo->state.next_state;
        evt->state->pc = evtinfo->state.pc;
        break;
    case LOG_EVENT_CTX_UPDATE:
        evt->event_case = QEMULOG_INSTR_EVT__EVENT_CTX_UPDATE;
        evt->ctx_update = g_malloc(sizeof(QEMULogInstrEvtCtxUpdate));
        qemulog_instr_evt_ctx_update__init(evt->ctx_update);
        evt->ctx_update->pid = evtinfo->ctx_update.pid;
        evt->ctx_update->tid = evtinfo->ctx_update.tid;
        evt->ctx_update->cid = evtinfo->ctx_update.cid;
        /* Safe to de-const cast as the pointer is only used during packing */
        evt->ctx_update->mode =
            (char *)cpu_get_mode_name(evtinfo->ctx_update.mode);
        break;
    case LOG_EVENT_MARKER:
        evt->event_case = QEMULOG_INSTR_EVT__EVENT_MARKER;
        evt->marker = evtinfo->marker;
        break;
    default:
        assert(0 && "unknown event ID");
    }
    *pb_evt = evt;
}

static void release_protobuf_event(QEMULogInstrEvt *pb_evt)
{
    if (pb_evt->event_case == QEMULOG_INSTR_EVT__EVENT_STATE) {
        g_free(pb_evt->state);
    }
    if (pb_evt->event_case == QEMULOG_INSTR_EVT__EVENT_CTX_UPDATE) {
        g_free(pb_evt->ctx_update);
    }
    g_free(pb_evt);
}

void init_protobuf_backend(CPUArchState *env)
{
    /*
     * TODO should handle a separate log file to avoid pollution of the main log
     * file with binary data from protobufs. Since this seems to be a common
     * pattern, maybe generalize it.
     *
     * XXX we may want to store a cache of protobuf structures in the backend
     * data so that we avoid all the g_malloc() and g_free().
     */

    if (protobuf_logfile == NULL) {
        protobuf_logfile = fopen("qemu-protobuf.pb", "w+b");
    }
}

void sync_protobuf_backend(CPUArchState *env)
{
    if (protobuf_logfile != NULL) {
        fflush(protobuf_logfile);
    }
}

void emit_protobuf_entry(CPUArchState *env, cpu_log_entry_t *entry)
{
    QEMULogInstrEntry pb_entry = QEMULOG_INSTR_ENTRY__INIT;
    QEMULogInstrExc pb_exc = QEMULOG_INSTR_EXC__INIT;
    QEMULogInstrMem **pb_mem;
    QEMULogInstrReg **pb_reg;
    QEMULogInstrEvt **pb_evt;
    uint8_t *buf;
    size_t len;
    uint32_t preamble = 0;
    int i;

    pb_entry.pc = entry->pc;

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA) {
        pb_entry.insn_case = QEMULOG_INSTR_ENTRY__INSN_DISAS;
        pb_entry.disas = disas_one_strbuf(env_cpu(env), entry->insn_bytes,
                                          sizeof(entry->insn_bytes), entry->pc);
        pb_entry.cpu = env_cpu(env)->cpu_index;
        pb_entry.asid = entry->asid;
        if (entry->flags & LI_FLAG_MODE_SWITCH) {
            /*
             * Safe to de-const cast as the pointer is only used during packing
             */
            pb_entry.mode = (char *)cpu_get_mode_name(entry->next_cpu_mode);
        }
        if (entry->flags & LI_FLAG_INTR_MASK) {
            pb_entry.exception = &pb_exc;
            pb_exc.vector = entry->intr_vector;
            pb_exc.code = entry->intr_code;
            if (entry->flags & LI_FLAG_INTR_TRAP) {
                pb_exc.type = QEMULOG_INSTR_EXC_TYPE__TRAP;
                pb_exc.faultaddr = entry->intr_faultaddr;
            } else if (entry->flags & LI_FLAG_INTR_ASYNC) {
                pb_exc.type = QEMULOG_INSTR_EXC_TYPE__INTR;
            } else {
                assert(0 && "invalid exception flags");
            }
        }
        if (entry->mem->len > 0) {
            pb_mem = g_malloc(entry->mem->len * sizeof(QEMULogInstrMem *));
            pb_entry.n_mem = entry->mem->len;
            pb_entry.mem = pb_mem;
            for (i = 0; i < entry->mem->len; i++, pb_mem++) {
                log_meminfo_t *minfo =
                    &g_array_index(entry->mem, log_meminfo_t, i);
                emit_protobuf_meminfo(minfo, pb_mem);
            }
        }
        if (entry->regs->len > 0) {
            pb_reg = g_malloc(entry->regs->len * sizeof(QEMULogInstrReg *));
            pb_entry.n_reg = entry->regs->len;
            pb_entry.reg = pb_reg;
            for (i = 0; i < entry->regs->len; i++, pb_reg++) {
                log_reginfo_t *rinfo =
                    &g_array_index(entry->regs, log_reginfo_t, i);
                emit_protobuf_reginfo(rinfo, pb_reg);
            }
        }
    }

    if (entry->events->len > 0) {
        pb_evt = NULL;
        pb_evt = g_malloc(entry->events->len * sizeof(QEMULogInstrEvt *));
        pb_entry.n_evt = entry->events->len;
        pb_entry.evt = pb_evt;
        for (i = 0; i < entry->events->len; i++, pb_evt++) {
            log_event_t *event = &g_array_index(entry->events, log_event_t, i);
            emit_protobuf_event(event, pb_evt);
        }
    }

    len = qemulog_instr_entry__get_packed_size(&pb_entry);
    preamble = len;
    assert(preamble == len && "Message preamble overflow");

    buf = g_malloc(len + sizeof(preamble));
    *((uint32_t *)buf) = preamble;
    qemulog_instr_entry__pack(&pb_entry, buf + sizeof(preamble));

    /*
     * Technically we should not use the qemu logfile as it is not open in
     * binary mode
     */
    qemu_flockfile(protobuf_logfile);
    fwrite(buf, len + sizeof(preamble), 1, protobuf_logfile);
    qemu_funlockfile(protobuf_logfile);

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA) {
        g_free(pb_entry.disas);

        if (entry->mem->len > 0) {
            for (i = 0; i < entry->mem->len; i++) {
                release_protobuf_meminfo(pb_entry.mem[i]);
            }
            g_free(pb_entry.mem);
        }
        if (entry->regs->len > 0) {
            for (i = 0; i < entry->regs->len; i++) {
                release_protobuf_reginfo(pb_entry.reg[i]);
            }
            g_free(pb_entry.reg);
        }
    }
    if (entry->events->len > 0) {
        for (i = 0; i < entry->events->len; i++) {
            release_protobuf_event(pb_entry.evt[i]);
        }
        g_free(pb_entry.evt);
    }
    g_free(buf);
}
