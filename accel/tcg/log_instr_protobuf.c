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

#include "qemu_log_entry.pb-c.h"

static FILE *protobuf_logfile;

/*
 * Helpers to simplify access to namespaced protobuf values
 * For consistency, redefine types to mirror the generated
 * code from protobuf-c but strip the package prefix.
 */
#define GEN_TYPE_NS(x)     Perfetto__Protos__##x
#define GEN_TYPE_PREFIX(x) GEN_TYPE_NS(QEMULogEntry##x)
typedef GEN_TYPE_PREFIX(Capability) QEMULogEntryCapability;
typedef GEN_TYPE_PREFIX(Mem) QEMULogEntryMem;
typedef GEN_TYPE_PREFIX(Reg) QEMULogEntryReg;
typedef GEN_TYPE_PREFIX(Evt) QEMULogEntryEvt;
typedef GEN_TYPE_PREFIX(Exc) QEMULogEntryExc;
typedef GEN_TYPE_PREFIX() QEMULogEntry;
typedef GEN_TYPE_PREFIX(EvtTraceState) QEMULogEntryEvtTraceState;
typedef GEN_TYPE_PREFIX(EvtCtxUpdate) QEMULogEntryEvtCtxUpdate;
typedef GEN_TYPE_PREFIX(EvtRegdump) QEMULogEntryEvtRegdump;
typedef GEN_TYPE_NS(QEMULogEventTraceState) QEMULogEventTraceState;

#define GEN_FN_NS(x)                        perfetto__protos__##x
#define GEN_FN_PREFIX(x)                    GEN_FN_NS(qemulog_entry_##x)
#define qemulog_entry_capability__init      GEN_FN_PREFIX(capability__init)
#define qemulog_entry_mem__init             GEN_FN_PREFIX(mem__init)
#define qemulog_entry_reg__init             GEN_FN_PREFIX(reg__init)
#define qemulog_entry_evt__init             GEN_FN_PREFIX(evt__init)
#define qemulog_entry_evt_trace_state__init GEN_FN_PREFIX(evt_trace_state__init)
#define qemulog_entry_evt_ctx_update__init  GEN_FN_PREFIX(evt_ctx_update__init)
#define qemulog_entry_evt_regdump__init     GEN_FN_PREFIX(evt_regdump__init)
#define qemulog_entry__get_packed_size      GEN_FN_PREFIX(_get_packed_size)
#define qemulog_entry__pack                 GEN_FN_PREFIX(_pack)

#define GEN_CONST_NS(x)         PERFETTO__PROTOS__##x
#define GEN_CONST_PREFIX(x)     GEN_CONST_NS(QEMULOG_ENTRY_##x)
#define ENUM_ENTRY_MEM_VALUE(v) GEN_CONST_PREFIX(MEM__VALUE_##v)
#define ENUM_ENTRY_REG_VALUE(v) GEN_CONST_PREFIX(REG__VALUE_##v)
#define ENUM_ENTRY_EVT_CASE(v)  GEN_CONST_PREFIX(EVT__EVENT_##v)
#define ENUM_ENTRY_INSN_CASE(v) GEN_CONST_PREFIX(_INSN_##v)
#define ENUM_ENTRY_MODE_CASE(v) GEN_CONST_PREFIX(_MODE_MODE_##v)
#define ENUM_ENTRY_EXC_CASE(v)  GEN_CONST_PREFIX(EXC_TYPE__##v)
#define QEMULOG_ENTRY__INIT     GEN_CONST_NS(QEMULOG_ENTRY__INIT)
#define QEMULOG_ENTRY_EXC__INIT GEN_CONST_PREFIX(EXC__INIT)

#ifdef TARGET_CHERI
static QEMULogEntryCapability *emit_protobuf_capability(cap_register_t *cap)
{
    QEMULogEntryCapability *pb_cap = g_malloc(sizeof(QEMULogEntryCapability));

    qemulog_entry_capability__init(pb_cap);
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
                                  QEMULogEntryMem **pb_mem)
{
    QEMULogEntryMem *mem = g_malloc(sizeof(QEMULogEntryMem));

    qemulog_entry_mem__init(mem);
    mem->is_load = (minfo->flags & LMI_LD) != 0;
    mem->size = memop_size(minfo->op);
    mem->addr = minfo->addr;
#ifndef TARGET_CHERI
    assert((minfo->flags & LMI_CAP) == 0 &&
           "Capability memory access without CHERI support");
#else
    if (minfo->flags & LMI_CAP) {
        mem->value_case = ENUM_ENTRY_MEM_VALUE(CAP_VALUE);
        mem->cap_value = emit_protobuf_capability(&minfo->cap);
    } else
#endif
    {
        mem->value_case = ENUM_ENTRY_MEM_VALUE(INT_VALUE);
        mem->int_value = minfo->value;
    }
    *pb_mem = mem;
}

static void release_protobuf_meminfo(QEMULogEntryMem *pb_mem)
{
    if (pb_mem->value_case == ENUM_ENTRY_MEM_VALUE(CAP_VALUE)) {
        g_free(pb_mem->cap_value);
    }
    g_free(pb_mem);
}

static void emit_protobuf_reginfo(log_reginfo_t *rinfo,
                                  QEMULogEntryReg **pb_reg)
{
    QEMULogEntryReg *reg = g_malloc(sizeof(QEMULogEntryReg));

    qemulog_entry_reg__init(reg);
    /* Safe to de-const cast as the pointer is only used during packing */
    reg->name = (char *)rinfo->name;

#ifndef TARGET_CHERI
    assert(!reginfo_is_cap(rinfo) && "Register marked as capability "
                                     "register whitout CHERI support");
#else
    if (reginfo_is_cap(rinfo)) {
        if (reginfo_has_cap(rinfo)) {
            reg->value_case = ENUM_ENTRY_REG_VALUE(CAP_VALUE);
            reg->cap_value = emit_protobuf_capability(&rinfo->cap);
        } else {
            reg->value_case = ENUM_ENTRY_REG_VALUE(INT_VALUE);
            reg->int_value = rinfo->gpr;
        }
    } else
#endif
    {
        reg->value_case = ENUM_ENTRY_REG_VALUE(INT_VALUE);
        reg->int_value = rinfo->gpr;
    }
    *pb_reg = reg;
}

static void release_protobuf_reginfo(QEMULogEntryReg *pb_reg)
{
    if (pb_reg->value_case == ENUM_ENTRY_REG_VALUE(CAP_VALUE)) {
        g_free(pb_reg->cap_value);
    }
    g_free(pb_reg);
}

static void emit_protobuf_event(log_event_t *evtinfo, QEMULogEntryEvt **pb_evt)
{
    QEMULogEntryEvt *pb_evt_entry = g_malloc(sizeof(QEMULogEntryEvt));
    int i;

    qemulog_entry_evt__init(pb_evt_entry);
    switch (evtinfo->id) {
    case LOG_EVENT_STATE:
        pb_evt_entry->event_case = ENUM_ENTRY_EVT_CASE(STATE);
        pb_evt_entry->state = g_malloc(sizeof(QEMULogEntryEvtTraceState));
        qemulog_entry_evt_trace_state__init(pb_evt_entry->state);
        pb_evt_entry->state->next_state =
            (QEMULogEventTraceState)evtinfo->state.next_state;
        pb_evt_entry->state->pc = evtinfo->state.pc;
        break;
    case LOG_EVENT_CTX_UPDATE:
        pb_evt_entry->event_case = ENUM_ENTRY_EVT_CASE(CTX_UPDATE);
        pb_evt_entry->ctx_update = g_malloc(sizeof(QEMULogEntryEvtCtxUpdate));
        qemulog_entry_evt_ctx_update__init(pb_evt_entry->ctx_update);
        pb_evt_entry->ctx_update->pid = evtinfo->ctx_update.pid;
        pb_evt_entry->ctx_update->tid = evtinfo->ctx_update.tid;
        pb_evt_entry->ctx_update->cid = evtinfo->ctx_update.cid;
        /* Safe to de-const cast as the pointer is only used during packing */
        pb_evt_entry->ctx_update->mode =
            (char *)cpu_get_mode_name(evtinfo->ctx_update.mode);
        break;
    case LOG_EVENT_MARKER:
        pb_evt_entry->event_case = ENUM_ENTRY_EVT_CASE(MARKER);
        pb_evt_entry->marker = evtinfo->marker;
        break;
    case LOG_EVENT_REGDUMP: {
        log_event_regdump_t *regdump = &evtinfo->reg_dump;
        QEMULogEntryEvtRegdump *pb_regdump =
            g_malloc(sizeof(QEMULogEntryEvtRegdump));
        QEMULogEntryReg **pb_regs;
        qemulog_entry_evt_regdump__init(pb_regdump);

        pb_evt_entry->event_case = ENUM_ENTRY_EVT_CASE(REGDUMP);
        pb_evt_entry->regdump = pb_regdump;
        pb_regdump->n_regs = regdump->gpr->len;
        pb_regs = g_malloc(regdump->gpr->len * sizeof(QEMULogEntryReg *));
        pb_regdump->regs = pb_regs;
        for (i = 0; i < regdump->gpr->len; i++, pb_regs++) {
            log_reginfo_t *rinfo =
                &g_array_index(regdump->gpr, log_reginfo_t, i);
            emit_protobuf_reginfo(rinfo, pb_regs);
        }
    } break;
    case LOG_EVENT_COUNTER:
        break;
    default:
        assert(0 && "unknown event ID");
    }
    *pb_evt = pb_evt_entry;
}

static void release_protobuf_event(QEMULogEntryEvt *pb_evt)
{
    int i;

    if (pb_evt->event_case == ENUM_ENTRY_EVT_CASE(STATE)) {
        g_free(pb_evt->state);
    }
    if (pb_evt->event_case == ENUM_ENTRY_EVT_CASE(CTX_UPDATE)) {
        g_free(pb_evt->ctx_update);
    }
    if (pb_evt->event_case == ENUM_ENTRY_EVT_CASE(REGDUMP)) {
        for (i = 0; i < pb_evt->regdump->n_regs; i++) {
            release_protobuf_reginfo(pb_evt->regdump->regs[i]);
        }
        g_free(pb_evt->regdump->regs);
        g_free(pb_evt->regdump);
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
    QEMULogEntry pb_entry = QEMULOG_ENTRY__INIT;
    QEMULogEntryExc pb_exc = QEMULOG_ENTRY_EXC__INIT;
    QEMULogEntryMem **pb_mem;
    QEMULogEntryReg **pb_reg;
    QEMULogEntryEvt **pb_evt;
    uint8_t *buf;
    size_t len;
    uint32_t preamble = 0;
    int i;

    pb_entry.pc = entry->pc;

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA) {
        pb_entry.insn_case = ENUM_ENTRY_INSN_CASE(DISAS);
        pb_entry.disas = disas_one_strbuf(env_cpu(env), entry->insn_bytes,
                                          sizeof(entry->insn_bytes), entry->pc);
        pb_entry.cpu = env_cpu(env)->cpu_index;
        pb_entry.asid = entry->asid;
        if (entry->flags & LI_FLAG_MODE_SWITCH) {
            /*
             * Safe to de-const cast as the pointer is only used during packing
             */
            pb_entry.mode_case = ENUM_ENTRY_MODE_CASE(NAME);
            pb_entry.mode_name =
                (char *)cpu_get_mode_name(entry->next_cpu_mode);
        }
        if (entry->flags & LI_FLAG_INTR_MASK) {
            pb_entry.exception = &pb_exc;
            pb_exc.vector = entry->intr_vector;
            pb_exc.code = entry->intr_code;
            if (entry->flags & LI_FLAG_INTR_TRAP) {
                pb_exc.type = ENUM_ENTRY_EXC_CASE(TRAP);
                pb_exc.faultaddr = entry->intr_faultaddr;
            } else if (entry->flags & LI_FLAG_INTR_ASYNC) {
                pb_exc.type = ENUM_ENTRY_EXC_CASE(INTR);
            } else {
                assert(0 && "invalid exception flags");
            }
        }
        if (entry->mem->len > 0) {
            pb_mem = g_malloc(entry->mem->len * sizeof(QEMULogEntryMem *));
            pb_entry.n_mem = entry->mem->len;
            pb_entry.mem = pb_mem;
            for (i = 0; i < entry->mem->len; i++, pb_mem++) {
                log_meminfo_t *minfo =
                    &g_array_index(entry->mem, log_meminfo_t, i);
                emit_protobuf_meminfo(minfo, pb_mem);
            }
        }
        if (entry->regs->len > 0) {
            pb_reg = g_malloc(entry->regs->len * sizeof(QEMULogEntryReg *));
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
        pb_evt = g_malloc(entry->events->len * sizeof(QEMULogEntryEvt *));
        pb_entry.n_evt = entry->events->len;
        pb_entry.evt = pb_evt;
        for (i = 0; i < entry->events->len; i++, pb_evt++) {
            log_event_t *event = &g_array_index(entry->events, log_event_t, i);
            emit_protobuf_event(event, pb_evt);
        }
    }

    len = qemulog_entry__get_packed_size(&pb_entry);
    preamble = len;
    assert(preamble == len && "Message preamble overflow");

    buf = g_malloc(len + sizeof(preamble));
    *((uint32_t *)buf) = preamble;
    qemulog_entry__pack(&pb_entry, buf + sizeof(preamble));

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
