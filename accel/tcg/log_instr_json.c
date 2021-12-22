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
#include <cjson/cJSON.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/memop.h"
#include "disas/disas.h"

static inline cJSON *emit_json_hex(uint64_t value)
{
    char buf[sizeof(value) * 2 + 1];

    snprintf((char *)&buf, sizeof(buf), "%lx", value);
    return cJSON_CreateString((char *)&buf);
}

#ifdef TARGET_CHERI
static inline cJSON *emit_json_capability(cap_register_t *cap)
{
    cJSON *js_cap = cJSON_CreateObject();
    cJSON *valid = cJSON_CreateBool(cap->cr_tag);
    cJSON *sealed = cJSON_CreateBool(cap_is_sealed_with_type(cap));
    cJSON *perms = cJSON_CreateNumber(COMBINED_PERMS_VALUE(cap));
    cJSON *flags = cJSON_CreateNumber(cap_get_flags(cap));
    cJSON *base = emit_json_hex(cap_get_base(cap));
    cJSON *length = emit_json_hex(cap_get_length_sat(cap));
    cJSON *offset = emit_json_hex(cap_get_offset(cap));
    cJSON *otype = emit_json_hex(cap_get_otype_unsigned(cap));

    cJSON_AddItemToObject(js_cap, "v", valid);
    cJSON_AddItemToObject(js_cap, "s", sealed);
    cJSON_AddItemToObject(js_cap, "p", perms);
    cJSON_AddItemToObject(js_cap, "f", flags);
    cJSON_AddItemToObject(js_cap, "b", base);
    cJSON_AddItemToObject(js_cap, "l", length);
    cJSON_AddItemToObject(js_cap, "o", offset);
    cJSON_AddItemToObject(js_cap, "t", otype);
    return js_cap;
}
#endif

static inline void emit_json_ldst(log_meminfo_t *minfo, cJSON *list)
{
    cJSON *mem = cJSON_CreateObject();
    cJSON *is_load = cJSON_CreateBool((minfo->flags & LMI_LD) != 0);
    cJSON *size = cJSON_CreateNumber(memop_size(minfo->op));
    cJSON *addr = emit_json_hex(minfo->addr);
    cJSON *value;

#ifndef TARGET_CHERI
    assert((minfo->flags & LMI_CAP) == 0 &&
           "Capability memory access without CHERI support");
#else
    if (minfo->flags & LMI_CAP) {
        value = emit_json_capability(&minfo->cap);
    } else
#endif
    {
        value = emit_json_hex(minfo->value);
    }

    cJSON_AddItemToObject(mem, "is_load", is_load);
    cJSON_AddItemToObject(mem, "size", size);
    cJSON_AddItemToObject(mem, "addr", addr);
    cJSON_AddItemToObject(mem, "value", value);
    cJSON_AddItemToArray(list, mem);
}

static inline void emit_json_reg(log_reginfo_t *rinfo, cJSON *list)
{
    cJSON *reg = cJSON_CreateObject();
    cJSON *name = cJSON_CreateString(rinfo->name);
    cJSON *value;

    cJSON_AddItemToObject(reg, "name", name);

#ifndef TARGET_CHERI
    assert(!reginfo_is_cap(rinfo) && "Register marked as capability "
                                     "register whitout CHERI support");
#else
    if (reginfo_is_cap(rinfo)) {
        if (reginfo_has_cap(rinfo)) {
            value = emit_json_capability(&rinfo->cap);
        } else {
            value = cJSON_CreateNumber(rinfo->gpr);
        }
    } else
#endif
    {
        value = cJSON_CreateNumber(rinfo->gpr);
    }

    cJSON_AddItemToObject(reg, "value", value);
    cJSON_AddItemToArray(list, reg);
}

void sync_json_backend(CPUArchState *env)
{
    /*
     * If we are shutting down, close the json entry list manually
     * and add a dummy entry. This is an hack but it's easier than
     * deleting the preceding comma.
     */
    qemu_log("{}]");
}

void init_json_backend(CPUArchState *env)
{
    /* Initialize the json logfile */
    static bool initialized;

    if (!initialized) {
        initialized = true;
        qemu_log("[");
    }
}

void emit_json_entry(CPUArchState *env, cpu_log_entry_t *entry)
{
    const log_event_t *event;
    int i;

    /*
     * XXX would be nice to use libxo but it's an annoying requirement for Linux
     * targets.
     */
    cJSON *js_entry = cJSON_CreateObject();

    if (entry->flags & LI_FLAG_HAS_INSTR_DATA) {
        cJSON *pc = emit_json_hex(entry->pc);
        cJSON *cpu = cJSON_CreateNumber(env_cpu(env)->cpu_index);
        cJSON *asid = cJSON_CreateNumber(entry->asid);
        cJSON *insn = cJSON_CreateString(
            disas_one_strbuf(env_cpu(env), entry->insn_bytes,
                             sizeof(entry->insn_bytes), entry->pc));
        cJSON_AddItemToObject(js_entry, "pc", pc);
        cJSON_AddItemToObject(js_entry, "cpu", cpu);
        cJSON_AddItemToObject(js_entry, "asid", asid);
        cJSON_AddItemToObject(js_entry, "insn", insn);

        if (entry->flags & LI_FLAG_MODE_SWITCH) {
            cJSON *mode =
                cJSON_CreateString(cpu_get_mode_name(entry->next_cpu_mode));
            cJSON_AddItemToObject(js_entry, "mode-switch", mode);
        }

        if (entry->flags & LI_FLAG_INTR_MASK) {
            cJSON *exc = cJSON_CreateObject();
            cJSON *vec = cJSON_CreateNumber(entry->intr_vector);
            cJSON *code = cJSON_CreateNumber(entry->intr_code);
            cJSON *faultaddr = NULL;
            cJSON *type;
            if (entry->flags & LI_FLAG_INTR_TRAP) {
                type = cJSON_CreateString("trap");
                faultaddr = emit_json_hex(entry->intr_faultaddr);

            } else if (entry->flags & LI_FLAG_INTR_ASYNC) {
                type = cJSON_CreateString("intr");
            } else {
                assert(0 && "invalid exception flags");
            }
            cJSON_AddItemToObject(exc, "type", type);
            cJSON_AddItemToObject(exc, "vec", vec);
            cJSON_AddItemToObject(exc, "code", code);
            if (faultaddr) {
                cJSON_AddItemToObject(exc, "faultaddr", faultaddr);
            }
            cJSON_AddItemToObject(js_entry, "exc", exc);
        }

        if (entry->mem->len > 0) {
            cJSON *mem = cJSON_CreateArray();
            for (i = 0; i < entry->mem->len; i++) {
                log_meminfo_t *minfo =
                    &g_array_index(entry->mem, log_meminfo_t, i);
                emit_json_ldst(minfo, mem);
            }
            cJSON_AddItemToObject(js_entry, "mem", mem);
        }

        if (entry->regs->len > 0) {
            cJSON *reg = cJSON_CreateArray();
            for (i = 0; i < entry->regs->len; i++) {
                log_reginfo_t *rinfo =
                    &g_array_index(entry->regs, log_reginfo_t, i);
                emit_json_reg(rinfo, reg);
            }
            cJSON_AddItemToObject(js_entry, "reg", reg);
        }
    }

    if (entry->events->len > 0) {
        for (i = 0; i < entry->events->len; i++) {
            event = &g_array_index(entry->events, const log_event_t, i);
            switch (event->id) {
            case LOG_EVENT_STATE:
                break;
            case LOG_EVENT_CTX_UPDATE:
                break;
            case LOG_EVENT_MARKER:
                break;
            default:
                assert(0 && "unknown event ID");
            }
        }
    }
    qemu_log("%s,", cJSON_PrintUnformatted(js_entry));
    cJSON_Delete(js_entry);
}
