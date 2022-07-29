/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Mingle Chen
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under Defense Advanced Research Projects Agency (DARPA)
 * Contract No. HR001122C0110 ("ETC").
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

#include "trace_extra/memory_interceptor.hh"

DynamorioTraceInterceptor::ThreadLocalState::ThreadLocalState(
    ThreadLocalStateArgs &)
{
}

io::filtering_ostream DynamorioTraceInterceptor::mem_logfile;

void DynamorioTraceInterceptor::OnTracePacket(InterceptorContext context)
{
    perfetto::protos::pbzero::TracePacket::Decoder packet(
        context.packet_data.data, context.packet_data.size);
    if (packet.has_track_event()) {
        perfetto::protos::pbzero::TrackEvent::Decoder track_event(
            packet.track_event());
        if (track_event.has_qemu()) {
            perfetto::protos::pbzero::QEMUEventInfo::Decoder qemu(
                track_event.qemu());
            // create trace_entry_t compatible with drcachesim
            if (qemu.has_instr()) {
                perfetto::protos::pbzero::QEMULogEntry::Decoder instr(
                    qemu.instr());
                if (instr.has_pc() && instr.has_opcode_obj()) {
                    perfetto::protos::pbzero::Opcode::Decoder opcode(
                        instr.opcode_obj());
                    if (opcode.has_size()) {
                        trace_entry_t entry;
                        entry.type = TRACE_TYPE_INSTR;
                        entry.addr = reinterpret_cast<addr_t>(instr.pc());
                        entry.size = opcode.size();
                        mem_logfile.write((char *)(&entry), sizeof(entry));
                    }
                }
                if (instr.has_mem()) {
                    for (auto iter = instr.mem(); iter; iter++) {
                        perfetto::protos::pbzero::QEMULogEntryMem::Decoder mem(
                            *iter);
                        trace_entry_t trace;
                        trace.addr = reinterpret_cast<addr_t>(mem.addr());
                        trace.size = mem.size();
                        switch (mem.op()) {
                        case perfetto::protos::pbzero::
                            QEMULogEntryMem_MemOp_LOAD:
                        case perfetto::protos::pbzero::
                            QEMULogEntryMem_MemOp_CLOAD:
                            trace.type = TRACE_TYPE_READ;
                            break;
                        case perfetto::protos::pbzero::
                            QEMULogEntryMem_MemOp_STORE:
                        case perfetto::protos::pbzero::
                            QEMULogEntryMem_MemOp_CSTORE:
                            trace.type = TRACE_TYPE_WRITE;
                            break;
                        default:
                            break;
                        }
                        mem_logfile.write((char *)&trace, sizeof(trace));
                    }
                }
            }
        }
    }
}
