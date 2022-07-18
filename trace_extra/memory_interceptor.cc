//
// Created by mc2262 on 15/07/22.
//

#include "trace_extra/memory_interceptor.hh"

DynamorioTraceInterceptor::ThreadLocalState::ThreadLocalState(
    ThreadLocalStateArgs &)
{
}

ofstream DynamorioTraceInterceptor::mem_logfile;

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
            if (qemu.has_instr()) {
                perfetto::protos::pbzero::QEMULogEntry::Decoder instr(
                    qemu.instr());
                if (instr.has_mem()) {
                    for (auto iter = instr.mem(); iter; iter++) {
                        perfetto::protos::pbzero::QEMULogEntryMem::Decoder mem(
                            *iter);
                        // create a trace_entry_t compatible with drcachesim
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
