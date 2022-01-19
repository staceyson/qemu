/*-
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
 * QEMU instruction logging bridge to the perfetto framework.
 */
#include <cassert>
#include <memory>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <string>
#include <map>
#include <vector>
#include <pthread.h>
#include <fcntl.h>
#include <perfetto.h>
#include <boost/filesystem.hpp>

// #include "qemu/cpu-defs.h"
#include "qemu/log_instr.h"
#include "exec/log_instr_internal.h"
#include "exec/log_instr_perfetto.h"
#include "trace_extra/trace_stats.hh"
#include "trace_extra/guest_context_tracker.hh"

PERFETTO_TRACK_EVENT_STATIC_STORAGE();

namespace fs = boost::filesystem;

namespace
{

/* Tracing session pointer */
std::unique_ptr<perfetto::TracingSession> session;

/* perfetto logfile */
fs::path logfile("qemu_trace.pb");

/* category strings */
std::vector<std::string> categories;

/* Global scheduling event track */
std::unique_ptr<perfetto::Track> sched_track;

/*
 * Private per-CPU state.
 */
struct perfetto_backend_data {
    // Per-CPU control track. This records tracing control events.
    perfetto::Track ctrl_track_;
    // Tracker that resolves the current context scheduled on a CPU
    cheri::guest_context_tracker ctx_tracker_;
    /*
     * Cached copy of the logging activation status.
     * It is easier to keep a cached copy here than exposing the loglevel_active
     * flag to the C++ interface.
     */
    bool loglevel_active_;

    perfetto_backend_data(int cpu_id)
        : ctrl_track_(perfetto::Track::Global(cheri::gen_track_uuid())),
          ctx_tracker_(cpu_id)

    {
        std::string track_name("CPU " + std::to_string(cpu_id) + " ctrl");

        auto desc = ctrl_track_.Serialize();
        desc.set_name(track_name);
        perfetto::TrackEvent::SetTrackDescriptor(ctrl_track_, desc);
    }
};

/*
 * Initialize perfetto tracing.
 *
 * Create the following data sources for qemu events:
 * - Track events data source
 * * XXX-AM: should use in process on UNIX only
 * Should allow flags/options to control backend type, buffer sizes and
 * other things
 */
bool perfetto_start_tracing(void)
{

    perfetto::TracingInitArgs args;
    perfetto::TraceConfig cfg;
    perfetto::protos::gen::TrackEventConfig track_cfg;

    args.backends |= perfetto::kInProcessBackend;

    perfetto::Tracing::Initialize(args);
    perfetto::TrackEvent::Register();

    cfg.add_buffers()->set_size_kb(1 << 17); // 128MiB
    cfg.set_flush_period_ms(2000);
    cfg.set_file_write_period_ms(1000);
    fs::remove(logfile);
    cfg.set_write_into_file(true);
    cfg.set_output_path(logfile.string());

    auto *ds_cfg = cfg.add_data_sources()->mutable_config();
    ds_cfg->set_name("track_event");
    track_cfg.add_disabled_categories("*");
    for (auto &category : categories) {
        track_cfg.add_enabled_categories(category);
    }
    ds_cfg->set_track_event_config_raw(track_cfg.SerializeAsString());
    auto *producer_cfg = cfg.add_producers();
    producer_cfg->set_producer_name("qemu-tcg");
    producer_cfg->set_shm_size_kb(1 << 15); // 32MiB

    session = perfetto::Tracing::NewTrace();

    session->Setup(cfg);
    session->StartBlocking();

    perfetto::ProcessTrack qemu_proc = perfetto::ProcessTrack::Current();
    auto desc = qemu_proc.Serialize();
    desc.mutable_process()->set_process_name("qemu");
    perfetto::TrackEvent::SetTrackDescriptor(qemu_proc, desc);

    sched_track.reset(new perfetto::Track(cheri::gen_track_uuid()));
    desc = sched_track->Serialize();
    desc.set_name("Scheduler ctrl");
    perfetto::TrackEvent::SetTrackDescriptor(*sched_track, desc);
    return true;
}

void perfetto_tracing_stop(void)
{
    // NOTE: This is not sufficient for flushing the buffers, we currently
    // also need to call the buffer sync function for each CPU on the exit path.
    session->FlushBlocking();
    session->StopBlocking();
}

void trace_cap_register(perfetto::protos::pbzero::QEMULogEntryCapability *cap,
                        cap_register_handle chandle)
{
    cap->set_valid(perfetto_cap_tag(chandle));
    cap->set_sealed(perfetto_cap_sealed(chandle));
    cap->set_cap_base(perfetto_cap_base(chandle));
    cap->set_cap_length(perfetto_cap_length(chandle));
    cap->set_cap_cursor(perfetto_cap_cursor(chandle));
    cap->set_perms(perfetto_cap_perms(chandle));
    cap->set_otype(perfetto_cap_otype(chandle));
}

void process_events(perfetto_backend_data *data, cpu_log_entry_handle entry)
{
    int nevents = perfetto_log_entry_events(entry);
    bool have_startstop_event = false;
    auto *ctx_data = &data->ctx_tracker_.get_ctx_data();
    auto *ctx_track = &data->ctx_tracker_.get_ctx_track();

    /*
     * Note: LOG_EVENT_STATE events are emitted even when tracing is disabled.
     * The rest of the events should only be emitted when tracing is active.
     */
    for (int i = 0; i < nevents; i++) {
        log_event_t *evt = perfetto_log_event(entry, i);
        switch (evt->id) {
        case LOG_EVENT_STATE: {
            switch (evt->state.next_state) {
            case LOG_EVENT_STATE_FLUSH:
                TRACE_EVENT_INSTANT("ctrl", "flush", data->ctrl_track_);
                data->ctx_tracker_.flush_all_ctx_data();
                perfetto::TrackEvent::Flush();
                break;
            case LOG_EVENT_STATE_START:
                ctx_data->stats.unpause(*ctx_track, evt->state.pc);
                TRACE_EVENT_BEGIN("ctrl", "tracing", data->ctrl_track_);
                have_startstop_event = true;
                break;
            case LOG_EVENT_STATE_STOP:
                ctx_data->stats.pause(*ctx_track, evt->state.pc);
                TRACE_EVENT_END("ctrl", data->ctrl_track_);
                have_startstop_event = true;
                break;
            default:
                assert(false && "Invalid state event");
            }
        } break;
        case LOG_EVENT_CTX_UPDATE: {
            /* Swap current context. */
            if (evt->ctx_update.op == LOG_EVENT_CTX_OP_SETUP ||
                evt->ctx_update.op == LOG_EVENT_CTX_OP_SWITCH) {
                ctx_data->stats.pause(*ctx_track, perfetto_log_entry_pc(entry));
                data->ctx_tracker_.context_update(&evt->ctx_update);
                /* Reload data and track as context_update will have changed
                 * them */
                ctx_data = &data->ctx_tracker_.get_ctx_data();
                ctx_track = &data->ctx_tracker_.get_ctx_track();
                ctx_data->stats.unpause(*ctx_track,
                                        perfetto_log_entry_pc(entry));
            }
        } break;
        case LOG_EVENT_MARKER: {
            auto cpu_track = data->ctx_tracker_.get_cpu_track();
            TRACE_EVENT_INSTANT("marker", "guest", cpu_track,
                                [&](perfetto::EventContext ctx) {
                                    auto *qemu_arg = ctx.event()->set_qemu();
                                    qemu_arg->set_marker(evt->marker);
                                });
        } break;
        default:
            assert(false && "Invalid event identifier");
        }
    }
    if (perfetto_log_entry_flags(entry) & LI_FLAG_MODE_SWITCH) {
        auto mode = cheri::qemu_cpu_mode_to_trace(
            perfetto_log_entry_next_cpu_mode(entry));
        // XXX-AM: consider making the mode switch an event, possibly with its
        // own separate pc signaling the PC of the next instruction we are
        // landing to?
        ctx_data->stats.pause(*ctx_track, perfetto_log_entry_pc(entry));
        data->ctx_tracker_.mode_update(mode);
        ctx_data = &data->ctx_tracker_.get_ctx_data();
        ctx_track = &data->ctx_tracker_.get_ctx_track();
        ctx_data->stats.unpause(*ctx_track, perfetto_log_entry_pc(entry));
    }

    /*
     * If we have instruction data, we assume that tracing is enabled and run
     * extra stats gathering to track the executed instruction PC in the stats
     * histograms. This avoids having to keep a shadow copy of the tracing state
     * in the backend.
     */
    if (!have_startstop_event &&
        (perfetto_log_entry_flags(entry) & LI_FLAG_HAS_INSTR_DATA) != 0)
        ctx_data->stats.process_instr(*ctx_track, entry);
}

void process_instr(perfetto_backend_data *data, cpu_log_entry_handle entry)
{
    /*
     * XXX-AM: instead of having one big instruction record, we may have
     * different messages for optional parts of the instruction message, on the
     * same track/category: e.g. mode swtich, interrupt information and modified
     * registers?
     */
    TRACE_EVENT_INSTANT(
        "instructions", "stream", data->ctx_tracker_.get_ctx_track(),
        [&](perfetto::EventContext ctx) {
            auto *qemu_arg = ctx.event()->set_qemu();
            auto *instr = qemu_arg->set_instr();
            auto flags = perfetto_log_entry_flags(entry);

            /*
             * Populate protobuf from internal qemu structure.
             * XXX-AM: It would be very nice if we could somehow skip this step
             * and have the qemu internal representation be protobuf-based, so
             * that here we only have to embed the qemu-specific packet
             * into the track_event. Ideally this would save us all this copying
             * around of the event data but I have no clue about the
             * implications for the stability of the C/C++ protobuf-generated
             * structures or whether we can embed the qemu portion of the packet
             * already in the serialized wire-format (which should be stable by
             * design). This can probably be done via
             * protozero::Message::AppendScatteredBytes().
             */
            assert(flags & LI_FLAG_HAS_INSTR_DATA);
            const char *bytes = perfetto_log_entry_insn_bytes(entry);
            int size = perfetto_log_entry_insn_size(entry);
            int nitems;

            instr->set_opcode((const uint8_t *)bytes, size);
            instr->set_pc(perfetto_log_entry_pc(entry));

            nitems = perfetto_log_entry_regs(entry);
            for (int i = 0; i < nitems; i++) {
                auto flags = perfetto_reg_info_flags(entry, i);
                auto *reginfo = instr->add_reg();
                reginfo->set_name(perfetto_reg_info_name(entry, i));
                if ((flags & LRI_CAP_REG) && (flags & LRI_HOLDS_CAP)) {
                    cap_register_handle cap_handle =
                        perfetto_reg_info_cap(entry, i);
                    auto *capinfo = reginfo->set_cap_value();
                    trace_cap_register(capinfo, cap_handle);
                } else {
                    reginfo->set_int_value(perfetto_reg_info_gpr(entry, i));
                }
            }
            nitems = perfetto_log_entry_mem(entry);
            for (int i = 0; i < nitems; i++) {
                auto flags = perfetto_mem_info_flags(entry, i);
                auto *meminfo = instr->add_mem();
                meminfo->set_addr(perfetto_mem_info_addr(entry, i));
                switch (flags) {
                case LMI_LD:
                    meminfo->set_op(
                        perfetto::protos::pbzero::QEMULogEntryMem::LOAD);
                    break;
                case LMI_LD | LMI_CAP:
                    meminfo->set_op(
                        perfetto::protos::pbzero::QEMULogEntryMem::CLOAD);
                    break;
                case LMI_ST:
                    meminfo->set_op(
                        perfetto::protos::pbzero::QEMULogEntryMem::STORE);
                    break;
                case LMI_ST | LMI_CAP:
                    meminfo->set_op(
                        perfetto::protos::pbzero::QEMULogEntryMem::CSTORE);
                    break;
                default:
                    // XXX Notify error somehow?
                    break;
                }
                if (flags & LMI_CAP) {
                    auto *capinfo = meminfo->set_cap_value();
                    cap_register_handle cap_handle =
                        perfetto_reg_info_cap(entry, i);
                    trace_cap_register(capinfo, cap_handle);
                } else {
                    meminfo->set_int_value(perfetto_mem_info_value(entry, i));
                }
            }

            if (flags & LI_FLAG_INTR_MASK) {
                // interrupt
                auto *exc = instr->set_exception();
                if (flags & LI_FLAG_INTR_TRAP)
                    exc->set_type(
                        perfetto::protos::pbzero::QEMULogEntryExcType::TRAP);
                else {
                    exc->set_type(
                        perfetto::protos::pbzero::QEMULogEntryExcType::INTR);
                }
                exc->set_code(perfetto_log_entry_intr_code(entry));
            }
            if (flags & LI_FLAG_MODE_SWITCH) {
                auto mode = cheri::qemu_cpu_mode_to_trace(
                    perfetto_log_entry_next_cpu_mode(entry));
                instr->set_mode_code(mode);
            }
        });
}

} // namespace

extern "C" void qemu_log_instr_perfetto_conf_logfile(const char *name)
{
    logfile = name;
}

extern "C" void
qemu_log_instr_perfetto_conf_categories(const char *category_str)
{
    std::string strspec(category_str);
    int pos;

    while ((pos = strspec.find(',', 0)) != std::string::npos) {
        categories.push_back(strspec.substr(0, pos));
        strspec = strspec.substr(pos + 1);
    }
    if (strspec.size())
        categories.push_back(strspec);
}

/*
 * Initialize perfetto tracing.
 *
 * Start tracing thread when first called.
 */
extern "C" void perfetto_init_cpu(int cpu_index, void **backend_data)
{
    static std::once_flag init_flag;

    std::call_once(init_flag, [&]() {
        atexit(perfetto_tracing_stop);
        perfetto_start_tracing();
    });

    // XXX-AM: The backend data is currently missing a cleanup hook, so it
    // leaks. This is not a big issue as it should be live until the qemu
    // process terminates.
    *backend_data = new perfetto_backend_data(cpu_index);
}

/*
 * This is required because of how perfetto TraceSession::Flush works,
 * see comment on this method for more details.
 * We need to flush the data source directly to see the last packet.
 */
extern "C" void perfetto_sync_cpu(void *backend_data)
{
    perfetto::TrackEvent::Flush();
}

extern "C" void perfetto_emit_instr(void *backend_data,
                                    cpu_log_entry_handle entry)
{
    auto *data = reinterpret_cast<perfetto_backend_data *>(backend_data);
    auto flags = perfetto_log_entry_flags(entry);

    /* Process events first to react to START/STOP tracing events if needed */
    process_events(data, entry);
    if (flags & LI_FLAG_HAS_INSTR_DATA) {
        process_instr(data, entry);
    }
}
