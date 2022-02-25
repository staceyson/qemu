/*-
 * Copyright (c) 2021 Alfredo Mazzinghi
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include "trace_extra/guest_context_tracker.hh"

namespace cheri
{

/*
 * Dynamically created tracks and track data.
 * The tracks lock protects both tracks and ctx_data.
 */
std::mutex tracks_lock;
std::unordered_map<qemu_context_track::qemu_ctx_id,
                   std::shared_ptr<qemu_context_track>,
                   cheri::tuple_hasher<qemu_context_track::qemu_ctx_id>>
    tracks;

/* Helper to generate unique IDs for dynamic tracks */
unsigned long gen_track_uuid()
{
    // use perfetto::Uuid?
    static std::atomic<unsigned long> next_track_id(0xdead);
    return (next_track_id++);
}

perfetto::protos::pbzero::QEMULogEntryModeSwitch
qemu_cpu_mode_to_trace(qemu_log_instr_cpu_mode_t mode)
{
    // NOTE: We rely on the fact that the protobuf enum ModeSwitch
    // uses the same numbering as qemu_log_instr_cpu_mode_t
    return static_cast<perfetto::protos::pbzero::QEMULogEntryModeSwitch>(mode);
}

/* static */
std::shared_ptr<qemu_context_track>
qemu_context_track::make_context_track(qemu_ctx_id key)
{
    return std::make_shared<qemu_context_track>(key);
}

qemu_context_track::qemu_ctx_id qemu_context_track::get_id() const
{
    return std::make_tuple(pid, tid, cid, mode);
}

perfetto::protos::gen::TrackDescriptor qemu_context_track::Serialize() const
{
    auto desc = Track::Serialize();
    auto cheri_desc = desc.mutable_cheri_context();
    cheri_desc->set_pid(pid);
    cheri_desc->set_tid(tid);
    cheri_desc->set_cid(cid);
    cheri_desc->set_el(mode);
    return desc;
}

qemu_context_track::qemu_context_track(qemu_ctx_id key)
    : perfetto::Track(cheri::gen_track_uuid(), perfetto::Track()),
      pid(std::get<0>(key)), tid(std::get<1>(key)), cid(std::get<2>(key)),
      mode(std::get<3>(key))
{
}

qemu_context_track::~qemu_context_track()
{
    perfetto::TrackEvent::EraseTrackDescriptor(*this);
}

guest_context_tracker::guest_context_tracker(int cpu_id)
    : cpu_track_(perfetto::Track::Global(gen_track_uuid()))
{
    std::string track_name("CPU " + std::to_string(cpu_id));
    auto desc = cpu_track_.Serialize();
    desc.set_name(track_name);
    perfetto::TrackEvent::SetTrackDescriptor(cpu_track_, desc);
}

void guest_context_tracker::mode_update(
    perfetto::protos::pbzero::QEMULogEntryModeSwitch new_mode)
{
    if (ctx_track_ == nullptr)
        return;

    auto key = ctx_track_->get_id();
    std::get<3>(key) = new_mode;
    /* Check if we have a track for this mode */
    std::shared_ptr<qemu_context_track> track;
    {
        std::lock_guard<std::mutex> tracks_guard(tracks_lock);
        auto found_track_iter = tracks.find(key);
        if (found_track_iter == tracks.end()) {
            track = qemu_context_track::make_context_track(key);
            auto desc = track->Serialize();
            desc.set_name("CTX " + std::to_string(track->pid) + ":" +
                          std::to_string(track->tid) + ":" +
                          std::to_string(track->cid) + ":" +
                          std::to_string(track->mode));
            perfetto::TrackEvent::SetTrackDescriptor(*track, desc);
            tracks.emplace(key, track);
        } else {
            /* Existing context */
            track = found_track_iter->second;
        }
    }
    ctx_track_ = track;
}

void guest_context_tracker::context_update(const log_event_ctx_update_t *evt)
{
    // Currently these are the only ones existing
    assert((evt->op == LOG_EVENT_CTX_OP_SWITCH) && "Invalid ctx update op");
    /*
     * Find or create the track associated with the new context and set it as
     * the current context track on the CPU. This will be used to log
     * per-context events.
     * XXX-AM: Currently it is assumed that contexts are unique, this is clearly
     * not the case with PID/TID reuse and we should do something to detect
     * this. This seems mostly relevant only for long-lived traces.
     */

    auto mode = qemu_cpu_mode_to_trace(evt->mode);
    /* Fetch the tracks for the new context */
    qemu_context_track::qemu_ctx_id key =
        std::make_tuple(evt->pid, evt->tid, evt->cid, mode);
    std::shared_ptr<qemu_context_track> track;
    {
        std::lock_guard<std::mutex> tracks_guard(tracks_lock);
        auto ctx_track_iter = tracks.find(key);
        if (ctx_track_iter == tracks.end()) {
            /* New context */
            track = qemu_context_track::make_context_track(key);
            auto desc = track->Serialize();
            desc.set_name("CTX " + std::to_string(evt->pid) + ":" +
                          std::to_string(evt->tid) + ":" +
                          std::to_string(evt->cid) + ":" +
                          std::to_string(mode));
            perfetto::TrackEvent::SetTrackDescriptor(*track, desc);
            tracks.emplace(key, track);
        } else {
            /* Existing context */
            track = ctx_track_iter->second;
        }
    }
    ctx_track_ = track;
}

void guest_context_tracker::flush_all_ctx_data()
{
    /* Flush per-CPU stats */
    cpu_ctx_data_.stats.flush(cpu_track_);
    for (auto &id_and_track : tracks) {
        qemu_context_data &ctx_data = id_and_track.second->ctx_data;
        ctx_data.stats.flush(*id_and_track.second);
    }
}

perfetto::Track &guest_context_tracker::get_cpu_track()
{
    return cpu_track_;
}

perfetto::Track &guest_context_tracker::get_ctx_track()
{
    if (ctx_track_)
        return *ctx_track_;
    else
        return cpu_track_;
}

qemu_context_data &guest_context_tracker::get_ctx_data()
{
    if (ctx_track_)
        return ctx_track_->ctx_data;
    else
        return cpu_ctx_data_;
}

} // namespace cheri
