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
#include "trace_extra/guest_context_tracker.hh"

namespace {

struct qemu_context_track : public perfetto::Track
{
    const uint64_t pid;
    const uint64_t tid;
    const uint64_t cid;

    using qemu_ctx_id = std::tuple<uint64_t, uint64_t, uint64_t>;

    static std::shared_ptr<qemu_context_track>
    make_context_track(uint64_t pid, uint64_t tid, uint64_t cid)
    {
        return std::make_shared<qemu_context_track>(pid, tid, cid);
    }

    qemu_ctx_id
    get_id() const
    {
        return std::make_tuple(pid, tid, cid);
    }

    perfetto::protos::gen::TrackDescriptor
    Serialize() const
    {
        auto desc = Track::Serialize();
        auto qemu_desc = desc.mutable_qemu_context();
        qemu_desc->set_pid(pid);
        qemu_desc->set_tid(tid);
        qemu_desc->set_cid(cid);
        return desc;
    }

    qemu_context_track(uint64_t pid, uint64_t tid, uint64_t cid)
            : perfetto::Track(cheri::gen_track_uuid(), perfetto::Track()), pid(pid), tid(tid), cid(cid)
    {}

    ~qemu_context_track()
    {
        perfetto::TrackEvent::EraseTrackDescriptor(*this);
    }
};

/*
 * Dynamically created tracks.
 * Here we do not commit to a hierarchical model of process/thread, as context
 * events are guest-driven. Instead we defer any hierarchical interpretation of
 * the context identifier to post-processing.
 */
std::mutex tracks_lock;
std::map<qemu_context_track::qemu_ctx_id, std::shared_ptr<qemu_context_track>> tracks;
} /* anonymous */

namespace std {
/*
 * Make the qemu track ID hashable
 */
template<> struct hash<qemu_context_track::qemu_ctx_id>
{
    std::size_t operator()(const qemu_context_track::qemu_ctx_id& key) const noexcept
    {
        return (std::hash<uint64_t>{}(std::get<0>(key)) ^
                std::hash<uint64_t>{}(std::get<1>(key)) ^
                std::hash<uint64_t>{}(std::get<2>(key)));

    }
};
} /* std */

namespace cheri
{

/* Helper to generate unique IDs for dynamic tracks */
unsigned long
gen_track_uuid()
{
    // use perfetto::Uuid?
    static std::atomic<unsigned long> next_track_id(0xdead);
    return (next_track_id++);
}

guest_context_tracker::guest_context_tracker(int cpu_id) :
        cpu_track_(perfetto::Track::Global(gen_track_uuid()))
{
    std::string track_name("CPU " + std::to_string(cpu_id));
    auto desc = cpu_track_.Serialize();
    desc.set_name(track_name);
    perfetto::TrackEvent::SetTrackDescriptor(cpu_track_, desc);
}

void
guest_context_tracker::context_update(const log_event_ctx_update_t *evt)
{
    // Currently this is the only one existing
    assert(evt->op == LOG_EVENT_CTX_OP_SWITCH && "Invalid ctx update op");
    /*
     * Find or create the track associated with the new context and set it as the current
     * context track on the CPU. This will be used to log per-context events.
     * XXX-AM: Currently it is assumed that contexts are unique, this is clearly not the case
     * with PID/TID reuse and we should do something to detect this. This is mostly relevant
     * only for long-lived traces.
     */

    /* Fetch the tracks for the new context */
    std::lock_guard<std::mutex> tracks_guard(tracks_lock);
    qemu_context_track::qemu_ctx_id key = std::make_tuple(evt->pid, evt->tid, evt->cid);
    auto ctx_track_iter = tracks.find(key);
    std::shared_ptr<qemu_context_track> track;
    if (ctx_track_iter == tracks.end()) {
        /* New context */
        track = qemu_context_track::make_context_track(evt->pid, evt->tid, evt->cid);
        auto desc = track->Serialize();
        desc.set_name("CTX " + std::to_string(evt->pid) + ":" +
                      std::to_string(evt->tid) + ":" +
                      std::to_string(evt->cid));
        perfetto::TrackEvent::SetTrackDescriptor(*track, desc);
        tracks.emplace(key, track);
    } else {
        /* Existing context */
        track = ctx_track_iter->second;
    }
    ctx_track_ = track;
    /* XXX-AM: for debugging, remove */
    TRACE_EVENT_INSTANT("sched", "switch", cpu_track_,
                        "pid", evt->pid, "tid", evt->tid, "cid", evt->cid);
}

perfetto::Track&
guest_context_tracker::get_cpu_track()
{
    return cpu_track_;
}

perfetto::Track&
guest_context_tracker::get_ctx_track()
{
    if (ctx_track_)
        return *ctx_track_;
    else
        return cpu_track_;
}

} /* cheri */
