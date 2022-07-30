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
#include <limits>
#include <mutex>
#include <random>
#include <string>
#include <utility>
#include <unordered_map>
#include "trace_extra/guest_context_tracker.hh"

namespace icl = boost::icl;

using addr_range = icl::interval<uint64_t>;

namespace cheri
{

/*
 * Dynamically created tracks and track data.
 * The track_state_lock must be held for updating the track_state map.
 */
std::mutex track_state_lock;
std::unordered_map<qemu_ctx_id, std::shared_ptr<qemu_context_state>,
                   tuple_hasher<qemu_ctx_id>>
    track_state_map;

/*
 * Constant mapping of QEMUDebugCounter IDs to counter track names
 */
const std::array<const std::string, QEMU_LOG_INSTR_DBG_MAX> debug_counter_names{
    "tb_icount",
    "tb_icount_tracing",
};

/* Helper to generate unique IDs for dynamic tracks */
unsigned long gen_track_uuid()
{
    static std::mutex rnd_mutex;
    static std::random_device rand_dev;
    static std::mt19937_64 rand_gen(rand_dev());
    static std::uniform_int_distribution<unsigned long> track_uuid_gen(
        0ul, std::numeric_limits<unsigned long>::max());

    {
        const std::lock_guard<std::mutex> lock(rnd_mutex);
        return track_uuid_gen(rand_gen);
    }
}

std::string ctx_track_name(qemu_ctx_id key)
{
    uint64_t pid = std::get<0>(key);
    uint64_t tid = std::get<1>(key);
    uint64_t cid = std::get<2>(key);
    int mode = std::get<3>(key);
    return "CTX " + std::to_string(pid) + ":" + std::to_string(tid) + ":" +
           std::to_string(cid) + ":" + std::to_string(mode);
}

perfetto::protos::pbzero::QEMULogEntryModeSwitch
qemu_cpu_mode_to_trace(qemu_log_instr_cpu_mode_t mode)
{
    // NOTE: We rely on the fact that the protobuf enum ModeSwitch
    // uses the same numbering as qemu_log_instr_cpu_mode_t
    return static_cast<perfetto::protos::pbzero::QEMULogEntryModeSwitch>(mode);
}

qemu_cpu_track::qemu_cpu_track(int id)
    : perfetto::Track(gen_track_uuid(), perfetto::Track()), cpu_id(id)
{
}

perfetto::protos::gen::TrackDescriptor qemu_cpu_track::Serialize() const
{
    auto desc = Track::Serialize();
    std::string name("CPU " + std::to_string(cpu_id));
    desc.set_name(name);
    return desc;
}

void qemu_cpu_track::Serialize(
    perfetto::protos::pbzero::TrackDescriptor *desc) const
{
    auto bytes = Serialize().SerializeAsString();
    desc->AppendRawProtoBytes(bytes.data(), bytes.size());
}

perfetto::protos::gen::TrackDescriptor qemu_context_track::Serialize() const
{
    auto desc = Track::Serialize();
    auto cheri_desc = desc.mutable_cheri_context();
    cheri_desc->set_pid(pid);
    cheri_desc->set_tid(tid);
    cheri_desc->set_cid(cid);
    cheri_desc->set_el(mode);
    desc.set_name(name);
    return desc;
}

void qemu_context_track::Serialize(
    perfetto::protos::pbzero::TrackDescriptor *desc) const
{
    auto bytes = Serialize().SerializeAsString();
    desc->AppendRawProtoBytes(bytes.data(), bytes.size());
}

qemu_context_track::qemu_context_track(qemu_ctx_id key)
    : perfetto::Track(gen_track_uuid(), perfetto::Track()),
      pid(std::get<0>(key)), tid(std::get<1>(key)), cid(std::get<2>(key)),
      mode(std::get<3>(key)), name(ctx_track_name(key))
{
}

qemu_ctx_id qemu_context_track::get_id() const
{
    return std::make_tuple(pid, tid, cid, mode);
}

void qemu_bb_tracker::track_next(cpu_log_entry_handle entry, uint64_t pc)
{
    if (!TRACE_EVENT_CATEGORY_ENABLED("bb_hit") &&
        !TRACE_EVENT_CATEGORY_ENABLED("br_hit")) {
        return;
    }

    if (pc == 0) {
        pc = perfetto_log_entry_pc(entry);
    }
    int size = perfetto_log_entry_insn_size(entry);
    /* When resuming after reset accept anything as a next instruction */
    if (bb_start == 0) {
        bb_start = pc;
        bb_icount = 0;
    } else if (pc != next_pc && next_pc != 0) {
        /* Presume we are branching */
        assert(bb_start != 0 && "PC bb start was not updated");
        assert(last_pc != 0 && "last_pc can not be zero");
        /* Update basic block info */
        bb_map += std::make_pair(addr_range::right_open(bb_start, last_pc),
                                 bb_value(1ul, bb_icount));
        /* Update branch info */
        branch_id bid = std::make_pair(last_pc, pc);
        branch_map[bid] += 1;
        /* Reset */
        bb_start = pc;
        bb_icount = 0;
    }
    bb_icount += 1;
    next_pc = pc + size;
    last_pc = pc;
}

void qemu_bb_tracker::reset(uint64_t pc)
{
    if (!TRACE_EVENT_CATEGORY_ENABLED("bb_hit") &&
        !TRACE_EVENT_CATEGORY_ENABLED("br_hit")) {
        return;
    }

    if (bb_start == 0) {
        /* Nothing to flush */
        return;
    }
    /* With pc=0 flush discarding any currently active bb */
    if (pc != 0) {
        bb_map += std::make_pair(addr_range::right_open(bb_start, pc),
                                 bb_value(1ul, bb_icount));
    }
    bb_start = bb_icount = next_pc = last_pc = 0;

    /* XXX-AM: Somewhat arbitrary tuning constant, depend on the SHM size */
    if (boost::icl::interval_count(bb_map) > 5000 || branch_map.size() > 5000)
        flush();
}

void qemu_bb_tracker::flush()
{
    for (const auto &keyval : bb_map) {
        auto &interval = keyval.first;
        TRACE_INTERVAL("bb_hit", track, interval.lower(), interval.upper(),
                       keyval.second.hit);
        TRACE_INTERVAL("bb_icount", track, interval.lower(), interval.upper(),
                       keyval.second.icount);
    }
    for (const auto &keyval : branch_map) {
        auto &bid = keyval.first;
        TRACE_INTERVAL("br_hit", track, std::get<0>(bid), std::get<1>(bid),
                       keyval.second);
    }
    bb_map.clear();
    branch_map.clear();
}

guest_context_tracker::guest_context_tracker(int cpu_id) : cpu_state(cpu_id) {}

void guest_context_tracker::mode_update(
    cpu_log_entry_handle entry,
    perfetto::protos::pbzero::QEMULogEntryModeSwitch new_mode)
{
    if (ctx_state == nullptr)
        return;

    auto key = ctx_state->track.get_id();
    std::get<3>(key) = new_mode;
    /* Check if we have a track for this mode */
    std::shared_ptr<qemu_context_state> state;
    {
        std::lock_guard<std::mutex> track_state_guard(track_state_lock);
        auto it = track_state_map.find(key);
        if (it == track_state_map.end()) {
            state = std::make_shared<qemu_context_state>(key);
            track_state_map.emplace(key, state);
        } else {
            /* Existing context */
            state = it->second;
        }
    }

    if (TRACE_EVENT_CATEGORY_ENABLED("bb_hit") ||
        TRACE_EVENT_CATEGORY_ENABLED("br_hit")) {
        if (ctx_state && ctx_state != state) {
            /* We are changing context */
            ctx_state->bb_tracker->reset(perfetto_log_entry_pc(entry));
        }
    }
    ctx_state = state;
}

void guest_context_tracker::context_update(cpu_log_entry_handle entry,
                                           const log_event_ctx_update_t *evt)
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
    qemu_ctx_id key = std::make_tuple(evt->pid, evt->tid, evt->cid, mode);
    std::shared_ptr<qemu_context_state> state;
    {
        std::lock_guard<std::mutex> track_state_guard(track_state_lock);
        auto it = track_state_map.find(key);
        if (it == track_state_map.end()) {
            state = std::make_shared<qemu_context_state>(key);
            track_state_map.emplace(key, state);
        } else {
            /* Existing context */
            state = it->second;
        }
    }

    if (TRACE_EVENT_CATEGORY_ENABLED("bb_hit") ||
        TRACE_EVENT_CATEGORY_ENABLED("br_hit")) {
        if (ctx_state && ctx_state != state) {
            /* We are changing context */
            ctx_state->bb_tracker->reset(perfetto_log_entry_pc(entry));
        }
    }
    ctx_state = state;
}

void guest_context_tracker::flush_all_ctx_data(uint64_t pc)
{
    /* Flush per-CPU and current context stats */
    if (TRACE_EVENT_CATEGORY_ENABLED("bb_hit") ||
        TRACE_EVENT_CATEGORY_ENABLED("br_hit")) {
        cpu_state.bb_tracker->reset(pc);
        cpu_state.bb_tracker->flush();
        if (ctx_state) {
            ctx_state->bb_tracker->reset(pc);
            ctx_state->bb_tracker->flush();
        }
        std::lock_guard<std::mutex> track_state_guard(track_state_lock);
        for (auto id_and_state : track_state_map) {
            qemu_bb_tracker *bb_tracker = id_and_state.second->bb_tracker.get();
            if (bb_tracker != ctx_state->bb_tracker.get()) {
                bb_tracker->reset(0);
                bb_tracker->flush();
            }
        }
    }
}

qemu_fallback_state *guest_context_tracker::get_cpu_state()
{
    return &cpu_state;
}

qemu_tracker_state *guest_context_tracker::get_ctx_state()
{
    if (ctx_state)
        return ctx_state.get();
    else
        return &cpu_state;
}

} // namespace cheri
