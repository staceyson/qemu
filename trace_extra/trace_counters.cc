/*-
 * Copyright (c) 2022 Alfredo Mazzinghi
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

#include "trace_extra/trace_counters.hh"
#include "trace_extra/guest_context_tracker.hh"

namespace cheri
{

namespace
{
/*
 * Global counter state.
 */
qemu_counters_state global_counters;

} // namespace

qemu_counter_track::qemu_counter_track(uint64_t uuid_, qemu_counter_id id,
                                       perfetto::Track parent)
    : perfetto::Track(uuid_, parent), name(std::get<0>(id)),
      slot(std::get<1>(id))
{
}

perfetto::protos::gen::TrackDescriptor qemu_counter_track::Serialize() const
{
    auto desc = Track::Serialize();
    /* TODO process custom trace descriptor in trace processor */
    desc.set_name(name + ":" + std::to_string(slot));
    auto *counter_desc = desc.mutable_counter();
    /* TODO fill counter descriptor with optional data */
    return desc;
}

void qemu_counter_track::Serialize(
    perfetto::protos::pbzero::TrackDescriptor *desc) const
{
    auto bytes = Serialize().SerializeAsString();
    desc->AppendRawProtoBytes(bytes.data(), bytes.size());
}

qemu_counter::qemu_counter(qemu_counter_id id, int64_t reset,
                           perfetto::Track parent)
    : track(gen_track_uuid(), id, parent), value(reset)
{
    auto desc = track.Serialize();
    perfetto::TrackEvent::SetTrackDescriptor(track, desc);
}

qemu_counter::~qemu_counter()
{
    perfetto::TrackEvent::EraseTrackDescriptor(track);
}

void qemu_counter::emit(int64_t sample) const
{
    PERFETTO_INTERNAL_TRACK_EVENT(
        "counter", /*name=*/nullptr,
        perfetto::protos::pbzero::TrackEvent::TYPE_COUNTER, track,
        [&](perfetto::EventContext ctx) {
            auto *event = ctx.event();
            event->set_counter_value(value);
        });
}

bool qemu_counters_state::try_set(qemu_counter_id id, int64_t value)
{
    std::shared_lock<std::shared_timed_mutex> lock(mutex);
    auto it = counters.find(id);
    if (it != counters.end()) {
        it->second->value = value;
        it->second->emit(value);
        return false;
    }
    return true;
}

boost::optional<int64_t> qemu_counters_state::try_fetch_add(qemu_counter_id id,
                                                            int64_t value)
{
    std::shared_lock<std::shared_timed_mutex> lock(mutex);
    auto it = counters.find(id);
    if (it != counters.end()) {
        value = it->second->value.fetch_add(value);
        it->second->emit(value);
        return value;
    }
    return boost::none;
}

void qemu_counters_state::set(qemu_counter_id id, int64_t value)
{
    if (try_set(id, value)) {
        /* Upgrade lock for insert */
        std::unique_lock<std::shared_timed_mutex> lock(mutex);
        auto it = counters.find(id);
        if (it == counters.end()) {
            auto counter =
                std::make_unique<qemu_counter>(id, value, parent_track);
            auto emplaced = counters.emplace(id, std::move(counter));
            it = emplaced.first;
        } else {
            it->second->value = value;
        }
        it->second->emit(value);
    }
}

int64_t qemu_counters_state::inc(qemu_counter_id id, int64_t value)
{
    auto result = try_fetch_add(id, value);
    if (!result) {
        /* Upgrade lock for insert */
        std::unique_lock<std::shared_timed_mutex> lock(mutex);
        auto it = counters.find(id);
        if (it == counters.end()) {
            auto counter =
                std::make_unique<qemu_counter>(id, value, parent_track);
            auto emplaced = counters.emplace(id, std::move(counter));
            it = emplaced.first;
        } else {
            value = it->second->value.fetch_add(value);
        }
        it->second->emit(value);
        return value;
    }
    return result.value();
}

void global_counter_inc_emit(qemu_counter_id id, int64_t value)
{
    global_counters.inc(id, value);
}

void global_counter_set_emit(qemu_counter_id id, int64_t value)
{
    global_counters.set(id, value);
}

} // namespace cheri
