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

#pragma once

#include <atomic>
#include <shared_mutex>
#include <memory>
#include <unordered_map>
#include <utility>
#include <string>
#include <perfetto.h>
#include <boost/optional.hpp>
#include <boost/utility/string_view.hpp>

#include "trace_extra/tuple_index.hh"

namespace cheri
{

/* (counter_name, counter_slot) */
using qemu_counter_id = std::tuple<std::string, unsigned int>;

/*
 * Custom track representing a dynamically allocated counter.
 * This is very similar to perfetto::CounterTrack but sadly it can not
 * be subclassed cleanly, does not support dynamic naming and does not yet
 * support incremental counters.
 */
class qemu_counter_track : public perfetto::Track
{
    const std::string name;
    const unsigned int slot;

  public:
    void Serialize(perfetto::protos::pbzero::TrackDescriptor *) const;
    perfetto::protos::gen::TrackDescriptor Serialize() const;
    qemu_counter_track(uint64_t uuid_, qemu_counter_id id);
};

struct qemu_counter {
    qemu_counter_track track;
    std::atomic<int64_t> value;

    void emit(int64_t sample) const;
    qemu_counter(qemu_counter_id id, int64_t reset);
    qemu_counter(const qemu_counter &other) = delete;
    ~qemu_counter();
};

/*
 * Manage blocks of named counters.
 * This can be reused at multiple levels: there is a global set of counters
 * for events that are common to the system, a per-cpu set of counters that
 * emit on the CPU tracks and a per-context set of counters that are context
 * switched by the context manager and emit on the per-context counter tracks.
 */
class qemu_counters_state
{
    /* The lock only protects find, insert, remove. Value updates are done
     * with atomics, so we do not need to get an exclusive lock to update
     * counter values.
     */
    std::shared_timed_mutex mutex;
    std::unordered_map<qemu_counter_id, std::unique_ptr<qemu_counter>,
                       tuple_hasher<qemu_counter_id>>
        counters;

    bool try_set(qemu_counter_id id, int64_t value);
    boost::optional<int64_t> try_fetch_add(qemu_counter_id id, int64_t value);

  public:
    qemu_counters_state() {}

    /* Set counter value or create new counter, emit the counter value */
    void set(qemu_counter_id id, int64_t value);
    /* Increment counter value or create new counter, emit the counter value */
    int64_t inc(qemu_counter_id id, int64_t value);
};

/* Increment counter and emit value to trace, for incremental counter handling
 */
void global_counter_inc_emit(qemu_counter_id id, int64_t value);
/* Set counter value and emit, for absolute counter handling */
void global_counter_set_emit(qemu_counter_id id, int64_t value);

} // namespace cheri
