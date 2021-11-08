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

#pragma once

#include <memory>
#include <iterator>
#include <utility>
#include <perfetto.h>
#include "qemu/log_instr.h"
#include "exec/log_instr_perfetto.h"
#include "trace_extra/trace_stats.hh"

namespace cheri
{

/*
 * Per-context data.
 * This is allocated and switched together with the context track.
 */
struct qemu_context_data {
    qemu_stats stats;
};

struct qemu_context_track : public perfetto::Track {

    using cpu_mode_type = perfetto::protos::pbzero::ModeSwitch;
    /* (pid, tid, cid, mode) */
    using qemu_ctx_id = std::tuple<uint64_t, uint64_t, uint64_t, cpu_mode_type>;

    const uint64_t pid;
    const uint64_t tid;
    const uint64_t cid;
    const cpu_mode_type mode;
    qemu_context_data ctx_data;

    static std::shared_ptr<qemu_context_track>
    make_context_track(qemu_ctx_id key);

    qemu_ctx_id get_id() const;

    perfetto::protos::gen::TrackDescriptor Serialize() const;

    qemu_context_track(qemu_ctx_id key);
    ~qemu_context_track();
};

/*
 * Track current guest context associated to a CPU.
 * This allows to charge events to the correct context by recording
 * what is currently active on a CPU.
 * There is one guest_context_tracker per virtual CPU.
 * We manage the following tracks for each CPU:
 * - A global CPU N track, for events charged to a CPU from an unknown context
 *    or where the context is not relevant.
 * - Each new process in the system gets allocated a new perfetto::ProcessTrack
 *    TODO: Currently there is no way to notify when the PID is discarded.
 * - Each new thread in the system gets allocated a new perfetto::ThreadTrack
 * and the corresponding process as parent.
 * - TODO Each new compartment ID gets allocated a new
 * perfetto::CheriCompartmentTrack. Note that compartment tracks are not
 * associated to a single thread, instead multiple threads may record events
 * there. Each new context can have associated data that is charged to that
 * context and only emitted to the track periodically. This is to avoid
 * generating too much data if it can be aggregated. Other options could be to
 * avoid the track subsystem and use a custom perfetto data source with
 * respective changes in the trace processor.
 * TODO:
 *  - The context shoud include information on address space
 */
class guest_context_tracker
{
    /* CPU track for events not assigned (or assignable) to a single context */
    perfetto::Track cpu_track_;
    /* context data for the CPU track */
    qemu_context_data cpu_ctx_data_;
    /* Currently active context track */
    std::shared_ptr<qemu_context_track> ctx_track_;

  public:
    guest_context_tracker(int cpu_id);
    void context_update(const log_event_ctx_update_t *evt);
    void mode_update(perfetto::protos::pbzero::ModeSwitch new_mode);
    void flush_all_ctx_data();
    perfetto::Track &get_cpu_track();
    perfetto::Track &get_ctx_track();
    qemu_context_data &get_ctx_data();
};

/*
 * Generate a unique track ID.
 * The ID is guaranteed to be unique within a qemu run, but not with
 * respect to other data sources.
 */
unsigned long gen_track_uuid();

perfetto::protos::pbzero::ModeSwitch
qemu_cpu_mode_to_trace(qemu_log_instr_cpu_mode_t mode);

} // namespace cheri
