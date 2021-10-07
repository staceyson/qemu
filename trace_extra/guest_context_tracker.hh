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
#include <perfetto.h>
#include "qemu/log_instr.h"
#include "exec/log_instr_perfetto.h"

namespace cheri
{
/*
 * Track current guest context associated to a CPU.
 * This allows to charge events to the correct context by recording
 * what is currently active on a CPU.
 * There is one guest_context_tracker per virtual CPU.
 * We manage the following tracks for each CPU:
 * 1. A global CPU N track, for events charged to a CPU from an unknown context
 *    or where the context is not relevant.
 * 2. Each new process in the system gets allocated a new perfetto::ProcessTrack
 *    TODO: Currently there is no way to notify when the PID is discarded.
 * 3. Each new thread in the system gets allocated a new perfetto::ThreadTrack and
 *    the corresponding process as parent.
 * 4. Each new compartment ID gets allocated a new perfetto::CheriCompartmentTrack.
 *    Note that compartment tracks are not associated to a single thread, instead
 *    multiple threads may record events there.
 */
class guest_context_tracker
{
    perfetto::Track cpu_track_;
    std::shared_ptr<perfetto::Track> ctx_track_;
  public:
    guest_context_tracker(int cpu_id);
    void context_update(const log_event_ctx_update_t *evt);
    perfetto::Track& get_cpu_track();
    perfetto::Track& get_ctx_track();
};

/*
 * Generate a unique track ID.
 * The ID is guaranteed to be unique within a qemu run, but not with
 * respect to other data sources.
 */
unsigned long gen_track_uuid();

} /* cheri */
