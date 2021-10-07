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

#include <utility>
#include <cstdint>
#include "qemu/log_instr.h"
#include "trace_extra/trace_stats.hh"

namespace icl = boost::icl;

using addr_range = icl::interval<uint64_t>;

namespace cheri
{

void qemu_stats::flush(perfetto::Track &track)
{
    /*
     * XXX-AM: Note: to avoid big packets we should probably write
     * the histogram samples separate from the hisogram descriptor and
     * tie them toghether in post-processing.
     * This would likely require specialized packet processing.
     */
    TRACE_EVENT_INSTANT("stats", "bb_hist", track,
                        [&](perfetto::EventContext ctx) {
                            auto *qemu_arg = ctx.event()->set_qemu();
                            auto *hist = qemu_arg->set_histogram();
                            for (const auto &keyval : bb_hit_map) {
                                auto &range = keyval.first;
                                auto *bucket = hist->add_bucket();
                                bucket->set_start(range.lower());
                                bucket->set_end(range.upper());
                                bucket->set_value(keyval.second);
                            }
                        });

    TRACE_EVENT_INSTANT("stats", "branch_hist", track,
                        [&](perfetto::EventContext ctx) {
                            auto *qemu_arg = ctx.event()->set_qemu();
                            auto *hist = qemu_arg->set_histogram();
                            for (const auto &keyval : branch_map) {
                                auto *bucket = hist->add_bucket();
                                bucket->set_start(keyval.first);
                                bucket->set_value(keyval.second);
                            }
                        });

    clear();
}

void qemu_stats::pause(perfetto::Track &track, uint64_t pc)
{
    /*
     * Treat this as the end of the block, otherwise the
     * current PC slice will be lost.
     */
    bb_hit_map +=
        std::make_pair(addr_range::right_open(pc_range_start, pc), icount);
    pc_range_start = last_pc = icount = 0;
    /*
     * Whenever we pause tracing, we need to sync the stats to trace,
     * otherwise we may charge the wrong context if tracing
     * is restarted in another thread.
     */
    flush(track);
}

void qemu_stats::unpause(perfetto::Track &track, uint64_t pc)
{
    /* Reset the pc-tracking state */
    pc_range_start = last_pc = pc;
    /* unpause will be called on the first instruction to be traced? */
    icount = 1; // Unpause is called for the first instruction being traced
}

void qemu_stats::clear()
{
    bb_hit_map.clear();
    branch_map.clear();
}

void qemu_stats::process_instr(perfetto::Track &ctx_track,
                               cpu_log_entry_handle entry)
{
    uint64_t pc = perfetto_log_entry_pc(entry);
    int size = perfetto_log_entry_insn_size(entry);
    if (pc - last_pc > size) {
        // presume we are branching
        bb_hit_map += std::make_pair(
            addr_range::right_open(pc_range_start, last_pc), icount);
        pc_range_start = pc;
        icount =
            1; // Reset icount triggered on the first instruction of the next BB
        branch_map[pc] += 1;
    } else {
        icount += 1;
    }
    last_pc = pc;
}

} // namespace cheri
