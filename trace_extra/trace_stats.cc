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

#include "exec/log_instr_stats.h"

#include <map>
#include <iostream>
#include <utility>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/icl/interval_map.hpp>

namespace icl = boost::icl;
namespace io = boost::iostreams;

using addr_range_imap = icl::interval_map<uint64_t, uint64_t>;
using addr_range = icl::interval<uint64_t>;

namespace
{

addr_range::interval_type make_addr_range(uint64_t start, uint64_t end)
{
    return addr_range::right_open(start, end);
}

struct QEMUStats {
    addr_range_imap call_map;
    addr_range_imap bb_hit_map;
    int cpu_id;

    QEMUStats(int cpu_id) : cpu_id(cpu_id) {}

    void record_bb_hit(uint64_t start, uint64_t end);
    void record_call(uint64_t addr, uint64_t link);
    void dump(int fd, bool csv_header);
    void clear();
};

QEMUStats &handle2stats(qemu_cpu_stats_t handle)
{
    return *reinterpret_cast<QEMUStats *>(handle);
}

void QEMUStats::dump(int fd, bool csv_header)
{
    io::file_descriptor_sink fd_sink(fd, io::never_close_handle);
    io::stream<io::file_descriptor_sink> ostream(fd_sink);

    if (csv_header)
        ostream << "CPU,start,end,count" << std::endl;
    for (const auto &keyval : bb_hit_map) {
        auto &range = keyval.first;
        ostream << cpu_id << "," << std::hex << range.lower() << ","
                << range.upper() << "," << std::dec << keyval.second
                << std::endl;
    }
}

void QEMUStats::clear()
{
    bb_hit_map.clear();
    call_map.clear();
}

void QEMUStats::record_bb_hit(uint64_t start, uint64_t end)
{
    bb_hit_map += std::make_pair(make_addr_range(start, end), 1UL);
}

void QEMUStats::record_call(uint64_t addr, uint64_t link)
{
    call_map += std::make_pair(make_addr_range(addr, link), 1UL);
}

} // namespace

/*
 * C API wrappers to the stats class.
 */
extern "C" {

qemu_cpu_stats_t qemu_cpu_stats_create(int cpu_id)
{
    auto *stats = new QEMUStats(cpu_id);
    return reinterpret_cast<qemu_cpu_stats_t>(stats);
}

void qemu_cpu_stats_destroy(qemu_cpu_stats_t handle)
{
    auto stats = &handle2stats(handle);
    delete stats;
}

void qemu_cpu_stats_dump(qemu_cpu_stats_t handle, int fd, bool csv_header)
{
    auto stats = handle2stats(handle);
    stats.dump(fd, csv_header);
    stats.clear();
}

void qemu_cpu_stats_record_bb_hit(qemu_cpu_stats_t handle, uint64_t start,
                                  uint64_t end)
{
    auto stats = handle2stats(handle);
    stats.record_bb_hit(start, end);
}

void qemu_cpu_stats_record_call(qemu_cpu_stats_t handle, uint64_t addr,
                                uint64_t link)
{
    auto stats = handle2stats(handle);
    stats.record_call(addr, link);
}

} /* C */
