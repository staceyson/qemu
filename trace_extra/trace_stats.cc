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

#include "stats/stats.h"

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

addr_range_imap &handle2imap(addr_range_hist_t handle)
{
    return *reinterpret_cast<addr_range_imap *>(handle);
}

} // namespace

extern "C" {

addr_range_hist_t qemu_stats_addr_range_hist_create()
{
    auto hist = new addr_range_imap();
    return reinterpret_cast<addr_range_hist_t>(hist);
}

void qemu_stats_addr_range_hist_destroy(addr_range_hist_t handle)
{
    auto hist = &handle2imap(handle);
    delete hist;
}

void qemu_stats_addr_range_hist_insert(addr_range_hist_t handle, uint64_t start,
                                       uint64_t end, uint64_t value)
{
    auto &hist = handle2imap(handle);
    hist += std::make_pair(make_addr_range(start, end), value);
}

void qemu_stats_addr_range_hist_dump(addr_range_hist_t handle, int fd,
                                     bool csv_header)
{
    auto &hist = handle2imap(handle);
    io::file_descriptor_sink fd_sink(fd, io::never_close_handle);
    io::stream<io::file_descriptor_sink> ostream(fd_sink);

    if (csv_header)
        ostream << "CPU, start, end, count" << std::endl;
    for (const auto &keyval : hist) {
        auto &range = keyval.first;
        ostream << std::hex << range.lower() << "," << range.upper() << ","
                << std::dec << keyval.second << std::endl;
    }
}

} /* C */
