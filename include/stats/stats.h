/*
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

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef CONFIG_TRACE_STATS
struct addr_range_hist;
typedef struct addr_range_hist *addr_range_hist_t;

/*
 * Interface to manipulate an interval histogram representing a count
 * over address ranges.
 * The pointer returned is an opaque handle.
 */
addr_range_hist_t qemu_stats_addr_range_hist_create(void);
void qemu_stats_addr_range_hist_destroy(addr_range_hist_t handle);
void qemu_stats_addr_range_hist_insert(addr_range_hist_t handle,
    uint64_t start, uint64_t end, uint64_t value);
void qemu_stats_addr_range_hist_dump(addr_range_hist_t handle, int fd,
    int cpu_id, bool csv_header);

#endif /* CONFIG_TRACE_STATS */
#ifdef __cplusplus
}
#endif
