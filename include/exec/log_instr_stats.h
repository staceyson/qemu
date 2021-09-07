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
extern "C" {
#endif

#ifdef CONFIG_TRACE_STATS
struct qemu_cpu_stats;
typedef struct qemu_cpu_stats *qemu_cpu_stats_t;

/*
 * Interface to manipulate an interval histogram representing a count
 * over address ranges.
 * The pointer returned is an opaque handle.
 */
qemu_cpu_stats_t qemu_cpu_stats_create(int cpu_id);
void qemu_cpu_stats_destroy(qemu_cpu_stats_t handle);
void qemu_cpu_stats_dump(qemu_cpu_stats_t handle, int fd, bool csv_header);
void qemu_cpu_stats_record_bb_hit(qemu_cpu_stats_t handle, uint64_t start,
                                  uint64_t end);
void qemu_cpu_stats_record_call(qemu_cpu_stats_t handle, uint64_t addr,
                                uint64_t link);

#endif /* CONFIG_TRACE_STATS */
#ifdef __cplusplus
}
#endif
