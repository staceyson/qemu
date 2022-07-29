/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Mingle Chen
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under Defense Advanced Research Projects Agency (DARPA)
 * Contract No. HR001122C0110 ("ETC").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once
#include <perfetto.h>
#include <iostream>
#include "dynamorio/clients/drcachesim/common/trace_entry.h"
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using namespace std;
namespace io = boost::iostreams;

class DynamorioTraceInterceptor
    : public perfetto::Interceptor<DynamorioTraceInterceptor>
{

  public:
    static io::filtering_ostream mem_logfile;
    ~DynamorioTraceInterceptor() override = default;

    struct ThreadLocalState
        : public perfetto::InterceptorBase::ThreadLocalState {
        ThreadLocalState(ThreadLocalStateArgs &);

        ~ThreadLocalState() override = default;
    };

    // This function is called for each intercepted trace packet. |context|
    // contains information about the trace packet as well as other state
    // tracked by the interceptor (e.g., see ThreadLocalState).
    //
    // Intercepted trace data is provided in the form of serialized protobuf
    // bytes, accessed through the |context.packet_data| field.
    //
    // Warning: this function can be called on any thread at any time. See
    // below for how to safely access shared interceptor data from here.
    static void OnTracePacket(InterceptorContext context);
};
