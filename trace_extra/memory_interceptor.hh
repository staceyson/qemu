//
// Created by mc2262 on 15/07/22.
//

#pragma once
#include <perfetto.h>
#include <iostream>
#include <fstream>
#include "dynamorio/clients/drcachesim/common/trace_entry.h"

using namespace std;

class DynamorioTraceInterceptor
    : public perfetto::Interceptor<DynamorioTraceInterceptor>
{

  public:
    static ofstream mem_logfile;
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
