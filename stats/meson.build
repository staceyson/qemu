
trace_stats_ss = ss.source_set()
trace_stats_ss.add(files('trace_stats.cc'))

boost_dep = dependency('boost', modules: ['iostreams'])

trace_stats_ss = trace_stats_ss.apply(config_all, strict: false)
libqemustats = static_library('qemustats',
                              sources: trace_stats_ss.sources(),
                              dependencies: [boost_dep],
                              cpp_args: ['-DCONFIG_TRACE_STATS'])

