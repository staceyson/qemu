
qemutrace_ss = ss.source_set()

qemutrace_ss.add(when: ['CONFIG_TCG', 'CONFIG_TRACE_STATS'],
                 if_true: files('trace_stats.cc'))
qemutrace_ss.add(when: ['CONFIG_TCG', 'CONFIG_TRACE_STATS'],
                 if_true: dependency('boost', modules: ['iostreams']))

qemutrace_ss.add(when: ['CONFIG_TCG', 'CONFIG_TRACE_PERFETTO'],
                 if_true: files('trace_perfetto.cc', 'cheri-perfetto/sdk/perfetto.cc'))

qemutrace_ss = qemutrace_ss.apply(config_all, strict: false)
libqemutrace = static_library('qemutrace',
                              sources: qemutrace_ss.sources(),
                              dependencies: qemutrace_ss.dependencies(),
                              include_directories: ['cheri-perfetto/sdk'],
                              cpp_args: ['-DCONFIG_TRACE_STATS', '-DQEMU_PERFETTO'])

qemuutil_libs += libqemutrace
