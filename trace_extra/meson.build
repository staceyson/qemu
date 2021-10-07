
qemutrace_ss = ss.source_set()

qemutrace_ss.add(when: ['CONFIG_TCG', 'CONFIG_TRACE_PERFETTO'],
                 if_true: dependency('boost', modules: ['filesystem']))

qemutrace_ss.add(when: ['CONFIG_TCG', 'CONFIG_TRACE_PERFETTO'],
                 if_true: files('trace_perfetto.cc', 'trace_stats.cc',
                                'guest_context_tracker.cc',
                                'cheri-perfetto/sdk/perfetto.cc'))

qemutrace_ss = qemutrace_ss.apply(config_all, strict: false)
libqemutrace = static_library('qemutrace',
                              sources: qemutrace_ss.sources(),
                              dependencies: qemutrace_ss.dependencies(),
                              include_directories: ['cheri-perfetto/sdk'],
                              cpp_args: ['-DCONFIG_TCG_LOG_INSTR',
                                         '-DQEMU_PERFETTO'])

qemuutil_libs += libqemutrace
