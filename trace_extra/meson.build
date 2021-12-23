
qemutrace_ss = ss.source_set()

if config_all.has_key('CONFIG_TCG_LOG_INSTR') and config_all.has_key('CONFIG_TRACE_PERFETTO')
   qemutrace_ss.add(dependency('boost', modules: ['filesystem', 'system']))
   qemutrace_ss.add(files('trace_perfetto.cc', 'trace_stats.cc',
                                'guest_context_tracker.cc',
                                'cheri-perfetto/sdk/perfetto.cc'))
endif

qemutrace_ss = qemutrace_ss.apply(config_all, strict: false)
libqemutrace = static_library('qemutrace',
                              sources: qemutrace_ss.sources(),
                              dependencies: qemutrace_ss.dependencies(),
                              include_directories: ['cheri-perfetto/sdk'],
                              cpp_args: ['-DCONFIG_TCG_LOG_INSTR',
                                         '-DQEMU_PERFETTO'])

qemuutil_libs += libqemutrace

subdir('proto')
