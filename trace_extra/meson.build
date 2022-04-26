fs = import('fs')

qemutrace_ss = ss.source_set()

if config_all.has_key('CONFIG_TCG_LOG_INSTR') and config_all.has_key('CONFIG_TRACE_PERFETTO')
   qemutrace_ss.add(dependency('boost', modules: ['filesystem', 'system']))
   qemutrace_ss.add(files('trace_perfetto.cc', 'trace_stats.cc',
                          'guest_context_tracker.cc', 'trace_counters.cc',
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

if config_all.has_key('CONFIG_TCG_LOG_INSTR') and config_all.has_key('CONFIG_TRACE_PROTOBUF')
   proc_protoc = find_program('protoc')
   proto_path = meson.current_source_dir() / 'cheri-perfetto/protos/perfetto/trace/track_event'
   protobuf_backend_files = files(proto_path / 'qemu_log_entry.proto')
   output_files = []
   foreach f : protobuf_backend_files
      fpath = '@0@'.format(f)
      output_files += fs.replace_suffix(fs.name(fpath), '.pb-c.c')
      output_files += fs.replace_suffix(fs.name(fpath), '.pb-c.h')
   endforeach
   gen_protos = custom_target('protobuf_backend_protos',
                              input: protobuf_backend_files,
                              output: output_files,
                              command: [proc_protoc, '--proto_path=@0@'.format(proto_path), '--c_out=@OUTDIR@', '@INPUT@'],
                              depend_files: protobuf_backend_files)
   specific_ss.add(gen_protos)
endif
