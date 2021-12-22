tcg_ss = ss.source_set()
tcg_ss.add(files(
  'tcg-all.c',
  'cpu-exec-common.c',
  'cpu-exec.c',
  'tcg-runtime-gvec.c',
  'tcg-runtime.c',
  'translate-all.c',
  'translator.c',
))
tcg_ss.add(when: 'CONFIG_USER_ONLY', if_true: files('user-exec.c'))
tcg_ss.add(when: 'CONFIG_SOFTMMU', if_false: files('user-exec-stub.c'))
tcg_ss.add(when: 'CONFIG_PLUGIN', if_true: [files('plugin-gen.c'), libdl])
specific_ss.add_all(when: 'CONFIG_TCG', if_true: tcg_ss)

specific_ss.add(when: ['CONFIG_SOFTMMU', 'CONFIG_TCG'], if_true: files(
  'cputlb.c',
  'tcg-accel-ops.c',
  'tcg-accel-ops-mttcg.c',
  'tcg-accel-ops-icount.c',
  'tcg-accel-ops-rr.c'
))
specific_ss.add(when: ['CONFIG_TCG_LOG_INSTR', 'CONFIG_TCG'], if_true: files('log_instr.c'))
specific_ss.add(when: ['CONFIG_TCG_LOG_INSTR', 'CONFIG_TCG'], if_true: files('log_instr_text.c'))
specific_ss.add(when: ['CONFIG_TCG_LOG_INSTR', 'CONFIG_TCG'], if_true: files('log_instr_cvtrace.c'))
specific_ss.add(when: ['CONFIG_TRACE_PERFETTO', 'CONFIG_TCG_LOG_INSTR', 'CONFIG_TCG'], if_true: files('log_instr_perfetto.c'))
specific_ss.add(when: ['CONFIG_TRACE_PROTOBUF', 'CONFIG_TCG_LOG_INSTR', 'CONFIG_TCG'], if_true: files('log_instr_protobuf.c'))
specific_ss.add(when: ['CONFIG_TRACE_JSON', 'CONFIG_TCG_LOG_INSTR', 'CONFIG_TCG'], if_true: files('log_instr_json.c'))

if config_all.has_key('CONFIG_TCG_LOG_INSTR') and config_all.has_key('CONFIG_TRACE_PROTOBUF')
   specific_ss.add(dependency('libprotobuf-c'))
endif

if config_all.has_key('CONFIG_TCG_LOG_INSTR') and config_all.has_key('CONFIG_TRACE_JSON')
   specific_ss.add(dependency('libcjson'))
endif
