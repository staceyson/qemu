
if config_all.has_key('CONFIG_TCG_LOG_INSTR') and config_all.has_key('CONFIG_TRACE_PROTOBUF')
   proc_protoc = find_program('protoc')
   protobuf_backend_files = files('protobuf_backend_entry.proto')
   gen_protos = custom_target('protobuf_backend_protos',
                              input: protobuf_backend_files,
                              output: ['protobuf_backend_entry.pb-c.c', 'protobuf_backend_entry.pb-c.h'],
                              command: [proc_protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--c_out=@OUTDIR@', '@INPUT@'],
                              depend_files: protobuf_backend_files)
   specific_ss.add(gen_protos)
endif
