# FIXME extra_args should accept files()
dir = meson.current_source_dir()

gen = [
  decodetree.process('insn16.decode', extra_args: ['--static-decode=decode_insn16', '--insnwidth=16']),
  decodetree.process('insn32.decode', extra_args: '--static-decode=decode_insn32'),
]

# FIXME: would be nice to avoid this duplication but I don't see an easy way to
# do this since the TARGET_CHERI check is evaulated later.
gen32_cheri = [
  decodetree.process('insn16.decode', extra_args: ['--static-decode=decode_insn16', '--insnwidth=16']),
  decodetree.process('insn32.decode', extra_args: [dir / 'insn32-cheri.decode', dir / 'insn32-cheri-32.decode', '--static-decode=decode_insn32']),
]
gen64_cheri = [
  decodetree.process('insn16.decode', extra_args: ['--static-decode=decode_insn16', '--insnwidth=16']),
  decodetree.process('insn32.decode', extra_args: [dir / 'insn32-cheri.decode', dir / 'insn32-cheri-64.decode', '--static-decode=decode_insn32']),
]

cheri_ss = ss.source_set()
cheri_ss.add(when: ['TARGET_CHERI', 'TARGET_RISCV32'], if_true: gen32_cheri)
cheri_ss.add(when: ['TARGET_CHERI', 'TARGET_RISCV64'], if_true: gen64_cheri)

riscv_ss = ss.source_set()
riscv_ss.add(when: 'TARGET_CHERI', if_false: gen)
riscv_ss.add_all(when: 'TARGET_CHERI', if_true: cheri_ss)

riscv_ss.add(files(
  'cpu.c',
  'cpu_helper.c',
  'csr.c',
  'fpu_helper.c',
  'gdbstub.c',
  'op_helper.c',
  'vector_helper.c',
  'bitmanip_helper.c',
  'translate.c',
))
riscv_ss.add(when: 'TARGET_CHERI', if_true: files('op_helper_cheri.c'))
riscv_ss.add(when: ['CONFIG_TCG', 'CONFIG_TCG_LOG_INSTR'], if_true: files('op_helper_log_instr.c'))

riscv_softmmu_ss = ss.source_set()
riscv_softmmu_ss.add(files(
  'arch_dump.c',
  'pmp.c',
  'monitor.c',
  'machine.c'
))

target_arch += {'riscv': riscv_ss}
target_softmmu_arch += {'riscv': riscv_softmmu_ss}
