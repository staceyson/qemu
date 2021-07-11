# XXX: Keyval does not support includes so we use a custom key as a workaround
INCLUDE_WORKAROUND=riscv64-softmmu.mak
#
# CHERI-specific settings:
#
# Same as riscv64-softmmu.mak but with the extra riscv-64bit-cheri.xml
TARGET_XML_FILES= gdb-xml/riscv-64bit-cpu.xml gdb-xml/riscv-32bit-fpu.xml gdb-xml/riscv-64bit-fpu.xml gdb-xml/riscv-64bit-virtual.xml gdb-xml/riscv-64bit-cheri.xml
TARGET_CHERI=y
# Capability loads/stores+tagged memory don't work with MTTCG
TARGET_SUPPORTS_MTTCG=n
