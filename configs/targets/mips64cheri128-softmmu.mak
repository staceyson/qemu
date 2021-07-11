# XXX: Keyval does not support includes so we use a custom key as a workaround
INCLUDE_WORKAROUND=mips64-softmmu.mak
#
# CHERI-specific settings:
#
# Same as mips64-softmmu.mak but with the extra mips64-cheri-c128.xml
TARGET_XML_FILES=gdb-xml/mips64-cpu.xml gdb-xml/mips64-cp0.xml gdb-xml/mips64-fpu.xml gdb-xml/mips64-sys.xml gdb-xml/mips64-cheri-c128.xml
TARGET_CHERI=y
# Capability loads/stores+tagged memory don't work with MTTCG
TARGET_SUPPORTS_MTTCG=n
