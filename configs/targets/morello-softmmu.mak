# Default configuration for morello-softmmu

INCLUDE_WORKAROUND=aarch64-softmmu.mak
#
# CHERI-specific settings:
#
# Same as aarch64-softmmu.mak but with the extra aarch64-cheri.xml
TARGET_XML_FILES= gdb-xml/aarch64-core.xml gdb-xml/aarch64-fpu.xml gdb-xml/arm-core.xml gdb-xml/arm-vfp.xml gdb-xml/arm-vfp3.xml gdb-xml/arm-neon.xml gdb-xml/arm-m-profile.xml gdb-xml/aarch64-capability.xml
TARGET_CHERI=y
TARGET_MORELLO=y
TARGET_SUPPORTS_MTTCG=n
