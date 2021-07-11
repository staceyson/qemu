# Default configuration for morello-softmmu
# We don't support 32-bit devices, so don't include aarch64-softmmu.mak and
# instead list all the devices manually

CONFIG_ARM_VIRT=y
CONFIG_MORELLO=y
CONFIG_SEMIHOSTING=y
CONFIG_ARM_COMPATIBLE_SEMIHOSTING=y

# CONFIG_ARM_V7M is currently always required - see arm-softmmu.mak
CONFIG_ARM_V7M=y
