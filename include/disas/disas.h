#ifndef QEMU_DISAS_H
#define QEMU_DISAS_H

#include "exec/hwaddr.h"

#ifdef NEED_CPU_H
#include "cpu.h"

/* Disassemble this for me please... (debugging). */
void disas(FILE *out, const void *code, unsigned long size);
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size);
void target_disas_buf(FILE *out, CPUState *cpu, void *code, unsigned long size,
                      target_ulong pc, target_ulong max_insns);

void monitor_disas(Monitor *mon, CPUState *cpu,
                   target_ulong pc, int nb_insn, int is_physical);

char *plugin_disas(CPUState *cpu, uint64_t addr, size_t size);

char *disas_one_strbuf(CPUState *cpu, void *code, unsigned long size,
                       target_ulong vma);

/* Look up symbol for debugging purpose.  Returns "" if unknown. */
const char *lookup_symbol(target_ulong orig_addr);
#endif

struct syminfo;
struct elf32_sym;
struct elf64_sym;

#if defined(CONFIG_USER_ONLY)
typedef const char *(*lookup_symbol_t)(struct syminfo *s, target_ulong orig_addr);
#else
typedef const char *(*lookup_symbol_t)(struct syminfo *s, hwaddr orig_addr);
#endif

struct syminfo {
    lookup_symbol_t lookup_symbol;
    unsigned int disas_num_syms;
    union {
      struct elf32_sym *elf32;
      struct elf64_sym *elf64;
    } disas_symtab;
    const char *disas_strtab;
    struct syminfo *next;
};

/* Filled in by elfload.c.  Simplistic, but will do for now. */
extern struct syminfo *syminfos;

#endif /* QEMU_DISAS_H */
