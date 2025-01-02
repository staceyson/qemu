/*
 *  ELF loading code
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"

#include <err.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/resource.h>

#include "qemu.h"
#include "disas/disas.h"
#include "qemu/path.h"

#ifdef TARGET_CHERI
#include "cheri-helper-utils.h"
#endif

abi_ulong target_auxents;   /* Where the AUX entries are in target */
size_t target_auxents_sz;   /* Size of AUX entries including AT_NULL */

#include "target_arch_reg.h"
#include "target_os_elf.h"
#include "target_os_mman.h"
#include "target_os_stack.h"
#include "target_os_thread.h"
#include "target_os_user.h"

#ifdef TARGET_CHERI
#include "cheri/cherireg.h"
#include "machine/cheri.h"
#endif

#ifndef ELF_NOTE_ROUNDSIZE
#define ELF_NOTE_ROUNDSIZE  4
#endif

#ifndef ELF_MACHINE
#define ELF_MACHINE ELF_ARCH
#endif

#define TARGET_NT_PRSTATUS              1       /* Process status. */
#define TARGET_NT_FPREGSET              2       /* Floating point registers. */
#define TARGET_NT_PRPSINFO              3       /* Process state info. */
#define TARGET_NT_THRMISC               7       /* Thread miscellaneous info. */
#define TARGET_NT_PROCSTAT_PROC         8       /* Procstat proc data. */
#define TARGET_NT_PROCSTAT_FILES        9       /* Procstat files data. */
#define TARGET_NT_PROCSTAT_VMMAP       10       /* Procstat vmmap data. */
#define TARGET_NT_PROCSTAT_GROUPS      11       /* Procstat groups data. */
#define TARGET_NT_PROCSTAT_UMASK       12       /* Procstat umask data. */
#define TARGET_NT_PROCSTAT_RLIMIT      13       /* Procstat rlimit data. */
#define TARGET_NT_PROCSTAT_OSREL       14       /* Procstat osreldate data. */
#define TARGET_NT_PROCSTAT_PSSTRINGS   15       /* Procstat ps_strings data. */
#define TARGET_NT_PROCSTAT_AUXV        16       /* Procstat auxv data. */

/* CHERI note types. */
#define TARGET_NT_CHERI_MORELLO_PURECAP_BENCHMARK_ABI   0x80000000

static int elf_core_dump(int signr, CPUArchState *env);
static int load_elf_sections(const struct elfhdr *hdr, struct elf_phdr *phdr,
    int fd, abi_ulong rbase, abi_ulong *baddrp, abi_ulong *max_addrp);

abi_ulong target_stksiz;
abi_ulong target_stkbas;

static inline void memcpy_fromfs(void * to, const void * from, unsigned long n)
{
    memcpy(to, from, n);
}

static int load_aout_interp(void * exptr, int interp_fd);

#ifdef BSWAP_NEEDED
static void bswap_ehdr(struct elfhdr *ehdr)
{
    bswap16s(&ehdr->e_type);            /* Object file type */
    bswap16s(&ehdr->e_machine);         /* Architecture */
    bswap32s(&ehdr->e_version);         /* Object file version */
    bswaptls(&ehdr->e_entry);           /* Entry point virtual address */
    bswaptls(&ehdr->e_phoff);           /* Program header table file offset */
    bswaptls(&ehdr->e_shoff);           /* Section header table file offset */
    bswap32s(&ehdr->e_flags);           /* Processor-specific flags */
    bswap16s(&ehdr->e_ehsize);          /* ELF header size in bytes */
    bswap16s(&ehdr->e_phentsize);       /* Program header table entry size */
    bswap16s(&ehdr->e_phnum);           /* Program header table entry count */
    bswap16s(&ehdr->e_shentsize);       /* Section header table entry size */
    bswap16s(&ehdr->e_shnum);           /* Section header table entry count */
    bswap16s(&ehdr->e_shstrndx);        /* Section header string table index */
}

static void bswap_phdr(struct elf_phdr *phdr, int phnum)
{
    int i;

    for (i = 0; i < phnum; i++, phdr++) {
        bswap32s(&phdr->p_type);        /* Segment type */
        bswap32s(&phdr->p_flags);       /* Segment flags */
        bswaptls(&phdr->p_offset);      /* Segment file offset */
        bswaptls(&phdr->p_vaddr);       /* Segment virtual address */
        bswaptls(&phdr->p_paddr);       /* Segment physical address */
        bswaptls(&phdr->p_filesz);      /* Segment size in file */
        bswaptls(&phdr->p_memsz);       /* Segment size in memory */
        bswaptls(&phdr->p_align);       /* Segment alignment */
    }
}

static void bswap_shdr(struct elf_shdr *shdr, int shnum)
{
    int i;

    for (i = 0; i < shnum; i++, shdr++) {
        bswap32s(&shdr->sh_name);
        bswap32s(&shdr->sh_type);
        bswaptls(&shdr->sh_flags);
        bswaptls(&shdr->sh_addr);
        bswaptls(&shdr->sh_offset);
        bswaptls(&shdr->sh_size);
        bswap32s(&shdr->sh_link);
        bswap32s(&shdr->sh_info);
        bswaptls(&shdr->sh_addralign);
        bswaptls(&shdr->sh_entsize);
    }
}

static void bswap_sym(struct elf_sym *sym)
{
    bswap32s(&sym->st_name);
    bswaptls(&sym->st_value);
    bswaptls(&sym->st_size);
    bswap16s(&sym->st_shndx);
}

static void bswap_note(struct elf_note *en)
{
    bswap32s(&en->n_namesz);
    bswap32s(&en->n_descsz);
    bswap32s(&en->n_type);
}

#else /* ! BSWAP_NEEDED */

static void bswap_ehdr(struct elfhdr *ehdr) { }
static void bswap_phdr(struct elf_phdr *phdr, int phnum) { }
static void bswap_shdr(struct elf_shdr *shdr, int shnum) { }
static void bswap_sym(struct elf_sym *sym) { }
static void bswap_note(struct elf_note *en) { }

#endif /* ! BSWAP_NEEDED */

/*
 * 'copy_elf_strings()' copies argument/envelope strings from user
 * memory to free pages in kernel mem. These are in a format ready
 * to be put directly into the top of new user memory.
 *
 */
static abi_ulong copy_elf_strings(int argc,char ** argv, void **page,
                                  abi_ulong p)
{
    char *tmp, *tmp1, *pag = NULL;
    int len, offset = 0;

    if (!p) {
        return 0;       /* bullet-proofing */
    }
    while (argc-- > 0) {
        tmp = argv[argc];
        if (!tmp) {
            fprintf(stderr, "VFS: argc is wrong");
            exit(-1);
        }
        tmp1 = tmp;
        while (*tmp++);
        len = tmp - tmp1;
        if (p < len) {  /* this shouldn't happen - 128kB */
                return 0;
        }
        while (len) {
            --p; --tmp; --len;
            if (--offset < 0) {
                offset = p % TARGET_PAGE_SIZE;
                pag = (char *)page[p/TARGET_PAGE_SIZE];
                if (!pag) {
                    pag = g_try_malloc0(TARGET_PAGE_SIZE);
                    page[p/TARGET_PAGE_SIZE] = pag;
                    if (!pag)
                        return 0;
                }
            }
            if (len == 0 || offset == 0) {
                *(pag + offset) = *tmp;
            }
            else {
              int bytes_to_copy = (len > offset) ? offset : len;
              tmp -= bytes_to_copy;
              p -= bytes_to_copy;
              offset -= bytes_to_copy;
              len -= bytes_to_copy;
              memcpy_fromfs(pag + offset, tmp, bytes_to_copy + 1);
            }
        }
    }
    return p;
}

static void setup_arg_pages(struct bsd_binprm *bprm, struct image_info *info,
                            abi_ulong *stackp, abi_ulong *stringp)
{
    abi_ulong size, size_guard;
    abi_long addr;
    int flags;

    /* Create enough stack to hold everything.  If we don't use
     * it for args, we'll use it for something else...
     */
    size = target_dflssiz;
    size_guard = size + qemu_host_page_size;
    flags = MAP_PRIVATE | MAP_ANON;
#ifdef TARGET_CHERI
    size_guard = CHERI_REPRESENTABLE_LENGTH(size_guard);
    flags |= MAP_ALIGNED_CHERI;
#endif
    addr = target_mmap(0, size_guard, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (addr == -1) {
        perror("stk mmap");
        exit(-1);
    }
    /* we reserve one extra page at the top of the stack as guard */
    target_mprotect(addr + size, qemu_host_page_size, PROT_NONE);

    target_stksiz = size;
    target_stkbas = addr;
#ifdef TARGET_CHERI
    assert(target_stkbas == CHERI_REPRESENTABLE_BASE(target_stkbas,
        target_stksiz));
#endif

    if (setup_initial_stack(bprm, stackp, stringp) != 0) {
        perror("stk setup");
        exit(-1);
    }
}

static void set_brk(abi_ulong start, abi_ulong end)
{
    /* page-align the start and end addresses... */
    start = HOST_PAGE_ALIGN(start);
    end = HOST_PAGE_ALIGN(end);
    if (end <= start)
        return;
    if (target_mmap(start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0) == -1) {
        perror("cannot mmap brk");
        exit(-1);
    }
}


/* We need to explicitly zero any fractional pages after the data
   section (i.e. bss).  This would contain the junk from the file that
   should not be in memory. */
static void padzero(abi_ulong elf_bss, abi_ulong last_bss)
{
    abi_ulong nbyte;

    if (elf_bss >= last_bss)
        return;

    /*
     * XXX: this is really a hack : if the real host page size is
     * smaller than the target page size, some pages after the end
     * of the file may not be mapped. A better fix would be to
     * patch target_mmap(), but it is more complicated as the file
     * size must be known.
     */
    if (qemu_real_host_page_size < qemu_host_page_size) {
        abi_ulong end_addr, end_addr1;
        end_addr1 = REAL_HOST_PAGE_ALIGN(elf_bss);
        end_addr = HOST_PAGE_ALIGN(elf_bss);
        if (end_addr1 < end_addr) {
            mmap((void *)g2h_untagged(end_addr1), end_addr - end_addr1,
                    PROT_READ|PROT_WRITE|PROT_EXEC,
                    MAP_FIXED|MAP_PRIVATE|MAP_ANON, -1, 0);
        }
    }

    nbyte = elf_bss & (qemu_host_page_size-1);
    if (nbyte) {
        nbyte = qemu_host_page_size - nbyte;
        do {
            /* FIXME - what to do if put_user() fails? */
            put_user_u8(0, elf_bss);
            elf_bss++;
        } while (--nbyte);
    }
}

/*
 * load_elf_interp() is based on __elfN(load_interp) and __elfN(load_file) from
 * sys/kern/imgact_elf.c in FreeBSD.
 */
static abi_ulong load_elf_interp(struct elfhdr * interp_elf_ex,
        int interpreter_fd, abi_ulong *interp_load_addr, abi_ulong *interp_end_addr)
{
    struct elf_phdr *elf_phdata  =  NULL;
    abi_ulong rbase;
    int retval;
    abi_ulong error, max_addr;

    max_addr = 0;
    error = 0;

    bswap_ehdr(interp_elf_ex);
    /* First of all, some simple consistency checks */
    if ((interp_elf_ex->e_type != ET_EXEC && interp_elf_ex->e_type != ET_DYN) ||
          !elf_check_arch(interp_elf_ex)) {
        return ~((abi_ulong)0UL);
    }


    /* Now read in all of the header information */
    if (sizeof(struct elf_phdr) * interp_elf_ex->e_phnum > TARGET_PAGE_SIZE)
        return ~(abi_ulong)0UL;

    elf_phdata =  (struct elf_phdr *) malloc(sizeof(struct elf_phdr) *
            interp_elf_ex->e_phnum);

    if (!elf_phdata)
        return ~((abi_ulong)0UL);

    /*
     * If the size of this structure has changed, then punt, since
     * we will be doing the wrong thing.
     */
    if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr)) {
        free(elf_phdata);
        return ~((abi_ulong)0UL);
    }

    retval = lseek(interpreter_fd, interp_elf_ex->e_phoff, SEEK_SET);
    if(retval >= 0) {
        retval = read(interpreter_fd, (char *) elf_phdata,
                sizeof(struct elf_phdr) * interp_elf_ex->e_phnum);
    }
    if (retval < 0) {
        perror("load_elf_interp");
        exit(-1);
        free (elf_phdata);
        return retval;
    }
    bswap_phdr(elf_phdata, interp_elf_ex->e_phnum);

    rbase = 0;
    if (interp_elf_ex->e_type == ET_DYN) {
        /*
         * In order to avoid hardcoding the interpreter load
         * address in qemu, we allocate a big enough memory zone.
         */
        rbase = target_mmap(0, INTERP_MAP_SIZE, PROT_NONE,
                MAP_PRIVATE | MAP_ANON, -1, 0);
        if (rbase == -1) {
            perror("mmap");
            exit(-1);
        }
    }

    error = load_elf_sections(interp_elf_ex, elf_phdata, interpreter_fd, rbase,
        interp_load_addr, &max_addr);
    if (error != 0) {
        perror("load_elf_sections");
        exit(-1);
    }
    *interp_end_addr = *interp_load_addr + max_addr;

    /* Now use mmap to map the library into memory. */
    close(interpreter_fd);
    free(elf_phdata);

    return ((abi_ulong) interp_elf_ex->e_entry) + rbase;
}

static int symfind(const void *s0, const void *s1)
{
    target_ulong addr = *(target_ulong *)s0;
    struct elf_sym *sym = (struct elf_sym *)s1;
    int result = 0;
    if (addr < sym->st_value) {
        result = -1;
    } else if (addr >= sym->st_value + sym->st_size) {
        result = 1;
    }
    return result;
}

static const char *lookup_symbolxx(struct syminfo *s, target_ulong orig_addr)
{
#if ELF_CLASS == ELFCLASS32
    struct elf_sym *syms = s->disas_symtab.elf32;
#else
    struct elf_sym *syms = s->disas_symtab.elf64;
#endif

    // binary search
    struct elf_sym *sym;

    sym = bsearch(&orig_addr, syms, s->disas_num_syms, sizeof(*syms), symfind);
    if (sym != NULL) {
        return s->disas_strtab + sym->st_name;
    }

    return "";
}

/* FIXME: This should use elf_ops.h  */
static int symcmp(const void *s0, const void *s1)
{
    struct elf_sym *sym0 = (struct elf_sym *)s0;
    struct elf_sym *sym1 = (struct elf_sym *)s1;
    return (sym0->st_value < sym1->st_value) ? -1 :
        ((sym0->st_value > sym1->st_value) ? 1 : 0);
}

/* Best attempt to load symbols from this ELF object. */
static void load_symbols(struct elfhdr *hdr, int fd)
{
    unsigned int i, nsyms;
    struct elf_shdr sechdr, symtab, strtab;
    char *strings;
    struct syminfo *s;
    struct elf_sym *syms, *new_syms;

    lseek(fd, hdr->e_shoff, SEEK_SET);
    for (i = 0; i < hdr->e_shnum; i++) {
        if (read(fd, &sechdr, sizeof(sechdr)) != sizeof(sechdr))
            return;
        bswap_shdr(&sechdr, 1);
        if (sechdr.sh_type == SHT_SYMTAB) {
            symtab = sechdr;
            lseek(fd, hdr->e_shoff
                  + sizeof(sechdr) * sechdr.sh_link, SEEK_SET);
            if (read(fd, &strtab, sizeof(strtab))
                != sizeof(strtab))
                return;
            bswap_shdr(&strtab, 1);
            goto found;
        }
    }
    return; /* Shouldn't happen... */

found:
    /* Now know where the strtab and symtab are.  Snarf them. */
    s = malloc(sizeof(*s));
    syms = malloc(symtab.sh_size);
    if (!syms) {
        free(s);
        return;
    }
    s->disas_strtab = strings = malloc(strtab.sh_size);
    if (!s->disas_strtab) {
        free(s);
        free(syms);
        return;
    }

    lseek(fd, symtab.sh_offset, SEEK_SET);
    if (read(fd, syms, symtab.sh_size) != symtab.sh_size) {
        free(s);
        free(syms);
        free(strings);
        return;
    }

    nsyms = symtab.sh_size / sizeof(struct elf_sym);

    i = 0;
    while (i < nsyms) {
        bswap_sym(syms + i);
        // Throw away entries which we do not need.
        if (syms[i].st_shndx == SHN_UNDEF ||
                syms[i].st_shndx >= SHN_LORESERVE ||
                ELF_ST_TYPE(syms[i].st_info) != STT_FUNC) {
            nsyms--;
            if (i < nsyms) {
                syms[i] = syms[nsyms];
            }
            continue;
        }
#if defined(TARGET_ARM) || defined (TARGET_MIPS)
        /* The bottom address bit marks a Thumb or MIPS16 symbol.  */
        syms[i].st_value &= ~(target_ulong)1;
#endif
        i++;
    }

     /* Attempt to free the storage associated with the local symbols
        that we threw away.  Whether or not this has any effect on the
        memory allocation depends on the malloc implementation and how
        many symbols we managed to discard. */
    new_syms = realloc(syms, nsyms * sizeof(*syms));
    if (new_syms == NULL) {
        free(s);
        free(syms);
        free(strings);
        return;
    }
    syms = new_syms;

    qsort(syms, nsyms, sizeof(*syms), symcmp);

    lseek(fd, strtab.sh_offset, SEEK_SET);
    if (read(fd, strings, strtab.sh_size) != strtab.sh_size) {
        free(s);
        free(syms);
        free(strings);
        return;
    }
    s->disas_num_syms = nsyms;
#if ELF_CLASS == ELFCLASS32
    s->disas_symtab.elf32 = syms;
    s->lookup_symbol = (lookup_symbol_t)lookup_symbolxx;
#else
    s->disas_symtab.elf64 = syms;
    s->lookup_symbol = (lookup_symbol_t)lookup_symbolxx;
#endif
    s->next = syminfos;
    syminfos = s;
}

/* Check the elf header and see if this a target elf binary. */
int is_target_elf_binary(int fd)
{
    uint8_t buf[128];
    struct elfhdr elf_ex;

    if (lseek(fd, 0L, SEEK_SET) < 0) {
        return 0;
    }
    if (read(fd, buf, sizeof(buf)) < 0) {
        return 0;
    }

    elf_ex = *((struct elfhdr *)buf);
    bswap_ehdr(&elf_ex);

    if ((elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) ||
        (!elf_check_arch(&elf_ex))) {
        return 0;
    } else {
        return 1;
    }
}

#if defined(TARGET_CHERI)
static int
parse_elf_notes(const char *buf, size_t size, const struct elfhdr *hdr,
    struct image_info *info)
{
    struct elf_note note;
    const char *src, *src_benchmarkabi;
    uint32_t benchmarkabi;

    src = buf;
    src_benchmarkabi = NULL;

    while (src + sizeof(note) <= buf + size) {
        memcpy(&note, src, sizeof(note));
        src += sizeof(note);
        if (src + roundup2(note.n_namesz + note.n_descsz, 4) > buf + size) {
            fprintf(stderr, "Truncated buffer with ELF notes\n");
            errno = EINVAL;
            return (-1);
        }
        if (strncmp((const char *) src, "CHERI", note.n_namesz) == 0) {
            if (src_benchmarkabi == NULL && note.n_type ==
                TARGET_NT_CHERI_MORELLO_PURECAP_BENCHMARK_ABI) {
                src_benchmarkabi = src + roundup2(note.n_namesz, 4);
            }
        }
        src += roundup2(note.n_namesz + note.n_descsz, 4);
    }

    if (src_benchmarkabi != NULL) {
        if (hdr->e_ident[EI_DATA] == ELFDATA2MSB)
            benchmarkabi = be32dec(src_benchmarkabi);
        else
            benchmarkabi = le32dec(src_benchmarkabi);
        if (benchmarkabi != 0 && benchmarkabi != 1) {
            fprintf(stderr, "Invalid NT_CHERI_MORELLO_PURECAP_BENCHMARK_ABI description data\n");
            errno = EINVAL;
            return (-1);
        }
        info->benchmarkabi = benchmarkabi;
    }

    return (0);
}

static int
parse_elf_segments(const struct elfhdr *hdr, const struct elf_phdr *phdrs,
    int fd, struct image_info *info)
{
    const struct elf_phdr *phdr;
    char *buf;
    int error;
    unsigned int ii;

    for (ii = 0, phdr = phdrs; ii < hdr->e_phnum; ii++, phdr++) {
        error = 0;

        if (phdr->p_type != PT_NOTE)
            continue;

        buf = malloc(phdr->p_filesz);
        if (buf == NULL) {
            return (-1);
        }

        if (lseek(fd, phdr->p_offset, SEEK_SET) < 0) {
            error = errno;
            goto next;
        }
        if (read(fd, buf, phdr->p_filesz) != phdr->p_filesz) {
            error = errno;
            goto next;
        }

        if (parse_elf_notes(buf, phdr->p_filesz, hdr, info) != 0) {
            error = errno;
            goto next;
        }

next:
        free(buf);
        if (error != 0) {
            errno = error;
            return (-1);
        }
    }

    return (0);
}
#endif


/*
 * load_elf_sections() is based on __elfN(load_sections) from
 * sys/kern/imgact_elf.c in FreeBSD.
 */
static int
load_elf_sections(const struct elfhdr *hdr, struct elf_phdr *phdr, int fd,
    abi_ulong rbase, abi_ulong *baddrp, abi_ulong *max_addrp)
{
    struct elf_phdr *elf_ppnt;
    abi_ulong baddr, max_addr;
    int i;
    bool first;

    max_addr = 0;
    first = true;

    /* Now we do a little grungy work by mmaping the ELF image into
     * the correct location in memory.  At this point, we assume that
     * the image should be loaded at fixed address, not at a variable
     * address.
     */
    for (i = 0, elf_ppnt = phdr; i < hdr->e_phnum; i++, elf_ppnt++) {
        int elf_prot = 0;
        abi_long error;

        /* XXX Skip memsz == 0. */
        if (elf_ppnt->p_type != PT_LOAD)
            continue;

        if (elf_ppnt->p_flags & PF_R) elf_prot |= PROT_READ;
        if (elf_ppnt->p_flags & PF_W) elf_prot |= PROT_WRITE;
        if (elf_ppnt->p_flags & PF_X) elf_prot |= PROT_EXEC;

        error = target_mmap(TARGET_ELF_PAGESTART(rbase + elf_ppnt->p_vaddr),
                            (elf_ppnt->p_filesz +
                             TARGET_ELF_PAGEOFFSET(elf_ppnt->p_vaddr)),
                            elf_prot,
                            (MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE),
                            fd,
                            (elf_ppnt->p_offset -
                             TARGET_ELF_PAGEOFFSET(elf_ppnt->p_vaddr)));
        if (error == -1) {
            perror("mmap");
            exit(-1);
        } else if (elf_ppnt->p_memsz != elf_ppnt->p_filesz) {
            abi_ulong start_bss, end_bss;

            start_bss = rbase + elf_ppnt->p_vaddr + elf_ppnt->p_filesz;
            end_bss = rbase + elf_ppnt->p_vaddr + elf_ppnt->p_memsz;

            /*
             * Calling set_brk effectively mmaps the pages that we need for the
             * bss and break sections.
             */
            set_brk(start_bss, end_bss);
            padzero(start_bss, end_bss);
        }

        if (first) {
            baddr = TARGET_ELF_PAGESTART(rbase + elf_ppnt->p_vaddr);
            first = false;
        }
        max_addr = MAX(max_addr, elf_ppnt->p_vaddr + elf_ppnt->p_memsz);
    }

    if (baddrp != NULL)
        *baddrp = baddr;
    if (max_addrp != NULL)
        *max_addrp = max_addr;

    return (0);
}

int load_elf_binary(struct bsd_binprm *bprm, struct target_pt_regs *regs,
                    struct image_info *info)
{
    struct elfhdr elf_ex;
    struct elfhdr interp_elf_ex;
    struct exec interp_ex;
    int interpreter_fd = -1; /* avoid warning */
    abi_ulong load_addr;
    unsigned int interpreter_type = INTERPRETER_NONE;
    unsigned char ibcs2_interpreter;
    int i;
    struct elf_phdr * elf_ppnt;
    struct elf_phdr *elf_phdata;
    int error, retval;
    char * elf_interpreter;
    const char *new_interp_path;
    abi_ulong baddr, elf_entry, end_addr, et_dyn_addr, interp_load_addr;
    abi_ulong reloc_func_desc, seg_size, seg_addr;
    char passed_fileno[6];

    ibcs2_interpreter = 0;
    load_addr = 0;
    elf_ex = *((struct elfhdr *) bprm->buf);          /* exec-header */
    bswap_ehdr(&elf_ex);

    /* First of all, some simple consistency checks */
    if ((elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) ||
                                (! elf_check_arch(&elf_ex))) {
            return -ENOEXEC;
    }

#ifndef __FreeBSD__
    bprm->p = copy_elf_strings(1, &bprm->filename, bprm->page, bprm->p);
    bprm->p = copy_elf_strings(bprm->envc,bprm->envp,bprm->page,bprm->p);
    bprm->p = copy_elf_strings(bprm->argc,bprm->argv,bprm->page,bprm->p);
    if (!bprm->p) {
        retval = -E2BIG;
    }
#endif /* ! __FreeBSD__ */

    /* Now read in all of the header information */
    elf_phdata = (struct elf_phdr *)malloc(elf_ex.e_phentsize*elf_ex.e_phnum);
    if (elf_phdata == NULL) {
        return -ENOMEM;
    }

    retval = lseek(bprm->fd, elf_ex.e_phoff, SEEK_SET);
    if(retval > 0) {
        retval = read(bprm->fd, (char *) elf_phdata,
                                elf_ex.e_phentsize * elf_ex.e_phnum);
    }

    if (retval < 0) {
        perror("load_elf_binary");
        exit(-1);
        free (elf_phdata);
        return -errno;
    }

    bswap_phdr(elf_phdata, elf_ex.e_phnum);
    elf_ppnt = elf_phdata;

    elf_interpreter = NULL;
    interp_load_addr = 0;
    info->start_addr = ~((abi_ulong)0UL);
    info->end_addr = 0;
    info->start_code = ~((abi_ulong)0UL);
    info->end_code = 0;
    info->start_data = ~((abi_ulong)0UL);
    info->end_data = 0;
    interp_ex.a_info = 0;
    reloc_func_desc = 0;

#ifdef TARGET_CHERI
    info->benchmarkabi = false;
    error = parse_elf_segments(&elf_ex, elf_phdata, bprm->fd, info);
    if (error != 0) {
        perror("parse_elf_segments");
        exit(-1);
    }
#endif

    for (i = 0; i < elf_ex.e_phnum; i++) {
        if (elf_ppnt->p_type == PT_INTERP) {
            if ( elf_interpreter != NULL )
            {
                free (elf_phdata);
                free(elf_interpreter);
                close(bprm->fd);
                return -EINVAL;
            }

            /* This is the program interpreter used for
             * shared libraries - for now assume that this
             * is an a.out format binary
             */

            elf_interpreter = (char *)malloc(elf_ppnt->p_filesz);

            if (elf_interpreter == NULL) {
                free (elf_phdata);
                close(bprm->fd);
                return -ENOMEM;
            }

            retval = lseek(bprm->fd, elf_ppnt->p_offset, SEEK_SET);
            if(retval >= 0) {
                retval = read(bprm->fd, elf_interpreter, elf_ppnt->p_filesz);
            }
            if(retval < 0) {
                perror("load_elf_binary2");
                exit(-1);
            }
        }
        elf_ppnt++;
    }

    /* Some simple consistency checks for the interpreter */
    if (elf_interpreter){
        if (strcmp(elf_interpreter, "/libexec/ld-elf.so.1") == 0) {
#ifdef TARGET_CHERI
            if (info->benchmarkabi) {
                new_interp_path = "/libexec/ld-elf64cb.so.1";
            } else
#endif
            {
                new_interp_path = interp_path;
            }
        } else {
            new_interp_path = NULL;
        }
        if (new_interp_path != NULL) {
            free(elf_interpreter);
            elf_interpreter = strdup(new_interp_path);
            if (elf_interpreter == NULL) {
                free(elf_phdata);
                close(bprm->fd);
                return (-ENOMEM);
            }
        }

        /* If the program interpreter is one of these two,
           then assume an iBCS2 image. Otherwise assume
           a native linux image. */

        /* JRP - Need to add X86 lib dir stuff here... */

        if (strcmp(elf_interpreter, "/usr/lib/libc.so.1") == 0 ||
                strcmp(elf_interpreter, "/usr/lib/ld-elf.so.1") == 0) {
            ibcs2_interpreter = 1;
        }

#if 0
        printf("Using ELF interpreter %s\n", path(elf_interpreter));
#endif
        if (retval >= 0) {
            retval = open(path(elf_interpreter), O_RDONLY);
            if(retval >= 0) {
                interpreter_fd = retval;
            }
            else {
                perror(elf_interpreter);
                exit(-1);
                /* retval = -errno; */
            }
        }

        if (retval >= 0) {
            retval = lseek(interpreter_fd, 0, SEEK_SET);
            if(retval >= 0) {
                retval = read(interpreter_fd,bprm->buf,128);
            }
        }
        if (retval >= 0) {
            interp_ex = *((struct exec *) bprm->buf); /* aout exec-header */
            interp_elf_ex = *((struct elfhdr *) bprm->buf); /* elf exec-header */
        }
        if (retval < 0) {
            perror("load_elf_binary3");
            exit(-1);
            free (elf_phdata);
            free(elf_interpreter);
            close(bprm->fd);
            return retval;
        }

        interpreter_type = INTERPRETER_ELF | INTERPRETER_AOUT;

        /* Now figure out which format our binary is */
        if ((N_MAGIC(interp_ex) != OMAGIC) && (N_MAGIC(interp_ex) != ZMAGIC) &&
                (N_MAGIC(interp_ex) != QMAGIC)) {
          interpreter_type = INTERPRETER_ELF;
        }

        if (interp_elf_ex.e_ident[0] != 0x7f ||
                strncmp((char *)&interp_elf_ex.e_ident[1], "ELF",3) != 0) {
            interpreter_type &= ~INTERPRETER_ELF;
        }

        if (!interpreter_type) {
            free(elf_interpreter);
            free(elf_phdata);
            close(bprm->fd);
            return -ELIBBAD;
        }
    }

    /* OK, we are done with that, now set up the arg stuff,
       and then start this sucker up */

    {
        char * passed_p;

        if (interpreter_type == INTERPRETER_AOUT) {
            snprintf(passed_fileno, sizeof(passed_fileno), "%d", bprm->fd);
            passed_p = passed_fileno;

            if (elf_interpreter) {
                bprm->p = copy_elf_strings(1,&passed_p,bprm->page,bprm->p);
                bprm->argc++;
            }
        }
        if (!bprm->p) {
            free(elf_interpreter);
            free (elf_phdata);
            close(bprm->fd);
            return -E2BIG;
        }
    }

    /* OK, This is the point of no return */
    info->end_data = 0;
    info->end_code = 0;
    info->start_mmap = (abi_ulong)ELF_START_MMAP;
    info->mmap = 0;
    elf_entry = (abi_ulong) elf_ex.e_entry;

    /* XXX Join this with PT_INTERP search? */
    baddr = 0;
    for (i = 0, elf_ppnt = elf_phdata; i < elf_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type != PT_LOAD)
            continue;
        baddr = elf_ppnt->p_vaddr;
        break;
    }

    et_dyn_addr = 0;
    if (elf_ex.e_type == ET_DYN && baddr == 0)
        et_dyn_addr = ELF_ET_DYN_LOAD_ADDR;

    /* Do this so that we can load the interpreter, if need be.  We will
       change some of these later */
    info->rss = 0;
    setup_arg_pages(bprm, info, &bprm->p, &bprm->stringp);
    info->start_stack = bprm->p;

    error = load_elf_sections(&elf_ex, elf_phdata, bprm->fd, et_dyn_addr,
        &load_addr, NULL);
    if (error != 0) {
        perror("load_elf_sections");
        exit(-1);
    }

    /*
     * This loop is based on __elfN(enforce_limits) from sys/kern/imgact_elf.c
     * in FreeBSD
     */
    for (i = 0, elf_ppnt = elf_phdata; i < elf_ex.e_phnum; i++, elf_ppnt++) {
        if (elf_ppnt->p_type != PT_LOAD || elf_ppnt->p_memsz == 0)
            continue;

        seg_addr = trunc_page(elf_ppnt->p_vaddr + et_dyn_addr);
        seg_size = round_page(elf_ppnt->p_memsz + elf_ppnt->p_vaddr +
            et_dyn_addr - seg_addr);

        info->start_addr = MIN(info->start_addr, seg_addr);
        end_addr = seg_addr + seg_size;
        info->end_addr = MAX(info->end_addr, end_addr);

        if ((elf_ppnt->p_flags & PF_X) != 0 &&
            info->end_code - info->start_code < seg_size) {
            info->start_code = seg_addr;
            info->end_code = end_addr;
        } else {
            info->start_data = seg_addr;
            info->end_data = end_addr;
        }
    }
    info->start_brk += et_dyn_addr;
    info->brk = info->start_brk;
    /* XXXKW: Detect code offset for GDB. */
    info->code_offset = info->start_code - 0xff00;
    info->data_offset = info->start_data;

    if (elf_interpreter) {
        if (interpreter_type & 1) {
            elf_entry = load_aout_interp(&interp_ex, interpreter_fd);
        }
        else if (interpreter_type & 2) {
            elf_entry = load_elf_interp(&interp_elf_ex, interpreter_fd,
                                            &interp_load_addr, &info->interp_end);
        }
        reloc_func_desc = interp_load_addr;

        close(interpreter_fd);
        free(elf_interpreter);

        if (elf_entry == ~((abi_ulong)0UL)) {
            printf("Unable to load interpreter\n");
            free(elf_phdata);
            exit(-1);
            return 0;
        }
    } else {
        interp_load_addr = et_dyn_addr;
        elf_entry += interp_load_addr;
    }
    info->reloc_base = interp_load_addr;

    free(elf_phdata);

    if (qemu_log_enabled())
        load_symbols(&elf_ex, bprm->fd);

    if (interpreter_type != INTERPRETER_AOUT) close(bprm->fd);
    info->personality = (ibcs2_interpreter ? PER_SVR4 : PER_LINUX);

    bprm->p = target_create_elf_tables(bprm->p,
                    bprm->argc,
                    bprm->envc,
                    bprm->stringp,
                    &elf_ex,
                    load_addr, et_dyn_addr,
                    interp_load_addr,
                    (interpreter_type == INTERPRETER_AOUT ? 0 : 1),
                    info);
    info->load_addr = reloc_func_desc;
    info->start_stack = bprm->p;
    info->load_bias = 0; //load_bias;

#if 0
    printf("(start_brk) 0x" TARGET_FMT_lx "\n" , info->start_brk);
    printf("(end_code) 0x" TARGET_FMT_lx "\n" , info->end_code);
    printf("(start_code) 0x" TARGET_FMT_lx "\n" , info->start_code);
    printf("(start_data) 0x" TARGET_FMT_lx "\n" , info->start_data);
    printf("(end_data) 0x" TARGET_FMT_lx "\n" , info->end_data);
    printf("(start_stack) 0x" TARGET_FMT_lx "\n" , info->start_stack);
    printf("(brk) 0x" TARGET_FMT_lx "\n" , info->brk);
#endif

    if ( info->personality == PER_SVR4 )
    {
            /* Why this, you ask???  Well SVr4 maps page 0 as read-only,
               and some applications "depend" upon this behavior.
               Since we do not have the power to recompile these, we
               emulate the SVr4 behavior.  Sigh.  */
            if (target_mmap(0, qemu_host_page_size, PROT_READ | PROT_EXEC,
                            MAP_FIXED | MAP_PRIVATE, -1, 0) == -1) {
                return -1;
            }
    }

    info->entry = elf_entry;

#ifdef USE_ELF_CORE_DUMP
    bprm->core_dump = &elf_core_dump;
#else
    bprm->core_dump = NULL;
#endif

    return 0;
}

#ifdef USE_ELF_CORE_DUMP
/*
 * Write out ELF coredump.
 *
 * See documentation of ELF object file format in:
 * http://www.caldera.com/developers/devspecs/gabi41.pdf
 * and sys/kern_imgact_elf.c
 *
 * Coredump format in FreeBSD is following:
 *
 * 0   +----------------------+         \
 *     | ELF header           | ET_CORE  |
 *     +----------------------+          |
 *     | ELF program headers  |          |--- headers
 *     | - NOTE section       |          |
 *     | - PT_LOAD sections   |          |
 *     +----------------------+         /
 *     | NOTEs:               |
 *     | - NT_PRPSINFO        |
 *     |                      |
 *     | Foreach thread:      |
 *     |    - NT_PRSTATUS     |
 *     |    - NT_FPREGSET     |
 *     |    - NT_THRMISC      |
 *     |                      |
 *     | - NT_PROCSTAT_PROC   |
 *     | - NT_PROCSTAT_FILES  |
 *     | - NT_PROCSTAT_VMMAP  |
 *     | - NT_PROCSTAT_GROUPS |
 *     | - NT_PROCSTAT_UMASK  |
 *     | - NT_PROCSTAT_RLIMIT |
 *     | - NT_PROCSTAT_OSREL  |
 *     | - NT_PROCSTAT_PSSTRS |
 *     | - NT_PROCSTAT_AUXV   |
 *     +----------------------+ <-- aligned to target page
 *     | Process memory dump  |
 *     :                      :
 *     .                      .
 *     :                      :
 *     |                      |
 *     +----------------------+
 *
 * Format follows System V format as close as possible.  Current
 * version limitations are as follows:
 *     - no floating point registers are dumped
 *
 * Function returns 0 in case of success, negative errno otherwise.
 *
 * TODO: make this work also during runtime: it should be
 * possible to force coredump from running process and then
 * continue processing.  For example qemu could set up SIGUSR2
 * handler (provided that target process haven't registered
 * handler for that) that does the dump when signal is received.
 */

#define TARGET_PRFNAMESZ           16   /* Maximum command length saved */
#define TARGET_PRARGSZ             80   /* Maximum argument bytes saved */

#define TARGET_PRPSINFO_VERSION    1    /* Current vers of target_prpsinfo_t */

/* From sys/procfs.h */
typedef struct target_prpsinfo {
    int32_t     pr_version;     /* Version number of struct (1) */
    abi_ulong   pr_psinfosz;    /* sizeof(prpsinfo_t) (1) */
    char        pr_fname[TARGET_PRFNAMESZ+1]; /* Command name + NULL (1) */
    char        pr_psargs[TARGET_PRARGSZ+1];  /* Arguments + NULL (1) */
} target_prpsinfo_t;

#ifdef BSWAP_NEEDED
static void bswap_prpsinfo(target_prpsinfo_t *prpsinfo)
{
    prpsinfo->pr_version = tswap32(prpsinfo->pr_version);

    prpsinfo->pr_psinfosz = tswapal(prpsinfo->pr_psinfosz);
}
#else
static inline void bswap_prpsinfo(target_prpsinfo_t *p) { }
#endif /* ! BSWAP_NEEDED */

static abi_long fill_prpsinfo(TaskState *ts, target_prpsinfo_t **prpsinfo)
{
    struct bsd_binprm *bprm = ts->bprm;
    char *p, **argv = bprm->argv;
    int i, sz, argc = bprm->argc;
    size_t len;
    target_prpsinfo_t *pr;

    pr = g_malloc0(sizeof(*pr));
    if (pr == NULL)
        return (-ENOMEM);
    *prpsinfo = pr;
    pr->pr_version = 1;
    pr->pr_psinfosz = sizeof(target_prpsinfo_t);

    strncpy(pr->pr_fname, bprm->filename, TARGET_PRFNAMESZ);
    p = pr->pr_psargs;
    sz = TARGET_PRARGSZ;
    for(i = 0; i < argc; i++) {
        strncpy(p, argv[i], sz);
        len = strlen(argv[i]);
        p += len;
        sz -= len;
        if (sz <= 0)
            break;
        strncat(p, " ", sz);
        p += 1;
        sz -= 1;
        if (sz <= 0)
            break;
    }

    bswap_prpsinfo(pr);
    return 0;
}


/*
 * Pre-Thread structure definitions.
 */
#define TARGET_PRSTATUS_VERSION    1    /* Current vers of target_prstatus_t */

/* From sys/procfs.h */
typedef struct target_prstatus {
    int32_t     pr_version;     /* Version number of struct (1) */
    abi_ulong   pr_statussz;    /* sizeof(prstatus_t) (1) */
    abi_ulong   pr_gregsetsz;   /* sizeof(gregset_t) (1) */
    abi_ulong   pr_fpregsetsz;  /* sizeof(fpregset_t) (1) */
    int32_t     pr_osreldate;   /* Kernel version (1) */
    int32_t     pr_cursig;      /* Current signal (1) */
    int32_t     pr_pid;         /* Process ID (1) */
    target_reg_t pr_reg;        /* General purpose registers (1) */
} target_prstatus_t;

#ifdef BSWAP_NEEDED
static void bswap_prstatus(target_prstatus_t *prstatus)
{
    prstatus->pr_version = tswap32(prstatus->pr_version);

    prstatus->pr_statussz = tswapal(prstatus->pr_statussz);
    prstatus->pr_gregsetsz = tswapal(prstatus->pr_gregsetsz);
    prstatus->pr_fpregsetsz = tswapal(prstatus->pr_fpregsetsz);

    prstatus->pr_osreldate = tswap32(prstatus->pr_osreldate);
    prstatus->pr_cursig = tswap32(prstatus->pr_cursig);
    prstatus->pr_pid = tswap32(prstatus->pr_pid);

    /* general registers should be already bswap'ed. */
}
#else
static inline void bswap_prstatus(target_prstatus_t *p) { }
#endif /* ! BSWAP_NEEDED */

static abi_long fill_osreldate(int *osreldatep)
{
    abi_long ret;
    size_t len;
    int mib[2];

    *osreldatep = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_OSRELDATE;
    len = sizeof(*osreldatep);
    ret = get_errno(sysctl(mib, 2, osreldatep, &len, NULL, 0));
    if (is_error(ret) && errno != ESRCH) {
        warn("sysctl: kern.proc.osreldate");
        return ret;
    } else {
        *osreldatep = tswap32(*osreldatep);
        return 0;
    }
}

/*
 * Populate the target_prstatus struct.
 *
 * sys/kern/imagact_elf.c _elfN(note_prstatus)
 */
static abi_long fill_prstatus(CPUArchState *env,
        struct target_prstatus *prstatus, int signr)
{
    abi_long ret;

    /*
    prstatus = g_malloc0(sizeof (struct target_prstatus));
    if (prstatus == NULL)
        return -TARGET_ENOMEM;
        */
    prstatus->pr_version = TARGET_PRSTATUS_VERSION;
    prstatus->pr_statussz = sizeof(target_prstatus_t);
    prstatus->pr_gregsetsz = sizeof(target_reg_t);
    prstatus->pr_fpregsetsz = sizeof(target_fpreg_t);

    ret = fill_osreldate(&prstatus->pr_osreldate);
    prstatus->pr_cursig = signr;
    prstatus->pr_pid = getpid();

    target_copy_regs(&prstatus->pr_reg, env);

    bswap_prstatus(prstatus);

    return ret;
}

static abi_long fill_fpregs(TaskState *ts, target_fpreg_t *fpregs)
{
    /* XXX Need to add support for FP Regs. */
    memset(fpregs, 0, sizeof (*fpregs));

    return 0;
}

#if 0
static abi_long fill_umask(pid_t pid, unsigned short *maskp)
{
    abi_long ret;
    int mib[4];
    size_t len;

    *maskp = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_UMASK;
    mib[3] = pid;
    len = sizeof(*maskp);
    ret = get_errno(sysctl(mib, 4, maskp, &len, NULL, 0));
    if (is_error(ret) && errno != ESRCH && errno != EPERM) {
        warn("sysctl: kern.proc.umask: %d", pid);
        return ret;
    } else {
        *maskp = tswap16(*maskp);
        return (0);
    }
}
#endif

static gid_t *alloc_groups(size_t *gidset_sz)
{
    int num = sysconf(_SC_NGROUPS_MAX) + 1;
    size_t sz = num * sizeof(gid_t);
    gid_t *gs = g_malloc0(sz);

    if (gs == NULL)
        return NULL;

    if ((num = getgroups(num, gs)) == -1) {
        g_free(gs);
        return NULL;
    }
    *gidset_sz = num * sizeof(gid_t);

    return (gs);
}

static abi_long fill_groups(gid_t *gs, size_t *sz)
{
#ifdef BSWAP_NEEDED
    int i, num = *sz / sizeof (*gs);

    for(i = 0; i < num; i++)
        gs[i] = tswap32(gs[i]);
#endif /* BSWAP_NEEDED */
    return (0);
}

#ifdef BSWAP_NEEDED
static void bswap_rlimit(struct rlimit *rlimit)
{

    rlimit->rlim_cur = tswap64(rlimit->rlim_cur);
    rlimit->rlim_max = tswap64(rlimit->rlim_max);
}
#else /* ! BSWAP_NEEDED */
static void bswap_rlimit(struct rlimit *rlimit) {}
#endif /* ! BSWAP_NEEDED */

/*
 * Get all the rlimits.  Caller must free rlimits.
 */
static abi_long fill_rlimits(struct rlimit *rlimits)
{
    abi_long ret;
    int i;

    for(i = 0; i < RLIM_NLIMITS; i++) {
        ret = get_errno(getrlimit(i, &rlimits[i]));
        if (is_error(ret)) {
            warn("getrlimit");
            g_free(rlimits);
            return ret;
        }
        bswap_rlimit(&rlimits[i]);
    }
    return 0;
}

/*
 * Get the file info: kifiles.
 */
static struct target_kinfo_file *alloc_kifiles(pid_t pid, size_t *kif_sz)
{
    abi_long ret;
    size_t sz;
    struct target_kinfo_file *kif;

    ret = do_sysctl_kern_proc_filedesc(pid, 0, NULL, &sz);
    if (is_error(ret)) {
        return NULL;
    }

    *kif_sz = sz;

    kif = g_malloc0(sz);
    if (kif == NULL) {
        return NULL;
    }
    return kif;
}

static abi_long fill_kifiles(pid_t pid, struct target_kinfo_file *kif,
        size_t *kif_sz)
{

    return do_sysctl_kern_proc_filedesc(pid, *kif_sz, kif, kif_sz);
}

static struct target_kinfo_vmentry *alloc_kivmentries(pid_t pid,
        size_t *kivme_sz)
{
    abi_long ret;
    size_t sz;
    struct target_kinfo_vmentry *kivme;

    ret = do_sysctl_kern_proc_vmmap(pid, 0, NULL, &sz);
    if (is_error(ret)) {
        return NULL;
    }

    *kivme_sz = sz;

    kivme = g_malloc0(sz);
    if (kivme == NULL) {
        return NULL;
    }
    return kivme;
}

static abi_long fill_kivmentries(pid_t pid,
        struct target_kinfo_vmentry *kivme, size_t *kivme_sz)
{

    return do_sysctl_kern_proc_vmmap(pid, *kivme_sz, kivme, kivme_sz);
}

#define TARGET_MACOMLEN             19

/* From sys/procfs.h */
typedef struct target_thrmisc {
    char       pr_tname[MAXCOMLEN + 1]; /* Thread name + NULL */
    uint32_t   _pad;                    /* Pad, 0-filled */
} target_thrmisc_t;


static abi_long fill_thrmisc(const CPUArchState *env, const TaskState *ts,
        struct target_thrmisc *thrmisc)
{
    struct bsd_binprm *bprm = ts->bprm;

    /* XXX - need to figure out how to get td_name out of the kernel. */
    snprintf(thrmisc->pr_tname, MAXCOMLEN, "%s", bprm->argv[1]);

    return 0;
}

/*
 * An ELF note in memory.
 */
struct memelfnote {
    const char *name;
    size_t     namesz;
    size_t     namesz_rounded;
    int        type;
    size_t     datasz;
    size_t     datasz_rounded;
    void       *data;
    size_t     notesz;
    int        addsize;
};

/*
 * Per-Thread status.
 */
struct elf_thread_status {
    QTAILQ_ENTRY(elf_thread_status) ets_link;
    target_prstatus_t           *prstatus;      /* NT_PRSTATUS */
    target_fpreg_t              *fpregs;        /* NT_FPREGSET */
    target_thrmisc_t            *thrmisc;       /* NT_THRMISC */
    struct memelfnote           notes[3];
    int                         num_notes;
};

/*
 * Process status notes.
 */
struct elf_note_info {
    struct memelfnote           *notes;
    target_prpsinfo_t           *prpsinfo;      /* NT_PRPSINFO */

    target_prstatus_t           *prstatus;      /* NT_PRSTATUS */
    target_fpreg_t              *fpregs;        /* NT_FPREGSET */
    target_thrmisc_t            *thrmisc;       /* NT_THRMISC */

    QTAILQ_HEAD(thread_list_head, elf_thread_status) thread_list;

    struct target_kinfo_proc    *kiproc;        /* NT_PROCSTAT_PROC */
    struct target_kinfo_file    *kifiles;       /* NT_PROCSTAT_FILES */
    size_t                      kifiles_sz;
    struct target_kinfo_vmentry *kivmentries;   /* NT_PROCSTAT_VMMAP */
    size_t                      kivmentries_sz;
    gid_t                       *groups;        /* NT_PROCSTAT_GROUPS */
    size_t                      groups_sz;
    uint16_t                    umask;          /* NT_PROCSTAT_UMASK */
    struct rlimit               *rlimits;        /* NT_PROCSTAT_RLIMIT */
    int32_t                     osreldate;      /* NT_PROCSTAT_OSREL */
    abi_ulong                   psstrings;     /* NT_PROCSTAT_PSSTRINGS */
    void                        *auxv;          /* NT_PROCSTAT_AUXV */
    size_t                      auxv_sz;
    int                         notes_size;
    int                         numnote;
};

struct vm_area_struct {
    target_ulong   vma_start;  /* start vaddr of memory region */
    target_ulong   vma_end;    /* end vaddr of memory region */
    abi_ulong      vma_flags;  /* protection etc. flags for the region */
    QTAILQ_ENTRY(vm_area_struct) vma_link;
};

struct mm_struct {
    QTAILQ_HEAD(, vm_area_struct) mm_mmap;
    int mm_count;           /* number of mappings */
};

static struct mm_struct *vma_init(void)
{
    struct mm_struct *mm;

    if ((mm = g_malloc(sizeof (*mm))) == NULL)
        return (NULL);

    mm->mm_count = 0;
    QTAILQ_INIT(&mm->mm_mmap);

    return (mm);
}

static struct vm_area_struct *vma_first(const struct mm_struct *mm)
{

    return (QTAILQ_FIRST(&mm->mm_mmap));
}

static struct vm_area_struct *vma_next(struct vm_area_struct *vma)
{

    return (QTAILQ_NEXT(vma, vma_link));
}

static void vma_delete(struct mm_struct *mm)
{
    struct vm_area_struct *vma;

    while ((vma = vma_first(mm)) != NULL) {
        QTAILQ_REMOVE(&mm->mm_mmap, vma, vma_link);
        g_free(vma);
    }
    g_free(mm);
}

static int vma_add_mapping(struct mm_struct *mm, target_ulong start,
                           target_ulong end, abi_ulong flags)
{
    struct vm_area_struct *vma;

    if ((vma = g_malloc0(sizeof (*vma))) == NULL)
        return (-1);

    vma->vma_start = start;
    vma->vma_end = end;
    vma->vma_flags = flags;

    QTAILQ_INSERT_TAIL(&mm->mm_mmap, vma, vma_link);
    mm->mm_count++;

    return (0);
}

static int vma_get_mapping_count(const struct mm_struct *mm)
{

    return (mm->mm_count);
}

/*
 * Calculate file (dump) size of given memory region.
 */
static abi_ulong vma_dump_size(const struct vm_area_struct *vma)
{

    /* if we cannot even read the first page, skip it */
    if (!access_ok(VERIFY_READ, vma->vma_start, TARGET_PAGE_SIZE))
        return (0);

    /*
     * Usually we don't dump executable pages as they contain
     * non-writable code that debugger can read directly from
     * target library etc.  However, thread stacks are marked
     * also executable so we read in first page of given region
     * and check whether it contains elf header.  If there is
     * no elf header, we dump it.
     */
    if (vma->vma_flags & PROT_EXEC) {
        char page[TARGET_PAGE_SIZE];

        copy_from_user(page, vma->vma_start, sizeof (page));
        if ((page[EI_MAG0] == ELFMAG0) &&
            (page[EI_MAG1] == ELFMAG1) &&
            (page[EI_MAG2] == ELFMAG2) &&
            (page[EI_MAG3] == ELFMAG3)) {
            /*
             * Mappings are possibly from ELF binary.  Don't dump
             * them.
             */
            return (0);
        }
    }

    return (vma->vma_end - vma->vma_start);
}

static int vma_walker(void *priv, target_ulong start, target_ulong end,
                      unsigned long flags)
{
    struct mm_struct *mm = (struct mm_struct *)priv;

    vma_add_mapping(mm, start, end, flags);
    return (0);
}


/*
 * Construct the name of the coredump file in the form of:
 *
 * Long form:
 *   qemu_<basename_of_target>_<date>-<time>_<pid>.core
 *
 * Short form:
 *   qemu_<basename_of_target>.core
 *
 * On success return 0, otherwise return -1 (and errno).
 */
static int core_dump_filename(const TaskState *ts, char *buf,
        size_t bufsize)
{
#ifdef QEMU_LONG_CORE_FILENAME
    char timestamp[64];
    char *filename = NULL;
    char *base_filename = NULL;
    struct timeval tv;
    struct tm tm;

    assert(bufsize >= PATH_MAX);

    if (gettimeofday(&tv, NULL) < 0) {
        (void) fprintf(stderr, "unable to get current timestamp: %s",
                strerror(errno));
        return (-1);
    }

    filename = strdup(ts->bprm->filename);
    base_filename = basename(filename);
    (void) strftime(timestamp, sizeof (timestamp), "%Y%m%d-%H%M%S",
            localtime_r(&tv.tv_sec, &tm));
    (void) snprintf(buf, bufsize, "qemu_%s_%s_%d.core",
            base_filename, timestamp, (int)getpid());
    free(filename);
#else /* ! QEMU_LONG_CORE_FILENAME */
    char *filename, *base_filename;

    assert(bufsize >= PATH_MAX);

    filename = strdup(ts->bprm->filename);
    base_filename = basename(filename);
    (void) snprintf(buf, bufsize, "qemu_%s.core", base_filename);
    free(filename);
#endif /* ! QEMU_LONG_CORE_FILENAME */

    return (0);
}


static void fill_elf_header(struct elfhdr *elf, int segs, uint16_t machine,
        uint32_t flags)
{

    (void) memset(elf, 0, sizeof(*elf));

    elf->e_ident[EI_MAG0] = ELFMAG0;
    elf->e_ident[EI_MAG1] = ELFMAG1;
    elf->e_ident[EI_MAG2] = ELFMAG2;
    elf->e_ident[EI_MAG3] = ELFMAG3;
    elf->e_ident[EI_CLASS] = ELF_CLASS;
    elf->e_ident[EI_DATA] = ELF_DATA;
    elf->e_ident[EI_VERSION] = EV_CURRENT;
#ifdef __FreeBSD__
    elf->e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
#else
    elf->e_ident[EI_OSABI] = ELF_OSABI;
#endif /* ! __FreeBSD__ */
    elf->e_type = ET_CORE;
    elf->e_machine = machine;
    elf->e_version = EV_CURRENT;
    elf->e_phoff = sizeof(struct elfhdr);
    elf->e_flags = flags;
    elf->e_ehsize = sizeof(struct elfhdr);
    elf->e_phentsize = sizeof(struct elf_phdr);
    // elf->e_shentsize = sizeof(struct elf_phdr);
    elf->e_phnum = segs;
    elf->e_shstrndx = SHN_UNDEF;

    bswap_ehdr(elf);
}

static void fill_elf_note_phdr(struct elf_phdr *phdr, int sz, off_t offset)
{

    phdr->p_type = PT_NOTE;
    phdr->p_flags = PF_R;       /* Readable */
    phdr->p_offset = offset;
    phdr->p_vaddr = 0;
    phdr->p_paddr = 0;
    phdr->p_filesz = sz;
    phdr->p_memsz = 0;
    phdr->p_align = ELF_NOTE_ROUNDSIZE;

    bswap_phdr(phdr, 1);
}

static void fill_note(struct memelfnote *note, const char *name, int type,
        unsigned int sz, void *data, int addsize)
{
    unsigned int namesz;

    namesz = strlen(name) + 1;
    note->name = name;
    note->namesz = namesz;
    note->namesz_rounded = roundup2(namesz, sizeof (int32_t));
    note->type = type;
    note->addsize = tswap32(addsize);

    if (addsize) {
        note->datasz = sz;
        note->datasz_rounded =
            roundup2((sz + sizeof(uint32_t)), sizeof (int32_t));
    } else {
        note->datasz = sz;
        note->datasz_rounded = roundup2(sz, sizeof (int32_t));
    }
    note->data = data;

    /*
     * We calculate rounded up note size here as specified by
     * ELF document.
     */
    note->notesz = sizeof (struct elf_note) +
        note->namesz_rounded + note->datasz_rounded;
}

/*
 * Initialize the perthread_note_info and process_note_info structures
 * so that it is at least safe to call free_note_info() on it. Must be
 * called before calling fill_note_info().
 */
static void init_note_info(struct elf_note_info *info)
{

    memset(info, 0, sizeof (*info));
    QTAILQ_INIT(&info->thread_list);
}

static void free_note_info(struct elf_note_info *info)
{
    struct elf_thread_status *ets;

    if (info->prpsinfo)
        g_free(info->prpsinfo);

    if (info->prstatus)
        g_free(info->prstatus);
    if (info->fpregs)
        g_free(info->fpregs);
    if (info->thrmisc)
        g_free(info->thrmisc);

    while (!QTAILQ_EMPTY(&info->thread_list)) {
        ets = QTAILQ_FIRST(&info->thread_list);
        QTAILQ_REMOVE(&info->thread_list, ets, ets_link);
        if (ets) {
            if (ets->prstatus)
                g_free(ets->prstatus);
            if (ets->fpregs)
                g_free(ets->fpregs);
            if (ets->thrmisc)
                g_free(ets->thrmisc);
            g_free(ets);
        }
    }

    if (info->kiproc)
        g_free(info->kiproc);
    if (info->kifiles)
        g_free(info->kifiles);
    if (info->kivmentries)
        g_free(info->kivmentries);
    if (info->groups)
        g_free(info->groups);
    if (info->rlimits)
        g_free(info->rlimits);
    if (info->auxv)
        g_free(info->auxv);
}

static int dump_write(int fd, const void *ptr, size_t size)
{
    const char *bufp = (const char *)ptr;
    ssize_t bytes_written, bytes_left;
    struct rlimit dumpsize;
    off_t pos;

    bytes_written = 0;
    getrlimit(RLIMIT_CORE, &dumpsize);
    if ((pos = lseek(fd, 0, SEEK_CUR))==-1) {
        if (errno == ESPIPE) { /* not a seekable stream */
            bytes_left = size;
        } else {
            return pos;
        }
    } else {
        if (dumpsize.rlim_cur <= pos) {
            return -1;
        } else if (dumpsize.rlim_cur == RLIM_INFINITY) {
            bytes_left = size;
        } else {
            size_t limit_left=dumpsize.rlim_cur - pos;
            bytes_left = limit_left >= size ? size : limit_left ;
        }
    }

    /*
     * In normal conditions, single write(2) should do but
     * in case of socket etc. this mechanism is more portable.
     */
    do {
        bytes_written = write(fd, bufp, bytes_left);
        if (bytes_written < 0) {
            if (errno == EINTR)
                continue;
            return (-1);
        } else if (bytes_written == 0) { /* eof */
            return (-1);
        }
        bufp += bytes_written;
        bytes_left -= bytes_written;
    } while (bytes_left > 0);

    return (0);
}


static int write_note(struct memelfnote *men, int fd)
{
    struct elf_note en;

    en.n_namesz = men->namesz_rounded;
    en.n_descsz = men->datasz_rounded;
    en.n_type = men->type;

#if 0
    printf("n_type=%d n_namesz=%ld n_descsz=%ld\n",
            en.n_type, (long)en.n_namesz, (long)en.n_descsz);
#endif

    bswap_note(&en);

    if (dump_write(fd, &en, sizeof(en)) != 0) {
        return (-1);
    }
    if (dump_write(fd, men->name, men->namesz_rounded) != 0) {
        return (-1);
    }

    if (men->addsize)
        if (dump_write(fd, &men->addsize, sizeof (uint32_t)) != 0) {
            return (-1);
        }

    if (dump_write(fd, men->data, men->datasz) != 0) {
        return (-1);
    }

    return (0);
}

static int write_note_info(struct elf_note_info *info, int fd)
{
    struct elf_thread_status *ets;
    int i, error = 0;

    /* write prpsinfo, prstatus, fpregs, and thrmisc */
    for (i = 0; i < 4; i++)
        if ((error = write_note(&info->notes[i], fd)) != 0) {
            return (error);
        }

    /* write prstatus, fpregset, & thrmisc for each additional thread */
    QTAILQ_FOREACH(ets, &info->thread_list, ets_link) {
        if ((error = write_note(&ets->notes[0], fd)) != 0) {
            return (error);
        }
        if ((error = write_note(&ets->notes[1], fd)) != 0) {
            return (error);
        }
        if ((error = write_note(&ets->notes[2], fd)) != 0) {
            return (error);
        }
    }

    /*
     * write kiproc, kifiles, kivmmap, groups, umask, rlimits, osrel,
     * psstrings, and auxv.
     */
    for (i = 4; i < info->numnote; i++)
        if ((error = write_note(&info->notes[i], fd)) != 0) {
            return (error);
        }

    return (0);
}

static size_t note_size(const struct memelfnote *note)
{

    return (note->notesz);
}

static abi_long fill_thread_info(struct elf_note_info *info, int signr,
    CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = (TaskState *)cpu->opaque;
    struct elf_thread_status *ets;

    ets = g_malloc0(sizeof (*ets));
    if (ets == NULL)
        return (-TARGET_ENOMEM);
    ets->num_notes = 3;

    ets->prstatus = g_malloc0(sizeof (struct target_prstatus));
    if (ets->prstatus == NULL) {
        return -TARGET_ENOMEM;
    }
    fill_prstatus(env, ets->prstatus, signr);
    fill_note(&ets->notes[0], "FreeBSD", TARGET_NT_PRSTATUS,
            sizeof (struct target_prstatus), &ets->prstatus, 0);


    ets->fpregs = g_malloc0(sizeof (*ets->fpregs));
    if (ets->fpregs == NULL) {
        return -TARGET_ENOMEM;
    }
    fill_fpregs(ts, ets->fpregs);
    fill_note(&ets->notes[1], "FreeBSD", TARGET_NT_FPREGSET,
            sizeof(*ets->fpregs), ets->fpregs, 0);

    ets->thrmisc = g_malloc0(sizeof (*ets->thrmisc));
    if (ets->thrmisc == NULL) {
        return -TARGET_ENOMEM;
    }
    fill_thrmisc(env, ts, ets->thrmisc);
    fill_note(&ets->notes[2], "FreeBSD", TARGET_NT_THRMISC,
            sizeof(*ets->thrmisc), ets->thrmisc, 0);

    QTAILQ_INSERT_TAIL(&info->thread_list, ets, ets_link);

    info->notes_size += (note_size(&ets->notes[0]) +
        note_size(&ets->notes[1]) + note_size(&ets->notes[2]));

    return (0);
}

static abi_long fill_kiproc(TaskState *ts, pid_t pid,
        struct target_kinfo_proc *tkip)
{
    abi_long ret;
    size_t len = sizeof (*tkip);
    struct bsd_binprm *bprm = ts->bprm;

    ret = do_sysctl_kern_getprocs(KERN_PROC_PID, pid, len, tkip, &len);

    if (is_error(ret))
        g_free(tkip);

    /* Fix up some to be the target values. */
#if defined(__FreeBSD_version) && __FreeBSD_version >= 900000
    strncpy(tkip->ki_tdname, basename(bprm->argv[0]), TARGET_TDNAMLEN);
#else
    strncpy(tkip->ki_ocomm, basename(bprm->argv[0]), TARGET_TDNAMLEN);
#endif
    strncpy(tkip->ki_comm, basename(bprm->argv[0]), TARGET_COMMLEN);
#if TARGET_ABI_BITS == 32
    strncpy(tkip->ki_emul, "FreeBSD ELF32", TARGET_KI_EMULNAMELEN);
#else
    strncpy(tkip->ki_emul, "FreeBSD ELF64", TARGET_KI_EMULNAMELEN);
#endif

    return ret;
}


struct target_elf_auxinfo {
    abi_long    a_type;
    abi_long    a_value;
};


static abi_long fill_auxv(void *auxv, size_t *sz)
{

    *sz = target_auxents_sz;

    return (copy_from_user(auxv, target_auxents, target_auxents_sz));
}

static abi_long fill_psstrings(abi_ulong *psstrings)
{

#if defined(TARGET_PS_STRINGS)
    *psstrings = tswapal(TARGET_PS_STRINGS);
#else
#   warning "TARGET_PS_STRINGS is not defined."
    *psstrings = 0;
#endif
    return 0;
}

#define MAXNUMNOTES    13

static int fill_note_info(struct elf_note_info *info,
        int signr, CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = (TaskState *)cpu->opaque;
    int i, err, numnotes = 0;
    pid_t pid = getpid();

    info->notes = g_malloc0(MAXNUMNOTES * sizeof (struct memelfnote));
    if (info->notes == NULL) {
        err = ENOMEM;
        goto edone;
    }

    /* NT_PRPSINFO */
    info->prpsinfo = g_malloc0(sizeof(*info->prpsinfo));
    if (info->prpsinfo == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_prpsinfo(ts, &info->prpsinfo)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PRPSINFO,
            sizeof (*info->prpsinfo), info->prpsinfo, 0);

    /* prstatus, fpregs, and thrmisc for main thread. */

    /* NT_PRSTATUS */
    info->prstatus = g_malloc0(sizeof (struct target_prstatus));
    if (info->prstatus == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_prstatus(env, info->prstatus, signr)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PRSTATUS,
            sizeof (struct target_prstatus), info->prstatus, 0);

    /* NT_FPREGSET */
    info->fpregs = g_malloc0(sizeof (*info->fpregs));
    if (info->fpregs == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    fill_fpregs(ts, info->fpregs);
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_FPREGSET,
            sizeof(*info->fpregs), info->fpregs, 0);

    /* NT_THRMISC */
    info->thrmisc = g_malloc0(sizeof (*info->thrmisc));
    if (info->thrmisc == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    fill_thrmisc(env, ts, info->thrmisc);
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_THRMISC,
            sizeof(*info->thrmisc), info->thrmisc, 0);

    /* NT_PROCSTAT_PROC */
    info->kiproc = g_malloc0(sizeof (*info->kiproc));
    if (info->kiproc == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_kiproc(ts, pid, info->kiproc)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_PROC,
            sizeof (*info->kiproc), info->kiproc,
            sizeof (struct target_kinfo_proc));

    /* NT_PROCSTAT_FILES */
    info->kifiles = alloc_kifiles(pid, &info->kifiles_sz);
    if (info->kifiles == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_kifiles(pid, info->kifiles, &info->kifiles_sz)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_FILES,
            info->kifiles_sz, info->kifiles,
            sizeof (struct target_kinfo_file));

    /* NT_PROCSTAT_VMMAP */
    info->kivmentries = alloc_kivmentries(pid, &info->kivmentries_sz);
    if (info->kivmentries == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_kivmentries(pid, info->kivmentries,
                    &info->kivmentries_sz)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_VMMAP,
            info->kivmentries_sz, info->kivmentries,
            sizeof (struct target_kinfo_vmentry));

    /* NT_PROCSTAT_GROUPS */
    info->groups = alloc_groups(&info->groups_sz);
    if (info->groups == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_groups(info->groups, &info->groups_sz)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_GROUPS,
            info->groups_sz, info->groups,
            sizeof (uint32_t));

#if 0
    /* NT_PROCSTAT_UMASK */
    if ((err = fill_umask(pid, &info->umask)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_UMASK,
            /* sizeof (info->umask) */ sizeof (uint16_t), &info->umask,
            sizeof (uint16_t));
#endif

    /* NT_PROCSTAT_RLIMIT */
    info->rlimits = g_malloc0(RLIM_NLIMITS * sizeof(struct rlimit));
    if (info->rlimits == NULL) {
        return (-TARGET_ENOMEM);
    }
    if ((err = fill_rlimits(info->rlimits)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_RLIMIT,
            sizeof(struct rlimit) * RLIM_NLIMITS, info->rlimits,
            sizeof (struct rlimit) * RLIM_NLIMITS);

    /* NT_PROCSTAT_OSREL */
    if ((err = fill_osreldate(&info->osreldate)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_OSREL,
            sizeof (info->osreldate), &info->osreldate,
            sizeof (int32_t));

    /* NT_PROCSTAT_PSSTRINGS */
    if ((err = fill_psstrings(&info->psstrings)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_PSSTRINGS,
            sizeof (info->psstrings), &info->psstrings,
            sizeof (abi_ulong));

    /* NT_PROCSTAT_AUXV */
    info->auxv = g_malloc0(target_auxents_sz);
    if (info->auxv == NULL) {
        err = -TARGET_ENOMEM;
        goto edone;
    }
    if ((err = fill_auxv(info->auxv, &info->auxv_sz)) != 0) {
        goto edone;
    }
    fill_note(&info->notes[numnotes++], "FreeBSD", TARGET_NT_PROCSTAT_AUXV,
            info->auxv_sz, info->auxv,
            sizeof (struct target_elf_auxinfo));

    assert(numnotes <= MAXNUMNOTES);
    info->numnote = numnotes;
    info->notes_size = 0;
    for (i = 0; i < numnotes; i++) {
        info->notes_size += note_size(&info->notes[i]);
    }

    /* read and fill status of all threads */
    cpu_list_lock();
    CPU_FOREACH(cpu) {
        if (cpu == thread_cpu) {
            continue;
        }
        if ((err = fill_thread_info(info, signr,
                        (CPUArchState *)cpu->env_ptr)) != 0) {
            cpu_list_unlock();
            goto edone;
        }
    }
    cpu_list_unlock();

    return (0);

edone:
    free_note_info(info);
    return (err);
}

static int elf_core_dump(int signr, CPUArchState *env)
{
    int fd = -1;
    int segs = 0;
    off_t offset = 0, data_offset = 0;
    CPUState *cpu = env_cpu(env);
    TaskState *ts = (TaskState *)cpu->opaque;
    struct vm_area_struct *vma = NULL;
    struct mm_struct *mm = NULL;
    struct rlimit dumpsize;
    struct elfhdr elf;
    struct elf_phdr phdr;
    struct elf_note_info info;
    char corefile[PATH_MAX];

    init_note_info(&info);

    errno = 0;
    getrlimit(RLIMIT_CORE, &dumpsize);
    if (dumpsize.rlim_cur == 0)
        return 0;

    if (core_dump_filename(ts, corefile, sizeof (corefile)) < 0)
        return -(errno);

    if ((fd = open(corefile, O_WRONLY | O_CREAT,
                    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0)
        return -(errno);

    /*
     * Walk through target process memory mappings and
     * set up structure containing this information.  After
     * this point vma_xxx functions can be used.
     */
    if ((mm = vma_init()) == NULL)
        goto out;

    walk_memory_regions(mm, vma_walker);
    segs = vma_get_mapping_count(mm);

    /*
     * Construct the coredump ELF header.  Add another segment for
     * notes.
     *
     * See kern/imgact_elf.c  __elfN(corehdr)().
     */
    fill_elf_header(&elf, segs + 1, ELF_MACHINE, 0);
    if (dump_write(fd, &elf, sizeof (elf)) != 0)
        goto out;

    /*
     * Construct the note segment and write it out.
     */
    if (fill_note_info(&info, signr, env) < 0) {
        goto out;
    }

    offset += sizeof (elf);                             /* elf header */
    offset += (segs + 1) * sizeof (struct elf_phdr);    /* program headers */

    /* Write out notes program header. */
    fill_elf_note_phdr(&phdr, info.notes_size, offset);

    offset += info.notes_size;
    if (dump_write(fd, &phdr, sizeof (phdr)) != 0) {
        goto out;
    }

    /*
     * ELF specification wants data to start at page boundary so
     * we align it here.
     */
    data_offset = offset = roundup(offset, ELF_EXEC_PAGESIZE);

    /*
     * Write program headers for memory regions mapped in the
     * target process.
     *
     * See cb_put_phdr() in sys/kern/imgact_ef.c
     */
    for (vma = vma_first(mm); vma != NULL; vma = vma_next(vma)) {
        (void) memset(&phdr, 0, sizeof (phdr));

        phdr.p_type = PT_LOAD;
        phdr.p_offset = offset;
        phdr.p_vaddr = vma->vma_start;
        phdr.p_paddr = 0;
        phdr.p_filesz = vma_dump_size(vma); /* ??? */
        offset += phdr.p_filesz;
        phdr.p_memsz = vma->vma_end - vma->vma_start;
        phdr.p_flags = vma->vma_flags & PROT_READ ? PF_R : 0;
        if (vma->vma_flags & PROT_WRITE)
            phdr.p_flags |= PF_W;
        if (vma->vma_flags & PROT_EXEC)
            phdr.p_flags |= PF_X;
        phdr.p_align = ELF_EXEC_PAGESIZE;  /* or PAGE_SIZE? */

        bswap_phdr(&phdr, 1);
        dump_write(fd, &phdr, sizeof (phdr));
    }

    /*
     * Next write notes just after program headers.
     */
    if (write_note_info(&info, fd) < 0)
        goto out;

    /*
     * Align data to page boundary.
     */
    if (lseek(fd, data_offset, SEEK_SET) != data_offset)
        goto out;

    /*
     * Finally, dump the process memory into the corefile as well.
     */
    for (vma = vma_first(mm); vma != NULL; vma = vma_next(vma)) {
        abi_ulong addr;
        abi_ulong end;

        end = vma->vma_start + vma_dump_size(vma);

        for (addr = vma->vma_start; addr < end;
                addr += TARGET_PAGE_SIZE) {
            char page[TARGET_PAGE_SIZE];
            int error;

            /*
             * Read in page from target process memory and
             * write it to coredump file.
             */
            error = copy_from_user(page, addr, sizeof (page));
            if (error != 0) {
                (void) fprintf(stderr, "unable to dump " TARGET_ABI_FMT_lx "\n",
                        addr);
                errno = -error;
                goto out;
            }
            if (dump_write(fd, page, TARGET_PAGE_SIZE) < 0)
                goto out;
        }
    }
    errno = 0;

out:
    if (mm != NULL)
        vma_delete(mm);

    (void) close(fd);

    if (errno != 0)
        return (-errno);
    return (0);
}

#endif /* USE_ELF_CORE_DUMP */

static int load_aout_interp(void * exptr, int interp_fd)
{

    printf("a.out interpreter not yet supported\n");
    return(0);
}

void do_init_thread(struct target_pt_regs *regs,
#ifdef TARGET_CHERI
    cap_register_t *sigcodecapp,
#endif
    struct image_info *infop)
{

#ifdef TARGET_CHERI
    target_thread_init(regs, sigcodecapp, infop);
#else
    target_thread_init(regs, infop);
#endif
}
