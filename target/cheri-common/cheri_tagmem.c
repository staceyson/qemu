/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2016 Stacey Son <sson@FreeBSD.org>
 * Copyright (c) 2016-2018 Alfredo Mazzinghi <am2419@cl.cam.ac.uk>
 * Copyright (c) 2016-2018 Alex Richardson <Alexander.Richardson@cl.cam.ac.uk>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "cheri_tagmem.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "exec/ramblock.h"
#include "cheri_defs.h"
#include "cheri-helper-utils.h"
// XXX: use hbitmap? Or a different data structure?
#include "qemu/bitmap.h"
#include "glib/ghash.h"

#if defined(TARGET_MIPS)
#include "cheri_utils.h"
#include "internal.h"
#endif

#if !defined(TARGET_CHERI)
#error "Should only be included for TARGET_CHERI"
#endif

// XXX: use secure/target_tlb_bit0/target_tlb_bit1 for cheri TLB permissions?

/*
 * Tagged Memory Emulation
 *
 * CHERI requires a 1-bit tag for every capability-aligned,
 * capability-sized word in physical memory.  This allows capabilities
 * to be safely loaded and stored in meory without loss of integrity.
 *
 * For emulation purposes the tag is stored in a two-level array containing
 * fixed size bitmaps. To reduce the amount of memory needed the tag flag array
 * is allocated sparsely, 4K tags at at time, and on demand.
 * This 4K number is arbitary and depending on the workload other sizes may be
 * better.
 *
 * Note: We also support an mode where we use one byte per tag. This makes it
 * easy to set or unset a tag without the need of locking or atomics.
 * This requires eight times the memory.
 *
 * As tag accesses are not atomic with regard to data writes/reads spurious
 * invalid capabilities could be created in a threaded context.
 * Therefore, we don't use atomic bitwise RMW operations and the one byte per
 * tag variant actually performs slightly worse due to increased memory usage.
 *
 * FIXME: find a solution to make tags safe (or just always disable multi-tcg)
 *
 * XXX Should consider adding a reference count per tag block so that
 * blocks can be deallocated when no longer used maybe.
 *
 * FIXME: rewrite using somethign more like the upcoming MTE changes (https://github.com/rth7680/qemu/commits/tgt-arm-mte-user)
 *
 * XXX: I/O threads still exist even without MTTCG and need to have tag
 * clearing be atomic with their writes. Currently various places just write to
 * guest memory directly and then we tag clear in invalidate_and_set_dirty.
 * Well-behaved guests should not be touching memory handed off to DMA-capable
 * devices but a malicious guest could repeatedly DMA powerful capability bit
 * patterns on top of valid capabilities and try to race to read in between the
 * DMA write and the tag invalidate.
 */

#define CAP_TAGBLK_SHFT     12          // 2^12 or 4096 tags per block
#define CAP_TAGBLK_MSK      ((1 << CAP_TAGBLK_SHFT) - 1)
#define CAP_TAGBLK_SIZE       (1 << CAP_TAGBLK_SHFT)
#define CAP_TAGBLK_IDX(tag_idx) ((tag_idx) & CAP_TAGBLK_MSK)
#define TAGS_PER_PAGE        (TARGET_PAGE_SIZE / CHERI_CAP_SIZE)

#ifndef CAP_TAG_GET_MANY_SHFT
#error "Define a CAP_TAG_GET_MANY_SHFT in appropriate cheri-archspecific.h"
#endif

_Static_assert(CAP_TAG_GET_MANY_SHFT <= 3, "");

#if (CAP_TAG_GET_MANY_SHFT == 3)
#define byte_unpack byte_unpack_64
#define byte_pack byte_pack_64
#else
#define byte_unpack byte_unpack_32
#define byte_pack byte_pack_32
#endif

#define CAP_TAG_GET_MANY_MASK ((1 << (1UL << CAP_TAG_GET_MANY_SHFT)) - 1UL)
#define CAP_TAG_MANY_DATA_SIZE (CHERI_CAP_SIZE << CAP_TAG_GET_MANY_SHFT)

static inline size_t num_tagblocks(RAMBlock* ram)
{
    uint64_t memory_size = memory_region_size(ram->mr);
    size_t result = DIV_ROUND_UP(memory_size, CHERI_CAP_SIZE * CAP_TAGBLK_SIZE);
    if (memory_size != result * CHERI_CAP_SIZE * CAP_TAGBLK_SIZE) {
        warn_report_once(
            "WARNING: memory region %s size %" PRIu64
            " is not a multiple of tag block size %d\r",
            memory_region_name(ram->mr),
            memory_size,
            CHERI_CAP_SIZE * CAP_TAGBLK_SIZE);
    }
    return result;
}

typedef struct CheriTagBlock {
    DECLARE_BITMAP(tag_bitmap, CAP_TAGBLK_SIZE);
} CheriTagBlock;


static CheriTagBlock *cheri_tag_new_tagblk(RAMBlock *ram, uint64_t tagidx)
{
    CheriTagBlock *tagblk, *old;

    tagblk = g_malloc0(sizeof(CheriTagBlock));
    if (tagblk == NULL) {
        error_report("Can't allocate tag block.");
        exit(1);
    }

    CheriTagBlock **tagmem = (CheriTagBlock **)ram->cheri_tags;
    size_t tagblock_index = (tagidx >> CAP_TAGBLK_SHFT);
    /* Possible race here so use atomic compare and swap. */
    cheri_debug_assert(tagblock_index < num_tagblocks(ram) &&
                       "Tag index out of bounds");
    old = qatomic_cmpxchg(&tagmem[tagblock_index], NULL, tagblk);
    if (old != NULL) {
        /* Lost the race, free. */
        g_free(tagblk);
        return old;
    } else {
        return tagblk;
    }
}

static inline QEMU_ALWAYS_INLINE CheriTagBlock *cheri_tag_block(size_t tag_index,
                                                                RAMBlock *ram)
{
    const size_t tagbock_index = tag_index >> CAP_TAGBLK_SHFT;
    cheri_debug_assert(ram->cheri_tags);
    cheri_debug_assert(tagbock_index < num_tagblocks(ram));
    CheriTagBlock **tagmem = (CheriTagBlock **)ram->cheri_tags;
    return tagmem[tagbock_index];
}

static inline QEMU_ALWAYS_INLINE bool tagblock_get_tag_tagmem(void *tagmem,
                                                              size_t index)
{
    unsigned long *p = (unsigned long *)tagmem + BIT_WORD(index);
    unsigned long word;

    word = qatomic_read(p);
    return (word & BIT_MASK(index)) != 0;
}

static inline QEMU_ALWAYS_INLINE bool tagblock_get_tag(CheriTagBlock *block,
                                                       size_t block_index)
{
    return block ? tagblock_get_tag_tagmem(block->tag_bitmap, block_index)
                 : false;
}

static inline QEMU_ALWAYS_INLINE int
tagblock_get_tag_many_tagmem(void *tagmem, size_t block_index)
{
    unsigned long *p = (unsigned long *)tagmem + BIT_WORD(block_index);
    unsigned long word;

    word = qatomic_read(p);
    return (word >> (block_index % BITS_PER_LONG)) & CAP_TAG_GET_MANY_MASK;
}

static inline QEMU_ALWAYS_INLINE void
tagblock_set_tag_tagmem(void *tagmem, size_t block_index)
{
    unsigned long *p = (unsigned long *)tagmem + BIT_WORD(block_index);

    qatomic_or(p, BIT_MASK(block_index));
}

static inline QEMU_ALWAYS_INLINE void
tagblock_set_tag_many_tagmem(void *tagmem, size_t block_index, uint8_t tags)
{
    unsigned long *p = (unsigned long *)tagmem + BIT_WORD(block_index);
    size_t shift = block_index % BITS_PER_LONG;
    unsigned long mask = CAP_TAG_GET_MANY_MASK << shift;
    unsigned long tags_shifted = ((unsigned long)tags << shift) & mask;

    if (likely(tags_shifted == 0)) {
        qatomic_and(p, ~mask);
    } else {
        unsigned long old, new, cmp;
        cmp = qatomic_read(p);
        do {
            old = cmp;
            new = (old & ~mask) | tags_shifted;
            cmp = qatomic_cmpxchg(p, old, new);
        } while (cmp != old);
    }
}

static inline QEMU_ALWAYS_INLINE void tagblock_clear_tag_tagmem(void *tagmem,
                                                                size_t index)
{
    unsigned long *p = (unsigned long *)tagmem + BIT_WORD(index);

    qatomic_and(p, ~BIT_MASK(index));
}

static inline QEMU_ALWAYS_INLINE void tagblock_clear_tag(CheriTagBlock *block,
                                                         size_t block_index)
{
    tagblock_clear_tag_tagmem(block->tag_bitmap, block_index);
}

void cheri_tag_init(MemoryRegion *mr, uint64_t memory_size)
{
    assert(memory_region_is_ram(mr));
    assert(memory_region_size(mr) == memory_size &&
           "Incorrect tag mem size passed?");
    assert(mr->ram_block->cheri_tags == NULL && "Already initialized?");

    size_t cheri_ntagblks = num_tagblocks(mr->ram_block);
    mr->ram_block->cheri_tags =
        g_malloc0(cheri_ntagblks * sizeof(CheriTagBlock *));
    if (mr->ram_block->cheri_tags == NULL) {
        error_report("%s: Can't allocated tag memory", __func__);
        exit(-1);
    }
    if (qemu_tcg_mttcg_enabled()) {
        warn_report("The CHERI tagged memory implementation is not thread-safe "
                    "and therefore not compatible with MTTCG. Capability tags "
                    "may mysteriously appear/disappear. Run with \"--accel "
                    "tcg,thread=single\" to fix.");
    }
}

void *cheri_tagmem_for_addr(CPUArchState *env, target_ulong vaddr,
                            RAMBlock *ram, ram_addr_t ram_offset, size_t size,
                            int *prot, bool tag_write)
{

    if (unlikely(!ram || !ram->cheri_tags)) {
        /* Tags stored here are effectively cleared (unless they should trap) */
        if (!(*prot & PAGE_SC_TRAP)) {
            *prot |= PAGE_SC_CLEAR;
        }
        if (tag_write) {
            error_report("Attempting change tag bit on memory without tags:");
            error_report("%s: vaddr=0x%jx -> %s+0x%jx", __func__,
                         (uintmax_t)vaddr, ram ? ram->idstr : NULL,
                         (uintmax_t)ram_offset);
        }
        return ALL_ZERO_TAGBLK;
    }

    uint64_t tag = ram_offset / CHERI_CAP_SIZE;
#ifndef TARGET_AARCH64
    // AArch64 seems to use different sizes. Might be worth looking into.
    cheri_debug_assert(size == TARGET_PAGE_SIZE && "Unexpected size");
#endif
    CheriTagBlock *tagblk = cheri_tag_block(tag, ram);

    if (tag_write && !tagblk) {
        cheri_tag_new_tagblk(ram, tag);
        CPUState *cpu = env_cpu(env);
        /*
         * A vaddr-based shootdown is insufficient as multiple mappings may
         * exist. Short of an inverted table, a complete shootdown is required.
         */
        tlb_flush_all_cpus_synced(cpu);
        /*
         * An un-synced flush the current cpu is required as we want to complete
         * this instruction and THEN exit.
         */
        tlb_flush(cpu);
        tagblk = cheri_tag_block(tag, ram);
        cheri_debug_assert(tagblk);
    }

    if (tagblk != NULL) {
        const size_t tagblk_index = CAP_TAGBLK_IDX(tag);
        return tagblk->tag_bitmap + BIT_WORD(tagblk_index);
    }

    if (!(*prot & PAGE_SC_CLEAR)) {
        // Add in a (fake) SC_TRAP to prompt a TLB refill if a tag is stored
        // to this location. See the comment around TLBENTRYCAP_INVALID_WRITE_*.
        *prot |= PAGE_SC_TRAP;
    }

    return ALL_ZERO_TAGBLK;
}

static inline void *get_tagmem_from_iotlb_entry(CPUArchState *env,
                                                target_ulong vaddr, int mmu_idx,
                                                bool isWrite,
                                                uintptr_t *flags_out)
{
    /* XXXAR: see mte_helper.c */
    /*
     * Find the iotlbentry for ptr.  This *must* be present in the TLB
     * because we just found the mapping.
     * TODO: Perhaps there should be a cputlb helper that returns a
     * matching tlb entry + iotlb entry.
     */
#ifdef CONFIG_DEBUG_TCG
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, vaddr);
    g_assert(tlb_hit(isWrite ? tlb_addr_write(entry) : entry->addr_read, vaddr));
#endif
    CPUIOTLBEntry *iotlbentry =
        &env_tlb(env)->d[mmu_idx].iotlb[tlb_index(env, mmu_idx, vaddr)];
    if (isWrite) {
        *flags_out = IOTLB_GET_TAGMEM_FLAGS(iotlbentry, write);
        return IOTLB_GET_TAGMEM(iotlbentry, write);
    } else {
        *flags_out = IOTLB_GET_TAGMEM_FLAGS(iotlbentry, read);
        return IOTLB_GET_TAGMEM(iotlbentry, read);
    }
}

typedef struct TagOffset {
    target_ulong value;
} TagOffset;

static QEMU_ALWAYS_INLINE TagOffset addr_to_tag_offset(target_ulong addr)
{
    return (struct TagOffset){.value = addr / CHERI_CAP_SIZE};
}

static QEMU_ALWAYS_INLINE target_ulong
page_vaddr_to_tag_offset(target_ulong addr)
{
    return (addr & ~TARGET_PAGE_MASK) / CHERI_CAP_SIZE;
}

static QEMU_ALWAYS_INLINE target_ulong tag_offset_to_addr(TagOffset offset)
{
    return offset.value * CHERI_CAP_SIZE;
}

static void *cheri_tag_invalidate_one(CPUArchState *env, target_ulong vaddr,
                                      int32_t size, uintptr_t pc, int mmu_idx);

void *cheri_tag_invalidate_aligned(CPUArchState *env, target_ulong vaddr,
                                   uintptr_t pc, int mmu_idx)
{
    cheri_debug_assert(QEMU_IS_ALIGNED(vaddr, CHERI_CAP_SIZE));
    return cheri_tag_invalidate_one(env, vaddr, CHERI_CAP_SIZE, pc, mmu_idx);
}

void cheri_tag_invalidate(CPUArchState *env, target_ulong vaddr, int32_t size,
                          uintptr_t pc, int mmu_idx)
{
    target_ulong first_addr = vaddr;
    target_ulong last_addr = (vaddr + size - 1);
    TagOffset tag_start = addr_to_tag_offset(first_addr);
    TagOffset tag_end = addr_to_tag_offset(last_addr);
    if (likely(tag_start.value == tag_end.value)) {
        // Common case, only one tag (i.e. an aligned store)
        cheri_tag_invalidate_one(env, vaddr, size, pc, mmu_idx);
        return;
    }
    // Unaligned store -> can cross a capabiblity alignment boundary and
    // therefore invalidate two tags. It can also cross pages
    size_t ntags = tag_end.value - tag_start.value + 1;
    assert(ntags == 2 && "Should invalidate at most two tag bits here");
    // Note: we always do a new page lookup here since unaligned stores
    // should be rare and the probing should be fast if it's in the QEMU TLB
#if defined(TARGET_ALIGNED_ONLY)
#if defined(CHERI_UNALIGNED)
    if (unlikely((first_addr & TARGET_PAGE_MASK) !=
                 (last_addr & TARGET_PAGE_MASK))) {
        warn_report("Got unaligned %d-byte store across page "
                    "boundary at 0x" TARGET_FMT_lx "\r\n",
                    size, vaddr);
    }
#else
    qemu_log_flush();
    error_report("FATAL: %s: " TARGET_FMT_lx
                 "+%d crosses a page boundary\r",
                 __func__, vaddr, size);
    char buffer[256];
    FILE *f = fmemopen(buffer, sizeof(buffer), "w");
    fprintf(f, "Probably caused by guest instruction: ");
    target_disas(f, env_cpu(env), cpu_get_current_pc(env, pc, false),
                 /* Only one instr*/ -1);
    fprintf(f, "\r");
    fclose(f);
    buffer[sizeof(buffer) - 1] = '\0';
    error_report("%s", buffer);
    exit(1);
#endif
#endif
    target_ulong second_addr = tag_offset_to_addr(tag_start) + CHERI_CAP_SIZE;
    cheri_tag_invalidate_one(env, first_addr, second_addr - first_addr, pc,
                             mmu_idx);
    for (target_ulong addr = second_addr; addr <= tag_offset_to_addr(tag_end);
         addr += CHERI_CAP_SIZE) {
        target_ulong inval_size = MIN(CHERI_CAP_SIZE, last_addr + 1 - addr);
        cheri_tag_invalidate_one(env, addr, inval_size, pc, mmu_idx);
    }
}

static void *cheri_tag_invalidate_one(CPUArchState *env, target_ulong vaddr,
                                      int32_t size, uintptr_t pc, int mmu_idx)
{
    cheri_debug_assert(size > 0);

    /*
     * When resolving this address in the TLB, treat it like a data store
     * (MMU_DATA_STORE) rather than a capability store (MMU_DATA_CAP_STORE),
     * so that we don't require that the SC inhibit be clear.
     */

    void *host_addr = probe_write(env, vaddr, size, mmu_idx, pc);
    // Only RAM and ROM regions are backed by host addresses so if
    // probe_write() returns NULL we know that we can't write the tagmem.
    if (unlikely(!host_addr)) {
        return NULL;
    }

    uintptr_t tagmem_flags;
    void *tagmem =
        get_tagmem_from_iotlb_entry(env, vaddr, mmu_idx, true, &tagmem_flags);

    if (tagmem == ALL_ZERO_TAGBLK) {
        // All tags for this page are zero -> no need to invalidate. We also
        // couldn't invalidate if we wanted to since ALL_ZERO_TAGBLK is not a
        // valid pointer but a magic constant.
        return host_addr;
    }

    cheri_debug_assert(!(tagmem_flags & TLBENTRYCAP_FLAG_CLEAR) &&
                       "Unimplemented");

    // We cached the tagblock address in the iotlb -> find find the tag
    // bit: The iotlb->tagmem pointer always points to the tag memory
    // for the start of the page so we can simply add the index for the
    // page offset.
    target_ulong tag_offset = page_vaddr_to_tag_offset(vaddr);
    if (qemu_log_instr_enabled(env)) {
        bool old_value = tagblock_get_tag_tagmem(tagmem, tag_offset);
        qemu_log_instr_extra(
            env,
            "    Cap Tag Write [" TARGET_FMT_lx "/" RAM_ADDR_FMT "] %d -> 0\n",
            vaddr, qemu_ram_addr_from_host(host_addr), old_value);
    }

    tagblock_clear_tag_tagmem(tagmem, tag_offset);
    return host_addr;
}

void cheri_tag_phys_invalidate(CPUArchState *env, RAMBlock *ram,
                               ram_addr_t ram_offset, ram_addr_t len,
                               const target_ulong *vaddr)
{
    // Ignore tag clearing requests for ROM, etc.
    if (!ram->cheri_tags) {
        return;
    }
    cheri_debug_assert(!memory_region_is_rom(ram->mr) &&
                       !memory_region_is_romd(ram->mr));

    ram_addr_t endaddr = (uint64_t)(ram_offset + len);
    ram_addr_t startaddr = QEMU_ALIGN_DOWN(ram_offset, CHERI_CAP_SIZE);

    for(ram_addr_t addr = startaddr; addr < endaddr; addr += CHERI_CAP_SIZE) {
        uint64_t tag = addr / CHERI_CAP_SIZE;
        CheriTagBlock *tagblk = cheri_tag_block(tag, ram);
        if (tagblk != NULL) {
            const size_t tagblk_index = CAP_TAGBLK_IDX(tag);
            if (unlikely(env && vaddr && qemu_log_instr_enabled(env))) {
                target_ulong write_vaddr =
                    QEMU_ALIGN_DOWN(*vaddr, CHERI_CAP_SIZE) + (addr - startaddr);
                qemu_log_instr_extra(env, "    Cap Tag Write [" TARGET_FMT_lx
                    "/" RAM_ADDR_FMT "] %d -> 0\n", write_vaddr, addr,
                    tagblock_get_tag(tagblk, tagblk_index));
            } else if (unlikely(env && qemu_log_instr_enabled(env))) {
                qemu_log_instr_extra(env, "    Cap Tag ramaddr Write ["
                    RAM_ADDR_FMT "] %d -> 0\n", addr,
                    tagblock_get_tag(tagblk, tagblk_index));
            }
            // changed |= tagblock_get_tag(tagblk, tagblk_index);
            tagblock_clear_tag(tagblk, tagblk_index);
        }
    }
}

/*
 * TODO: Basically nothing uses this physical address. Tag set probably should
 * not have to return it.
 */
#define handle_paddr_return(rw)                                                \
    do {                                                                       \
        if (ret_paddr) {                                                       \
            *ret_paddr = (vaddr & ~TARGET_PAGE_MASK) |                         \
                         (tlb_entry(env, mmu_idx, vaddr)->addr_##rw &          \
                          TARGET_PAGE_MASK);                                   \
        }                                                                      \
    } while (0)

#ifdef TARGET_MIPS
#define store_capcause_reg(env, reg) cpu_mips_store_capcause_reg(env, reg)
#define clear_capcause_reg(env) cpu_mips_clear_capcause_reg(env)
#else
#define store_capcause_reg(env, reg)
#define clear_capcause_reg(env)
#endif

void *cheri_tag_set(CPUArchState *env, target_ulong vaddr, int reg,
                    hwaddr *ret_paddr, uintptr_t pc, int mmu_idx)
{
    /*
     * This attempt to resolve a virtual address may cause both a data store
     * TLB fault (entry missing or D bit clear) and a capability store TLB
     * fault (SC bit set).
     */
    store_capcause_reg(env, reg);
    // Note: this probe will handle any store cap faults
    void *host_addr = probe_cap_write(env, vaddr, CHERI_CAP_SIZE, mmu_idx, pc);
    clear_capcause_reg(env);

    handle_paddr_return(write);

    if (unlikely(!host_addr)) {
        return NULL;
    }

    uintptr_t tagmem_flags;
    void *tagmem = get_tagmem_from_iotlb_entry(env, vaddr, mmu_idx,
                                               /*write=*/true, &tagmem_flags);

    /* Clear + ALL_ZERO_TAGBLK means no tags can be stored here. */
    if ((tagmem_flags & TLBENTRYCAP_FLAG_CLEAR) &&
        (tagmem == ALL_ZERO_TAGBLK)) {
        return host_addr;
    }

    cheri_debug_assert(!(tagmem_flags & TLBENTRYCAP_FLAG_CLEAR) &&
                       "Unimplemented");

    cheri_debug_assert(!(tagmem_flags & TLBENTRYCAP_FLAG_TRAP));

    /*
     * probe_cap_write() should have ensured there was a tagmem for this
     * location. A NULL ram should have been indicated via
     * TLBENTRYCAPFLAG_CLEAR or TLBENTRYCAPFLAG_TRAP.
     */
    cheri_debug_assert(tagmem != ALL_ZERO_TAGBLK);

    target_ulong tag_offset = page_vaddr_to_tag_offset(vaddr);

    qemu_maybe_log_instr_extra(
        env, "    Cap Tag Write [" TARGET_FMT_lx "/" RAM_ADDR_FMT "] %d -> 1\n",
        vaddr, qemu_ram_addr_from_host(host_addr),
        tagblock_get_tag_tagmem(tagmem, tag_offset));

    tagblock_set_tag_tagmem(tagmem, tag_offset);
    return host_addr;
}

bool cheri_tag_get(CPUArchState *env, target_ulong vaddr, int reg,
                   hwaddr *ret_paddr, int *prot, uintptr_t pc, int mmu_idx,
                   void *host_addr)
{

    if (host_addr == NULL) {
        host_addr = probe_read(env, vaddr, CHERI_CAP_SIZE, mmu_idx, pc);
    }
    handle_paddr_return(read);

    uintptr_t tagmem_flags;
    void *tagmem = get_tagmem_from_iotlb_entry(env, vaddr, mmu_idx,
                                               /*write=*/false, &tagmem_flags);

    if (prot) {
        *prot = 0;
        if (tagmem_flags & TLBENTRYCAP_FLAG_CLEAR) {
            *prot |= PAGE_LC_CLEAR;
        }
        if (tagmem_flags & TLBENTRYCAP_FLAG_TRAP) {
            *prot |= PAGE_LC_TRAP;
        }
        if (tagmem_flags & TLBENTRYCAP_FLAG_TRAP_ANY) {
            *prot |= PAGE_LC_TRAP_ANY;
        }
    }

    /*
     * Squash happens in the caller, so read the tagblk even if
     * TLBENTRYCAP_FLAG_CLEAR
     */
    bool result =
        (tagmem == ALL_ZERO_TAGBLK)
            ? 0
            : tagblock_get_tag_tagmem(tagmem, page_vaddr_to_tag_offset(vaddr));

    // XXX: Not atomic w.r.t. writes to tag memory
    qemu_maybe_log_instr_extra(
        env, "    Cap Tag Read [" TARGET_FMT_lx "/" RAM_ADDR_FMT "] -> %d\n",
        vaddr, qemu_ram_addr_from_host(host_addr), result);
    return result;
}

int cheri_tag_get_many(CPUArchState *env, target_ulong vaddr, int reg,
        hwaddr *ret_paddr, uintptr_t pc)
{

    const int mmu_idx = cpu_mmu_index(env, false);
    probe_read(env, vaddr, CAP_TAG_MANY_DATA_SIZE, mmu_idx, pc);
    handle_paddr_return(read);

    uintptr_t tagmem_flags;
    void *tagmem = get_tagmem_from_iotlb_entry(env, vaddr, mmu_idx,
                                               /*write=*/false, &tagmem_flags);

    int result =
        ((tagmem == ALL_ZERO_TAGBLK) || (tagmem_flags & TLBENTRYCAP_FLAG_CLEAR))
            ? 0
            : tagblock_get_tag_many_tagmem(tagmem,
                                           page_vaddr_to_tag_offset(vaddr));

    if ((result && (tagmem_flags & TLBENTRYCAP_FLAG_TRAP)) ||
        (tagmem_flags & TLBENTRYCAP_FLAG_TRAP_ANY)) {
        raise_load_tag_exception(env, vaddr, reg, pc);
    }

    return result;
}

void cheri_tag_set_many(CPUArchState *env, uint32_t tags, target_ulong vaddr,
                        int reg, hwaddr *ret_paddr, uintptr_t pc)
{
    tags &= CAP_TAG_GET_MANY_MASK;

    const int mmu_idx = cpu_mmu_index(env, false);
    store_capcause_reg(env, reg);
    /*
     * We call probe_(cap)_write rather than probe_access since the branches
     * checking access_type can be eliminated.
     */
    if (tags) {
        // Note: this probe will handle any store cap faults
        probe_cap_write(env, vaddr, CAP_TAG_MANY_DATA_SIZE, mmu_idx, pc);
    } else {
        probe_write(env, vaddr, CAP_TAG_MANY_DATA_SIZE, mmu_idx, pc);
    }
    clear_capcause_reg(env);

    handle_paddr_return(write);

    uintptr_t tagmem_flags;
    void *tagmem =
        get_tagmem_from_iotlb_entry(env, vaddr, mmu_idx, true, &tagmem_flags);

    if ((tagmem_flags & TLBENTRYCAP_FLAG_CLEAR) &&
        (tagmem == ALL_ZERO_TAGBLK)) {
        return;
    }

    if (!tags && tagmem == ALL_ZERO_TAGBLK) {
        return;
    }

    cheri_debug_assert(!(tagmem_flags & TLBENTRYCAP_FLAG_CLEAR) &&
                       "Unimplemented");

    /*
     * TLBENTRYCAP_FLAG_TRAP prevents writing non-zero tags, and should have
     * trapped in probe_cap_write().
     */
    assert(tags == 0 || !(tagmem_flags & TLBENTRYCAP_FLAG_TRAP));

    cheri_debug_assert(tagmem);

    tagblock_set_tag_many_tagmem(tagmem, page_vaddr_to_tag_offset(vaddr), tags);
}

bool cheri_tag_get_debug(RAMBlock *ram, ram_addr_t ram_offset)
{
    /* Return zero tag for ROM, etc. */
    if (!ram->cheri_tags) {
        return false;
    }
    cheri_debug_assert(!memory_region_is_rom(ram->mr) &&
                       !memory_region_is_romd(ram->mr));

    cheri_debug_assert(QEMU_ALIGN_DOWN(ram_offset, CHERI_CAP_SIZE) ==
                       ram_offset);

    uint64_t tag = ram_offset / CHERI_CAP_SIZE;
    CheriTagBlock *tagblk = cheri_tag_block(tag, ram);
    const size_t tagblk_index = CAP_TAGBLK_IDX(tag);
    return tagblock_get_tag(tagblk, tagblk_index);
}
