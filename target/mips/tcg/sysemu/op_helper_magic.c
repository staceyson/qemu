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
#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "exec/log_instr.h"
#ifdef TARGET_CHERI
#include "cheri_tagmem.h"
#endif

#define TARGET_PAGE_SIZE_MIN (1 << TARGET_PAGE_BITS_MIN)
static uint8_t ZEROARRAY[TARGET_PAGE_SIZE_MIN];

/* Reduce the length so that addr + len doesn't cross a page boundary.  */
static inline target_ulong adj_len_to_page(target_ulong len, target_ulong addr)
{
#ifndef CONFIG_USER_ONLY
    target_ulong low_bits = (addr & ~TARGET_PAGE_MASK);
    if (low_bits + len - 1 >= TARGET_PAGE_SIZE_MIN) {
        return TARGET_PAGE_SIZE_MIN - low_bits;
    }
#endif
    return len;
}

#define MAGIC_LIBCALL_HELPER_CONTINUATION_FLAG UINT64_C(0xbadc0de)
#define MIPS_REGNUM_V0 2
#define MIPS_REGNUM_V1 3
#define MIPS_REGNUM_A0 4
#define MIPS_REGNUM_A1 5
#define MIPS_REGNUM_A2 6
#define MIPS_REGNUM_A3 7

#ifdef CONFIG_DEBUG_TCG
#define MAGIC_MEMSET_STATS 1
#else
#define MAGIC_MEMSET_STATS 0
#endif

#if MAGIC_MEMSET_STATS != 0
static bool memset_stats_dump_registered = false;

struct nop_stats {
    uint64_t kernel_mode_bytes;
    uint64_t kernel_mode_count;
    uint64_t user_mode_bytes;
    uint64_t user_mode_count;
};

static struct nop_stats magic_memset_zero_bytes;
static struct nop_stats magic_memset_nonzero_bytes;

static struct nop_stats magic_memcpy_bytes;
static struct nop_stats magic_memmove_bytes;
static struct nop_stats magic_bcopy_bytes;

static struct nop_stats magic_memmove_slowpath;

static inline void print_nop_stats(const char* msg, struct nop_stats* stats) {
    warn_report("%s in kernel mode: %" PRId64 " (%f MB) in %" PRId64 " calls\r", msg,
                stats->kernel_mode_bytes, stats->kernel_mode_bytes / (1024.0 * 1024.0), stats->kernel_mode_count);
    warn_report("%s in user   mode: %" PRId64 " (%f MB) in %" PRId64 " calls\r", msg,
                stats->user_mode_bytes, stats->user_mode_bytes / (1024.0 * 1024.0), stats->user_mode_count);
}

static void dump_memset_stats_on_exit(void) {
    print_nop_stats("memset (zero)    with magic nop", &magic_memset_zero_bytes);
    print_nop_stats("memset (nonzero) with magic nop", &magic_memset_nonzero_bytes);
    print_nop_stats("memcpy with magic nop", &magic_memcpy_bytes);
    print_nop_stats("memmove with magic nop", &magic_memmove_bytes);
    print_nop_stats("bcopy with magic nop", &magic_bcopy_bytes);
    print_nop_stats("memmove/memcpy/bcopy slowpath", &magic_memmove_slowpath);
}

static inline void collect_magic_nop_stats(CPUMIPSState *env, struct nop_stats* stats, target_ulong bytes) {
    if (!memset_stats_dump_registered) {
        // TODO: move this to CPU_init
        atexit(dump_memset_stats_on_exit);
        memset_stats_dump_registered = true;
    }
    if (in_kernel_mode(env)) {
        stats->kernel_mode_bytes += bytes;
        stats->kernel_mode_count++;
    } else {
        stats->user_mode_bytes += bytes;
        stats->user_mode_count++;
    }
}
#else
#define collect_magic_nop_stats(env, stats, bytes)
#endif

static inline void
store_byte_and_clear_tag(CPUMIPSState *env, target_ulong vaddr, uint8_t val,
                         MemOpIdx oi, uintptr_t retaddr)
{
    helper_ret_stb_mmu(env, vaddr, val, oi, retaddr);
#ifdef TARGET_CHERI
    // If we returned (i.e. write was successful) we also need to invalidate the
    // tags bit to ensure we are consistent with sb
    cheri_tag_invalidate(env, vaddr, 1, retaddr, cpu_mmu_index(env, false));
#endif
}

static inline void
store_u32_and_clear_tag(CPUMIPSState *env, target_ulong vaddr, uint32_t val,
                         MemOpIdx oi, uintptr_t retaddr)
{
    helper_ret_stw_mmu(env, vaddr, val, oi, retaddr);
#ifdef TARGET_CHERI
    // If we returned (i.e. write was successful) we also need to invalidate the
    // tags bit to ensure we are consistent with sb
    cheri_tag_invalidate(env, vaddr, 4, retaddr, cpu_mmu_index(env, false));
#endif
}

#ifdef TARGET_CHERI
#define CHECK_AND_ADD_DDC(env, perms, ptr, len, retpc) check_ddc(env, perms, ptr, len, retpc);
#else
#define CHECK_AND_ADD_DDC(env, perms, ptr, len, retpc) ptr
#endif

static bool do_magic_memmove(CPUMIPSState *env, uint64_t ra, int dest_regnum, int src_regnum)
{
    tcg_debug_assert(dest_regnum != src_regnum);
    const target_ulong original_dest_ddc_offset = env->active_tc.gpr[dest_regnum]; // $a0 = dest
    const target_ulong original_src_ddc_offset = env->active_tc.gpr[src_regnum];  // $a1 = src
    const target_ulong original_len = env->active_tc.gpr[MIPS_REGNUM_A2];  // $a2 = len
    int mmu_idx = cpu_mmu_index(env, false);
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);
    target_ulong len = original_len;
    target_ulong already_written = 0;
    const bool is_continuation = (env->active_tc.gpr[MIPS_REGNUM_V1] >> 32) == MAGIC_LIBCALL_HELPER_CONTINUATION_FLAG;
    if (is_continuation) {
        // This is a partial write -> $a0 is the original dest argument.
        // The already written bytes (from the partial write) was stored in $v0 by the previous call
        already_written = env->active_tc.gpr[MIPS_REGNUM_V0];
        tcg_debug_assert(already_written < len);
        len -= already_written; // update the remaining length
#if 0
        fprintf(stderr, "--- %s: Got continuation for 0x" TARGET_FMT_lx " byte access at 0x" TARGET_FMT_plx
                        " -- current dest = 0x" TARGET_FMT_plx " -- current len = 0x" TARGET_FMT_lx "\r\n",
                        __func__, original_len, original_dest, dest, len);
#endif
    } else {
        // Not a partial write -> $v0 should be zero otherwise this is a usage error!
        if (env->active_tc.gpr[MIPS_REGNUM_V0] != 0) {
            error_report("ERROR: Attempted to call memset library function "
                          "with non-zero value in $v0 (0x" TARGET_FMT_lx
                          ") and continuation flag not set in $v1 (0x" TARGET_FMT_lx
                          ")!\n", env->active_tc.gpr[MIPS_REGNUM_V0], env->active_tc.gpr[MIPS_REGNUM_V1]);
            do_raise_exception(env, EXCP_RI, GETPC());
        }
    }
    if (len == 0) {
        goto success; // nothing to do
    }
    if (original_src_ddc_offset == original_dest_ddc_offset) {
        already_written = original_len;
        goto success; // nothing to do
    }
    // Check capability bounds for the whole copy
    // If it is going to fail we don't bother doing a partial copy!
    const target_ulong original_src = CHECK_AND_ADD_DDC(env, CAP_PERM_LOAD, original_src_ddc_offset, original_len, ra);
    const target_ulong original_dest = CHECK_AND_ADD_DDC(env, CAP_PERM_STORE, original_dest_ddc_offset, original_len, ra);

    // Mark this as a continuation in $v1 (so that we continue sensibly if we get a tlb miss and longjump out)
    env->active_tc.gpr[MIPS_REGNUM_V1] = (MAGIC_LIBCALL_HELPER_CONTINUATION_FLAG << 32) | env->active_tc.gpr[3];

    const target_ulong dest_past_end = original_dest + original_len;
    const target_ulong src_past_end = original_src + original_len;
#if 0 // FIXME: for some reason this causes errors
    const bool dest_same_page = (original_dest & TARGET_PAGE_MASK) == ((dest_past_end - 1) & TARGET_PAGE_MASK);
    const bool src_same_page = (original_dest & TARGET_PAGE_MASK) == ((dest_past_end - 1) & TARGET_PAGE_MASK);
    // If neither src nor dest buffer cross a page boundary we can just do an address_space_read+write
    // Fast case: less than a page and neither of the buffers crosses a page boundary
    CPUState *cs = env_cpu(env);
    if (dest_same_page && src_same_page) {
        tcg_debug_assert(already_written == 0);
        tcg_debug_assert(len <= TARGET_PAGE_SIZE);
        // The translation operation might trap and longjump out!
        hwaddr src_paddr = cpu_mips_translate_address(env, original_src,
            MMU_DATA_LOAD, ra);
        hwaddr dest_paddr = cpu_mips_translate_address(env, original_dest,
            MMU_DATA_STORE, ra);
        // Do a single load+store to update the MMU flags
        // uint8_t first_value = helper_ret_ldub_mmu(env, original_src, oi, ra);
        // Note: address_space_write will also clear the tag bits!
        MemTxResult result = MEMTX_ERROR;
        uint8_t buffer[TARGET_PAGE_SIZE];
        result = address_space_read(cs->as, src_paddr, MEMTXATTRS_UNSPECIFIED, buffer, len);
        if (result != MEMTX_OK) {
            warn_report("magic memmove: error reading %d bytes from paddr %"HWADDR_PRIx
                        ". Unmapped memory? Error code was %d\r", (int)len, src_paddr, result);
            // same ignored error would happen with normal loads/stores -> just continue
        }
        fprintf(stderr, "Used fast path to read %d bytes\r\n", (int)len);
        // do_hexdump(stderr, buffer, len, original_src);
        // fprintf(stderr, "\r");
        // also write one byte to the target buffer to ensure that the flags are updated
        // store_byte_and_clear_tag(env, original_dest, first_value, oi, ra); // might trap
        result = address_space_write(cs->as, dest_paddr, MEMTXATTRS_UNSPECIFIED, buffer, len);
#ifdef CONFIG_TCG_LOG_INSTR
        if (qemu_log_instr_enabled(env)) {
            for (int i = 0; i < len; i++) {
                helper_qemu_log_instr_load64(env, original_src + i, buffer[i], MO_8);
                helper_qemu_log_instr_store64(env, original_dest + i, buffer[i], MO_8);
            }
        }
#endif
        if (result != MEMTX_OK) {
            warn_report("magic memmove: error writing %d bytes to paddr %"HWADDR_PRIx
                        ". Unmapped memory? Error code was %d\r", (int)len, dest_paddr, result);
            // same ignored error would happen with normal loads/stores -> just continue
        }
        already_written += len;
        env->active_tc.gpr[MIPS_REGNUM_V0] = already_written;
        goto success;
    }
#endif

    const bool has_overlap = MAX(original_dest, original_src) >= MAX(dest_past_end, src_past_end);
    if (has_overlap) {
        warn_report("Found multipage magic memmove with overlap: dst=" TARGET_FMT_plx " src=" TARGET_FMT_plx
                    " len=0x" TARGET_FMT_lx "\r", original_dest, original_src, original_len);
        // slow path: byte copies
    }

    const bool copy_backwards = original_src < original_dest;
    if (copy_backwards) {
        target_ulong current_dest_cursor = original_dest + len - 1;
        target_ulong current_src_cursor = original_src + len - 1;
        /* Slow path (probably attempt to do this to an I/O device or
         * similar, or clearing of a block of code we have translations
         * cached for). Just do a series of byte writes as the architecture
         * demands. It's not worth trying to use a cpu_physical_memory_map(),
         * memset(), unmap() sequence here because:
         *  + we'd need to account for the blocksize being larger than a page
         *  + the direct-RAM access case is almost always going to be dealt
         *    with in the fastpath code above, so there's no speed benefit
         *  + we would have to deal with the map returning NULL because the
         *    bounce buffer was in use
         */
        tcg_debug_assert(original_len - already_written == len);
        collect_magic_nop_stats(env, &magic_memmove_slowpath, len);
        while (already_written < original_len) {
            uint8_t value = helper_ret_ldub_mmu(env, current_src_cursor, oi, ra);
            store_byte_and_clear_tag(env, current_dest_cursor, value, oi, ra); // might trap
             current_dest_cursor--;
            current_src_cursor--;
            already_written++;
            env->active_tc.gpr[MIPS_REGNUM_V0] = already_written;
        }
    } else {
        // copy forwards
        target_ulong current_dest_cursor = original_dest + already_written;
        target_ulong current_src_cursor = original_src + already_written;
        /* Slow path (probably attempt to do this to an I/O device or
         * similar, or clearing of a block of code we have translations
         * cached for). Just do a series of byte writes as the architecture
         * demands. It's not worth trying to use a cpu_physical_memory_map(),
         * memset(), unmap() sequence here because:
         *  + we'd need to account for the blocksize being larger than a page
         *  + the direct-RAM access case is almost always going to be dealt
         *    with in the fastpath code above, so there's no speed benefit
         *  + we would have to deal with the map returning NULL because the
         *    bounce buffer was in use
         */
        tcg_debug_assert(original_len - already_written == len);
        collect_magic_nop_stats(env, &magic_memmove_slowpath, len);
        while (already_written < original_len) {
            uint8_t value = helper_ret_ldub_mmu(env, current_src_cursor, oi, ra);
            store_byte_and_clear_tag(env, current_dest_cursor, value, oi, ra); // might trap
            current_dest_cursor++;
            current_src_cursor++;
            already_written++;
            env->active_tc.gpr[MIPS_REGNUM_V0] = already_written;
        }
    }

    env->lladdr = 1;
success:
    if (unlikely(already_written != original_len)) {
        error_report("ERROR: %s: failed to memmove all bytes to " TARGET_FMT_plx " (" TARGET_FMT_plx " with $ddc added).\r\n"
                     "Remainig len = " TARGET_FMT_plx ", full len = " TARGET_FMT_plx ".\r\n"
                     "Source address = " TARGET_FMT_plx " (" TARGET_FMT_plx " with $ddc added)\r\n",
                     __func__, original_dest_ddc_offset, original_dest, len, original_len, original_src_ddc_offset, original_src);
        error_report("$a0: " TARGET_FMT_plx "\r\n", env->active_tc.gpr[MIPS_REGNUM_A0]);
        error_report("$a1: " TARGET_FMT_plx "\r\n", env->active_tc.gpr[MIPS_REGNUM_A1]);
        error_report("$a2: " TARGET_FMT_plx "\r\n", env->active_tc.gpr[MIPS_REGNUM_A2]);
        error_report("$v0: " TARGET_FMT_plx "\r\n", env->active_tc.gpr[MIPS_REGNUM_V0]);
        error_report("$v1: " TARGET_FMT_plx "\r\n", env->active_tc.gpr[MIPS_REGNUM_V1]);
        abort();
    }
    env->active_tc.gpr[MIPS_REGNUM_V0] = original_dest_ddc_offset; // return value of memcpy is the dest argument
    return true;
}

static void do_memset_pattern_hostaddr(void* hostaddr, uint64_t value, uint64_t nitems, unsigned pattern_length, uint64_t ra) {
    if (pattern_length == 1) {
        memset(hostaddr, value, nitems);
    } else if (pattern_length == 4) {
        uint32_t* ptr = hostaddr;
        uint32_t target_value = tswap32((uint32_t)value);
        for (target_ulong i = 0; i < nitems; i++) {
            *ptr = target_value;
            ptr++;
        }
    } else {
        assert(false && "unsupported memset pattern length");
    }
}

static bool do_magic_memset(CPUMIPSState *env, uint64_t ra, uint pattern_length)
{
    // TODO: just use address_space_write?

    // See target/s390x/mem_helper.c and arm/helper.c HELPER(dc_zva)
    int mmu_idx = cpu_mmu_index(env, false);
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);

    const target_ulong original_dest_ddc_offset = env->active_tc.gpr[MIPS_REGNUM_A0];      // $a0 = dest
    uint64_t value = env->active_tc.gpr[MIPS_REGNUM_A1]; // $a1 = c
    const target_ulong original_len_nitems = env->active_tc.gpr[MIPS_REGNUM_A2];       // $a2 = len
    const target_ulong original_len_bytes = original_len_nitems * pattern_length;
    target_ulong dest = original_dest_ddc_offset;
    target_ulong len_nitems = original_len_nitems;
    const bool is_continuation = (env->active_tc.gpr[MIPS_REGNUM_V1] >> 32) == MAGIC_LIBCALL_HELPER_CONTINUATION_FLAG;
    if (is_continuation) {
        // This is a partial write -> $a0 is the original dest argument.
        // The updated dest (after the partial write) was stored in $v0 by the previous call
        dest = env->active_tc.gpr[MIPS_REGNUM_V0];
        if (dest < original_dest_ddc_offset || dest >= original_dest_ddc_offset + original_len_bytes) {
            error_report("ERROR: Attempted to call memset library function "
                         "with invalid dest in $v0 (0x" TARGET_FMT_lx
                         ") and continuation flag set. orig dest = 0x" TARGET_FMT_lx
                         " and orig bytes = 0x" TARGET_FMT_lx "!\n",
                         env->active_tc.gpr[MIPS_REGNUM_V0], env->active_tc.gpr[MIPS_REGNUM_A0],
                         env->active_tc.gpr[MIPS_REGNUM_A2]);
            do_raise_exception(env, EXCP_RI, ra);
        }
        target_ulong already_written = dest - original_dest_ddc_offset;
        len_nitems -= already_written / pattern_length; // update the remaining length
        assert((already_written % pattern_length) == 0);
#if 0
        fprintf(stderr, "--- %s: Got continuation for 0x" TARGET_FMT_lx " byte access at 0x" TARGET_FMT_plx
                        " -- current dest = 0x" TARGET_FMT_plx " -- current len = 0x" TARGET_FMT_lx "\r\n",
                        __func__, original_len, original_dest, dest, len_nitems);
#endif
    } else {
        // Not a partial write -> $v0 should be zero otherwise this is a usage error!
        if (env->active_tc.gpr[MIPS_REGNUM_V0] != 0) {
            error_report("ERROR: Attempted to call memset library function "
                         "with non-zero value in $v0 (0x" TARGET_FMT_lx
                         ") and continuation flag not set in $v1 (0x" TARGET_FMT_lx
                         ")!\n", env->active_tc.gpr[MIPS_REGNUM_V0], env->active_tc.gpr[MIPS_REGNUM_V1]);
            do_raise_exception(env, EXCP_RI, ra);
        }
    }

    if (len_nitems == 0) {
        goto success; // nothing to do
    }

    dest = CHECK_AND_ADD_DDC(env, CAP_PERM_STORE, dest, len_nitems * pattern_length, ra);
    const target_ulong original_dest = CHECK_AND_ADD_DDC(env, CAP_PERM_STORE, original_dest_ddc_offset, original_len_nitems, ra);

    tcg_debug_assert(dest + (len_nitems * pattern_length) == original_dest + original_len_bytes && "continuation broken?");

    CPUState *cs = env_cpu(env);

    while (len_nitems > 0) {
        const target_ulong total_len_nbytes = len_nitems * pattern_length;
        assert(dest + total_len_nbytes == original_dest + original_len_bytes && "continuation broken?");
        // probing for write access:
        // fprintf(stderr, "Probing for write access at " TARGET_FMT_plx "\r\n", dest);
        // fflush(stderr);
        // update $v0 to point to the updated dest in case probe_write_access takes a tlb fault:
        env->active_tc.gpr[MIPS_REGNUM_V0] = dest;
        // and mark this as a continuation in $v1 (so that we continue sensibly after the tlb miss was handled)
        env->active_tc.gpr[MIPS_REGNUM_V1] = (MAGIC_LIBCALL_HELPER_CONTINUATION_FLAG << 32) | env->active_tc.gpr[3];
        // If the host address is not in the tlb after the second write we are writing
        // to something strange so just fall back to the slowpath
        target_ulong l_adj_bytes = adj_len_to_page(total_len_nbytes, dest);
        target_ulong l_adj_nitems = l_adj_bytes;
        if (unlikely(pattern_length != 1)) {
            l_adj_nitems = l_adj_bytes / pattern_length;
        }
        tcg_debug_assert(l_adj_nitems != 0);
        tcg_debug_assert(((dest + l_adj_bytes - 1) & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK) && "should not cross a page boundary!");
        void* hostaddr = NULL;
#if 0
        for (int try = 0; try < 2; try++) {
            hostaddr = tlb_vaddr_to_host(env, dest, 1, mmu_idx);
            if (hostaddr)
                break;
            /* OK, try a store and see if we can populate the tlb. This
             * might cause an exception if the memory isn't writable,
             * in which case we will longjmp out of here. We must for
             * this purpose use the actual register value passed to us
             * so that we get the fault address right.
             */
            store_byte_and_clear_tag(env, dest, 0xff, oi, ra);
            // This should definitely fill the host TLB. If not we are probably writing to I/O memory
            // FIXME: tlb_vaddr_to_host() also returns null if the notdirty flag is set (not sure if that's a bug
            probe_write(env, dest, 1, mmu_idx, ra);
        }
#endif
        if (hostaddr) {
            /* If it's all in the TLB it's fair game for just writing to;
             * we know we don't need to update dirty status, etc.
             */
            tcg_debug_assert(dest + total_len_nbytes == original_dest + original_len_bytes && "continuation broken?");
            // Do one store byte to update MMU flags (not sure this is necessary)
            store_byte_and_clear_tag(env, dest, value, oi, ra);
            do_memset_pattern_hostaddr(hostaddr, value, l_adj_nitems, pattern_length, ra);
#ifdef TARGET_CHERI
            // We also need to invalidate the tags bits written by the memset
            // qemu_ram_addr_from_host is faster than using the v2r routines in cheri_tag_invalidate
            ram_addr_t ram_offset;
            RAMBlock *block = qemu_ram_block_from_host(hostaddr, false, &ram_offset);
            cheri_tag_phys_invalidate(env, block, ram_offset, l_adj_bytes, &dest);
#endif
#ifdef CONFIG_TCG_LOG_INSTR
            if (qemu_log_instr_enabled(env)) {
                // TODO: dump as a single big block?
                for (target_ulong i = 0; i < l_adj_nitems; i++) {
                    if (pattern_length == 1)
                        helper_qemu_log_instr_store64(env, dest + i, value, MO_8);
                    else if (pattern_length == 4)
                        helper_qemu_log_instr_store64(
                            env, dest + (i * pattern_length), value, MO_32);
                    else
                        assert(false && "invalid pattern length");
                }
                qemu_log_instr_extra(env, "%s: Set " TARGET_FMT_ld
                    " %d-byte items to 0x%" PRIx64 " at 0x" TARGET_FMT_plx "\n",
                    __func__, l_adj_nitems, pattern_length, value, dest);
            }
#endif
            // fprintf(stderr, "%s: Set " TARGET_FMT_ld " bytes to 0x%x at 0x" TARGET_FMT_plx "/%p\r\n", __func__, l_adj, value, dest, hostaddr);
            dest += l_adj_bytes;
            len_nitems -= l_adj_nitems;
        } else {
            // First try address_space_write and if that fails fall back to bytewise setting
            hwaddr paddr = cpu_mips_translate_address(env, dest, MMU_DATA_STORE, ra);
            // Note: address_space_write will also clear the tag bits!
            MemTxResult result = MEMTX_ERROR;
            if (value == 0) {
                tcg_debug_assert(l_adj_bytes <= sizeof(ZEROARRAY));
                result = address_space_write(cs->as, paddr, MEMTXATTRS_UNSPECIFIED, ZEROARRAY, l_adj_bytes);
            } else {
                // create a buffer filled with the correct value and use that for the write
                uint8_t setbuffer[TARGET_PAGE_SIZE_MIN];
                tcg_debug_assert(l_adj_bytes <= sizeof(setbuffer));
                do_memset_pattern_hostaddr(setbuffer, value, l_adj_nitems, pattern_length, ra);
                result = address_space_write(cs->as, paddr, MEMTXATTRS_UNSPECIFIED, setbuffer, l_adj_bytes);
            }
            if (result == MEMTX_OK) {
                dest += l_adj_bytes;
                len_nitems -= l_adj_nitems;
#ifdef CONFIG_TCG_LOG_INSTR
                if (qemu_log_instr_enabled(env)) {
                    // TODO: dump as a single big block?
                    for (target_ulong i = 0; i < l_adj_nitems; i++) {
                        if (pattern_length == 1)
                            helper_qemu_log_instr_store64(
                                env, dest + i, value, MO_8);
                        else if (pattern_length == 4)
                            helper_qemu_log_instr_store64(
                                env, dest + (i * pattern_length), value, MO_32);
                        else
                            assert(false && "invalid pattern length");
                    }
                    qemu_log_instr_extra(env, "%s: Set " TARGET_FMT_ld
                        " %d-byte items to 0x%" PRIx64 " at 0x" TARGET_FMT_plx "\n",
                        __func__, l_adj_nitems, pattern_length, value, dest);
                }
#endif
                continue; // try again with next page
            } else {
                warn_report("address_space_write failed with error %d for %"HWADDR_PRIx "\r", result, paddr);
                // fall back to bytewise copy slow path
            }
            /* Slow path (probably attempt to do this to an I/O device or
             * similar, or clearing of a block of code we have translations
             * cached for). Just do a series of byte writes as the architecture
             * demands. It's not worth trying to use a cpu_physical_memory_map(),
             * memset(), unmap() sequence here because:
             *  + we'd need to account for the blocksize being larger than a page
             *  + the direct-RAM access case is almost always going to be dealt
             *    with in the fastpath code above, so there's no speed benefit
             *  + we would have to deal with the map returning NULL because the
             *    bounce buffer was in use
             */
            warn_report("%s: Falling back to memset slowpath for address "
                        TARGET_FMT_plx " (phys addr=%" HWADDR_PRIx", len_nitems=0x"
                        TARGET_FMT_lx ")! I/O memory or QEMU TLB bug?\r",
                        __func__, dest, mips_cpu_get_phys_page_debug(env_cpu(env), dest), len_nitems);
            target_ulong end = original_dest + original_len_bytes;
            tcg_debug_assert(((end - dest) % pattern_length) == 0);
            // in case we fault mark this as a continuation in $v1 (so that we continue sensibly after the tlb miss was handled)
            env->active_tc.gpr[MIPS_REGNUM_V1] = (MAGIC_LIBCALL_HELPER_CONTINUATION_FLAG << 32) | env->active_tc.gpr[MIPS_REGNUM_V1];
            while (dest < end) {
                tcg_debug_assert(dest + (len_nitems * pattern_length) == original_dest + original_len_bytes && "continuation broken?");
                // update $v0 to point to the updated dest in case probe_write_access takes a tlb fault:
                env->active_tc.gpr[MIPS_REGNUM_V0] = dest;
                if (pattern_length == 1) {
                    store_byte_and_clear_tag(env, dest, value, oi, ra); // might trap
                } else if (pattern_length == 4) {
                    store_u32_and_clear_tag(env, dest, value, oi, ra); // might trap
                } else {
                    assert(false && "invalid pattern length");
                }
#ifdef CONFIG_TCG_LOG_INSTR
                if (qemu_log_instr_enabled(env)) {
                    if (pattern_length == 1)
                        helper_qemu_log_instr_store64(env, dest, value, MO_8);
                    else if (pattern_length == 4)
                        helper_qemu_log_instr_store64(env, dest, value, MO_32);
                    else
                        assert(false && "invalid pattern length");
                    helper_qemu_log_instr_store64(env, dest, value, MO_8);
                }
#endif
                dest += pattern_length;
                len_nitems--;
            }
        }
    }
    tcg_debug_assert(len_nitems == 0);
    env->lladdr = 1;
success:
    env->active_tc.gpr[MIPS_REGNUM_V0] = original_dest_ddc_offset; // return value of memset is the src argument
    // also update a0 and a2 to match what the kernel memset does (a0 -> buf end, a2 -> 0):
    env->active_tc.gpr[MIPS_REGNUM_A0] = dest;
    env->active_tc.gpr[MIPS_REGNUM_A2] = len_nitems;
#if MAGIC_MEMSET_STATS != 0
    collect_magic_nop_stats(env, value == 0 ? &magic_memset_zero_bytes : &magic_memset_nonzero_bytes, original_len_bytes);
#endif
    return true;
}

#define MAGIC_HELPER_DONE_FLAG 0xDEC0DED

enum {
    MAGIC_NOP_MEMSET = 1,
    MAGIC_NOP_MEMSET_C = 2,
    MAGIC_NOP_MEMCPY = 3,
    MAGIC_NOP_MEMCPY_C = 4,
    MAGIC_NOP_MEMMOVE = 5,
    MAGIC_NOP_MEMMOVE_C = 6,
    MAGIC_NOP_BCOPY = 7,
    MAGIC_NOP_U32_MEMSET = 8,
};

// Magic library function calls:
void helper_magic_library_function(CPUMIPSState *env, target_ulong which)
{
    qemu_log_instr_extra(env, "--- Calling magic library function 0x"
                         TARGET_FMT_lx "\n", which);
    // High bits can be used by function to indicate continuation after TLB miss
    switch (which & UINT32_MAX) {
    case MAGIC_NOP_MEMSET:
        if (!do_magic_memset(env, GETPC(), /*pattern_size=*/1))
            return;
        // otherwise update $v1 to indicate success
        break;

    case MAGIC_NOP_U32_MEMSET:
        if (!do_magic_memset(env, GETPC(), /*pattern_size=*/4))
            return;
        // otherwise update $v1 to indicate success
        break;

    case MAGIC_NOP_MEMCPY:
        if (!do_magic_memmove(env, GETPC(), MIPS_REGNUM_A0, MIPS_REGNUM_A1))
            goto error;
        collect_magic_nop_stats(env, &magic_memcpy_bytes, env->active_tc.gpr[MIPS_REGNUM_A2]);
        break;

    case MAGIC_NOP_MEMMOVE:
        if (!do_magic_memmove(env, GETPC(), MIPS_REGNUM_A0, MIPS_REGNUM_A1))
            goto error;
        collect_magic_nop_stats(env, &magic_memmove_bytes, env->active_tc.gpr[MIPS_REGNUM_A2]);
        break;

    case MAGIC_NOP_BCOPY: // src + dest arguments swapped
        if (!do_magic_memmove(env, GETPC(), MIPS_REGNUM_A1, MIPS_REGNUM_A0))
            goto error;
        collect_magic_nop_stats(env, &magic_bcopy_bytes, env->active_tc.gpr[MIPS_REGNUM_A2]);
        break;

    case 0xf0:
    case 0xf1:
    {
        uint8_t buffer[TARGET_PAGE_SIZE_MIN];
        // to match memset/memcpy calling convention (use a0 and a2)
        target_ulong src = env->active_tc.gpr[MIPS_REGNUM_A0];
        target_ulong real_len = env->active_tc.gpr[MIPS_REGNUM_A2];
        fprintf(stderr, "--- Memory dump at %s(%s): " TARGET_FMT_lu " bytes at " TARGET_FMT_plx "\r\n",
                lookup_symbol(PC_ADDR(env)), ((which & UINT32_MAX) == 0xf0 ? "entry" : "exit"), real_len, src);
        while (real_len > 0) {
            target_ulong len = adj_len_to_page(real_len, src);
            real_len -= len;
            if (len != env->active_tc.gpr[MIPS_REGNUM_A2]) {
                fprintf(stderr, "--- partial dump at %s(%s): " TARGET_FMT_lu " bytes at " TARGET_FMT_plx "\r\n",
                        lookup_symbol(PC_ADDR(env)), ((which & UINT32_MAX) == 0xf0 ? "entry" : "exit"), len, src);
            }
            if (cpu_memory_rw_debug(env_cpu(env), src, buffer, len, false) == 0) {
                bool have_nonzero = false;
                for (int i = 0; i < len; i++)
                    if (buffer[i] != 0)
                        have_nonzero = true;
                if (have_nonzero) {
                    /* This is probably inefficient but we don't dump that much.. */
                    GString *strbuf = g_string_sized_new(TARGET_PAGE_SIZE_MIN);
                    do_hexdump(strbuf, buffer, len, src);
                    fwrite(strbuf->str, strbuf->len, 1, stderr);
                    g_string_free(strbuf, true);
                }
                else
                    fprintf(stderr, "   -- all zeroes\r\n");
            } else {
                fprintf(stderr, "--- Memory dump at %s(%s): Could not fetch" TARGET_FMT_lu " bytes at " TARGET_FMT_plx "\r\n",
                        lookup_symbol(PC_ADDR(env)), ((which & UINT32_MAX) == 0xf0 ? "entry" : "exit"), len, src);
            }
        }
    }
    case 0xfe:
    case 0xff:
        // dump argument and return registers:
        warn_report("%s(%s): argument+return registers: \r\n"
                    "\tv0 = 0x" TARGET_FMT_lx "\tv1 = 0x" TARGET_FMT_lx "\r\n"
                    "\ta0 = 0x" TARGET_FMT_lx "\ta1 = 0x" TARGET_FMT_lx "\r\n"
                    "\ta2 = 0x" TARGET_FMT_lx "\ta3 = 0x" TARGET_FMT_lx "\r\n",
                    lookup_symbol(PC_ADDR(env)), ((which & UINT32_MAX) == 0xfe ? "entry" : "exit"),
                    env->active_tc.gpr[2], env->active_tc.gpr[3],
                    env->active_tc.gpr[4], env->active_tc.gpr[5],
                    env->active_tc.gpr[6], env->active_tc.gpr[7]);
        break;
    case MAGIC_HELPER_DONE_FLAG:
        qemu_maybe_log_instr_extra(env, "ERROR: Attempted to call library "
            "function with success flag set in $v1!\n");
        do_raise_exception(env, EXCP_RI, GETPC());
    default:
        qemu_maybe_log_instr_extra(env, "ERROR: Attempted to call invalid "
            "library function " TARGET_FMT_lx "\n", which);
        return;
    }
    // Indicate success by setting $v1 to 0xaffe
    env->active_tc.gpr[MIPS_REGNUM_V1] = MAGIC_HELPER_DONE_FLAG;
    return;
error:
    warn_report("%s: magic nop %d failed: \r\n"
                    "\tv0 = 0x" TARGET_FMT_lx "\tv1 = 0x" TARGET_FMT_lx "\r\n"
                    "\ta0 = 0x" TARGET_FMT_lx "\ta1 = 0x" TARGET_FMT_lx "\r\n"
                    "\ta2 = 0x" TARGET_FMT_lx "\ta3 = 0x" TARGET_FMT_lx "\r\n",
                    __func__, (int)(which & UINT32_MAX),
                    env->active_tc.gpr[MIPS_REGNUM_V0], env->active_tc.gpr[MIPS_REGNUM_V1],
                    env->active_tc.gpr[MIPS_REGNUM_A0], env->active_tc.gpr[MIPS_REGNUM_A1],
                    env->active_tc.gpr[MIPS_REGNUM_A2], env->active_tc.gpr[MIPS_REGNUM_A3]);
}

void helper_smp_yield(CPUMIPSState *env) {
    CPUState *cs = env_cpu(env);
    cs->exception_index = EXCP_YIELD;

    cpu_loop_exit(cs);
}
