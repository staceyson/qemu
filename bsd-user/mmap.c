/*
 *  mmap support for qemu
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
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

#include <sys/param.h>

#include "qemu.h"
#include "qemu-common.h"
#include "translate-all.h"

#ifdef TARGET_CHERI
#include "exec/ramblock.h"
#include "target/cheri-common/cheri_usermem.h"
#endif

#include "target_os_errno.h"
#include "target_os_syscallsubr.h"
#include "target_os_mman.h"

#include "machine/vmparam.h"
#include "target_arch_param.h"
#include "target_arch_vmparam.h"

#ifdef TARGET_CHERI
#include "cheri/cherireg.h"
#include "cheri/cheric.h"
#include "cheri/cheri.h"
#endif

static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int mmap_lock_count;

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        pthread_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    if (--mmap_lock_count == 0) {
        pthread_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0 ? true : false;
}

/* Grab lock to make sure things are in a consistent state after fork().  */
void mmap_fork_start(void)
{
    if (mmap_lock_count)
        abort();
    pthread_mutex_lock(&mmap_mutex);
}

void mmap_fork_end(int child)
{
    if (child)
        pthread_mutex_init(&mmap_mutex, NULL);
    else
        pthread_mutex_unlock(&mmap_mutex);
}

#ifdef TARGET_CHERI
#define PERM_READ  (CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define PERM_WRITE (CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
                    CHERI_PERM_STORE_LOCAL_CAP)
#define PERM_EXEC  CHERI_PERM_EXECUTE
#define PERM_RWX   (PERM_READ | PERM_WRITE | PERM_EXEC)
/*
 * Given a starting set of CHERI permissions (operms), set (not AND) the load,
 * store, and execute permissions based on the mmap permissions (prot).
 *
 * This function is intended to be used when creating a capability to a
 * new region or rederiving a capability when upgrading a sub-region.
 */
static register_t
mmap_prot2perms(int prot)
{
    register_t perms = 0;

    if (prot & PROT_READ)
        perms |= CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP;
    if (prot & PROT_WRITE)
        perms |= CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
        CHERI_PERM_STORE_LOCAL_CAP;
    if (prot & PROT_EXEC)
        perms |= CHERI_PERM_EXECUTE;

    return (perms);
}

static cap_register_t
mmap_retcap(vm_offset_t addr, const struct mmap_req *mrp)
{
    cap_register_t newcap;
    size_t cap_base, cap_len;
    register_t perms, cap_prot;

    /*
     * Return the original capability when MAP_CHERI_NOSETBOUNDS is set.
     *
     * NB: This means no permission changes.
     * The assumption is that the larger capability has the correct
     * permissions and we're only intrested in adjusting page mappings.
     */
    if (mrp->mr_flags & MAP_CHERI_NOSETBOUNDS)
        return (mrp->mr_source_cap);

    newcap = mrp->mr_source_cap;

    /*
     * If PROT_MAX() was not passed, use the prot value to derive
     * capability permissions.
     */
    cap_prot = PROT_MAX_EXTRACT(mrp->mr_prot);
    if (cap_prot == 0)
        cap_prot = PROT_EXTRACT(mrp->mr_prot);
    /*
     * Set the permissions to PROT_MAX to allow a full
     * range of access subject to page permissions.
     */
    perms = ~PERM_RWX | mmap_prot2perms(cap_prot);
    (void)cheri_andperm(&newcap, perms);

    if (mrp->mr_flags & MAP_FIXED) {
        /*
         * If hint was under aligned, we need to return a
         * capability to the whole, properly aligned region
         * with the offset pointing to hint.
         */
        cap_base = cheri_getbase(&newcap);
        /* TODO: use cheri_setaddress? */
        /* Set offset to vaddr of page */
        (void)cheri_setoffset(&newcap, rounddown2(addr, TARGET_PAGE_SIZE) -
            cap_base);
        (void)cheri_setbounds(&newcap,
            roundup2(mrp->mr_len + (addr - rounddown2(addr, TARGET_PAGE_SIZE)),
            TARGET_PAGE_SIZE));
        /* Shift offset up if required */
        cap_base = cheri_getbase(&newcap);
        (void)cheri_setoffset(&newcap, cap_base - addr);
    } else {
        cap_base = cheri_getbase(&newcap);
        cap_len = cheri_getlen(&newcap);
        assert(addr >= cap_base && addr + mrp->mr_len <= cap_base + cap_len);
        (void)cheri_setbounds(cheri_setoffset(&newcap, addr - cap_base),
            roundup2(mrp->mr_len, TARGET_PAGE_SIZE));
    }

    return (newcap);
}
#endif

/* NOTE: all the constants are the HOST ones, but addresses are target. */
int target_mprotect(abi_ulong start, abi_ulong len, int prot)
{
    abi_ulong end, host_start, host_end, addr;
    int prot1, ret;

#ifdef DEBUG_MMAP
    printf("mprotect: start=0x" TARGET_ABI_FMT_lx
           "len=0x" TARGET_ABI_FMT_lx " prot=%c%c%c\n", start, len,
           prot & PROT_READ ? 'r' : '-',
           prot & PROT_WRITE ? 'w' : '-',
           prot & PROT_EXEC ? 'x' : '-');
#endif

    if ((start & ~TARGET_PAGE_MASK) != 0)
        return -EINVAL;
    len = TARGET_PAGE_ALIGN(len);
    end = start + len;
    if (end < start)
        return -EINVAL;
    prot &= PROT_READ | PROT_WRITE | PROT_EXEC;
    if (len == 0)
        return 0;

    mmap_lock();
    host_start = start & qemu_host_page_mask;
    host_end = HOST_PAGE_ALIGN(end);
    if (start > host_start) {
        /* handle host page containing start */
        prot1 = prot;
        for(addr = host_start; addr < start; addr += TARGET_PAGE_SIZE) {
            prot1 |= page_get_flags(addr);
        }
        if (host_end == host_start + qemu_host_page_size) {
            for(addr = end; addr < host_end; addr += TARGET_PAGE_SIZE) {
                prot1 |= page_get_flags(addr);
            }
            end = host_end;
        }
        ret = mprotect(g2h_untagged(host_start),
                       qemu_host_page_size, prot1 & PAGE_BITS);
        if (ret != 0)
            goto error;
        host_start += qemu_host_page_size;
    }
    if (end < host_end) {
        prot1 = prot;
        for(addr = end; addr < host_end; addr += TARGET_PAGE_SIZE) {
            prot1 |= page_get_flags(addr);
        }
        ret = mprotect(g2h_untagged(host_end - qemu_host_page_size),
                       qemu_host_page_size, prot1 & PAGE_BITS);
        if (ret != 0)
            goto error;
        host_end -= qemu_host_page_size;
    }

    /* handle the pages in the middle */
    if (host_start < host_end) {
        ret = mprotect(g2h_untagged(host_start), host_end - host_start, prot);
        if (ret != 0)
            goto error;
    }
    page_set_flags(start, start + len, prot | PAGE_VALID);
    mmap_unlock();
    return 0;
error:
    mmap_unlock();
    return ret;
}

/* map an incomplete host page */
static int mmap_frag(abi_ulong real_start,
                     abi_ulong start, abi_ulong end,
                     int prot, int flags, int fd, abi_ulong offset)
{
    abi_ulong real_end, addr;
    void *host_start;
    int prot1, prot_new;

    real_end = real_start + qemu_host_page_size;
    host_start = g2h_untagged(real_start);

    /* get the protection of the target pages outside the mapping */
    prot1 = 0;
    for(addr = real_start; addr < real_end; addr++) {
        if (addr < start || addr >= end)
            prot1 |= page_get_flags(addr);
    }

    if (prot1 == 0) {
        /* no page was there, so we allocate one */
        void *p = mmap(host_start, qemu_host_page_size, prot,
                       flags | ((fd != -1) ? MAP_ANONYMOUS : 0), -1, 0);
        if (p == MAP_FAILED)
            return -1;
        prot1 = prot;
    }
    prot1 &= PAGE_BITS;

    prot_new = prot | prot1;
    if (fd != -1) {
        /* msync() won't work here, so we return an error if write is
           possible while it is a shared mapping */
        if ((flags & TARGET_BSD_MAP_FLAGMASK) == MAP_SHARED &&
            (prot & PROT_WRITE))
            return -1;

        /* adjust protection to be able to read */
        if (!(prot1 & PROT_WRITE))
            mprotect(host_start, qemu_host_page_size, prot1 | PROT_WRITE);

        /* read the corresponding file data */
        if (pread(fd, g2h_untagged(start), end - start, offset) == -1)
            return -1;

        /* put final protection */
        if (prot_new != (prot1 | PROT_WRITE))
            mprotect(host_start, qemu_host_page_size, prot_new);
    } else {
        if (prot_new != prot1) {
            mprotect(host_start, qemu_host_page_size, prot_new);
        }
        if (prot_new & PROT_WRITE) {
            memset(g2h(start), 0, end - start);
        }
    }
    return 0;
}

#if HOST_LONG_BITS == 64 && TARGET_ABI_BITS == 64
# define TASK_UNMAPPED_BASE  (1ul << 38)
#else
# define TASK_UNMAPPED_BASE  0x40000000
#endif
abi_ulong mmap_next_start = TASK_UNMAPPED_BASE;

unsigned long last_brk;

/* Subroutine of mmap_find_vma, used when we have pre-allocated a chunk
   of guest address space.  */
static abi_ulong mmap_find_vma_reserved(abi_ulong start, abi_ulong size, abi_ulong alignment)
{
    abi_ulong addr;
    abi_ulong end_addr;
    int prot;
    int looped = 0;

    if (size > reserved_va) {
        return (abi_ulong)-1;
    }

    size = HOST_PAGE_ALIGN(size) + alignment;
    end_addr = start + size;
    if (end_addr > reserved_va) {
        end_addr = reserved_va;
    }
    addr = end_addr - qemu_host_page_size;

    while (1) {
        if (addr > end_addr) {
            if (looped) {
                return (abi_ulong)-1;
            }
            end_addr = reserved_va;
            addr = end_addr - qemu_host_page_size;
            looped = 1;
            continue;
        }
        prot = page_get_flags(addr);
        if (prot) {
            end_addr = addr;
        }
        if (end_addr - addr >= size) {
            break;
        }
        addr -= qemu_host_page_size;
    }

    if (start == mmap_next_start) {
        mmap_next_start = addr;
    }
    /* addr is sufficiently low to align it up */
    if (alignment != 0)
        addr = (addr + alignment) & ~(alignment - 1);
    return addr;
}

/*
 * Find and reserve a free memory area of size 'size'. The search
 * starts at 'start'.
 * It must be called with mmap_lock() held.
 * Return -1 if error.
 */
static abi_ulong mmap_find_vma_aligned(abi_ulong start, abi_ulong size, abi_ulong alignment)
{
    void *ptr, *prev;
    abi_ulong addr;
    int flags;
    int wrapped, repeat;

    /* If 'start' == 0, then a default start address is used. */
    if (start == 0) {
        start = mmap_next_start;
    } else {
        start &= qemu_host_page_mask;
    }

    size = HOST_PAGE_ALIGN(size);

    if (reserved_va) {
        return mmap_find_vma_reserved(start, size,
            (alignment != 0 ? 1 << alignment : 0));
    }

    addr = start;
    wrapped = repeat = 0;
    prev = 0;
    flags = MAP_ANONYMOUS|MAP_PRIVATE;
    if (alignment != 0)
		flags |= MAP_ALIGNED(alignment);

    for (;; prev = ptr) {
        /*
         * Reserve needed memory area to avoid a race.
         * It should be discarded using:
         *  - mmap() with MAP_FIXED flag
         *  - mremap() with MREMAP_FIXED flag
         *  - shmat() with SHM_REMAP flag
         */
        ptr = mmap(g2h(addr), size, PROT_NONE,
                   flags, -1, 0);

        /* ENOMEM, if host address space has no memory */
        if (ptr == MAP_FAILED) {
            return (abi_ulong)-1;
        }

        /* Count the number of sequential returns of the same address.
           This is used to modify the search algorithm below.  */
        repeat = (ptr == prev ? repeat + 1 : 0);

        if (h2g_valid(ptr + size - 1)) {
            addr = h2g(ptr);

            if ((addr & ~TARGET_PAGE_MASK) == 0) {
                /* Success.  */
                if (start == mmap_next_start && addr >= TASK_UNMAPPED_BASE) {
                    mmap_next_start = addr + size;
                }
                return addr;
            }

            /* The address is not properly aligned for the target.  */
            switch (repeat) {
            case 0:
                /* Assume the result that the kernel gave us is the
                   first with enough free space, so start again at the
                   next higher target page.  */
                addr = TARGET_PAGE_ALIGN(addr);
                break;
            case 1:
                /* Sometimes the kernel decides to perform the allocation
                   at the top end of memory instead.  */
                addr &= TARGET_PAGE_MASK;
                break;
            case 2:
                /* Start over at low memory.  */
                addr = 0;
                break;
            default:
                /* Fail.  This unaligned block must the last.  */
                addr = -1;
                break;
            }
        } else {
            /* Since the result the kernel gave didn't fit, start
               again at low memory.  If any repetition, fail.  */
            addr = (repeat ? -1 : 0);
        }

        /* Unmap and try again.  */
        munmap(ptr, size);

        /* ENOMEM if we checked the whole of the target address space.  */
        if (addr == (abi_ulong)-1) {
            return (abi_ulong)-1;
        } else if (addr == 0) {
            if (wrapped) {
                return (abi_ulong)-1;
            }
            wrapped = 1;
            /* Don't actually use 0 when wrapping, instead indicate
               that we'd truly like an allocation in low memory.  */
            addr = TARGET_PAGE_SIZE;
        } else if (wrapped && addr >= start) {
            return (abi_ulong)-1;
        }
    }
}

abi_ulong mmap_find_vma(abi_ulong start, abi_ulong size)
{
    return mmap_find_vma_aligned(start, size, 0);
}

abi_long
target_mmap(abi_ulong addr0, abi_ulong len, int prot, int flags, int fd,
    off_t pos)
{
#ifdef TARGET_CHERI
    cap_register_t retvalm;
#else
    abi_long retvalm;
#endif
    abi_long error;
    struct mmap_req mr;
    abi_syscallret_t retval;

    memset(&mr, 0, sizeof(mr));
    mr.mr_hint = addr0;
    mr.mr_len = len;
    mr.mr_prot = prot;
    mr.mr_flags = flags;
    mr.mr_fd = fd;
    mr.mr_pos = pos;

    retval = &retvalm;
    error = target_mmap_req(NULL, retval, &mr);
    return (error == -1 ? -1 : syscallret_value(retval));
}

/*
 * See sys_mmap() in vm/vm_mmap.c.
 */
abi_long
target_sys_mmap(TaskState *ts, abi_syscallret_t retval,
    abi_syscallarg_t ua_addr, abi_syscallarg_t ua_len, abi_syscallarg_t ua_prot,
    abi_syscallarg_t ua_flags, abi_syscallarg_t ua_fd, abi_syscallarg_t ua_pos)
{
    struct target_mmap_args ua;
#ifdef TARGET_CHERI
    int flags;
    const cap_register_t *source_cap;
    uint64_t perms, reqperms;
    vm_offset_t hint;
    struct mmap_req mr;
#else
    abi_long error;
#endif

    ua.addr = syscallarg_uintptr(ua_addr);
    ua.len = syscallarg_value(ua_len);
    ua.prot = syscallarg_int(ua_prot);
    ua.flags = syscallarg_int(ua_flags);
    ua.fd = syscallarg_int(ua_fd);
    ua.pos = syscallarg_value(ua_pos);

#ifndef TARGET_CHERI
    error = target_mmap(ua.addr, ua.len, ua.prot, ua.flags, ua.fd, ua.pos);
    if (error != -1) {
        *retval = error;
    }
    return (error);
#else
    flags = ua.flags;

    if (flags & MAP_32BIT) {
        qemu_log("MAP_32BIT not supported in CheriABI\n");
        errno = EINVAL;
        goto fail;
    }

    /*
     * Allow existing mapping to be replaced using the MAP_FIXED
     * flag IFF the addr argument is a valid capability with the
     * VMMAP user permission.  In this case, the new capability is
     * derived from the passed capability.  In all other cases, the
     * new capability is derived from the per-thread mmap capability.
     *
     * If MAP_FIXED specified and addr does not meet the above
     * requirements, then MAP_EXCL is implied to prevent changing
     * page contents without permission.
     *
     * XXXBD: The fact that using valid a capability to a currently
     * unmapped region with and without the VMMAP permission will
     * yield different results (and even failure modes) is potentially
     * confusing and incompatible with non-CHERI code.  One could
     * potentially check if the region contains any mappings and
     * switch to using the per-thread mmap capability as the source
     * capability if this pattern proves common.
     */
    hint = cheri_getaddress(ua_addr);
    if (cheri_gettag(ua_addr) &&
        (cheri_getperm(ua_addr) & CHERI_PERM_CHERIABI_VMMAP) &&
        (flags & MAP_FIXED)) {
        source_cap = ua_addr;
    } else {
        if (flags & MAP_FIXED)
            flags |= MAP_EXCL;

        if (flags & MAP_CHERI_NOSETBOUNDS) {
            qemu_log("MAP_CHERI_NOSETBOUNDS without a valid addr capability\n");
            errno = EINVAL;
            goto fail;
        }

        source_cap = &userspace_cap;
    }
    assert(cheri_gettag(source_cap) &&
        ("ts->cheri_mmap_cap is untagged!"));

    /*
     * If MAP_FIXED is specified, make sure that that the reqested
     * address range fits within the source capability.
     */
    /*
     * XXXKW: Use cheri_getbase() instead of cheri_getaddress()?
     */
    if ((flags & MAP_FIXED) &&
        (rounddown2(hint, TARGET_PAGE_SIZE) < cheri_getbase(source_cap) ||
        roundup2(hint + ua.len, TARGET_PAGE_SIZE) >
        cheri_getbase(source_cap) + cheri_getlen(source_cap))) {
        qemu_log("MAP_FIXED and too little space in "
            "capablity (0x%zx > 0x%zx)\n",
            roundup2(hint + ua.len, TARGET_PAGE_SIZE),
            cheri_getbase(source_cap) + cheri_getlen(source_cap));
        errno = EPROT;
        goto fail;
    }

    perms = cheri_getperm(source_cap);
    reqperms = mmap_prot2perms(ua.prot);
    if ((perms & reqperms) != reqperms) {
        qemu_log("capability has insufficient perms (0x%lx)"
            "for request (0x%lx)\n", perms, reqperms);
        errno = EPROT;
        goto fail;
    }

    /*
     * If alignment is specified, check that it is sufficent and
     * increase as required.  If not, assume data alignment.
     */
    switch (flags & MAP_ALIGNMENT_MASK) {
    case MAP_ALIGNED(0):
        flags &= ~MAP_ALIGNMENT_MASK;
        /*
         * Request CHERI data alignment when no other request is made.
         * However, do not request alignment if both MAP_FIXED and
         * MAP_CHERI_NOSETBOUNDS is set since that means we are filling
         * in reserved address space from a file or MAP_ANON memory.
         */
        if (!((flags & MAP_FIXED) && (flags & MAP_CHERI_NOSETBOUNDS))) {
            flags |= MAP_ALIGNED_CHERI;
        }
        break;
    case MAP_ALIGNED_CHERI:
    case MAP_ALIGNED_CHERI_SEAL:
        break;
    case MAP_ALIGNED_SUPER:
#if TARGET_VM_NRESERVLEVEL > 0
        /*
         * pmap_align_superpage() is a no-op for allocations
         * less than a super page so request data alignment
         * in that case.
         *
         * In practice this is a no-op as super-pages are
         * precisely representable.
         */
        if (ua.len < (1UL << (TARGET_VM_LEVEL_0_ORDER + TARGET_PAGE_SHIFT)) &&
            CHERI_REPRESENTABLE_ALIGNMENT(ua.len) >
            (1UL << TARGET_PAGE_SHIFT)) {
            flags &= ~MAP_ALIGNMENT_MASK;
            flags |= MAP_ALIGNED_CHERI;
        }
#endif
        break;
    default:
        /* Reject nonsensical sub-page alignment requests */
        if ((flags >> MAP_ALIGNMENT_SHIFT) < TARGET_PAGE_SHIFT) {
            qemu_log("subpage alignment request\n");
            errno = EINVAL;
            goto fail;
        }

        /*
         * Honor the caller's alignment request, if any unless
         * it is too small.  If is, promote the request to
         * MAP_ALIGNED_CHERI.
         *
         * However, do not request alignment if both MAP_FIXED and
         * MAP_CHERI_NOSETBOUNDS is set since that means we are filling
         * in reserved address space from a file or MAP_ANON memory.
         */
        if (!((flags & MAP_FIXED) && (flags & MAP_CHERI_NOSETBOUNDS))) {
            if ((1UL << (flags >> MAP_ALIGNMENT_SHIFT)) <
                CHERI_REPRESENTABLE_ALIGNMENT(ua.len)) {
                flags &= ~MAP_ALIGNMENT_MASK;
                flags |= MAP_ALIGNED_CHERI;
            }
        }
        break;
    }
    /*
     * NOTE: If this architecture requires an alignment constraint, it is
     * set at this point.  A simple assert is not easy to contruct...
     */

    memset(&mr, 0, sizeof(mr));
    mr.mr_hint = hint;
    mr.mr_max_addr = cheri_gettop(source_cap);
    mr.mr_len = ua.len;
    mr.mr_prot = ua.prot;
    mr.mr_flags = flags;
    mr.mr_fd = ua.fd;
    mr.mr_pos = ua.pos;
    mr.mr_source_cap = *source_cap;

    return (target_mmap_req(ts, retval, &mr));
fail:
    return (-1);
#endif
}

/* NOTE: all the constants are the HOST ones */
abi_long
target_mmap_req(TaskState *ts, abi_syscallret_t retval, struct mmap_req *mrp)
{
    abi_ulong addr, ret, end, real_start, real_end, host_offset, host_len;
    abi_ulong start, len, size;
    int error, fd, flags, prot;
    off_t offset;
    vm_offset_t addr_mask = ~TARGET_PAGE_MASK;
#ifdef TARGET_CHERI
    vm_size_t padded_size = 0;
#endif
    int align;

    start = mrp->mr_hint;
    len = mrp->mr_len;
    prot = PROT_EXTRACT(mrp->mr_prot);
    flags = mrp->mr_flags;
    fd = mrp->mr_fd;
    offset = mrp->mr_pos;

    mmap_lock();
#ifdef DEBUG_MMAP
    {
        printf("mmap: start=0x" TARGET_ABI_FMT_lx
               " len=0x" TARGET_ABI_FMT_lx " prot=%c%c%c flags=",
               start, len,
               prot & PROT_READ ? 'r' : '-',
               prot & PROT_WRITE ? 'w' : '-',
               prot & PROT_EXEC ? 'x' : '-');
        if (flags & MAP_ALIGNMENT_MASK)
            printf ("MAP_ALIGNED(%u) ", (flags & MAP_ALIGNMENT_MASK) >> MAP_ALIGNMENT_SHIFT);
#if defined(__FreeBSD_version) && __FreeBSD_version >= 1200035
        if (flags & MAP_GUARD)
            printf("MAP_GUARD ");
#endif
        if (flags & MAP_FIXED)
            printf("MAP_FIXED ");
        if (flags & MAP_ANONYMOUS)
            printf("MAP_ANON ");
#ifdef MAP_EXCL
        if (flags & MAP_EXCL)
            printf("MAP_EXCL ");
#endif
	if (flags & MAP_PRIVATE)
	    printf("MAP_PRIVATE ");
	if (flags & MAP_SHARED)
	    printf("MAP_SHARED ");
	if (flags & MAP_NOCORE)
	    printf("MAP_NOCORE ");
#ifdef MAP_STACK
	if (flags & MAP_STACK)
	    printf("MAP_STACK ");
#endif
        printf("fd=%d offset=0x%llx\n", fd, offset);
    }
#endif

    if ((flags & MAP_ANONYMOUS) && fd != -1) {
        errno = EINVAL;
        goto fail;
    }
#ifdef MAP_STACK
    if (flags & MAP_STACK) {
        if ((fd != -1) || ((prot & (PROT_READ | PROT_WRITE)) !=
                    (PROT_READ | PROT_WRITE))) {
            errno = EINVAL;
            goto fail;
        }
    }
#endif /* MAP_STACK */
#if defined(__FreeBSD_version) && __FreeBSD_version >= 1200035
    if ((flags & MAP_GUARD) && (prot != PROT_NONE || fd != -1 ||
        offset != 0 || (flags & (MAP_SHARED | MAP_PRIVATE | /* MAP_PREFAULT | */ /* MAP_PREFAULT not in mman.h */
        MAP_PREFAULT_READ | MAP_ANON | MAP_STACK)) != 0)) {
        qemu_log("%s: Invalid arguments with MAP_GUARD\n", __func__);
        errno = EINVAL;
        goto fail;
    }
#endif

#ifdef TARGET_CHERI
#if defined(__FreeBSD_version) && __FreeBSD_version < 1200035
    /*
     * Disable MAP_GUARD for the forward compatibility.
     *
     * XXXKW: This is experimental and requires proper MAP_GUARD emulation
     * if it's not supported by a host.
     */
    flags &= ~MAP_GUARD;
#endif
#endif /* TARGET_CHERI */

    if (offset & ~TARGET_PAGE_MASK) {
        errno = EINVAL;
        goto fail;
    }

    size = TARGET_PAGE_ALIGN(len);
    if (size == 0) {
        errno = EINVAL;
        goto fail;
    }
    real_start = start & qemu_host_page_mask;
    host_offset = offset & qemu_host_page_mask;

    align = flags & MAP_ALIGNMENT_MASK;
#ifndef TARGET_CHERI
    /* In the non-CHERI case, remove the alignment request. */
    if (align == MAP_ALIGNED_CHERI || align == MAP_ALIGNED_CHERI_SEAL) {
        flags &= ~MAP_ALIGNMENT_MASK;
        align = 0;
    }
#else /* TARGET_CHERI */
    /*
     * Convert MAP_ALIGNED_CHERI(_SEAL) into explicit alignment
     * requests and pad lengths.  The combination of alignment (via
     * the updated, explicit alignment flags) and padding is required
     * for any request that would otherwise be unrepresentable due
     * to compressed capability bounds.
     *
     * XXX: With CHERI Concentrate, there is no difference in
     * precision between sealed and unsealed capabilities.  We
     * retain the duplicate code paths in case other otype tradeoffs
     * are made at a later date.
     */
    if (align == MAP_ALIGNED_CHERI) {
        flags &= ~MAP_ALIGNMENT_MASK;
        if (CHERI_REPRESENTABLE_ALIGNMENT(size) > TARGET_PAGE_SIZE) {
            flags |= MAP_ALIGNED(CHERI_ALIGN_SHIFT(size));

            if (size != CHERI_REPRESENTABLE_LENGTH(size))
                padded_size = CHERI_REPRESENTABLE_LENGTH(size);

            if (CHERI_ALIGN_MASK(size) != 0)
                addr_mask = CHERI_ALIGN_MASK(size);
        }
        align = flags & MAP_ALIGNMENT_MASK;
    } else if (align == MAP_ALIGNED_CHERI_SEAL) {
        flags &= ~MAP_ALIGNMENT_MASK;
        if (CHERI_SEALABLE_ALIGNMENT(size) > (1UL << TARGET_PAGE_SHIFT)) {
            flags |= MAP_ALIGNED(CHERI_SEAL_ALIGN_SHIFT(size));

            if (size != CHERI_SEALABLE_LENGTH(size))
                padded_size = CHERI_SEALABLE_LENGTH(size);

            if (CHERI_SEAL_ALIGN_MASK(size) != 0)
                addr_mask = CHERI_SEAL_ALIGN_MASK(size);
        }
        align = flags & MAP_ALIGNMENT_MASK;
    }
    if ((flags & MAP_STACK) != 0 && padded_size != 0) {
        qemu_log("%s: MAP_STACK request requires padding to "
            "be representable (%#lx -> %#lx)\n", __func__, size, padded_size);
        goto fail;
    }
#endif /* !TARGET_CHERI */

    /* Ensure alignment is at least a page and fits in a pointer. */
    if (align != 0 && align != MAP_ALIGNED_SUPER &&
        (align >> MAP_ALIGNMENT_SHIFT >= sizeof(ABI_PTR_SIZE) * NBBY ||
        align >> MAP_ALIGNMENT_SHIFT < TARGET_PAGE_SHIFT)) {
        qemu_log("%s: nonsensical alignment (2^%d)\n",
            __func__, align >> MAP_ALIGNMENT_SHIFT);
        goto fail;
    }

    if (flags & MAP_FIXED) {
        /*
         * The specified address must have the same remainder
         * as the file offset taken modulo TARGET_PAGE_SIZE, so it
         * should be aligned after adjustment by offset.
         */
        if ((start - offset) & addr_mask) {
            qemu_log("%s: addr (%p) is underaligned "
                "(mask 0x%zx)\n", __func__, (void *)(start - offset),
                addr_mask);
            goto fail;
        }
    }

#ifdef TARGET_CHERI
    if (padded_size != 0) {
        assert(size != padded_size);
        /*
         * Request a padded mapping instead of the original one.
         *
         * CheriBSD makes a reservation in this place before requesting an
         * actual mapping for a system call. We do not have to worry about that
         * as each emulated process interacts with a kernel itself.
         */
        len = padded_size;
    }
#endif

    /* If the user is asking for the kernel to find a location, do that
       before we truncate the length for mapping files below.  */
    if (!(flags & MAP_FIXED)) {
        host_len = len + offset - host_offset;
        host_len = HOST_PAGE_ALIGN(host_len);
        if ((flags & MAP_ALIGNMENT_MASK) != 0)
            start = mmap_find_vma_aligned(real_start, host_len,
                (flags & MAP_ALIGNMENT_MASK) >> MAP_ALIGNMENT_SHIFT);
        else
            start = mmap_find_vma(real_start, host_len);
        if (start == (abi_ulong)-1) {
            errno = ENOMEM;
            goto fail;
        }
    }

    /* When mapping files into a memory area larger than the file, accesses
       to pages beyond the file size will cause a SIGBUS. 

       For example, if mmaping a file of 100 bytes on a host with 4K pages
       emulating a target with 8K pages, the target expects to be able to
       access the first 8K. But the host will trap us on any access beyond
       4K.  

       When emulating a target with a larger page-size than the hosts, we
       may need to truncate file maps at EOF and add extra anonymous pages
       up to the targets page boundary.  */

    if ((qemu_real_host_page_size < qemu_host_page_size) && fd != -1) {
       struct stat sb;

       if (fstat (fd, &sb) == -1)
           goto fail;

       /* Are we trying to create a map beyond EOF?.  */
       if (offset + len > sb.st_size) {
           /* If so, truncate the file map at eof aligned with 
              the hosts real pagesize. Additional anonymous maps
              will be created beyond EOF.  */
           len = REAL_HOST_PAGE_ALIGN(sb.st_size - offset);
       }
    }

    if (!(flags & MAP_FIXED)) {
        unsigned long host_start;
        void *p;

        host_len = len + offset - host_offset;
        host_len = HOST_PAGE_ALIGN(host_len);

        /* Note: we prefer to control the mapping address. It is
           especially important if qemu_host_page_size >
           qemu_real_host_page_size */
        p = mmap(g2h_untagged(start), host_len, prot,
                 flags | MAP_FIXED | ((fd != -1) ? MAP_ANONYMOUS : 0), -1, 0);
        if (p == MAP_FAILED)
            goto fail;
        /* update start so that it points to the file position at 'offset' */
        host_start = (unsigned long)p;
        if (fd != -1) {
            p = mmap(g2h(start), len, prot,
                     flags | MAP_FIXED, fd, host_offset);
            if (p == MAP_FAILED) {
                munmap(g2h(start), host_len);
                goto fail;
            }
            host_start += offset - host_offset;
        }
        start = h2g(host_start);
    } else {
        if (start & ~TARGET_PAGE_MASK) {
            errno = EINVAL;
            goto fail;
        }
        end = start + len;
        real_end = HOST_PAGE_ALIGN(end);

	/*
	 * Test if requested memory area fits target address space
	 * It can fail only on 64-bit host with 32-bit target.
	 * On any other target/host host mmap() handles this error correctly.
	 */
#if TARGET_ABI_BITS == 32 && HOST_LONG_BITS == 64
        if ((unsigned long)start + len - 1 > (abi_ulong) -1) {
            errno = EINVAL;
            goto fail;
        }
#endif

        /* worst case: we cannot map the file because the offset is not
           aligned, so we read it */
        if (fd != -1 &&
            (offset & ~qemu_host_page_mask) != (start & ~qemu_host_page_mask)) {
            struct mmap_req mr;

            /* msync() won't work here, so we return an error if write is
               possible while it is a shared mapping */
            if ((flags & TARGET_BSD_MAP_FLAGMASK) == MAP_SHARED &&
                (prot & PROT_WRITE)) {
                errno = EINVAL;
                goto fail;
            }

            memset(&mr, 0, sizeof(mr));
            mr.mr_hint = start;
            mr.mr_len = len;
            mr.mr_prot = prot | PROT_WRITE;
            mr.mr_flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
            mr.mr_fd = -1;
            mr.mr_pos = 0;
            if (target_mmap_req(ts, retval, &mr) == -1)
                goto fail;
            if (pread(fd, g2h_untagged(start), len, offset) == -1)
                goto fail;
            if (!(prot & PROT_WRITE)) {
                ret = target_mprotect(start, len, prot);
                assert(ret == 0);
            }
            goto the_end;
        }
#ifdef MAP_EXCL
        /* Reject the mapping if any page within the range is mapped */
        if (flags & MAP_EXCL) {
            for (addr = start; addr < end; addr++) {
                if (page_get_flags(addr) != 0)
                    goto fail;
            }
        }
#endif

        /* handle the start of the mapping */
        if (start > real_start) {
            if (real_end == real_start + qemu_host_page_size) {
                /* one single host page */
                ret = mmap_frag(real_start, start, end,
                                prot, flags, fd, offset);
                if (ret == -1)
                    goto fail;
                goto the_end1;
            }
            ret = mmap_frag(real_start, start, real_start + qemu_host_page_size,
                            prot, flags, fd, offset);
            if (ret == -1)
                goto fail;
            real_start += qemu_host_page_size;
        }
        /* handle the end of the mapping */
        if (end < real_end) {
            ret = mmap_frag(real_end - qemu_host_page_size,
                            real_end - qemu_host_page_size, end,
                            prot, flags, fd,
                            offset + real_end - qemu_host_page_size - start);
            if (ret == -1)
                goto fail;
            real_end -= qemu_host_page_size;
        }

        /* map the middle (easier) */
        if (real_start < real_end) {
            void *p;
            unsigned long offset1;
            if (flags & MAP_ANONYMOUS)
                offset1 = 0;
            else
                offset1 = offset + real_start - start;
            p = mmap(g2h_untagged(real_start), real_end - real_start,
                     prot, flags, fd, offset1);
            if (p == MAP_FAILED)
                goto fail;
        }
    }
 the_end1:
    page_set_flags(start, start + len, prot | PAGE_VALID);
 the_end:
#ifdef DEBUG_MMAP
    printf("ret=0x" TARGET_ABI_FMT_lx "\n", start);
    page_dump(stdout);
    printf("\n");
#endif
    tb_invalidate_phys_range(start, start + len);
#ifdef TARGET_CHERI
    qemu_ram_clear_region(len, g2h(start));
    (void)qemu_ram_alloc_from_ptr(len, g2h((void *)(uintptr_t)start));
#endif
    mmap_unlock();
#ifdef TARGET_CHERI
    if (ts != NULL) {
        /*
         * An emulated process called mmap(2).
         *
         * XXXKW: We should check SV_CHERI instead as in CheriBSD.
         */
        *retval = mmap_retcap(start, mrp);
    } else {
        /*
         * The QEMU user mode called mmap(2), e.g. to build a stack.
         */
        *retval = *cheri_ptr((void *)(uintptr_t)start, len);
    }
#else
    *retval = start;
#endif
    return start;
fail:
    error = errno;
    mmap_unlock();
    errno = error;
    return -1;
}

static void mmap_reserve(abi_ulong start, abi_ulong size)
{
    abi_ulong real_start;
    abi_ulong real_end;
    abi_ulong addr;
    abi_ulong end;
    int prot;

    real_start = start & qemu_host_page_mask;
    real_end = HOST_PAGE_ALIGN(start + size);
    end = start + size;
    if (start > real_start) {
        /* handle host page containing start */
        prot = 0;
        for (addr = real_start; addr < start; addr += TARGET_PAGE_SIZE) {
            prot |= page_get_flags(addr);
        }
        if (real_end == real_start + qemu_host_page_size) {
            for (addr = end; addr < real_end; addr += TARGET_PAGE_SIZE) {
                prot |= page_get_flags(addr);
            }
            end = real_end;
        }
        if (prot != 0)
            real_start += qemu_host_page_size;
    }
    if (end < real_end) {
        prot = 0;
        for (addr = end; addr < real_end; addr += TARGET_PAGE_SIZE) {
            prot |= page_get_flags(addr);
        }
        if (prot != 0)
            real_end -= qemu_host_page_size;
    }
    if (real_start != real_end) {
        mmap(g2h(real_start), real_end - real_start, PROT_NONE,
                 MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                 -1, 0);
    }
}

int target_munmap(abi_ulong start, abi_ulong len)
{
    abi_ulong end, real_start, real_end, addr;
    int prot, ret;

#ifdef DEBUG_MMAP
    printf("munmap: start=0x" TARGET_ABI_FMT_lx " len=0x"
           TARGET_ABI_FMT_lx "\n",
           start, len);
#endif
    if (start & ~TARGET_PAGE_MASK)
        return -EINVAL;
    len = TARGET_PAGE_ALIGN(len);
    if (len == 0)
        return -EINVAL;
    mmap_lock();
    end = start + len;
    real_start = start & qemu_host_page_mask;
    real_end = HOST_PAGE_ALIGN(end);

    if (start > real_start) {
        /* handle host page containing start */
        prot = 0;
        for(addr = real_start; addr < start; addr += TARGET_PAGE_SIZE) {
            prot |= page_get_flags(addr);
        }
        if (real_end == real_start + qemu_host_page_size) {
            for(addr = end; addr < real_end; addr += TARGET_PAGE_SIZE) {
                prot |= page_get_flags(addr);
            }
            end = real_end;
        }
        if (prot != 0)
            real_start += qemu_host_page_size;
    }
    if (end < real_end) {
        prot = 0;
        for(addr = end; addr < real_end; addr += TARGET_PAGE_SIZE) {
            prot |= page_get_flags(addr);
        }
        if (prot != 0)
            real_end -= qemu_host_page_size;
    }

    ret = 0;
    /* unmap what we can */
    if (real_start < real_end) {
        if (reserved_va) {
            mmap_reserve(real_start, real_end - real_start);
        } else {
            ret = munmap(g2h_untagged(real_start), real_end - real_start);
        }
    }

    if (ret == 0) {
        page_set_flags(start, start + len, 0);
        tb_invalidate_phys_range(start, start + len);
#ifdef TARGET_CHERI
        qemu_ram_clear_region(len, g2h(start));
#endif
    }
    mmap_unlock();
    return ret;
}

int target_msync(abi_ulong start, abi_ulong len, int flags)
{
    abi_ulong end;

    if (start & ~TARGET_PAGE_MASK)
        return -EINVAL;
    len = TARGET_PAGE_ALIGN(len);
    end = start + len;
    if (end < start)
        return -EINVAL;
    if (end == start)
        return 0;

    start &= qemu_host_page_mask;
    return msync(g2h_untagged(start), end - start, flags);
}
