/*
 *  BSD syscalls
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
 *  Copyright (c) 2013-14 Stacey D. Son
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

#define _WANT_FREEBSD11_STAT
#define _WANT_FREEBSD11_STATFS
#define _WANT_FREEBSD11_DIRENT
#define _WANT_KERNEL_ERRNO
#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/path.h"
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <utime.h>

#include "qemu.h"
#include "qemu-common.h"
#include "qemu/timer.h"
#include "user/syscall-trace.h"

#define target_to_host_bitmask(x, tbl) (x)

/* BSD independent syscall shims */
#include "bsd-file.h"
#include "bsd-ioctl.h"
#include "bsd-mem.h"
#include "bsd-misc.h"
#include "bsd-proc.h"
#include "bsd-signal.h"
#include "bsd-socket.h"

/* *BSD dependent syscall shims */
#include "os-extattr.h"
#include "os-file.h"
#include "os-time.h"
#include "os-misc.h"
#include "os-proc.h"
#include "os-signal.h"
#include "os-socket.h"
#include "os-stat.h"
#include "os-thread.h"

#include "machine/proc.h"

/* #define DEBUG */
/* Used in os-thread */
safe_syscall1(int, thr_suspend, struct timespec *, timeout);
safe_syscall5(int, _umtx_op, void *, obj, int, op, unsigned long, val, void *,
    uaddr, void *, uaddr2);

/* used in os-time */
safe_syscall2(int, nanosleep, const struct timespec *, rqtp, struct timespec *,
    rmtp);
safe_syscall4(int, clock_nanosleep, clockid_t, clock_id, int, flags,
    const struct timespec *, rqtp, struct timespec *, rmtp);

safe_syscall6(int, kevent, int, kq, const struct kevent *, changelist,
    int, nchanges, struct kevent *, eventlist, int, nevents,
    const struct timespec *, timeout);

/* used in os-proc */
safe_syscall4(pid_t, wait4, pid_t, wpid, int *, status, int, options,
    struct rusage *, rusage);
safe_syscall6(pid_t, wait6, idtype_t, idtype, id_t, id, int *, status, int,
    options, struct __wrusage *, wrusage, siginfo_t *, infop);

/* I/O */
safe_syscall3(int, open, const char *, path, int, flags, mode_t, mode);
safe_syscall4(int, openat, int, fd, const char *, path, int, flags, mode_t,
    mode);

safe_syscall3(ssize_t, read, int, fd, void *, buf, size_t, nbytes);
safe_syscall4(ssize_t, pread, int, fd, void *, buf, size_t, nbytes, off_t,
    offset);
safe_syscall3(ssize_t, readv, int, fd, const struct iovec *, iov, int, iovcnt);
safe_syscall4(ssize_t, preadv, int, fd, const struct iovec *, iov, int, iovcnt,
    off_t, offset);

safe_syscall3(ssize_t, write, int, fd, void *, buf, size_t, nbytes);
safe_syscall4(ssize_t, pwrite, int, fd, void *, buf, size_t, nbytes, off_t,
    offset);
safe_syscall3(ssize_t, writev, int, fd, const struct iovec *, iov, int, iovcnt);
safe_syscall4(ssize_t, pwritev, int, fd, const struct iovec *, iov, int, iovcnt,
    off_t, offset);

safe_syscall5(int, select, int, nfds, fd_set *, readfs, fd_set *, writefds,
    fd_set *, exceptfds, struct timeval *, timeout);
safe_syscall6(int, pselect, int, nfds, fd_set * restrict, readfs,
    fd_set * restrict, writefds, fd_set * restrict, exceptfds,
    const struct timespec * restrict, timeout,
    const sigset_t * restrict, newsigmask);

safe_syscall6(ssize_t, recvfrom, int, fd, void *, buf, size_t, len, int, flags,
    struct sockaddr * restrict, from, socklen_t * restrict, fromlen);
safe_syscall6(ssize_t, sendto, int, fd, const void *, buf, size_t, len, int,
    flags, const struct sockaddr *, to, socklen_t, tolen);
safe_syscall3(ssize_t, recvmsg, int, s, struct msghdr *, msg, int, flags);
safe_syscall3(ssize_t, sendmsg, int, s, const struct msghdr *, msg, int, flags);

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300133
safe_syscall6(ssize_t, copy_file_range, int, infd, off_t *, inoffp, int, outfd,
    off_t *, outoffp, size_t, len, unsigned int, flags);
#endif

int g_posix_timers[32] = { 0, } ;

/*
 * errno conversion.
 */
abi_long get_errno(abi_long ret)
{

    if (ret == -1) {
        /* XXX need to translate host -> target errnos here */
        return -host_to_target_errno(errno);
    } else {
        return ret;
    }
}

int host_to_target_errno(int err)
{
    /* XXX need to translate host errnos here */
    return err;
}

int is_error(abi_long ret)
{

    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

struct iovec *lock_iovec(int type, abi_ulong target_addr,
        int count, int copy)
{
    struct target_iovec *target_vec;
    struct iovec *vec;
    abi_ulong total_len, max_len;
    int i;
    int err = 0;
    bool bad_address = false;

    if (count == 0) {
        errno = 0;
        return NULL;
    }
    if (count < 0 || count > IOV_MAX) {
        errno = EINVAL;
        return NULL;
    }

    vec = calloc(count, sizeof(struct iovec));
    if (vec == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    target_vec = lock_user(VERIFY_READ, target_addr,
                           count * sizeof(struct target_iovec), 1);
    if (target_vec == NULL) {
        err = EFAULT;
        goto fail2;
    }

    /* ??? If host page size > target page size, this will result in a
       value larger than what we can actually support.  */
    max_len = 0x7fffffff & TARGET_PAGE_MASK;
    total_len = 0;

    for (i = 0; i < count; i++) {
        abi_vaddr_t base = uintptr_vaddr(tswapuintptr(target_vec[i].iov_base));
        abi_long len = tswapal(target_vec[i].iov_len);

        if (len < 0) {
            err = EINVAL;
            goto fail;
        } else if (len == 0) {
            /* Zero length pointer is ignored.  */
            vec[i].iov_base = 0;
        } else {
            vec[i].iov_base = lock_user(type, base, len, copy);
            /* If the first buffer pointer is bad, this is a fault.  But
             * subsequent bad buffers will result in a partial write; this
             * is realized by filling the vector with null pointers and
             * zero lengths. */
            if (!vec[i].iov_base) {
                if (i == 0) {
                    err = EFAULT;
                    goto fail;
                } else {
                    bad_address = true;
                }
            }
            if (bad_address) {
                len = 0;
            }
            if (len > max_len - total_len) {
                len = max_len - total_len;
            }
        }
        vec[i].iov_len = len;
        total_len += len;
    }

    unlock_user(target_vec, target_addr, 0);
    return vec;

 fail:
    while (--i >= 0) {
        if (tswapal(target_vec[i].iov_len) > 0) {
            unlock_user(vec[i].iov_base,
                uintptr_vaddr(tswapuintptr(target_vec[i].iov_base)), 0);
        }
    }
    unlock_user(target_vec, target_addr, 0);
 fail2:
    free(vec);
    errno = err;
    return NULL;
}

void unlock_iovec(struct iovec *vec, abi_ulong target_addr,
        int count, int copy)
{
    struct target_iovec *target_vec;
    int i;

    target_vec = lock_user(VERIFY_READ, target_addr,
                           count * sizeof(struct target_iovec), 1);
    if (target_vec) {
        for (i = 0; i < count; i++) {
            abi_vaddr_t base =
                uintptr_vaddr(tswapuintptr(target_vec[i].iov_base));
            abi_long len = tswapal(target_vec[i].iov_len);
            if (len < 0) {
                break;
            }
            unlock_user(vec[i].iov_base, base, copy ? vec[i].iov_len : 0);
        }
        unlock_user(target_vec, target_addr, 0);
    }

    free(vec);
}


/* stub for arm semihosting support */
abi_long do_brk(abi_ulong new_brk)
{
    return do_obreak(new_brk);
}

int
do_bsd_nosys(struct thread *td, struct target_nosys_args *args)
{

    return (ENOSYS);
}

/* do_syscall() should always have a single exit point at the end so
   that actions, such as logging of syscall results, can be performed.
   All errnos that do_syscall() returns must be -TARGET_<errcode>. */
abi_long do_freebsd_syscall(void *cpu_env, abi_syscallret_t *retvalp,
    struct target_syscall_args *sa)
{
    CPUState *cpu = env_cpu(cpu_env);
    abi_long arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, ret;
#ifdef TARGET_CHERI
    static cap_register_t retreg;
#else
    static abi_long retreg;
#endif
    uint64_t timestamp;
    abi_syscallret_t retval;

    assert(retvalp != NULL);

    retval = NULL;
    arg1 = syscallarg_value(&sa->args[0]);
    arg2 = syscallarg_value(&sa->args[1]);
    arg3 = syscallarg_value(&sa->args[2]);
    arg4 = syscallarg_value(&sa->args[3]);
    arg5 = syscallarg_value(&sa->args[4]);
    arg6 = syscallarg_value(&sa->args[5]);
    arg7 = syscallarg_value(&sa->args[6]);
    arg8 = syscallarg_value(&sa->args[7]);

#ifdef DEBUG
    gemu_log("freebsd syscall %d\n", sa->code);
#endif
    record_syscall_start(cpu, sa->code, arg1, arg2, arg3, arg4, arg5, arg6, 0,
        0);

    if(do_strace) {
        print_freebsd_syscall(sa->code, arg1, arg2, arg3, arg4, arg5, arg6);
        timestamp = get_clock();
    }

    switch (sa->code) {
        /*
         * process system calls
         */
    case TARGET_FREEBSD_NR_fork: /* fork(2) */
        ret = do_freebsd_fork(cpu_env);
        break;

    case TARGET_FREEBSD_NR_vfork: /* vfork(2) */
        ret = do_freebsd_vfork(cpu_env);
        break;

    case TARGET_FREEBSD_NR_rfork: /* rfork(2) */
        ret = do_freebsd_rfork(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_pdfork: /* pdfork(2) */
        ret = do_freebsd_pdfork(cpu_env, arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_execve: /* execve(2) */
        ret = do_freebsd_execve(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_fexecve: /* fexecve(2) */
        ret = do_freebsd_fexecve(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_wait4: /* wait4(2) */
        ret = do_freebsd_wait4(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_wait6: /* wait6(2) */
        ret = do_freebsd_wait6(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
        break;

    case TARGET_FREEBSD_NR_exit: /* exit(2) */
        ret = do_bsd_exit(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_getgroups: /* getgroups(2) */
        ret = do_bsd_getgroups(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_setgroups: /* setgroups(2) */
        ret = do_bsd_setgroups(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_umask: /* umask(2) */
        ret = do_bsd_umask(arg1);
        break;

    case TARGET_FREEBSD_NR_setlogin: /* setlogin(2) */
        ret = do_bsd_setlogin(arg1);
        break;

    case TARGET_FREEBSD_NR_getlogin: /* getlogin(2) */
        ret = do_bsd_getlogin(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_getrusage: /* getrusage(2) */
        ret = do_bsd_getrusage(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_getrlimit: /* getrlimit(2) */
        ret = do_bsd_getrlimit(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_setrlimit: /* setrlimit(2) */
        ret = do_bsd_setrlimit(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_getpid: /* getpid(2) */
        ret = do_bsd_getpid();
        break;

    case TARGET_FREEBSD_NR_getppid: /* getppid(2) */
        ret = do_bsd_getppid();
        break;

    case TARGET_FREEBSD_NR_getuid: /* getuid(2) */
        ret = do_bsd_getuid();
        break;

    case TARGET_FREEBSD_NR_geteuid: /* geteuid(2) */
        ret = do_bsd_geteuid();
        break;

    case TARGET_FREEBSD_NR_getgid: /* getgid(2) */
        ret = do_bsd_getgid();
        break;

    case TARGET_FREEBSD_NR_getegid: /* getegid(2) */
        ret = do_bsd_getegid();
        break;

    case TARGET_FREEBSD_NR_setuid: /* setuid(2) */
        ret = do_bsd_setuid(arg1);
        break;

    case TARGET_FREEBSD_NR_seteuid: /* seteuid(2) */
        ret = do_bsd_seteuid(arg1);
        break;

    case TARGET_FREEBSD_NR_setgid: /* setgid(2) */
        ret = do_bsd_setgid(arg1);
        break;

    case TARGET_FREEBSD_NR_setegid: /* setegid(2) */
        ret = do_bsd_setegid(arg1);
        break;

    case TARGET_FREEBSD_NR_getpgrp: /* getpgrp(2) */
        ret = do_bsd_getpgrp();
        break;

    case TARGET_FREEBSD_NR_getpgid: /* getpgid(2) */
	ret = do_bsd_getpgid(arg1);
	break;

    case TARGET_FREEBSD_NR_setpgid: /* setpgid(2) */
	ret = do_bsd_setpgid(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_setreuid: /* setreuid(2) */
        ret = do_bsd_setreuid(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_setregid: /* setregid(2) */
        ret = do_bsd_setregid(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_getresuid: /* getresuid(2) */
        ret = do_bsd_getresuid(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getresgid: /* getresgid(2) */
        ret = do_bsd_getresgid(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_setresuid: /* setresuid(2) */
        ret = do_bsd_setresuid(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_setresgid: /* setresgid(2) */
        ret = do_bsd_setresgid(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getsid: /* getsid(2) */
        ret = do_bsd_getsid(arg1);
        break;

    case TARGET_FREEBSD_NR_setsid: /* setsid(2) */
        ret = do_bsd_setsid();
        break;

    case TARGET_FREEBSD_NR_issetugid: /* issetugid(2) */
        ret = do_bsd_issetugid();
        break;

    case TARGET_FREEBSD_NR_profil: /* profil(2) */
        ret = do_bsd_profil(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_ktrace: /* ktrace(2) */
        ret = do_bsd_ktrace(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_setloginclass: /* setloginclass(2) */
        ret = do_freebsd_setloginclass(arg1);
        break;

    case TARGET_FREEBSD_NR_getloginclass: /* getloginclass(2) */
        ret = do_freebsd_getloginclass(arg1, arg2);
        break;

#if 0
    case TARGET_FREEBSD_NR_pdwait4: /* pdwait4(2) */
        ret = do_freebsd_pdwait4(arg1, arg2, arg3, arg4);
        break;
#endif

    case TARGET_FREEBSD_NR_pdgetpid: /* pdgetpid(2) */
        ret = do_freebsd_pdgetpid(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___setugid: /* undocumented */
        ret = do_freebsd___setugid(arg1);
        break;

    case TARGET_FREEBSD_NR_jail: /* jail(2) */
        ret = do_freebsd_jail(arg1);
        break;

    case TARGET_FREEBSD_NR_jail_attach: /* jail_attach(2) */
        ret = do_freebsd_jail_attach(arg1);
        break;

    case TARGET_FREEBSD_NR_jail_remove: /* jail_remove(2) */
        ret = do_freebsd_jail_remove(arg1);
        break;

    case TARGET_FREEBSD_NR_jail_get: /* jail_get(2) */
        ret = do_freebsd_jail_get(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_jail_set: /* jail_set(2) */
        ret = do_freebsd_jail_set(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_cap_enter: /* cap_enter(2) */
        ret = do_freebsd_cap_enter();
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version < 1000000
    case TARGET_FREEBSD_NR_cap_new: /* cap_new(2) */
        ret = do_freebsd_cap_new(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_cap_getrights: /* cap_getrights(2) */
        ret = do_freebsd_cap_getrights(arg1, arg2);
        break;
#endif /* __FreeBSD_version < 1000000 */

    case TARGET_FREEBSD_NR_cap_getmode: /* cap_getmode(2) */
        ret = do_freebsd_cap_getmode(arg1);
        break;

    case TARGET_FREEBSD_NR_cap_rights_limit: /* cap_rights_limit(2) */
        ret = do_freebsd_cap_rights_limit(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_cap_ioctls_limit: /* cap_ioctls_limit(2) */
        ret = do_freebsd_cap_ioctls_limit(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_cap_ioctls_get: /* cap_ioctls_get(2) */
        ret = do_freebsd_cap_ioctls_get(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_cap_fcntls_limit: /* cap_fcntls_limit(2) */
        ret = do_freebsd_cap_fcntls_limit(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_cap_fcntls_get: /* cap_fcntls_get(2) */
        ret = do_freebsd_cap_fcntls_get(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_audit: /* audit(2) */
        ret = do_freebsd_audit(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_auditon: /* auditon(2) */
        ret = do_freebsd_auditon(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getaudit: /* getaudit(2) */
        ret = do_freebsd_getaudit(arg1);
        break;

    case TARGET_FREEBSD_NR_setaudit: /* setaudit(2) */
        ret = do_freebsd_setaudit(arg1);
        break;

    case TARGET_FREEBSD_NR_getaudit_addr: /* getaudit_addr(2) */
        ret = do_freebsd_getaudit_addr(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_setaudit_addr: /* setaudit_addr(2) */
        ret = do_freebsd_setaudit_addr(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_auditctl: /* auditctl(2) */
        ret = do_freebsd_auditctl(arg1);
        break;

    case TARGET_FREEBSD_NR_utrace: /* utrace(2) */
        ret = do_bsd_utrace(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_ptrace: /* ptrace(2) */
        ret = do_bsd_ptrace(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_getpriority: /* getpriority(2) */
        ret = do_bsd_getpriority(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_setpriority: /* setpriority(2) */
        ret = do_bsd_setpriority(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_procctl: /* procctl(2) */
        ret = do_freebsd_procctl(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

        /*
         * File system calls.
         */
    case TARGET_FREEBSD_NR_read: /* read(2) */
        ret = do_bsd_read(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_pread: /* pread(2) */
        ret = do_bsd_pread(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_readv: /* readv(2) */
        ret = do_bsd_readv(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_write: /* write(2) */
        ret = do_bsd_write(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_pwrite: /* pwrite(2) */
        ret = do_bsd_pwrite(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_writev: /* writev(2) */
        ret = do_bsd_writev(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_pwritev: /* pwritev(2) */
        ret = do_bsd_pwritev(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_open: /* open(2) */
        ret = do_bsd_open(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_openat: /* openat(2) */
        ret = do_bsd_openat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_close: /* close(2) */
        ret = do_bsd_close(arg1);
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1100502
    case TARGET_FREEBSD_NR_fdatasync: /* fdatasync(2) */
        ret = do_bsd_fdatasync(arg1);
        break;
#endif

    case TARGET_FREEBSD_NR_fsync: /* fsync(2) */
        ret = do_bsd_fsync(arg1);
        break;

    case TARGET_FREEBSD_NR_freebsd12_closefrom: /* closefrom(2) */
        ret = do_bsd_closefrom(arg1);
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300091
    case TARGET_FREEBSD_NR_close_range: /* close_range(2) */
        ret = do_freebsd_close_range(arg1, arg2, arg3);
        break;
#endif

    case TARGET_FREEBSD_NR_revoke: /* revoke(2) */
        ret = do_bsd_revoke(arg1);
        break;

#ifdef TARGET_FREEBSD_NR_creat
    case TARGET_FREEBSD_NR_creat: /* creat(2) (obsolete) */
        ret = do_bsd_creat(arg1);
        break;
#endif

    case TARGET_FREEBSD_NR_access: /* access(2) */
        ret = do_bsd_access(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_eaccess: /* eaccess(2) */
        ret = do_bsd_eaccess(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_faccessat: /* faccessat(2) */
        ret = do_bsd_faccessat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_chdir: /* chdir(2) */
        ret = do_bsd_chdir(arg1);
        break;

    case TARGET_FREEBSD_NR_fchdir: /* fchdir(2) */
        ret = do_bsd_fchdir(arg1);
        break;

    case TARGET_FREEBSD_NR_rename: /* rename(2) */
        ret = do_bsd_rename(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_renameat: /* renameat(2) */
        ret = do_bsd_renameat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_link: /* link(2) */
        ret = do_bsd_link(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_linkat: /* linkat(2) */
        ret = do_bsd_linkat(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_unlink: /* unlink(2) */
        ret = do_bsd_unlink(arg1);
        break;

    case TARGET_FREEBSD_NR_unlinkat: /* unlinkat(2) */
        ret = do_bsd_unlinkat(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_mkdir: /* mkdir(2) */
        ret = do_bsd_mkdir(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_mkdirat: /* mkdirat(2) */
        ret = do_bsd_mkdirat(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_rmdir: /* rmdir(2) (XXX no rmdirat()?) */
        ret = do_bsd_rmdir(arg1);
        break;

    case TARGET_FREEBSD_NR___getcwd: /* undocumented __getcwd() */
        ret = do_bsd___getcwd(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_dup: /* dup(2) */
        ret = do_bsd_dup(arg1);
        break;

    case TARGET_FREEBSD_NR_dup2: /* dup2(2) */
        ret = do_bsd_dup2(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_truncate: /* truncate(2) */
        ret = do_bsd_truncate(cpu_env, arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_ftruncate: /* ftruncate(2) */
        ret = do_bsd_ftruncate(cpu_env, arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_acct: /* acct(2) */
        ret = do_bsd_acct(arg1);
        break;

    case TARGET_FREEBSD_NR_sync: /* sync(2) */
        ret = do_bsd_sync();
        break;

    case TARGET_FREEBSD_NR_mount: /* mount(2) */
        ret = do_bsd_mount(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_unmount: /* unmount(2) */
        ret = do_bsd_unmount(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_nmount: /* nmount(2) */
        ret = do_bsd_nmount(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_symlink: /* symlink(2) */
        ret = do_bsd_symlink(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_symlinkat: /* symlinkat(2) */
        ret = do_bsd_symlinkat(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_readlink: /* readlink(2) */
        ret = do_bsd_readlink(cpu_env, arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_readlinkat: /* readlinkat(2) */
        ret = do_bsd_readlinkat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_chmod: /* chmod(2) */
        ret = do_bsd_chmod(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_fchmod: /* fchmod(2) */
        ret = do_bsd_fchmod(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_lchmod: /* lchmod(2) */
        ret = do_bsd_lchmod(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_fchmodat: /* fchmodat(2) */
        ret = do_bsd_fchmodat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_freebsd11_mknod: /* mknod(2) */
        ret = do_bsd_freebsd11_mknod(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_freebsd11_mknodat: /* mknodat(2) */
        ret = do_bsd_freebsd11_mknodat(arg1, arg2, arg3, arg4);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_mknodat: /* mknodat(2) */
        ret = do_bsd_mknodat(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
#endif

    case TARGET_FREEBSD_NR_chown: /* chown(2) */
        ret = do_bsd_chown(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_fchown: /* fchown(2) */
        ret = do_bsd_fchown(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_lchown: /* lchown(2) */
        ret = do_bsd_lchown(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_fchownat: /* fchownat(2) */
        ret = do_bsd_fchownat(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_chflags: /* chflags(2) */
        ret = do_bsd_chflags(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_chflagsat: /* chflagsat(2) */
        ret = do_bsd_chflagsat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_lchflags: /* lchflags(2) */
        ret = do_bsd_lchflags(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_fchflags: /* fchflags(2) */
        ret = do_bsd_fchflags(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_chroot: /* chroot(2) */
        ret = do_bsd_chroot(arg1);
        break;

    case TARGET_FREEBSD_NR_flock: /* flock(2) */
        ret = do_bsd_flock(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_mkfifo: /* mkfifo(2) */
        ret = do_bsd_mkfifo(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_mkfifoat: /* mkfifoat(2) */
        ret = do_bsd_mkfifoat(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_pathconf: /* pathconf(2) */
        ret = do_bsd_pathconf(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_lpathconf: /* lpathconf(2) */
        ret = do_bsd_lpathconf(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_fpathconf: /* fpathconf(2) */
        ret = do_bsd_fpathconf(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_undelete: /* undelete(2) */
        ret = do_bsd_undelete(arg1);
        break;

    case TARGET_FREEBSD_NR_poll: /* poll(2) */
        ret = do_bsd_poll(cpu_env, arg1, arg2, arg3);
        break;
#if defined(__FreeBSD_version) && __FreeBSD_version >= 1100000
    case TARGET_FREEBSD_NR_ppoll: /* ppoll(2) */
        ret = do_freebsd_ppoll(cpu_env, arg1, arg2, arg3, arg4);
        break;
#endif /* __FreeBSD_version >= 1100000 */

    case TARGET_FREEBSD_NR_lseek: /* lseek(2) */
        ret = do_bsd_lseek(cpu_env, arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_freebsd10_pipe: /* pipe(2) */
        ret = do_bsd_pipe(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_pipe2: /* pipe2(2) */
        ret = do_bsd_pipe2(cpu_env, arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_swapon: /* swapon(2) */
        ret = do_bsd_swapon(arg1);
        break;

    case TARGET_FREEBSD_NR_swapoff: /* swapoff(2) */
        ret = do_bsd_swapoff(arg1);
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300080
    case TARGET_FREEBSD_NR___realpathat:
        /* __realpathat(2) (XXX no realpathat()) */
        ret = do_freebsd_realpathat(arg1, arg2, arg3, arg4, arg5);
        break;
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300037
    case TARGET_FREEBSD_NR_copy_file_range:
        ret = do_freebsd_copy_file_range(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
#endif

        /*
         * stat system calls
         */
    case TARGET_FREEBSD_NR_freebsd11_stat: /* stat(2) */
        ret = do_freebsd11_stat(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_freebsd11_lstat: /* lstat(2) */
        ret = do_freebsd11_lstat(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_freebsd11_fstat: /* fstat(2) */
        ret = do_freebsd11_fstat(arg1, arg2);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_fstat: /* fstat(2) */
        ret = do_freebsd_fstat(arg1, arg2);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_fstatat: /* fstatat(2) */
        ret = do_freebsd11_fstatat(arg1, arg2, arg3, arg4);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_fstatat: /* fstatat(2) */
        ret = do_freebsd_fstatat(arg1, arg2, arg3, arg4);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_nstat: /* undocumented */
        ret = do_freebsd11_nstat(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_freebsd11_nfstat: /* undocumented */
        ret = do_freebsd11_nfstat(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_freebsd11_nlstat: /* undocumented */
        ret = do_freebsd11_nlstat(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_getfh: /* getfh(2) */
        ret = do_freebsd_getfh(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_lgetfh: /* lgetfh(2) */
        ret = do_freebsd_lgetfh(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_fhopen: /* fhopen(2) */
        ret = do_freebsd_fhopen(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_freebsd11_fhstat: /* fhstat(2) */
        ret = do_freebsd11_fhstat(arg1, arg2);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_fhstat: /* fhstat(2) */
        ret = do_freebsd_fhstat(arg1, arg2);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_fhstatfs: /* fhstatfs(2) */
        ret = do_freebsd11_fhstatfs(arg1, arg2);
        break;
        
#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_fhstatfs: /* fhstatfs(2) */
        ret = do_freebsd_fhstatfs(arg1, arg2);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_statfs: /* statfs(2) */
        ret = do_freebsd11_statfs(arg1, arg2);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_statfs: /* statfs(2) */
        ret = do_freebsd_statfs(arg1, arg2);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_fstatfs: /* fstatfs(2) */
        ret = do_freebsd11_fstatfs(arg1, arg2);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_fstatfs: /* fstatfs(2) */
        ret = do_freebsd_fstatfs(arg1, arg2);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_getfsstat: /* getfsstat(2) */
        ret = do_freebsd11_getfsstat(arg1, arg2, arg3);
        break;

#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_getfsstat: /* getfsstat(2) */
        ret = do_freebsd_getfsstat(arg1, arg2, arg3);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_getdents: /* getdents(2) */
        ret = do_freebsd11_getdents(arg1, arg2, arg3);
        break;
        
#ifdef BSD_HAVE_INO64
    case TARGET_FREEBSD_NR_getdirentries: /* getdirentries(2) */
        ret = do_freebsd_getdirentries(arg1, arg2, arg3, arg4);
        break;
#endif

    case TARGET_FREEBSD_NR_freebsd11_getdirentries: /* getdirentries(2) */
        ret = do_freebsd11_getdirentries(arg1, arg2, arg3, arg4);
        break;
    case TARGET_FREEBSD_NR_fcntl: /* fcntl(2) */
        ret = do_freebsd_fcntl(arg1, arg2, arg3);
        break;


        /*
         * Memory management system calls.
         */
    case TARGET_FREEBSD_NR_mmap: /* mmap(2) */
        ret = do_bsd_mmap(cpu_env, &retreg, &sa->args[0], &sa->args[1],
            &sa->args[2], &sa->args[3], &sa->args[4], &sa->args[5], &sa->args[6],
            &sa->args[7]);
        retval = &retreg;
        break;

    case TARGET_FREEBSD_NR_munmap: /* munmap(2) */
        ret = do_bsd_munmap(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_mprotect: /* mprotect(2) */
        ret = do_bsd_mprotect(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_msync: /* msync(2) */
        ret = do_bsd_msync(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_mlock: /* mlock(2) */
        ret = do_bsd_mlock(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_munlock: /* munlock(2) */
        ret = do_bsd_munlock(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_mlockall: /* mlockall(2) */
        ret = do_bsd_mlockall(arg1);
        break;

    case TARGET_FREEBSD_NR_munlockall: /* munlockall(2) */
        ret = do_bsd_munlockall();
        break;

    case TARGET_FREEBSD_NR_madvise: /* madvise(2) */
        ret = do_bsd_madvise(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_minherit: /* minherit(2) */
        ret = do_bsd_minherit(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_mincore: /* mincore(2) */
        ret = do_bsd_mincore(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_freebsd12_shm_open: /* shm_open(2) */
        ret = do_bsd_shm_open(arg1, arg2, arg3);
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300048
    case TARGET_FREEBSD_NR_shm_open2: /* shm_open2(2) */
        ret = do_freebsd_shm_open2(arg1, arg2, arg3, arg4, arg5);
        break;
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300049
    case TARGET_FREEBSD_NR_shm_rename: /* shm_rename(2) */
        ret = do_freebsd_shm_rename(arg1, arg2, arg3);
        break;
#endif

    case TARGET_FREEBSD_NR_shm_unlink: /* shm_unlink(2) */
        ret = do_bsd_shm_unlink(arg1);
        break;

    case TARGET_FREEBSD_NR_shmget: /* shmget(2) */
        ret = do_bsd_shmget(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_shmctl: /* shmctl(2) */
        ret = do_bsd_shmctl(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_shmat: /* shmat(2) */
        ret = do_bsd_shmat(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_shmdt: /* shmdt(2) */
        ret = do_bsd_shmdt(arg1);
        break;

    case TARGET_FREEBSD_NR_freebsd11_vadvise:
        ret = do_bsd_vadvise();
        break;

    case TARGET_FREEBSD_NR_sbrk:
        ret = do_bsd_sbrk();
        break;

    case TARGET_FREEBSD_NR_sstk:
        ret = do_bsd_sstk();
        break;

        /*
         * time related system calls.
         */
    case TARGET_FREEBSD_NR_nanosleep: /* nanosleep(2) */
        ret = do_freebsd_nanosleep(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_clock_nanosleep: /* clock_nanosleep(2) */
        ret = do_freebsd_clock_nanosleep(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_clock_gettime: /* clock_gettime(2) */
        ret = do_freebsd_clock_gettime(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_clock_settime: /* clock_settime(2) */
        ret = do_freebsd_clock_settime(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_clock_getres: /* clock_getres(2) */
        ret = do_freebsd_clock_getres(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_gettimeofday: /* gettimeofday(2) */
        ret = do_freebsd_gettimeofday(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_settimeofday: /* settimeofday(2) */
        ret = do_freebsd_settimeofday(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_adjtime: /* adjtime(2) */
        ret = do_freebsd_adjtime(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_ntp_adjtime: /* ntp_adjtime(2) */
        ret = do_freebsd_ntp_adjtime(arg1);
        break;

    case TARGET_FREEBSD_NR_clock_getcpuclockid2: /* Not documented. */
        ret = do_freebsd_clock_getcpuclockid2(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_ntp_gettime: /* ntp_gettime(2) */
        ret = do_freebsd_ntp_gettime(arg1);
        break;

    case TARGET_FREEBSD_NR_utimes: /* utimes(2) */
        ret = do_freebsd_utimes(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_lutimes: /* lutimes(2) */
        ret = do_freebsd_lutimes(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_futimes: /* futimes(2) */
        ret = do_freebsd_futimes(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_futimesat: /* futimesat(2) */
        ret = do_freebsd_futimesat(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_ktimer_create: /* timer_create(2) */
        ret = do_freebsd_ktimer_create(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_ktimer_delete: /* timer_delete(2) */
        ret = do_freebsd_ktimer_delete(arg1);
        break;

    case TARGET_FREEBSD_NR_ktimer_settime: /* timer_settime(2) */
        ret = do_freebsd_ktimer_settime(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_ktimer_gettime: /* timer_gettime(2) */
        ret = do_freebsd_ktimer_gettime(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_ktimer_getoverrun: /* timer_getoverrun(2) */
        ret = do_freebsd_ktimer_getoverrun(arg1);
        break;

    case TARGET_FREEBSD_NR_select: /* select(2) */
        ret = do_freebsd_select(cpu_env, arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_pselect: /* pselect(2) */
        ret = do_freebsd_pselect(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_kqueue: /* kqueue(2) */
        ret = do_freebsd_kqueue();
        break;

    case TARGET_FREEBSD_NR_freebsd11_kevent: /* kevent(2) */
        ret = do_freebsd_freebsd11_kevent(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

#ifdef BSD_HAVE_KEVENT64
    case TARGET_FREEBSD_NR_kevent: /* kevent(2) */
        ret = do_freebsd_kevent(&retreg, &sa->args[0], &sa->args[1], &sa->args[2],
            &sa->args[3], &sa->args[4], &sa->args[5]);
        retval = &retreg;
        break;
#endif

    case TARGET_FREEBSD_NR_setitimer: /* setitimer(2) */
        ret = do_freebsd_setitimer(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getitimer: /* getitimer(2) */
        ret = do_freebsd_getitimer(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_futimens: /* futimens(2) */
        ret = do_freebsd_futimens(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_utimensat: /* utimensat(2) */
        ret = do_freebsd_utimensat(arg1, arg2, arg3, arg4);
        break;

        /*
         * signal system calls
         */
    case TARGET_FREEBSD_NR_sigtimedwait: /* sigtimedwait(2) */
        ret = do_freebsd_sigtimedwait(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_sigaction: /* sigaction(2) */
        ret = do_bsd_sigaction(&retreg, &sa->args[0], &sa->args[1],
            &sa->args[2]);
        retval = &retreg;
        break;

    case TARGET_FREEBSD_NR_sigprocmask: /* sigprocmask(2) */
        ret = do_bsd_sigprocmask(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_sigpending: /* sigpending(2) */
        ret = do_bsd_sigpending(arg1);
        break;

    case TARGET_FREEBSD_NR_sigsuspend: /* sigsuspend(2) */
        ret = do_bsd_sigsuspend(cpu_env, arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_sigreturn: /* sigreturn(2) */
        ret = do_bsd_sigreturn(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_sigwait: /* sigwait(2) */
        ret = do_bsd_sigwait(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_sigwaitinfo: /* sigwaitinfo(2) */
        ret = do_bsd_sigwaitinfo(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_sigqueue: /* sigqueue(2) */
        ret = do_bsd_sigqueue(&retreg, &sa->args[0], &sa->args[1], &sa->args[2]);
        retval = &retreg;
        break;

    case TARGET_FREEBSD_NR_sigaltstack: /* sigaltstack(2) */
        ret = do_bsd_sigaltstack(cpu_env, &retreg, &sa->args[0], &sa->args[1]);
        retval = &retreg;
        break;

    case TARGET_FREEBSD_NR_kill: /* kill(2) */
        ret = do_bsd_kill(arg1, arg2);
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version < 1000000
    case TARGET_FREEBSD_NR_killpg: /* killpg(2) */
        ret = do_bsd_killpg(arg1, arg2);
        break;
#endif

    case TARGET_FREEBSD_NR_pdkill: /* pdkill(2) */
        ret = do_freebsd_pdkill(arg1, arg2);
        break;

        /*
         * socket related system calls
         */
    case TARGET_FREEBSD_NR_accept: /* accept(2) */
        ret = do_bsd_accept(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_accept4: /* accept4(2) */
        ret = do_freebsd_accept4(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_bind: /* bind(2) */
        ret = do_bsd_bind(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_bindat: /* bindat(2) */
        ret = do_freebsd_bindat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_connect: /* connect(2) */
        ret = do_bsd_connect(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_connectat: /* connectat(2) */
        ret = do_freebsd_connectat(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_getpeername: /* getpeername(2) */
        ret = do_bsd_getpeername(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getsockname: /* getsockname(2) */
        ret = do_bsd_getsockname(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getsockopt: /* getsockopt(2) */
        ret = do_bsd_getsockopt(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_setsockopt: /* setsockopt(2) */
        ret = do_bsd_setsockopt(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_listen: /* listen(2) */
        ret = get_errno(listen(arg1, arg2));
        break;

    case TARGET_FREEBSD_NR_recvfrom: /* recvfrom(2) */
        ret = do_bsd_recvfrom(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_recvmsg: /* recvmsg(2) */
        ret = do_sendrecvmsg(arg1, arg2, arg3, 0);
        break;

    case TARGET_FREEBSD_NR_sendmsg: /* sendmsg(2) */
        ret = do_sendrecvmsg(arg1, arg2, arg3, 1);
        break;

    case TARGET_FREEBSD_NR_sendto: /* sendto(2) */
        ret = do_bsd_sendto(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_socket: /* socket(2) */
        ret = do_bsd_socket(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_socketpair: /* socketpair(2) */
        ret = do_bsd_socketpair(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_shutdown: /* shutdown(2) */
        ret = do_bsd_shutdown(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_setfib: /* setfib(2) */
        ret = do_freebsd_setfib(arg1);
        break;

    case TARGET_FREEBSD_NR_sctp_peeloff: /* sctp_peeloff(2) */
        ret = do_freebsd_sctp_peeloff(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_sctp_generic_sendmsg: /* sctp_generic_sendmsg(2) */
        ret = do_freebsd_sctp_generic_sendmsg(arg1, arg2, arg2, arg4, arg5,
                arg6, arg7);
        break;

    case TARGET_FREEBSD_NR_sctp_generic_recvmsg: /* sctp_generic_recvmsg(2) */
        ret = do_freebsd_sctp_generic_recvmsg(arg1, arg2, arg2, arg4, arg5,
                arg6, arg7);
        break;

    case TARGET_FREEBSD_NR_sendfile: /* sendfile(2) */
        ret = do_freebsd_sendfile(arg1, arg2, arg2, arg4, arg5, arg6, arg7,
                arg8);
        break;

        /*
         * thread system calls
         */
    case TARGET_FREEBSD_NR_thr_create: /* thr_create(2) */
        ret = do_freebsd_thr_create(cpu_env, arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_thr_new: /* thr_new(2) */
        ret = do_freebsd_thr_new(cpu_env, arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_thr_set_name: /* thr_set_name(2) */
        ret = do_freebsd_thr_set_name(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_thr_self: /* thr_self(2) */
        ret = do_freebsd_thr_self(arg1);
        break;

    case TARGET_FREEBSD_NR_thr_suspend: /* thr_suspend(2) */
        ret = do_freebsd_thr_suspend(arg1);
        break;

    case TARGET_FREEBSD_NR_thr_wake: /* thr_wake(2) */
        ret = do_freebsd_thr_wake(arg1);
        break;

    case TARGET_FREEBSD_NR_thr_kill: /* thr_kill(2) */
        ret = do_freebsd_thr_kill(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_thr_kill2: /* thr_kill2(2) */
        ret = do_freebsd_thr_kill2(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_thr_exit: /* thr_exit(2) */
        ret = do_freebsd_thr_exit(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_rtprio_thread: /* rtprio_thread(2) */
        ret = do_freebsd_rtprio_thread(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_getcontext: /* getcontext(2) */
        ret = do_freebsd_getcontext(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_setcontext: /* setcontext(2) */
        ret = do_freebsd_setcontext(cpu_env, arg1);
        break;

    case TARGET_FREEBSD_NR_swapcontext: /* swapcontext(2) */
        ret = do_freebsd_swapcontext(cpu_env, arg1, arg2);
        break;

#if defined(__FreeBSD_version) && __FreeBSD_version < 1000000
    case TARGET_FREEBSD_NR__umtx_lock: /* undocumented */
        ret = do_freebsd__umtx_lock(arg1);
        break;

    case TARGET_FREEBSD_NR__umtx_unlock: /* undocumented */
        ret = do_freebsd__umtx_unlock(arg1);
        break;
#endif

    case TARGET_FREEBSD_NR__umtx_op: /* undocumented */
        ret = do_freebsd__umtx_op(arg1, arg2, arg3, arg4, arg5);
        break;

        /*
         * ioctl(2)
         */
    case TARGET_FREEBSD_NR_ioctl: /* ioctl(2) */
        ret = do_bsd_ioctl(arg1, arg2, arg3);
        break;

        /*
         * sys{ctl, arch, call}
         */
    case TARGET_FREEBSD_NR___sysctl: /* sysctl(3) */
        ret = do_freebsd_sysctl(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR___sysctlbyname: /* sysctlbyname(2) */
        ret = do_freebsd_sysctlbyname(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_sysarch: /* sysarch(2) */
        ret = do_freebsd_sysarch(cpu_env, arg1, arg2);
        break;

        /*
         * extended attributes system calls
         */
    case TARGET_FREEBSD_NR_extattrctl: /* extattrctl() */
        ret = do_freebsd_extattrctl(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_extattr_set_file: /* extattr_set_file(2) */
        ret = do_freebsd_extattr_set_file(arg1, arg2, arg3, arg4, arg4);
        break;

    case TARGET_FREEBSD_NR_extattr_get_file: /* extattr_get_file(2) */
        ret = do_freebsd_extattr_get_file(arg1, arg2, arg3, arg4, arg4);
        break;

    case TARGET_FREEBSD_NR_extattr_delete_file: /* extattr_delete_file(2) */
        ret = do_freebsd_extattr_delete_file(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_extattr_set_fd: /* extattr_set_fd(2) */
        ret = do_freebsd_extattr_set_fd(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_extattr_get_fd: /* extattr_get_fd(2) */
        ret = do_freebsd_extattr_get_fd(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_extattr_delete_fd: /* extattr_delete_fd(2) */
        ret = do_freebsd_extattr_delete_fd(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_extattr_get_link: /* extattr_get_link(2) */
        ret = do_freebsd_extattr_get_link(arg1, arg2, arg3, arg4, arg4);
        break;

    case TARGET_FREEBSD_NR_extattr_set_link: /* extattr_set_link(2) */
        ret = do_freebsd_extattr_set_link(arg1, arg2, arg3, arg4, arg4);
        break;

    case TARGET_FREEBSD_NR_extattr_delete_link: /* extattr_delete_link(2) */
        ret = do_freebsd_extattr_delete_link(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_extattr_list_fd: /* extattr_list_fd(2) */
        ret = do_freebsd_extattr_list_fd(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_extattr_list_file: /* extattr_list_file(2) */
        ret = do_freebsd_extattr_list_file(arg1, arg2, arg3,  arg4);
        break;

    case TARGET_FREEBSD_NR_extattr_list_link: /* extattr_list_link(2) */
        ret = do_freebsd_extattr_list_link(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR___acl_aclcheck_fd: /* __acl_aclcheck_fd() */
        ret = do_freebsd__acl_aclcheck_fd(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_aclcheck_file: /* __acl_aclcheck_file() */
        ret = do_freebsd__acl_aclcheck_file(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_aclcheck_link: /* __acl_aclcheck_link() */
        ret = do_freebsd__acl_aclcheck_link(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_delete_fd: /* __acl_delete_fd() */
        ret = do_freebsd__acl_delete_fd(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___acl_delete_file: /* __acl_delete_file() */
        ret = do_freebsd__acl_delete_file(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___acl_delete_link: /* __acl_delete_link() */
        ret = do_freebsd__acl_delete_link(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___acl_get_fd: /* __acl_get_fd() */
        ret =  do_freebsd__acl_get_fd(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_get_file: /* __acl_get_file() */
        ret = do_freebsd__acl_get_file(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_get_link: /* __acl_get_link() */
        ret = do_freebsd__acl_get_link(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_set_fd: /* __acl_get_fd() */
        ret = do_freebsd__acl_set_fd(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_set_file: /* __acl_set_file() */
        ret = do_freebsd__acl_set_file(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___acl_set_link: /* __acl_set_link() */
        ret = do_freebsd__acl_set_link(arg1, arg2, arg3);
        break;

        /*
         * SysV Semaphores
         */
    case TARGET_FREEBSD_NR_semget: /* semget(2) */
        ret = do_bsd_semget(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_semop: /* semop(2) */
        ret = do_bsd_semop(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR___semctl: { /* __semctl() undocumented */
        /* The semun argument to semctl is passed by value, so dereference the
         * ptr argument. */
        abi_ulong atptr;
        get_user_ual(atptr, (abi_ulong)arg4);
        ret = do_bsd___semctl(arg1, arg2, arg3,
                (union target_semun)(abi_ulong) atptr);
        break;
    }

        /*
         * SysV Messages
         */
    case TARGET_FREEBSD_NR_msgctl: /* msgctl(2) */
        ret = do_bsd_msgctl(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_msgget: /* msgget(2) */
        ret = do_bsd_msgget(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_msgsnd: /* msgsnd(2) */
        ret = do_bsd_msgsnd(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_msgrcv: /* msgrcv(2) */
        ret = do_bsd_msgrcv(arg1, arg2, arg3, arg4, arg5);
        break;

        /*
         * FreeBSD scheduler control
         */
    case TARGET_FREEBSD_NR_sched_setparam: /* sched_setparam(2) */
        ret = do_freebsd_sched_setparam(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_sched_getparam: /* sched_getparam(2) */
        ret = do_freebsd_sched_getparam(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_sched_setscheduler: /* sched_setscheduler(2) */
        ret = do_freebsd_sched_setscheduler(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_sched_getscheduler: /* sched_getscheduler(2) */
        ret = do_freebsd_sched_getscheduler(arg1);
        break;

    case TARGET_FREEBSD_NR_sched_get_priority_max: /* sched_get_priority_max(2)*/
		ret = do_bsd_sched_get_priority_max(arg1);
		break;

    case TARGET_FREEBSD_NR_sched_get_priority_min: /* sched_get_priority_min(2)*/
		ret = do_bsd_sched_get_priority_min(arg1);
		break;

    case TARGET_FREEBSD_NR_sched_rr_get_interval: /* sched_rr_get_interval(2) */
        ret = do_freebsd_sched_rr_get_interval(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_sched_yield: /* sched_yield(2)*/
		ret = do_bsd_sched_yield();
		break;


        /*
         * FreeBSD CPU affinity sets management
         */
    case TARGET_FREEBSD_NR_cpuset: /* cpuset(2) */
        ret = do_freebsd_cpuset(arg1);
        break;

    case TARGET_FREEBSD_NR_cpuset_setid: /* cpuset_setid(2) */
        ret = do_freebsd_cpuset_setid(cpu_env, arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_cpuset_getid: /* cpuset_getid(2) */
        ret = do_freebsd_cpuset_getid(arg1, arg2, arg3, arg4, arg5);
        break;

    case TARGET_FREEBSD_NR_cpuset_getaffinity: /* cpuset_getaffinity(2) */
        ret = do_freebsd_cpuset_getaffinity(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_cpuset_setaffinity: /* cpuset_setaffinity(2) */
        ret = do_freebsd_cpuset_setaffinity(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_cpuset_getdomain: /* cpuset_getdomain(2) */
        ret = do_freebsd_cpuset_getdomain(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_cpuset_setdomain: /* cpuset_setdomain(2) */
        ret = do_freebsd_cpuset_setdomain(arg1, arg2, arg3, arg4, arg5, arg6);
        break;


        /*
         * FreeBSD kernel module
         */
    case TARGET_FREEBSD_NR_modfnext: /* modfnext(2) */
        ret = do_freebsd_modfnext(arg1);
        break;

    case TARGET_FREEBSD_NR_modfind: /* modfind(2) */
        ret = do_freebsd_modfind(arg1);
        break;

    case TARGET_FREEBSD_NR_kldload: /* kldload(2) */
        ret = do_freebsd_kldload(arg1);
        break;

    case TARGET_FREEBSD_NR_kldunload: /* kldunload(2) */
        ret = do_freebsd_kldunload(arg1);
        break;

    case TARGET_FREEBSD_NR_kldunloadf: /* kldunloadf(2) */
        ret = do_freebsd_kldunloadf(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_kldfind: /* kldfind(2) */
        ret = do_freebsd_kldfind(arg1);
        break;

    case TARGET_FREEBSD_NR_kldnext: /* kldnext(2) */
        ret = do_freebsd_kldnext(arg1);
        break;

    case TARGET_FREEBSD_NR_kldstat: /* kldstat(2) */
        ret = do_freebsd_kldstat(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_kldfirstmod: /* kldfirstmod(2) */
        ret = do_freebsd_kldfirstmod(arg1);
        break;

    case TARGET_FREEBSD_NR_kldsym: /* kldsym(2) */
        ret = do_freebsd_kldsym(arg1, arg2, arg3);
        break;

        /*
         * FreeBSD resource controls (undocumented except for rctl(8)
         * and rctl.conf(5) )
         */
    case TARGET_FREEBSD_NR_rctl_get_racct: /* rctl_get_racct() */
        ret = do_freebsd_rctl_get_racct(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_rctl_get_rules: /* rctl_get_rules() */
        ret = do_freebsd_rctl_get_rules(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_rctl_add_rule: /* rctl_add_rule() */
        ret = do_freebsd_rctl_add_rule(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_rctl_remove_rule: /* rctl_remove_rule() */
        ret = do_freebsd_rctl_remove_rule(arg1, arg2, arg3, arg4);
        break;

    case TARGET_FREEBSD_NR_rctl_get_limits: /* rctl_get_limits() */
        ret = do_freebsd_rctl_get_limits(arg1, arg2, arg3, arg4);
        break;

        /*
         * FreeBSD Mandatory Access Control
         */
    case TARGET_FREEBSD_NR___mac_get_proc: /* __mac_get_proc() */
        ret = do_freebsd___mac_get_proc(arg1);
        break;

    case TARGET_FREEBSD_NR___mac_set_proc: /* __mac_set_proc() */
        ret = do_freebsd___mac_set_proc(arg1);
        break;

    case TARGET_FREEBSD_NR___mac_get_fd: /* __mac_get_fd() */
        ret = do_freebsd___mac_get_fd(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___mac_set_fd: /* __mac_set_fd() */
        ret = do_freebsd___mac_set_fd(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___mac_get_file: /* __mac_get_file() */
        ret = do_freebsd___mac_get_proc(arg1);
        break;

    case TARGET_FREEBSD_NR___mac_set_file: /* __mac_set_file() */
        ret = do_freebsd___mac_set_file(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___mac_get_link: /* __mac_get_link() */
        ret = do_freebsd___mac_get_link(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR___mac_set_link: /* __mac_set_link() */
        ret = do_freebsd___mac_set_link(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_mac_syscall: /* mac_syscall() */
        ret = do_freebsd_mac_syscall(arg1, arg2, arg3);
        break;

        /*
         * FreeBSD additional posix support
         */
    case TARGET_FREEBSD_NR_posix_fallocate: /* posix_fallocate(2) */
        ret = do_freebsd_posix_fallocate(arg1, arg2, arg3, arg4, arg5, arg6);
        break;

    case TARGET_FREEBSD_NR_posix_openpt: /* posix_openpt(2) */
        ret = do_freebsd_posix_openpt(arg1);
        break;

    case TARGET_FREEBSD_NR_posix_fadvise: /* posix_fadvise(2) */
        ret = do_freebsd_posix_fadvise(arg1, arg2, arg3, arg4);
        break;

        /*
         * Misc
         */
    case TARGET_FREEBSD_NR_quotactl: /* quotactl(2) */
        ret = do_bsd_quotactl(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_reboot: /* reboot(2) */
        ret = do_bsd_reboot(arg1);
        break;

    case TARGET_FREEBSD_NR_uuidgen: /* uuidgen(2) */
        ret = do_bsd_uuidgen(arg1, arg2);
        break;

    case TARGET_FREEBSD_NR_getdtablesize: /* getdtablesize(2) */
        ret = do_bsd_getdtablesize();
        break;

    case TARGET_FREEBSD_NR_kenv: /* kenv(2) */
        ret = do_freebsd_kenv(arg1, arg2, arg2, arg4);
        break;

    case TARGET_FREEBSD_NR_break:
        ret = do_obreak(arg1);
        break;

#if defined(HAVE_GETRANDOM)
    case TARGET_FREEBSD_NR_getrandom:
        ret = do_freebsd_getrandom(arg1, arg2, arg3);
        break;
#endif

	/*
	 * Asynchronous I/O
	 */
    case  TARGET_FREEBSD_NR_aio_read: /* aio_read(2) */
	ret = do_freebsd_aio_read(arg1);
	break;

    case  TARGET_FREEBSD_NR_aio_write: /* aio_write(2) */
	ret = do_freebsd_aio_write(arg1);
	break;

    case  TARGET_FREEBSD_NR_aio_suspend: /* aio_suspend(2) */
	ret = do_freebsd_aio_suspend(arg1, arg2, arg3);
	break;

    case  TARGET_FREEBSD_NR_aio_cancel: /* aio_cancel(2) */
	ret = do_freebsd_aio_cancel(arg1, arg2);
	break;

    case  TARGET_FREEBSD_NR_aio_error: /* aio_error(2) */
	ret = do_freebsd_aio_error(arg1);
	break;

    case  TARGET_FREEBSD_NR_aio_waitcomplete: /* aio_waitcomplete(2) */
	ret = do_freebsd_aio_waitcomplete(arg1, arg2);
	break;

    case  TARGET_FREEBSD_NR_aio_fsync: /* aio_fsync(2) */
	ret = do_freebsd_aio_fsync(arg1, arg2);
	break;

    case  TARGET_FREEBSD_NR_aio_mlock: /* aio_mlock(2) */
	ret = do_freebsd_aio_mlock(arg1);
	break;

    case TARGET_FREEBSD_NR_kbounce:
        ret = do_freebsd_kbounce(&retreg, &sa->args[0], &sa->args[1],
            &sa->args[2], &sa->args[3]);
        retval = &retreg;
        break;

    case TARGET_FREEBSD_NR_flag_captured:
        ret = do_freebsd_flag_captured(&retreg, &sa->args[0], &sa->args[1],
            __func__);
        retval = &retreg;
        break;

    default:
	gemu_log("qemu: unsupported syscall: %d (calling anyway)\n", sa->code);
        ret = get_errno(syscall(sa->code, arg1, arg2, arg3, arg4, arg5, arg6,
            arg7, arg8));
        break;
    }

#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace) {
        print_freebsd_syscall_ret(sa->code, ret, get_clock() - timestamp);
    }

    record_syscall_return(cpu, sa->code, ret);
    *retvalp = retval;
    return ret;
}

#if 0
/*
 * XXXKW: See bsd-user/qemu.h.
 */

abi_long do_netbsd_syscall(void *cpu_env, int num, abi_long arg1,
                           abi_long arg2, abi_long arg3, abi_long arg4,
                           abi_long arg5, abi_long arg6)
{
    CPUState *cpu = env_cpu(cpu_env);
    abi_long ret;

#ifdef DEBUG
    gemu_log("netbsd syscall %d\n", num);
#endif

    record_syscall_start(cpu, num, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0);

    if(do_strace)
        print_netbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_NETBSD_NR_exit:
#ifdef CONFIG_GPROF
        _mcleanup();
#endif
        gdb_exit(arg1);
        qemu_plugin_atexit_cb();
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;

    case TARGET_NETBSD_NR_read:
        ret = do_bsd_read(arg1, arg2, arg3);
        break;
    case TARGET_NETBSD_NR_write:
        ret = do_bsd_write(arg1, arg2, arg3);
        break;
    case TARGET_NETBSD_NR_open:
        ret = do_bsd_open(arg1, arg2, arg3);
        break;

    case TARGET_NETBSD_NR_mmap:
        ret = do_bsd_mmap(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0);
        break;
    case TARGET_NETBSD_NR_mprotect:
        ret = do_bsd_mprotect(arg1, arg2, arg3);
        break;

    case TARGET_NETBSD_NR_syscall:
    case TARGET_NETBSD_NR___syscall:
        ret = do_netbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_netbsd_syscall_ret(num, ret);

    record_syscall_return(cpu, num, ret);
    return ret;
}

abi_long do_openbsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6)
{
    CPUState *cpu = env_cpu(cpu_env);
    abi_long ret;

#ifdef DEBUG
    gemu_log("openbsd syscall %d\n", num);
#endif

    record_syscall_start(cpu, num, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0);

    if(do_strace)
        print_openbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_OPENBSD_NR_exit:
#ifdef CONFIG_GPROF
        _mcleanup();
#endif
        gdb_exit(arg1);
        qemu_plugin_atexit_cb();
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;

    case TARGET_OPENBSD_NR_read:
        ret = do_bsd_read(arg1, arg2, arg3);
        break;
    case TARGET_OPENBSD_NR_write:
        ret = do_bsd_write(arg1, arg2, arg3);
        break;
    case TARGET_OPENBSD_NR_open:
        ret = do_bsd_open(arg1, arg2, arg3);
        break;

    case TARGET_OPENBSD_NR_mmap:
        ret = do_bsd_mmap(cpu_env, arg1, arg2, arg3, arg4, arg5, arg6, 0, 0);
        break;
    case TARGET_OPENBSD_NR_mprotect:
        ret = do_bsd_mprotect(arg1, arg2, arg3);
        break;

    case TARGET_OPENBSD_NR_syscall:
    case TARGET_OPENBSD_NR___syscall:
        ret = do_openbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_openbsd_syscall_ret(num, ret);

    record_syscall_return(cpu, num, ret);
    return ret;
}
#endif

void syscall_init(void)
{

    init_bsd_ioctl();
}
