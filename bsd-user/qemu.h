/*
 *  qemu bsd user mode definition
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
#ifndef QEMU_H
#define QEMU_H

#include <sys/param.h>

int qemu_sigorset(sigset_t *dest, const sigset_t *left, const sigset_t *right);

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1200031
#define BSD_HAVE_INO64
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1200033
#define BSD_HAVE_KEVENT64
#endif

/* needed for fprintf() debug function */
#include <stdio.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu_ldst.h"

#undef DEBUG_REMAP
#ifdef DEBUG_REMAP
#include <stdio.h>
#endif /* DEBUG_REMAP */

#include "exec/user/abitypes.h"

enum BSDType {
    target_freebsd,
    target_netbsd,
    target_openbsd,
};
extern enum BSDType bsd_type;

#include "exec/user/thunk.h"
#include "target_arch.h"
#include "syscall_defs.h"
#include "target_syscall.h"
#include "target_os_siginfo.h"
#include "target_os_vmparam.h"
#include "target_arch_proc.h"
#include "hostdep.h"
#include "exec/gdbstub.h"

#define THREAD __thread
#define THREAD_ENV()    ((CPUArchState *)thread_cpu->env_ptr)
#define THREAD_STATE()  ((TaskState *)thread_cpu->opaque)

/* This struct is used to hold certain information about the image.
 * Basically, it replicates in user space what would be certain
 * task_struct fields in the kernel
 */
struct image_info {
    abi_ulong load_bias;
    abi_ulong load_addr;
    abi_ulong start_code;
    abi_ulong end_code;
    abi_ulong start_data;
    abi_ulong end_data;
    abi_ulong start_brk;
    abi_ulong brk;
    abi_ulong start_addr;
    abi_ulong end_addr;
    abi_ulong interp_end;
    abi_ulong start_mmap;
    abi_ulong mmap;
    abi_ulong rss;
    abi_ulong start_stack;
    abi_ulong entry;
    abi_ulong code_offset;
    abi_ulong data_offset;
    abi_ulong arg_start;
    abi_ulong arg_end;
    abi_ulong reloc_base;
    int       personality;
#ifdef TARGET_CHERI
    bool      benchmarkabi;
#endif
};

extern abi_ulong target_auxents;   /* Where the AUX entries are in target */
extern size_t target_auxents_sz;   /* Size of AUX entries including AT_NULL */

#define MAX_SIGQUEUE_SIZE 1024

#if defined(TARGET_CHERI) && !defined(SIGPROT)
#define SIGPROT 34 /* in-address space security exception. */
#endif

struct qemu_sigqueue {
    struct qemu_sigqueue *next;
    target_siginfo_t info;
};

struct emulated_sigtable {
    int pending; /* true if signal is pending */
    struct qemu_sigqueue *first;
    struct qemu_sigqueue info; /* in order to always have memory for the
                                  first signal, we put it here */
};

/* NOTE: we force a big alignment so that the stack stored after is
   aligned too */
typedef struct TaskState {
    pid_t ts_tid;     /* tid (or pid) of this task */

    struct TaskState *next;
    int used; /* non zero if used */
#ifdef TARGET_ARM
    int swi_errno;
#endif
#if defined(TARGET_ARM) || defined(TARGET_M68K) || defined(TARGET_UNICORE32)
    /* Extra fields for semihosted binaries. */
    uint32_t heap_base;
    uint32_t heap_limit;
    uint32_t stack_base;
#endif
    struct image_info *info;
    struct bsd_binprm *bprm;

    struct emulated_sigtable sigtab[TARGET_NSIG];
    struct qemu_sigqueue sigqueue_table[MAX_SIGQUEUE_SIZE]; /* siginfo queue */
    struct qemu_sigqueue *first_free; /* first free siginfo queue entry */
    int signal_pending; /* non zero if a signal may be pending */
    bool in_sigsuspend;
    sigset_t signal_mask;
    sigset_t sigsuspend_mask;

#ifdef TARGET_CHERI
#if defined(TARGET_AARCH64) || defined(TARGET_RISCV)
    cap_register_t cheri_sigcode_cap;
#endif
#endif

    uint8_t stack[];
} __attribute__((aligned(16))) TaskState;

/*
 * target_os_signal.h depends on TaskState.
 */
#include "target_os_signal.h"

void init_task_state(TaskState *ts);
void stop_all_tasks(void);
extern const char *interp_prefix;
extern const char *interp_path;
extern const char *qemu_uname_release;

/* ??? See if we can avoid exposing so much of the loader internals.  */
/*
 * TARGET_ARG_MAX defines the number of bytes allocated for arguments
 * and envelope for the new program. 256k should suffice for a reasonable
 * maxiumum env+arg in 32-bit environments, bump it up to 512k for !ILP32
 * platforms.
 */
#if TARGET_ABI_BITS > 32
#define TARGET_ARG_MAX (512 * 1024)
#else
#define TARGET_ARG_MAX (256 * 1024)
#endif
#define MAX_ARG_PAGES (TARGET_ARG_MAX / TARGET_PAGE_SIZE)

/*
 * This structure is used to hold the arguments that are
 * used when loading binaries.
 */
struct bsd_binprm {
        char buf[128];
        void *page[MAX_ARG_PAGES];
        abi_ulong p;
        abi_ulong stringp;
        int fd;
        int e_uid, e_gid;
        int argc, envc;
        char **argv;
        char **envp;
        char *filename;         /* (Given) Name of binary */
        char *fullpath;         /* Full path of binary */
        int (*core_dump)(int, CPUArchState *);
};

void do_init_thread(struct target_pt_regs *regs,
#ifdef TARGET_CHERI
    cap_register_t *sigcodecapp,
#endif
    struct image_info *infop);
abi_ulong loader_build_argptr(int envc, int argc, abi_ulong sp,
                              abi_ulong stringp, int push_ptr);
int loader_exec(const char *filename, char **argv, char **envp,
             struct target_pt_regs *regs,
#ifdef TARGET_CHERI
             cap_register_t *sigcodecapp,
#endif
             struct image_info *infop, struct bsd_binprm *bprm);

int load_elf_binary(struct bsd_binprm *bprm, struct target_pt_regs *regs,
                    struct image_info *info);
int load_flt_binary(struct bsd_binprm *bprm, struct target_pt_regs *regs,
                    struct image_info *info);
int is_target_elf_binary(int fd);

abi_long memcpy_to_target(abi_ulong dest, const void *src,
                          unsigned long len);
void target_set_brk(abi_ulong new_brk);
abi_long do_brk(abi_ulong new_brk);
void syscall_init(void);
abi_long do_freebsd_syscall(void *cpu_env, abi_syscallret_t *retvalp,
    struct target_syscall_args *sa);
#if 0
/*
 * XXXKW: do_{netbsd,openbsd}_syscall must be adapted to the current system
 * call interface to work with the current BSD user mode.
 */
abi_long do_netbsd_syscall(void *cpu_env, int num, abi_long arg1,
                           abi_long arg2, abi_long arg3, abi_long arg4,
                           abi_long arg5, abi_long arg6);
abi_long do_openbsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6);
#endif
void gemu_log(const char *fmt, ...) GCC_FMT_ATTR(1, 2);
extern THREAD CPUState *thread_cpu;
void cpu_loop(CPUArchState *env);
char *target_strerror(int err);
int get_osversion(void);
void fork_start(void);
void fork_end(int child);

#include "qemu/log.h"

/* strace.c */
struct syscallname {
    int nr;
    const char *name;
    const char *format;
    void (*call)(const struct syscallname *,
                 abi_long, abi_long, abi_long,
                 abi_long, abi_long, abi_long);
    void (*result)(const struct syscallname *, abi_long, uint64_t timespent);
};

void
print_freebsd_syscall(int num,
                      abi_long arg1, abi_long arg2, abi_long arg3,
                      abi_long arg4, abi_long arg5, abi_long arg6);
void print_freebsd_syscall_ret(int num, abi_long ret, uint64_t timespent);
#if 0
/*
 * XXXKW: do_{netbsd,openbsd}_syscall must be adapted to the current system
 * call interface to work with the current BSD user mode.
 */
void
print_netbsd_syscall(int num,
                     abi_long arg1, abi_long arg2, abi_long arg3,
                     abi_long arg4, abi_long arg5, abi_long arg6);
void print_netbsd_syscall_ret(int num, abi_long ret);
void
print_openbsd_syscall(int num,
                      abi_long arg1, abi_long arg2, abi_long arg3,
                      abi_long arg4, abi_long arg5, abi_long arg6);
void print_openbsd_syscall_ret(int num, abi_long ret);
#endif
/**
 * print_taken_signal:
 * @target_signum: target signal being taken
 * @tinfo: target_siginfo_t which will be passed to the guest for the signal
 *
 * Print strace output indicating that this signal is being taken by the guest,
 * in a format similar to:
 * --- SIGSEGV {si_signo=SIGSEGV, si_code=SI_KERNEL, si_addr=0} ---
 */
void print_taken_signal(int target_signum, const target_siginfo_t *tinfo);
extern int do_strace;

/* signal.c */
void process_pending_signals(CPUArchState *cpu_env);
void signal_init(void);
int queue_signal(CPUArchState *env, int sig, target_siginfo_t *info);
void host_to_target_siginfo(target_siginfo_t *tinfo, const siginfo_t *info);
void target_to_host_siginfo(siginfo_t *info, const target_siginfo_t *tinfo);
abi_long target_to_host_sigevent(struct sigevent *host_sevp, abi_ulong target_addr);
int target_to_host_signal(int sig);
int host_to_target_signal(int sig);
void host_to_target_sigset(target_sigset_t *d, const sigset_t *s);
void target_to_host_sigset(sigset_t *d, const target_sigset_t *s);
long do_sigreturn(CPUArchState *env, abi_ulong addr);
abi_long do_sigaltstack(abi_syscallret_t retval, abi_syscallarg_t ua_ss,
    abi_syscallarg_t ua_oss, abi_ulong sp);
int do_sigaction(int sig, const struct target_sigaction *act,
                struct target_sigaction *oact);
void QEMU_NORETURN force_sig(int target_sig);
/**
 * block_signals: block all signals while handling this guest syscall
 *
 * Block all signals, and arrange that the signal mask is returned to
 * its correct value for the guest before we resume execution of guest code.
 * If this function returns non-zero, then the caller should immediately
 * return -TARGET_ERESTARTSYS to the main loop, which will take the pending
 * signal and restart execution of the syscall.
 * If block_signals() returns zero, then the caller can continue with
 * emulation of the system call knowing that no signals can be taken
 * (and therefore that no race conditions will result).
 * This should only be called once, because if it is called a second time
 * it will always return non-zero. (Think of it like a mutex that can't
 * be recursively locked.)
 * Signals will be unblocked again by process_pending_signals().
 *
 * Return value: non-zero if there was a pending signal, zero if not.
 */
int block_signals(void); /* Returns non zero if signal pending */

/* mmap.c */
int target_mprotect(abi_ulong start, abi_ulong len, int prot);
/*
 * target_mmap() is an emulated mmap() system call handler for a host.
 *
 * This function can be used by a host to call mmap() without an ABI-specific
 * interface.
 */
abi_long target_mmap(abi_ulong start, abi_ulong len, int prot,
                     int flags, int fd, off_t offset);
/*
 * target_sys_mmap() is an emulated mmap() system call handler for an emulated
 * process.
 */
abi_long target_sys_mmap(TaskState *ts, abi_syscallret_t retval,
    abi_syscallarg_t ua_addr, abi_syscallarg_t ua_len, abi_syscallarg_t ua_prot,
    abi_syscallarg_t ua_flags, abi_syscallarg_t ua_fd, abi_syscallarg_t ua_pos);
int target_munmap(abi_ulong start, abi_ulong len);
abi_long target_mremap(abi_ulong old_addr, abi_ulong old_size,
                       abi_ulong new_size, unsigned long flags,
                       abi_ulong new_addr);
int target_msync(abi_ulong start, abi_ulong len, int flags);
extern unsigned long last_brk;
extern abi_ulong mmap_next_start;
void mmap_lock(void);
void mmap_unlock(void);
abi_ulong mmap_find_vma(abi_ulong start, abi_ulong size);
void mmap_fork_start(void);
void mmap_fork_end(int child);

/* main.c */
extern unsigned long target_maxtsiz;
extern unsigned long target_dfldsiz;
extern unsigned long target_maxdsiz;
extern unsigned long target_dflssiz;
extern unsigned long target_maxssiz;
extern unsigned long target_sgrowsiz;
extern char qemu_proc_pathname[];
void start_exclusive(void);
void end_exclusive(void);
void cpu_exec_start(CPUState *cpu);
void cpu_exec_end(CPUState *cpu);

/* syscall.c */
abi_long get_errno(abi_long ret);
int is_error(abi_long ret);
int host_to_target_errno(int err);

/* os-flag.c */
abi_long do_freebsd_sysctl_oid_handle_security__flags_captured(
    CPUArchState *env, void *holdp, size_t *holdlenp, void *hnewp,
    size_t newlen);
abi_long do_freebsd_sysctl_oid_handle_security__flags_captured_key(
    CPUArchState *env, void *holdp, size_t *holdlenp, void *hnewp,
    size_t newlen);
abi_long do_freebsd_sysctl_oid_handle_security__kernel_flags_captured(
    CPUArchState *env, void *holdp, size_t *holdlenp, void *hnewp,
    size_t newlen);
abi_long do_freebsd_sysctl_oid_handle_security__kernel_flags_captured_key(
    CPUArchState *env, void *holdp, size_t *holdlenp, void *hnewp,
    size_t newlen);
abi_long do_freebsd_flag_captured(abi_syscallret_t retval,
    abi_syscallarg_t ua_message, abi_syscallarg_t ua_key, const char *source);

/* os-kbounce.c */
abi_long do_freebsd_kbounce(abi_syscallret_t retval, abi_syscallarg_t ua_src,
    abi_syscallarg_t ua_dst, abi_syscallarg_t ua_len,
    abi_syscallarg_t ua_flags);

/* os-proc.c */
abi_long freebsd_exec_common(abi_ulong path_or_fd, abi_ulong guest_argp,
        abi_ulong guest_envp, int do_fexec);
abi_long do_freebsd_procctl(void *cpu_env, int idtype, abi_ulong arg2,
        abi_ulong arg3, abi_ulong arg4, abi_ulong arg5, abi_ulong arg6);

/* os-sys.c */
struct target_kinfo_proc;
struct target_kinfo_file;
struct target_kinfo_vmentry;
abi_long do_sysctl_kern_getprocs(int op, int arg, size_t olen,
        struct target_kinfo_proc *tki, size_t *tlen);
abi_long do_sysctl_kern_proc_filedesc(int pid, size_t olen,
        struct target_kinfo_file *tkif, size_t *tlen);
abi_long do_sysctl_kern_proc_vmmap(int pid, size_t olen,
        struct target_kinfo_vmentry *tkve, size_t *tlen);
abi_long do_freebsd_sysctl(CPUArchState *env, abi_ulong namep, int32_t namelen,
        abi_ulong oldp, abi_ulong oldlenp, abi_ulong newp, abi_ulong newlen);
abi_long do_freebsd_sysctlbyname(CPUArchState *env, abi_ulong namep,
        int32_t namelen, abi_ulong oldp, abi_ulong oldlenp, abi_ulong newp,
        abi_ulong newlen);
abi_long do_freebsd_sysarch(void *cpu_env, abi_long arg1, abi_long arg2);

/* os-thread.c */
extern pthread_mutex_t *new_freebsd_thread_lock_ptr;
extern pthread_mutex_t *freebsd_umtx_wait_lck_ptr;
void *new_freebsd_thread_start(void *arg);
abi_long freebsd_lock_umtx(abi_ulong target_addr, abi_long tid,
        size_t tsz, void *t);
abi_long freebsd_unlock_umtx(abi_ulong target_addr, abi_long id);
abi_long freebsd_umtx_wait(abi_ulong targ_addr, abi_ulong id,
        size_t tsz, void *t);
abi_long freebsd_umtx_wake(abi_ulong target_addr, uint32_t n_wake);
abi_long freebsd_umtx_mutex_wake(abi_ulong target_addr, abi_long val);
abi_long freebsd_umtx_wait_uint(abi_ulong obj, uint32_t val, size_t tsz,
        void *t);
abi_long freebsd_umtx_wait_uint_private(abi_ulong obj, uint32_t val,
        size_t tsz, void *t);
abi_long freebsd_umtx_wake_private(abi_ulong obj, uint32_t val);
#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
abi_long freebsd_umtx_nwake_private(abi_ulong obj, uint32_t val);
abi_long freebsd_umtx_mutex_wake2(abi_ulong obj, uint32_t val);
#if __FreeBSD_version > 1100000
abi_long freebsd_umtx_sem2_wait(abi_ulong obj, size_t tsz, void *t);
abi_long freebsd_umtx_sem2_wake(abi_ulong obj);
#endif /* __FreeBSD_version > 1100000 */
#endif /* __FreeBSD_version > 900000 */
abi_long freebsd_umtx_sem_wait(abi_ulong obj, size_t tsz, void *t);
abi_long freebsd_umtx_sem_wake(abi_ulong obj);
abi_long freebsd_lock_umutex(abi_ulong target_addr, uint32_t id,
        void *ts, size_t tsz, int mode);
abi_long freebsd_unlock_umutex(abi_ulong target_addr, uint32_t id);
abi_long freebsd_cv_wait(abi_ulong target_ucond_addr,
                abi_ulong target_umtx_addr, struct timespec *ts, int wflags);
abi_long freebsd_cv_signal(abi_ulong target_ucond_addr);
abi_long freebsd_cv_broadcast(abi_ulong target_ucond_addr);
abi_long freebsd_rw_rdlock(abi_ulong target_addr, long fflag,
        size_t tsz, void *t);
abi_long freebsd_rw_wrlock(abi_ulong target_addr, long fflag,
        size_t tsz, void *t);
abi_long freebsd_rw_unlock(abi_ulong target_addr);
#if defined(__FreeBSD_version) && __FreeBSD_version > 1200000
abi_long freebsd_umtx_shm(abi_ulong target_addr, long fflag);
abi_long freebsd_umtx_robust_list(abi_ulong target_addr, size_t rbsize);
#endif /* __FreeBSD_version > 1200000 */

/* user access */

#define VERIFY_READ  PAGE_READ
#define VERIFY_WRITE (PAGE_READ | PAGE_WRITE)

static inline bool access_ok(int type, abi_ulong addr, abi_ulong size)
{
    return page_check_range((target_ulong)addr, size, type) == 0;
}

/* NOTE __get_user and __put_user use host pointers and don't check access. */
/* These are usually used to access struct data members once the
 * struct has been locked - usually with lock_user_struct().
 */

/*
 * Tricky points:
 * - Use __builtin_choose_expr to avoid type promotion from ?:,
 * - Invalid sizes result in a compile time error stemming from
 *   the fact that abort has no parameters.
 * - It's easier to use the endian-specific unaligned load/store
 *   functions than host-endian unaligned load/store plus tswapN.
 * - The pragmas are necessary only to silence a clang false-positive
 *   warning: see https://bugs.llvm.org/show_bug.cgi?id=39113 .
 * - We have to disable -Wpragmas warnings to avoid a complaint about
 *   an unknown warning type from older compilers that don't know about
 *   -Waddress-of-packed-member.
 * - gcc has bugs in its _Pragma() support in some versions, eg
 *   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83256 -- so we only
 *   include the warning-suppression pragmas for clang
 */
#ifdef __clang__
#define PRAGMA_DISABLE_PACKED_WARNING                                   \
    _Pragma("GCC diagnostic push");                                     \
    _Pragma("GCC diagnostic ignored \"-Wpragmas\"");                    \
    _Pragma("GCC diagnostic ignored \"-Waddress-of-packed-member\"")

#define PRAGMA_REENABLE_PACKED_WARNING          \
    _Pragma("GCC diagnostic pop")

#else
#define PRAGMA_DISABLE_PACKED_WARNING
#define PRAGMA_REENABLE_PACKED_WARNING
#endif

#define __put_user(x, hptr)\
({\
    PRAGMA_DISABLE_PACKED_WARNING;\
    int size = sizeof(*(hptr));\
    switch(size) {\
    case 1:\
        *(uint8_t *)(hptr) = (uint8_t)(typeof(*(hptr)))(x);\
        break;\
    case 2:\
        *(uint16_t *)(hptr) = tswap16((typeof(*(hptr)))(x));\
        break;\
    case 4:\
        *(uint32_t *)(hptr) = tswap32((typeof(*(hptr)))(x));\
        break;\
    case 8:\
        *(uint64_t *)(hptr) = tswap64((typeof(*(hptr)))(x));\
        break;\
    default:\
        abort();\
    }\
    PRAGMA_REENABLE_PACKED_WARNING;\
    0;\
})

#define __get_user(x, hptr) \
({\
    PRAGMA_DISABLE_PACKED_WARNING;\
    int size = sizeof(*hptr);\
    switch(size) {\
    case 1:\
        x = (typeof(*hptr))*(uint8_t *)(hptr);\
        break;\
    case 2:\
        x = (typeof(*hptr))tswap16(*(uint16_t *)(hptr));\
        break;\
    case 4:\
        x = (typeof(*hptr))tswap32(*(uint32_t *)(hptr));\
        break;\
    case 8:\
        x = (typeof(*hptr))tswap64(*(uint64_t *)(hptr));\
        break;\
    default:\
        /* avoid warning */\
        x = 0;\
        abort();\
    }\
    PRAGMA_REENABLE_PACKED_WARNING;\
    0;\
})

/* put_user()/get_user() take a guest address and check access */
/* These are usually used to access an atomic data type, such as an int,
 * that has been passed by address.  These internally perform locking
 * and unlocking on the data type.
 */
#define put_user(x, gaddr, target_type)                                 \
({                                                                      \
    abi_ulong __gaddr = (gaddr);                                        \
    target_type *__hptr;                                                \
    abi_long __ret;                                                     \
    if ((__hptr = lock_user(VERIFY_WRITE, __gaddr, sizeof(target_type), 0))) { \
        __ret = __put_user((x), __hptr);                                \
        unlock_user(__hptr, __gaddr, sizeof(target_type));              \
    } else                                                              \
        __ret = -TARGET_EFAULT;                                         \
    __ret;                                                              \
})
#ifdef TARGET_CHERI
#define put_user_capability(tag, pesbt, cursor, gaddr)                  \
({                                                                      \
    abi_ulong __gaddr = (gaddr);                                        \
    uint8_t *__hptr;                                                    \
    abi_long __ret;                                                     \
    if ((__hptr = lock_user(VERIFY_WRITE, __gaddr, CHERI_CAP_SIZE, 0))) { \
        store_cap_memory_to_memory(THREAD_ENV(), REG_NONE, tag, pesbt,  \
                                   cursor, __gaddr, GETPC());           \
        __ret = 0;                                                      \
        unlock_user(__hptr, __gaddr, CHERI_CAP_SIZE);                   \
    } else                                                              \
        __ret = -TARGET_EFAULT;                                         \
    __ret;                                                              \
})
#endif

#define get_user(x, gaddr, target_type)                                 \
({                                                                      \
    abi_ulong __gaddr = (gaddr);                                        \
    target_type *__hptr;                                                \
    abi_long __ret;                                                     \
    if ((__hptr = lock_user(VERIFY_READ, __gaddr, sizeof(target_type), 1))) { \
        __ret = __get_user((x), __hptr);                                \
        unlock_user(__hptr, __gaddr, 0);                                \
    } else {                                                            \
        /* avoid warning */                                             \
        (x) = 0;                                                        \
        __ret = -TARGET_EFAULT;                                         \
    }                                                                   \
    __ret;                                                              \
})

#define put_user_ual(x, gaddr) put_user((x), (gaddr), abi_ulong)
#define put_user_sal(x, gaddr) put_user((x), (gaddr), abi_long)
#define put_user_u64(x, gaddr) put_user((x), (gaddr), uint64_t)
#define put_user_s64(x, gaddr) put_user((x), (gaddr), int64_t)
#define put_user_u32(x, gaddr) put_user((x), (gaddr), uint32_t)
#define put_user_s32(x, gaddr) put_user((x), (gaddr), int32_t)
#define put_user_u16(x, gaddr) put_user((x), (gaddr), uint16_t)
#define put_user_s16(x, gaddr) put_user((x), (gaddr), int16_t)
#define put_user_u8(x, gaddr)  put_user((x), (gaddr), uint8_t)
#define put_user_s8(x, gaddr)  put_user((x), (gaddr), int8_t)
#ifdef TARGET_CHERI
#define put_user_c(x, gaddr)                                            \
        put_user_capability((x)->cr_tag != 0, CAP_cc(compress_mem)(x),  \
                            (x)->_cr_cursor, gaddr)
#define put_user_p(x, gaddr)                                            \
({                                                                      \
                                                                        \
    assert(((gaddr) % ABI_PTR_SIZE) == 0);                              \
    put_user_c(cheri_setaddress(cheri_zerocap(), (x)), (gaddr));        \
})
#else
#define put_user_p(x, gaddr) put_user_ual(x, gaddr)
#endif
#ifdef TARGET_CHERI
#define put_user_uintcap(x, gaddr)                                      \
        put_user_capability(true, (x).pesbt, (x).cursor, gaddr)
#define put_user_uintptr(x, gaddr) put_user_uintcap(x, gaddr)
#else
#define put_user_uintptr(x, gaddr) put_user_ual(x, gaddr)
#endif

#define get_user_ual(x, gaddr) get_user((x), (gaddr), abi_ulong)
#define get_user_sal(x, gaddr) get_user((x), (gaddr), abi_long)
#define get_user_u64(x, gaddr) get_user((x), (gaddr), uint64_t)
#define get_user_s64(x, gaddr) get_user((x), (gaddr), int64_t)
#define get_user_u32(x, gaddr) get_user((x), (gaddr), uint32_t)
#define get_user_s32(x, gaddr) get_user((x), (gaddr), int32_t)
#define get_user_u16(x, gaddr) get_user((x), (gaddr), uint16_t)
#define get_user_s16(x, gaddr) get_user((x), (gaddr), int16_t)
#define get_user_u8(x, gaddr)  get_user((x), (gaddr), uint8_t)
#define get_user_s8(x, gaddr)  get_user((x), (gaddr), int8_t)
#ifdef TARGET_CHERI
#define get_user_uintcap(x, gaddr)                                      \
({                                                                      \
    abi_ulong __gaddr = (gaddr);                                        \
    uint8_t *__hptr;                                                    \
    abi_long __ret;                                                     \
    if ((__hptr = lock_user(VERIFY_READ, __gaddr, CHERI_CAP_SIZE, 1))) { \
        __ret = __get_user((x).cursor, (uint64_t *)(__hptr +            \
            CHERI_MEM_OFFSET_CURSOR));                                  \
        if (__ret == 0) {                                               \
            __ret = __get_user((x).pesbt, (uint64_t *)(__hptr +         \
                CHERI_MEM_OFFSET_METADATA));                            \
        }                                                               \
        unlock_user(__hptr, __gaddr, 0);                                \
    } else {                                                            \
        /* avoid warning */                                             \
        (x).cursor = 0;                                                 \
        (x).pesbt = 0;                                                  \
        __ret = -TARGET_EFAULT;                                         \
    }                                                                   \
    __ret;                                                              \
})
#define get_user_uintptr(x, gaddr)  get_user_uintcap(x, gaddr)
#else
#define get_user_uintptr(x, gaddr)  get_user_ual((x), (gaddr))
#endif

/* copy_from_user() and copy_to_user() are usually used to copy data
 * buffers between the target and host.  These internally perform
 * locking/unlocking of the memory.
 */
abi_long copy_from_user(void *hptr, abi_ulong gaddr, size_t len);
abi_long copy_to_user(abi_ulong gaddr, void *hptr, size_t len);

/* Functions for accessing guest memory.  The tget and tput functions
   read/write single values, byteswapping as necessary.  The lock_user function
   gets a pointer to a contiguous area of guest memory, but does not perform
   any byteswapping.  lock_user may return either a pointer to the guest
   memory, or a temporary buffer.  */

/* Lock an area of guest memory into the host.  If copy is true then the
   host area will have the same contents as the guest.  */
static inline void *lock_user(int type, abi_ulong guest_addr, long len, int copy)
{
    if (!access_ok(type, guest_addr, len))
        return NULL;
#ifdef DEBUG_REMAP
    {
        void *addr;
        addr = g_malloc(len);
        if (copy)
            memcpy(addr, g2h_untagged(guest_addr), len);
        else
            memset(addr, 0, len);
        return addr;
    }
#else
    return g2h_untagged(guest_addr);
#endif
}

/* Unlock an area of guest memory.  The first LEN bytes must be
   flushed back to guest memory. host_ptr = NULL is explicitly
   allowed and does nothing. */
static inline void unlock_user(void *host_ptr, abi_ulong guest_addr,
                               long len)
{

#ifdef DEBUG_REMAP
    if (!host_ptr)
        return;
    if (host_ptr == g2h_untagged(guest_addr))
        return;
    if (len > 0)
        memcpy(g2h_untagged(guest_addr), host_ptr, len);
    g_free(host_ptr);
#endif
}

/* Return the length of a string in target memory or -TARGET_EFAULT if
   access error. */
abi_long target_strlen(abi_ulong gaddr);

/* Like lock_user but for null terminated strings.  */
static inline void *lock_user_string(abi_ulong guest_addr)
{
    abi_long len;
    len = target_strlen(guest_addr);
    if (len < 0)
        return NULL;
    return lock_user(VERIFY_READ, guest_addr, (long)(len + 1), 1);
}

/* Helper macros for locking/unlocking a target struct.  */
#define lock_user_struct(type, host_ptr, guest_addr, copy)      \
    (host_ptr = lock_user(type, guest_addr, sizeof(*host_ptr), copy))
#define unlock_user_struct(host_ptr, guest_addr, copy)          \
    unlock_user(host_ptr, guest_addr, (copy) ? sizeof(*host_ptr) : 0)

#if TARGET_ABI_BITS == 32
static inline uint64_t
target_arg64(uint32_t word0, uint32_t word1)
{
#ifdef TARGET_WORDS_BIGENDIAN
    return ((uint64_t)word0 << 32) | word1;
#else
    return ((uint64_t)word1 << 32) | word0;
#endif
}
#else /* TARGET_ABI_BITS != 32 */
static inline uint64_t
target_arg64(uint64_t word0, uint64_t word1)
{
    return word0;
}
#endif /* TARGET_ABI_BITS != 32 */

/* ARM EABI and MIPS expect 64bit types aligned even on pairs of registers */
#ifdef TARGET_ARM
static inline int
regpairs_aligned(void *cpu_env) {
    return ((((CPUARMState *)cpu_env)->eabi) == 1);
}
#elif defined(TARGET_MIPS) && TARGET_ABI_BITS == 32
static inline int regpairs_aligned(void *cpu_env)
{
    return 1;
}
#elif defined(TARGET_PPC) && TARGET_ABI_BITS == 32
static inline int regpairs_aligned(void *cpu_env)
{
    return 1;
}
#else
static inline int regpairs_aligned(void *cpu_env)
{
    return 0;
}
#endif

#include <pthread.h>

/* safe_syscall.S */

/**
 * safe_syscall:
 * @int number: number of system call to make
 * ...: arguments to the system call
 *
 * Call a system call if guest signal not pending.
 * This has the same API as the libc syscall() function, except that it
 * may return -1 with errno == TARGET_ERESTARTSYS if a signal was pending.
 *
 * Returns: the system call result, or -1 with an error code in errno
 * (Errnos are host errnos; we rely on TARGET_ERESTARTSYS not clashing
 * with any of the host errno values.)
 */

/* A guide to using safe_syscall() to handle interactions between guest
 * syscalls and guest signals:
 *
 * Guest syscalls come in two flavours:
 *
 * (1) Non-interruptible syscalls
 *
 * These are guest syscalls that never get interrupted by signals and
 * so never return EINTR. They can be implemented straightforwardly in
 * QEMU: just make sure that if the implementation code has to make any
 * blocking calls that those calls are retried if they return EINTR.
 * It's also OK to implement these with safe_syscall, though it will be
 * a little less efficient if a signal is delivered at the 'wrong' moment.
 *
 * Some non-interruptible syscalls need to be handled using block_signals()
 * to block signals for the duration of the syscall. This mainly applies
 * to code which needs to modify the data structures used by the
 * host_signal_handler() function and the functions it calls, including
 * all syscalls which change the thread's signal mask.
 *
 * (2) Interruptible syscalls
 *
 * These are guest syscalls that can be interrupted by signals and
 * for which we need to either return EINTR or arrange for the guest
 * syscall to be restarted. This category includes both syscalls which
 * always restart (and in the kernel return -ERESTARTNOINTR), ones
 * which only restart if there is no handler (kernel returns -ERESTARTNOHAND
 * or -ERESTART_RESTARTBLOCK), and the most common kind which restart
 * if the handler was registered with SA_RESTART (kernel returns
 * -ERESTARTSYS). System calls which are only interruptible in some
 * situations (like 'open') also need to be handled this way.
 *
 * Here it is important that the host syscall is made
 * via this safe_syscall() function, and *not* via the host libc.
 * If the host libc is used then the implementation will appear to work
 * most of the time, but there will be a race condition where a
 * signal could arrive just before we make the host syscall inside libc,
 * and then then guest syscall will not correctly be interrupted.
 * Instead the implementation of the guest syscall can use the safe_syscall
 * function but otherwise just return the result or errno in the usual
 * way; the main loop code will take care of restarting the syscall
 * if appropriate.
 *
 * (If the implementation needs to make multiple host syscalls this is
 * OK; any which might really block must be via safe_syscall(); for those
 * which are only technically blocking (ie which we know in practice won't
 * stay in the host kernel indefinitely) it's OK to use libc if necessary.
 * You must be able to cope with backing out correctly if some safe_syscall
 * you make in the implementation returns either -TARGET_ERESTARTSYS or
 * EINTR though.)
 *
 * block_signals() cannot be used for interruptible syscalls.
 *
 *
 * How and why the safe_syscall implementation works:
 *
 * The basic setup is that we make the host syscall via a known
 * section of host native assembly. If a signal occurs, our signal
 * handler checks the interrupted host PC against the addresse of that
 * known section. If the PC is before or at the address of the syscall
 * instruction then we change the PC to point at a "return
 * -TARGET_ERESTARTSYS" code path instead, and then exit the signal handler
 * (causing the safe_syscall() call to immediately return that value).
 * Then in the main.c loop if we see this magic return value we adjust
 * the guest PC to wind it back to before the system call, and invoke
 * the guest signal handler as usual.
 *
 * This winding-back will happen in two cases:
 * (1) signal came in just before we took the host syscall (a race);
 *   in this case we'll take the guest signal and have another go
 *   at the syscall afterwards, and this is indistinguishable for the
 *   guest from the timing having been different such that the guest
 *   signal really did win the race
 * (2) signal came in while the host syscall was blocking, and the
 *   host kernel decided the syscall should be restarted;
 *   in this case we want to restart the guest syscall also, and so
 *   rewinding is the right thing. (Note that "restart" semantics mean
 *   "first call the signal handler, then reattempt the syscall".)
 * The other situation to consider is when a signal came in while the
 * host syscall was blocking, and the host kernel decided that the syscall
 * should not be restarted; in this case QEMU's host signal handler will
 * be invoked with the PC pointing just after the syscall instruction,
 * with registers indicating an EINTR return; the special code in the
 * handler will not kick in, and we will return EINTR to the guest as
 * we should.
 *
 * Notice that we can leave the host kernel to make the decision for
 * us about whether to do a restart of the syscall or not; we do not
 * need to check SA_RESTART flags in QEMU or distinguish the various
 * kinds of restartability.
 */
#ifdef HAVE_SAFE_SYSCALL
/* The core part of this function is implemented in assembly */
extern long safe_syscall_base(int *pending, long number, ...);

#define safe_syscall(...)                                               \
    ({                                                                  \
        long ret_;                                                      \
        int *psp_ = &((TaskState *)thread_cpu->opaque)->signal_pending; \
        ret_ = safe_syscall_base(psp_, __VA_ARGS__);                    \
        if (is_error(ret_)) {                                           \
            errno = -ret_;                                              \
            ret_ = -1;                                                  \
        }                                                               \
        ret_;                                                           \
    })

#else

/* Fallback for architectures which don't yet provide a safe-syscall assembly
 * fragment; note that this is racy!
 * This should go away when all host architectures have been updated.
 */
#define safe_syscall syscall

#endif

#endif /* QEMU_H */
