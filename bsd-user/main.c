/*
 *  qemu bsd user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *  Copyright (c) 2013-14 Stacey Son
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/units.h"
#include "qemu/accel.h"
#include "sysemu/tcg.h"
#include "qemu-version.h"
#include <machine/trap.h>

#include "qapi/error.h"
#include "qemu.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/path.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "exec/log.h"
#include "trace/control.h"

#include "host_os.h"
#include "target_arch_cpu.h"

#ifdef TARGET_CHERI
#include "cheri_tagtree.h"

#include "cheri/cherireg.h"

#include "machine/vmparam.h"
#include "machine/cheri.h"
#endif

#ifdef __FreeBSD__
pthread_mutex_t ras_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ras_cond = PTHREAD_COND_INITIALIZER;
pthread_t ras_thread;
bool ras_thread_set = false;
#endif
int singlestep;
static const char *cpu_model;
static const char *cpu_type;
uintptr_t guest_base;
bool have_guest_base;
#if (TARGET_LONG_BITS == 32) && (HOST_LONG_BITS == 64)
/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 */
# ifdef TARGET_MIPS
/* MIPS only supports 31 bits of virtual address space for user space */
unsigned long reserved_va = 0x77000000;
# elif defined(TARGET_PPC64)
unsigned long reserved_va = 0xfffff000;
# else
unsigned long reserved_va = 0xf7000000;
# endif
#else
unsigned long reserved_va;
#endif

const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *interp_path = NULL;
const char *qemu_uname_release;
extern char **environ;
enum BSDType bsd_type;

unsigned long target_maxtsiz = TARGET_MAXTSIZ;   /* max text size */
unsigned long target_dfldsiz = TARGET_DFLDSIZ;   /* initial data size limit */
unsigned long target_maxdsiz = TARGET_MAXDSIZ;   /* max data size */
unsigned long target_dflssiz = TARGET_DFLSSIZ;   /* initial data size limit */
unsigned long target_maxssiz = TARGET_MAXSSIZ;   /* max stack size */
unsigned long target_sgrowsiz = TARGET_SGROWSIZ; /* amount to grow stack */

char qemu_proc_pathname[PATH_MAX];  /* full path to exeutable */

/* Helper routines for implementing atomic operations. */

void fork_start(void)
{
    start_exclusive();
    cpu_list_lock();
    mmap_fork_start();
}

void fork_end(int child)
{
    if (child) {
        CPUState *cpu, *next_cpu;
        /*
         * Child processes created by fork() only have a single thread.
         * Discard information about the parent threads.
         */
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != thread_cpu) {
                QTAILQ_REMOVE_RCU(&cpus, cpu, node);
            }
        }
        mmap_fork_end(child);
        /* qemu_init_cpu_list() takes care of reinitializing the
         * exclusive state, so we don't need to end_exclusive() here.
         */
	qemu_init_cpu_list();
        gdbserver_fork(thread_cpu);
    } else {
        mmap_fork_end(child);
	cpu_list_unlock();
        end_exclusive();
    }

}

void cpu_loop(CPUArchState *env)
{
    target_cpu_loop(env);
}

static void usage(void)
{
    printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION
           "\n" QEMU_COPYRIGHT "\n"
           "usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "BSD CPU emulator (compiled for %s emulation)\n"
           "\n"
           "Standard options:\n"
           "-h                print this help\n"
           "-g port           wait gdb connection to port\n"
           "-L path           set the ELF interpreter prefix (default=%s)\n"
           "-interpreter path set the default ELF interpreter path relative to the ELF interpreter prefix\n"
           "-s size           set the stack size in bytes (default=%ld)\n"
           "-cpu model        select CPU (-cpu help for list)\n"
           "-drop-ld-preload  drop LD_PRELOAD for target process\n"
           "-E var=value      sets/modifies targets environment variable(s)\n"
           "-U var            unsets targets environment variable(s)\n"
           "-B address        set guest_base address to address\n"
           "-bsd type         select emulated BSD type FreeBSD/NetBSD/OpenBSD (default)\n"
           "\n"
           "Debug options:\n"
           "-d item1[,...]    enable logging of specified items\n"
           "                  (use '-d help' for a list of log items)\n"
           "-D logfile        write logs to 'logfile' (default stderr)\n"
           "-singlestep       always run in singlestep mode\n"
           "-strace           log system calls\n"
           "-trace            [[enable=]<pattern>][,events=<file>][,file=<file>]\n"
           "                  specify tracing options\n"
           "\n"
           "Environment variables:\n"
           "QEMU_STRACE       Print system calls and arguments similar to the\n"
           "                  'strace' program.  Enable by setting to any value.\n"
           "You can use -E and -U options to set/unset environment variables\n"
           "for target process.  It is possible to provide several variables\n"
           "by repeating the option.  For example:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "Note that if you provide several changes to single variable\n"
           "last change will stay in effect.\n"
           "\n"
           QEMU_HELP_BOTTOM "\n"
           ,
           TARGET_NAME,
           interp_prefix,
           target_dflssiz);
    exit(1);
}

THREAD CPUState *thread_cpu;

void stop_all_tasks(void)
{
    /*
     * We trust when using NPTL (pthreads) start_exclusive() handles thread
     * stopping correctly.
     */
    start_exclusive();
}

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void qemu_cpu_kick(CPUState *cpu)
{
    cpu_exit(cpu);
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;

    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    CPUState *new_cpu = cpu_create(cpu_type);
    CPUArchState *new_env = new_cpu->env_ptr;
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    memcpy(new_env, env, sizeof(CPUArchState));

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&cpu->breakpoints);
    QTAILQ_INIT(&cpu->watchpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        cpu_watchpoint_insert(new_cpu, wp->vaddr, wp->len, wp->flags, NULL);
    }

    return new_env;
}

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void
adjust_ssize(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_STACK, &rl) != 0)
        return;

    target_maxssiz = MIN(target_maxssiz, rl.rlim_max);
    target_dflssiz = MIN(MAX(target_dflssiz, rl.rlim_cur), target_maxssiz);

    rl.rlim_max = target_maxssiz;
    rl.rlim_cur = target_dflssiz;
    setrlimit(RLIMIT_STACK, &rl);
}

int main(int argc, char **argv)
{
    const char *filename;
    const char *log_file = NULL;
    const char *log_mask = NULL;
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct bsd_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
#ifdef TARGET_CHERI
    int ii;
#endif
    int optind;
    const char *r;
    const char *gdbstub = NULL;
    char **target_environ, **wrk;
    envlist_t *envlist = NULL;
    bsd_type = HOST_DEFAULT_BSD_TYPE;
    char * argv0 = NULL;

    adjust_ssize();

    if (argc <= 1)
        usage();

    error_init(argv[0]);
    save_proc_pathname(argv[0]);

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    cpu_model = NULL;

    qemu_add_opts(&qemu_trace_opts);

    optind = 1;
    for (;;) {
        if (optind >= argc)
            break;
        r = argv[optind];
        if (r[0] != '-')
            break;
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        } else if (!strcmp(r, "d")) {
            if (optind >= argc) {
                break;
            }
            log_mask = argv[optind++];
        } else if (!strcmp(r, "D")) {
            if (optind >= argc) {
                break;
            }
            log_file = argv[optind++];
        } else if (!strcmp(r, "E")) {
            r = argv[optind++];
            if (envlist_setenv(envlist, r) != 0)
                usage();
        } else if (!strcmp(r, "ignore-environment")) {
            envlist_free(envlist);
            envlist = envlist_create();
        } else if (!strcmp(r, "U")) {
            r = argv[optind++];
            if (envlist_unsetenv(envlist, r) != 0)
                usage();
        } else if (!strcmp(r, "s")) {
            r = argv[optind++];
            target_dflssiz = strtol(r, (char **)&r, 0);
            if (target_dflssiz <= 0) {
                usage();
            }
            if (*r == 'M') {
                target_dflssiz *= 1024 * 1024;
            } else if (*r == 'k' || *r == 'K') {
                target_dflssiz *= 1024;
            }
            if (target_dflssiz > target_maxssiz) {
                usage();
            }
#if 0
            /* XXX merge conflict This looks like weirdness XXX */
            if (*r == 'M')
                x86_stack_size *= MiB;
            else if (*r == 'k' || *r == 'K')
                x86_stack_size *= KiB;
#endif
        } else if (!strcmp(r, "L")) {
            interp_prefix = argv[optind++];
        } else if (!strcmp(r, "p")) {
            qemu_host_page_size = atoi(argv[optind++]);
            if (qemu_host_page_size == 0 ||
                (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
                fprintf(stderr, "page size must be a power of two\n");
                exit(1);
            }
        } else if (!strcmp(r, "g")) {
            gdbstub = g_strdup(argv[optind++]);
        } else if (!strcmp(r, "r")) {
            qemu_uname_release = argv[optind++];
        } else if (!strcmp(r, "cpu")) {
            cpu_model = argv[optind++];
            if (is_help_option(cpu_model)) {
/* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
                    cpu_list();
#endif
                exit(1);
            }
        } else if (!strcmp(r, "B")) {
           guest_base = strtol(argv[optind++], NULL, 0);
           have_guest_base = true;
        } else if (!strcmp(r, "drop-ld-preload")) {
            (void) envlist_unsetenv(envlist, "LD_PRELOAD");
        } else if (!strcmp(r, "bsd")) {
            if (!strcasecmp(argv[optind], "freebsd")) {
                bsd_type = target_freebsd;
            } else if (!strcasecmp(argv[optind], "netbsd")) {
                bsd_type = target_netbsd;
            } else if (!strcasecmp(argv[optind], "openbsd")) {
                bsd_type = target_openbsd;
            } else {
                usage();
            }
            optind++;
        } else if (!strcmp(r, "singlestep")) {
            singlestep = 1;
        } else if (!strcmp(r, "strace")) {
            do_strace = 1;
        } else if (!strcmp(r, "trace")) {
            trace_opt_parse(optarg);
        } else if (!strcmp(r, "interpreter")) {
            interp_path = argv[optind++];
        } else if (!strcmp(r, "0")) {
            argv0 = argv[optind++];    
        } else {
            usage();
        }
    }

    /* init debug */
    if (log_file) {
        qemu_log_needs_buffers();
        qemu_set_log_filename(log_file, &error_fatal);
    }
    if (log_mask) {
        int mask;

        mask = qemu_str_to_log_mask(log_mask);
        if (!mask) {
            qemu_print_log_usage(stdout);
            exit(1);
        }
        qemu_set_log(mask);
    }

    if (optind >= argc) {
        usage();
    }
    filename = argv[optind];
    if (argv0)
        argv[optind] = argv0;

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file();

    /* Zero out regs */
    memset(regs, 0, sizeof(*regs));

    memset(&bprm, 0, sizeof(bprm));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    if (cpu_model == NULL) {
        cpu_model = TARGET_DEFAULT_CPU_MODEL;
    }

    cpu_type = parse_cpu_option(cpu_model);
    /* init tcg before creating CPUs and to get qemu_host_page_size */
    {
        AccelClass *ac = ACCEL_GET_CLASS(current_accel());

        ac->init_machine(NULL);
        accel_init_interfaces(ac);
    }
    cpu = cpu_create(cpu_type);
    env = cpu->env_ptr;
    cpu_reset(cpu);
    thread_cpu = cpu;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    if (reserved_va) {
            mmap_next_start = reserved_va;
    }

    /*
     * Now that page sizes are configured in tcg_exec_init() we can do
     * proper page alignment for guest_base.
     */
    guest_base = HOST_PAGE_ALIGN(guest_base);

    /* build Task State */
    ts = g_new0(TaskState, 1);
    init_task_state(ts);

#ifdef TARGET_CHERI
    cheri_tagtree_init();
    for (ii = 0; ii < 32; ii++) {
        regs->regs[ii] = *cheri_get_ddc(env);
    }
    cheri_init_capabilities(cheri_get_ddc(env));
#endif

    if (loader_exec(filename, argv+optind, target_environ, regs,
#ifdef TARGET_CHERI
        &ts->cheri_sigcode_cap,
#endif
        info, &bprm)) {
        printf("Error loading %s\n", filename);
        _exit(1);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }

    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  %p\n", (void *)guest_base);
        log_page_dump("binary load");

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n",
                 info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
    }

    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(tcg_ctx);
    tcg_region_init();

    target_cpu_init(env, regs);

    if (gdbstub) {
        gdbserver_start(gdbstub);
        gdb_handlesig(cpu, 0);
    }
    cpu_loop(env);
    /* never exits */
    return 0;
}
