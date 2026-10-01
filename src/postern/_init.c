/*
 * postern-init: PID 1 of a postern guest.
 *
 * bwrap launches this with --as-pid-1, so it is the init of the guest's PID
 * namespace. Linux gives that process duties no ordinary program performs, and
 * this does them so the command it runs can behave normally:
 *
 *   - reap: orphans reparent to PID 1, and an unreaped zombie holds a pid and
 *     counts against RLIMIT_NPROC until the guest cannot fork;
 *   - forward signals: the kernel drops a default-action signal sent to a PID 1
 *     with no handler, so a command running as PID 1 could not be stopped
 *     politely. Every catchable signal is forwarded to the command's process
 *     group, so a pipeline or subshell hears it too;
 *   - pass the exit status through, as 128+N for death by signal N;
 *   - end the guest: when this exits the kernel kills whatever is left in the
 *     namespace, so it exits when the command does and background stragglers
 *     are cleaned up rather than left running.
 *
 * And what postern adds: it marks itself non-dumpable, so a same-uid process the
 * guest spawns cannot read its /proc/1; and the child sets RLIMIT_NPROC and
 * RLIMIT_AS before the exec, which is what carries them to a program that would
 * never set them itself.
 *
 * It never touches the command's stdio: the child inherits the descriptors bwrap
 * was given, so output streams to the host with nothing buffering it here.
 *
 * Usage:
 *   postern-init --version
 *   postern-init [--nproc N] [--as BYTES] -- argv...
 *
 * Input is the host's argv and nothing else; the guest can reach this process
 * only with signals and with its children's exit statuses. Built static by
 * `python -m postern.build_init`, so it needs nothing from the guest's rootfs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef POSTERN_VERSION
#define POSTERN_VERSION "unknown"
#endif

/* Exit statuses for failures of the init itself, before the command runs. */
#define EXIT_USAGE 2
#define EXIT_NOEXEC 126
#define EXIT_NOTFOUND 127

static void usage(void) {
    fputs("usage: postern-init --version\n"
          "       postern-init [--nproc N] [--as BYTES] -- argv...\n",
          stderr);
    exit(EXIT_USAGE);
}

static rlim_t parse_limit(const char *flag, const char *text) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || text[0] == '-') {
        fprintf(stderr, "postern-init: %s wants a non-negative integer, got '%s'\n", flag, text);
        exit(EXIT_USAGE);
    }
    return (rlim_t)value;
}

/* In the child: limits, a clean signal state, then the command. Never returns. */
static void exec_command(char **argv, const sigset_t *original_mask, rlim_t nproc, rlim_t as_bytes) {
    /* Its own process group, so a forwarded signal reaches everything it starts. */
    setpgid(0, 0);
    /* Undo what the init set up for itself: an inherited SIG_IGN would survive the
     * exec, and so would the blocked mask. */
    for (int sig = 1; sig < NSIG; sig++) {
        signal(sig, SIG_DFL);
    }
    sigprocmask(SIG_SETMASK, original_mask, NULL);

    struct rlimit limit;
    if (nproc > 0) {
        limit.rlim_cur = limit.rlim_max = nproc;
        if (setrlimit(RLIMIT_NPROC, &limit) != 0) {
            fprintf(stderr, "postern-init: setrlimit(RLIMIT_NPROC): %s\n", strerror(errno));
            _exit(1);
        }
    }
    /* Per-process, so this bounds one allocation spree rather than the guest's total
     * memory; a cgroup memory.max at the deploy layer is the real bound. */
    if (as_bytes > 0) {
        limit.rlim_cur = limit.rlim_max = as_bytes;
        if (setrlimit(RLIMIT_AS, &limit) != 0) {
            fprintf(stderr, "postern-init: setrlimit(RLIMIT_AS): %s\n", strerror(errno));
            _exit(1);
        }
    }

    execvp(argv[0], argv);
    int failure = errno;
    fprintf(stderr, "postern: cannot exec '%s': %s\n", argv[0], strerror(failure));
    _exit(failure == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC);
}

static int status_of(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

int main(int argc, char **argv) {
    rlim_t nproc = 0, as_bytes = 0;
    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            puts(POSTERN_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--nproc") == 0 && i + 1 < argc) {
            nproc = parse_limit("--nproc", argv[++i]);
        } else if (strcmp(argv[i], "--as") == 0 && i + 1 < argc) {
            as_bytes = parse_limit("--as", argv[++i]);
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            usage();
        }
    }
    if (i >= argc) {
        usage();
    }
    char **command = &argv[i];

    /* Best-effort: --clearenv already keeps the worker's environment out, so a
     * failure here costs a layer of defence rather than a secret. */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Block everything and take signals synchronously below: no async handlers,
     * and nothing arrives between the fork and the wait loop unaccounted for. */
    sigset_t all, original;
    sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &original);

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "postern-init: fork: %s\n", strerror(errno));
        return 1;
    }
    if (child == 0) {
        exec_command(command, &original, nproc, as_bytes);
    }
    /* Also from this side, so the group exists before any signal is forwarded to it. */
    setpgid(child, child);

    for (;;) {
        siginfo_t info;
        int sig = sigwaitinfo(&all, &info);
        if (sig < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "postern-init: sigwaitinfo: %s\n", strerror(errno));
            return 1;
        }
        if (sig != SIGCHLD) {
            /* ESRCH means the group is already gone; its SIGCHLD is on the way. */
            kill(-child, sig);
            continue;
        }
        /* One SIGCHLD can stand for many exits, so drain them all. */
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            if (pid == child) {
                return status_of(status);
            }
        }
    }
}
