/*
 * postern-launch: the host-side step between the worker and bwrap.
 *
 * The worker starts this with posix_spawn, never fork: a fork runs every
 * pthread_atfork handler the worker's libraries registered, and a handler that
 * starts threads in the child (gRPC's does) can abort it before the exec. What
 * fork was needed for, this does after the exec instead, in a process that is
 * single-threaded and runs nothing but this file:
 *
 *   - close every descriptor from --close-from up, so bwrap and the guest
 *     inherit only the ones the worker put below it (stdio, the --info-fd pipe,
 *     the seccomp filter), whatever a library left without O_CLOEXEC;
 *   - with --uid, drop to that uid, and to --gid, with no supplementary groups,
 *     and confirm the drop cannot be undone;
 *   - exec bwrap.
 *
 * Ids are numbers only: resolving a name would have static glibc dlopen the
 * host's NSS modules. The signal mask is left alone: it carries the worker's
 * blocked SIGTERM through bwrap to the guest init.
 *
 * Usage:
 *   postern-launch --version
 *   postern-launch --close-from FD [--uid UID [--gid GID]] -- BWRAP [ARG...]
 *
 * Built static, next to postern-init, into the Linux wheel.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef POSTERN_VERSION
#define POSTERN_VERSION "unknown"
#endif

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

/* Any failure before bwrap runs. Distinct from bwrap's own 1 and the shell's 126/127. */
#define EXIT_LAUNCH 125

__attribute__((noreturn)) static void usage(void) {
    fputs("usage: postern-launch --version\n"
          "       postern-launch --close-from FD [--uid UID [--gid GID]] -- BWRAP [ARG...]\n",
          stderr);
    exit(EXIT_LAUNCH);
}

__attribute__((noreturn)) static void fail(const char *what) {
    fprintf(stderr, "postern-launch: %s: %s\n", what, strerror(errno));
    exit(EXIT_LAUNCH);
}

__attribute__((noreturn)) static void refuse(const char *what) {
    fprintf(stderr, "postern-launch: %s\n", what);
    exit(EXIT_LAUNCH);
}

/* A decimal id or descriptor in [0, max]; anything else is a usage error. */
static unsigned long parse_number(const char *text, unsigned long max) {
    char *end;
    if (text == NULL || *text < '0' || *text > '9')
        usage();
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value > max)
        usage();
    return value;
}

static void close_from(int lowest) {
    if (syscall(SYS_close_range, (unsigned int)lowest, ~0U, 0) == 0)
        return;
    if (errno != ENOSYS)
        fail("close_range");
    /* Before Linux 5.9. Read before any uid drop: that makes /proc/self root's. */
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL)
        fail("open /proc/self/fd");
    int own = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;
        int fd = atoi(entry->d_name);
        if (fd >= lowest && fd != own)
            close(fd);
    }
    closedir(dir);
}

static void drop(uid_t uid, int have_gid, gid_t gid) {
    if (setgroups(0, NULL) != 0)
        fail("setgroups");
    if (have_gid && setresgid(gid, gid, gid) != 0)
        fail("setresgid");
    if (setresuid(uid, uid, uid) != 0)
        fail("setresuid");
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    if (getresuid(&ruid, &euid, &suid) != 0 || getresgid(&rgid, &egid, &sgid) != 0)
        fail("getresuid");
    if (ruid != uid || euid != uid || suid != uid)
        refuse("the uid drop did not take");
    if (have_gid && (rgid != gid || egid != gid || sgid != gid))
        refuse("the gid drop did not take");
    if (getgroups(0, NULL) != 0)
        refuse("supplementary groups survived the drop");
    if (uid != 0 && setuid(0) == 0)
        refuse("the uid drop could be undone");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts(POSTERN_VERSION);
        return 0;
    }
    long lowest = -1;
    int have_uid = 0, have_gid = 0;
    uid_t uid = 0;
    gid_t gid = 0;
    int i = 1;
    for (; i < argc && strcmp(argv[i], "--") != 0; i += 2) {
        if (i + 1 >= argc)
            usage();
        if (strcmp(argv[i], "--close-from") == 0) {
            lowest = (long)parse_number(argv[i + 1], 1L << 30);
        } else if (strcmp(argv[i], "--uid") == 0) {
            uid = (uid_t)parse_number(argv[i + 1], 0xfffffffeUL);
            have_uid = 1;
        } else if (strcmp(argv[i], "--gid") == 0) {
            gid = (gid_t)parse_number(argv[i + 1], 0xfffffffeUL);
            have_gid = 1;
        } else {
            usage();
        }
    }
    /* Stdio stays open: bwrap needs it. A gid alone would leave root's uid. */
    if (i + 1 >= argc || lowest < 3 || (have_gid && !have_uid))
        usage();

    close_from((int)lowest);
    if (have_uid)
        drop(uid, have_gid, gid);
    execv(argv[i + 1], &argv[i + 1]);
    fail(argv[i + 1]);
}
