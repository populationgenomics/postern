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
 * A failure exits 125 before bwrap runs, with the reason on stderr and, given
 * --error-fd, as {"postern-launch": "reason"} on that descriptor: the --info-fd
 * pipe, where the worker waits for bwrap's report and so can raise rather than
 * mistake the failure for the command's own status.
 *
 * Ids are numbers only: resolving a name would have static glibc dlopen the
 * host's NSS modules. The signal mask is left alone: it carries the worker's
 * blocked SIGTERM through bwrap to the guest init.
 *
 * Usage:
 *   postern-launch --version
 *   postern-launch --close-from FD [--error-fd FD] [--uid UID [--gid GID]] -- BWRAP [ARG...]
 *
 * Built static, next to postern-init, into the Linux wheel.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <stdarg.h>
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

static int error_fd = -1;

/* Report the failure on stderr and, as a JSON string, on error_fd; exit 125. */
__attribute__((noreturn, format(printf, 1, 2))) static void die(const char *format, ...) {
    char message[512];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof message, format, args);
    va_end(args);
    fprintf(stderr, "postern-launch: %s\n", message);
    if (error_fd >= 0) {
        char json[sizeof message * 6 + 32];
        size_t n = (size_t)snprintf(json, sizeof json, "{\"postern-launch\": \"");
        for (const unsigned char *c = (const unsigned char *)message; *c; c++) {
            if (*c == '"' || *c == '\\')
                n += (size_t)snprintf(json + n, sizeof json - n, "\\%c", *c);
            else if (*c < 0x20 || *c >= 0x80) /* the latter so a truncated character cannot break the UTF-8 */
                n += (size_t)snprintf(json + n, sizeof json - n, "\\u%04x", *c);
            else
                json[n++] = (char)*c;
        }
        n += (size_t)snprintf(json + n, sizeof json - n, "\"}");
        (void)!write(error_fd, json, n);
    }
    exit(EXIT_LAUNCH);
}

__attribute__((noreturn)) static void usage(void) {
    die("usage: postern-launch --version | --close-from FD [--error-fd FD] [--uid UID [--gid GID]] -- BWRAP [ARG...]");
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
#ifdef POSTERN_TEST_NO_CLOSE_RANGE /* the tests' way to reach the fallback */
    long closed = -1;
    errno = ENOSYS;
#else
    long closed = syscall(SYS_close_range, (unsigned int)lowest, ~0U, 0);
#endif
    if (closed == 0)
        return;
    /* ENOSYS before Linux 5.9; EPERM under a seccomp profile older than the call. */
    if (errno != ENOSYS && errno != EPERM)
        die("close_range: %s", strerror(errno));
    /* Read before any uid drop: that makes /proc/self root's. */
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL)
        die("open /proc/self/fd: %s", strerror(errno));
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
        die("setgroups: %s", strerror(errno));
    if (have_gid && setresgid(gid, gid, gid) != 0)
        die("setresgid: %s", strerror(errno));
    if (setresuid(uid, uid, uid) != 0)
        die("setresuid: %s", strerror(errno));
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    if (getresuid(&ruid, &euid, &suid) != 0 || getresgid(&rgid, &egid, &sgid) != 0)
        die("getresuid: %s", strerror(errno));
    if (ruid != uid || euid != uid || suid != uid)
        die("the uid drop did not take");
    if (have_gid && (rgid != gid || egid != gid || sgid != gid))
        die("the gid drop did not take");
    if (getgroups(0, NULL) != 0)
        die("supplementary groups survived the drop");
    if (uid != 0 && setuid(0) == 0)
        die("the uid drop could be undone");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts(POSTERN_VERSION);
        return 0;
    }
    long lowest = -1;
    long requested_error_fd = -1;
    int have_uid = 0, have_gid = 0;
    uid_t uid = 0;
    gid_t gid = 0;
    int i = 1;
    for (; i < argc && strcmp(argv[i], "--") != 0; i += 2) {
        if (i + 1 >= argc)
            usage();
        if (strcmp(argv[i], "--close-from") == 0) {
            lowest = (long)parse_number(argv[i + 1], 1L << 30);
        } else if (strcmp(argv[i], "--error-fd") == 0) {
            requested_error_fd = (long)parse_number(argv[i + 1], 1L << 30);
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
    /* Stdio stays open: bwrap needs it. A gid alone would leave root's uid. Until
     * the error descriptor is known to sit below the close, nothing is written to it. */
    if (i + 1 >= argc || lowest < 3 || requested_error_fd >= lowest || (have_gid && !have_uid))
        usage();
    error_fd = (int)requested_error_fd;

    close_from((int)lowest);
    if (have_uid)
        drop(uid, have_gid, gid);
    execv(argv[i + 1], &argv[i + 1]);
    die("%s: %s", argv[i + 1], strerror(errno));
}
