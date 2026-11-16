/*
 * postern-listen: open a guest's forwarded ports, from the host.
 *
 * The worker starts this through postern-launch (which closes stray descriptors
 * and makes any uid drop the launch makes), after bwrap has built the guest's
 * namespaces and while --block-fd still holds the guest before its init. It is
 * given the guest's network namespace as a descriptor, joins it, opens one
 * listening TCP socket per --port, and sends them all back over --send with
 * SCM_RIGHTS, in --port order. Then it exits: the sockets stay in the guest's
 * namespace, held by whoever the worker hands them to, and nothing of postern
 * runs in the guest to serve them.
 *
 * Joining takes a single-threaded process (setns refuses CLONE_NEWUSER to a
 * threaded one), which is why this is a program and not a call in the worker. It
 * joins the user namespace that owns the network namespace, not the guest's own:
 * bwrap nests the guest's user namespace inside the one that owns the network
 * namespace, and only the owner's gives CAP_SYS_ADMIN over it. Running as the
 * uid that started bwrap is what grants that, as the owner of both.
 *
 * Each socket is bound to the wildcard address, dual-stack (::, taking IPv4 as
 * mapped addresses), so a client resolving localhost to ::1 reaches it as one
 * using 127.0.0.1 does. A kernel without IPv6 gets 0.0.0.0. Not a loopback
 * address: bwrap reports the guest's pid before it brings the loopback interface
 * up, so none may exist yet, and a wildcard bind needs none. The guest's only
 * interface is its loopback, so the two reach the same place once it is up.
 *
 * Input is the host's argv and descriptors only; the guest cannot reach this
 * process. A failure exits 125 with the reason on stderr and sends nothing.
 *
 * Usage:
 *   postern-listen --version
 *   postern-listen --netns FD --send FD --port PORT [--port PORT...]
 *
 * Built static, next to postern-init and postern-launch, into the Linux wheel.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef POSTERN_VERSION
#define POSTERN_VERSION "unknown"
#endif

/* From linux/nsfs.h, which a static build's headers need not carry. */
#ifndef NS_GET_USERNS
#define NS_GET_USERNS 0xb701
#endif
#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE 0xb703
#endif

#define EXIT_LISTEN 125
/* More than any profile forwards; bounds the SCM_RIGHTS buffer. */
#define MAX_PORTS 64

__attribute__((noreturn, format(printf, 1, 2))) static void die(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fputs("postern-listen: ", stderr);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
    exit(EXIT_LISTEN);
}

__attribute__((noreturn)) static void usage(void) {
    die("usage: postern-listen --version | --netns FD --send FD --port PORT [--port PORT...]");
}

static unsigned long parse_number(const char *text, unsigned long min, unsigned long max) {
    char *end;
    if (text == NULL || *text < '0' || *text > '9')
        usage();
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value < min || value > max)
        usage();
    return value;
}

static void bind_ipv4(int fd, unsigned short port) {
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0)
        die("bind port %u: %s", port, strerror(errno));
}

static int listen_on(unsigned short port) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 && errno == EAFNOSUPPORT) {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            die("socket: %s", strerror(errno));
        bind_ipv4(fd, port);
    } else if (fd < 0) {
        die("socket: %s", strerror(errno));
    } else {
        int off = 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off) != 0)
            die("IPV6_V6ONLY: %s", strerror(errno));
        struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_ANY_INIT};
        if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0)
            die("bind port %u: %s", port, strerror(errno));
    }
    if (listen(fd, SOMAXCONN) != 0)
        die("listen on port %u: %s", port, strerror(errno));
    return fd;
}

static void send_all(int channel, const int *fds, int count) {
    char byte = 0;
    struct iovec payload = {.iov_base = &byte, .iov_len = 1};
    union {
        char buffer[CMSG_SPACE(sizeof(int) * MAX_PORTS)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof control);
    struct msghdr message = {
        .msg_iov = &payload,
        .msg_iovlen = 1,
        .msg_control = control.buffer,
        .msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)count),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)count);
    memcpy(CMSG_DATA(header), fds, sizeof(int) * (size_t)count);
    if (sendmsg(channel, &message, MSG_NOSIGNAL) != 1)
        die("sendmsg: %s", strerror(errno));
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts(POSTERN_VERSION);
        return 0;
    }
    int netns = -1, channel = -1, count = 0;
    unsigned short ports[MAX_PORTS];
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc)
            usage();
        if (strcmp(argv[i], "--netns") == 0) {
            netns = (int)parse_number(argv[i + 1], 3, 1UL << 30);
        } else if (strcmp(argv[i], "--send") == 0) {
            channel = (int)parse_number(argv[i + 1], 3, 1UL << 30);
        } else if (strcmp(argv[i], "--port") == 0) {
            if (count == MAX_PORTS)
                die("more than %d ports", MAX_PORTS);
            ports[count++] = (unsigned short)parse_number(argv[i + 1], 1, 65535);
        } else {
            usage();
        }
    }
    if (netns < 0 || channel < 0 || count == 0 || netns == channel)
        usage();

    if (ioctl(netns, NS_GET_NSTYPE) != CLONE_NEWNET)
        die("--netns %d is not a network namespace", netns);
    int owner = ioctl(netns, NS_GET_USERNS);
    if (owner < 0)
        die("the owner of the network namespace: %s", strerror(errno));
    if (setns(owner, CLONE_NEWUSER) != 0)
        die("join the user namespace owning the guest's network: %s", strerror(errno));
    close(owner);
    if (setns(netns, CLONE_NEWNET) != 0)
        die("join the guest's network namespace: %s", strerror(errno));

    int fds[MAX_PORTS];
    for (int i = 0; i < count; i++)
        fds[i] = listen_on(ports[i]);
    send_all(channel, fds, count);
    return 0;
}
