#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define UDP_RCVBUF                  4 * 1024 * 1024
#define UDP_SNDBUF                  2 * 1024 * 1024

#define WGM_HANDSHAKE_INITIATION    1
#define WGM_HANDSHAKE_RESPONSE      2
#define WGM_HANDSHAKE_COOKIE        3
#define WGM_DATA                    4

#define SERVER_MAX_CLIENTS          8
#define SERVER_AUTH_TIMEOUT         5
#define SERVER_IDLE_TIMEOUT         60

#define CLIENT_STATE_NONE           0
#define CLIENT_STATE_AUTH           1
#define CLIENT_STATE_NORMAL         2

#define STOP_SIGNAL1                SIGINT
#define STOP_SIGNAL2                SIGTERM

#define TRACE(sa, format, ...)                                                          \
    do {                                                                                \
        time_t      ts__;                                                               \
        struct tm*  tm__;                                                               \
        ts__ = time(NULL);                                                              \
        tm__ = localtime(&ts__);                                                        \
        fprintf(stdout, "[%d-%02d-%02d %d:%02d:%02d] [%s:%d] " format "\n",             \
                tm__->tm_year + 1900, tm__->tm_mon + 1, tm__->tm_mday,                  \
                tm__->tm_hour, tm__->tm_min, tm__->tm_sec,                              \
                inet_ntoa((sa)->sin_addr), ntohs((sa)->sin_port), ##__VA_ARGS__);       \
        fflush(stdout);                                                                 \
    }                                                                                   \
    while (0);

struct args
{
    struct sockaddr_in listen;
    struct sockaddr_in upstream;
};

struct clientcontext
{
    int                         state;
    int                         fd;
    int64_t                     rx;
    struct sockaddr_in          dnstream;
};

struct servercontext
{
    int                         fd;
    struct clientcontext        cc[SERVER_MAX_CLIENTS];
    struct sockaddr_in          upstream;
};

static int64_t monotonic()
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return tp.tv_sec;
}

static void setpollfd(struct pollfd* pollfd, int fd)
{
    pollfd->fd = fd;
    pollfd->events = POLLIN;
    pollfd->revents = 0;
}

static uint32_t wgtype(const unsigned char* msg, int len)
{
    uint32_t type;

    if (len < sizeof(uint32_t)) {
        return 0;
    }

    type = *(uint32_t*)msg; // assume the host is little endian
    switch (type) {
    case WGM_HANDSHAKE_INITIATION:
        if (len != 148) {
            return 0;
        }
        break;
    case WGM_HANDSHAKE_RESPONSE:
        if (len != 92) {
            return 0;
        }
        break;
    case WGM_HANDSHAKE_COOKIE:
        if (len != 64) {
            return 0;
        }
        break;
    case WGM_DATA:
        if (len < 32) {
            return 0;
        }
        break;
    }

    return type;
}

static int scsocket(const struct sockaddr_in* sa)
{
    int fd;
    int optval;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    optval = UDP_RCVBUF;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)) == -1) {
        perror("setsockopt[SO_RCVBUF]");
        close(fd);
        return -1;
    }

    optval = UDP_SNDBUF;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)) == -1) {
        perror("setsockopt[SO_SNDBUF]");
        close(fd);
        return -1;
    }

    if (sa && bind(fd, (const struct sockaddr*)sa, sizeof(struct sockaddr_in)) == -1) {
        perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}

static struct servercontext* scinit(const struct args* args)
{
    struct servercontext* sc;
    struct clientcontext* cc;
    struct clientcontext* ccend;
    int                   bufsize;

    sc = (struct servercontext*)malloc(sizeof(struct servercontext));
    if (!sc) {
        perror("malloc");
        return NULL;
    }

    sc->fd = scsocket(&args->listen);
    if (sc->fd == -1) {
        free(sc);
        return NULL;
    }

    ccend = sc->cc + SERVER_MAX_CLIENTS;
    for (cc = sc->cc; cc != ccend; ++cc) {
        cc->state = CLIENT_STATE_NONE;
        cc->fd = -1;
        cc->rx = -1;
        memset(&cc->dnstream, 0x00, sizeof(struct sockaddr_in));
    }

    memcpy(&sc->upstream, &args->upstream, sizeof(struct sockaddr_in));

    TRACE(&args->listen, "* LISTEN");

    return sc;
}

static void sccleanup(struct servercontext* sc)
{
    struct clientcontext* cc;
    struct clientcontext* ccend = sc->cc + SERVER_MAX_CLIENTS;

    close(sc->fd);
    for (cc = sc->cc; cc != ccend; ++cc) {
        if (cc->fd != -1) {
            close(cc->fd);
        }
    }
    free(sc);
}

static struct clientcontext* cclookup(struct servercontext* sc, const struct sockaddr_in* sa)
{
    struct clientcontext*   cc;
    struct clientcontext*   ccend = sc->cc + SERVER_MAX_CLIENTS;

    for (cc = sc->cc; cc != ccend; ++cc) {
        if (cc->fd != -1 && memcmp(&cc->dnstream, sa, sizeof(struct sockaddr_in)) == 0) {
            return cc;
        }
    }

    return NULL;
}

static int64_t cckickprio(struct clientcontext* cc, int64_t now)
{
    switch (cc->state) {
    case CLIENT_STATE_NONE:
        return INT64_MAX;
    case CLIENT_STATE_AUTH:
        return now - cc->rx >= SERVER_AUTH_TIMEOUT ?
            ((int64_t)6 << 60) | ((now - cc->rx) & ~((int64_t)0xf << 60)) : 0;
    case CLIENT_STATE_NORMAL:
        return now - cc->rx >= SERVER_IDLE_TIMEOUT ?
            ((int64_t)5 << 60) | ((now - cc->rx) & ~((int64_t)0xf << 60)) : 0;
    }
    return 0;
}

static struct clientcontext* cctokick(struct servercontext* sc)
{
    struct clientcontext*   cc;
    struct clientcontext*   ccend = sc->cc + SERVER_MAX_CLIENTS;
    int64_t                 pr;
    struct clientcontext*   ccres = NULL;
    int64_t                 prres = 0;
    int64_t                 now = monotonic();

    for (cc = sc->cc; cc != ccend; ++cc) {
        pr = cckickprio(cc, now);
        if (pr > prres) {
            ccres = cc;
            prres = pr;
        }
        if (pr == INT64_MAX) {
            break;
        }
    }

    return ccres;
}

static int ccreset(struct clientcontext* cc, const struct sockaddr_in* sa)
{
    int fd;

    fd = scsocket(NULL);
    if (fd == -1) {
        return -1;
    }
    if (cc->fd != -1) {
        close(cc->fd);
    }
    cc->state = CLIENT_STATE_AUTH;
    cc->fd = fd;
    cc->rx = 0;
    memcpy(&cc->dnstream, sa, sizeof(struct sockaddr_in));

    return 0;
}

static void screceive(struct servercontext* sc)
{
    char                    msg[1500];
    ssize_t                 msglen;
    uint32_t                mtype;
    struct sockaddr_in      sa;
    socklen_t               salen = sizeof(sa);
    struct clientcontext*   cc;

    msglen = recvfrom(sc->fd, msg, sizeof(msg), 0, (struct sockaddr*)&sa, &salen);
    if (msglen == -1) {
        perror("recvfrom");
        return;
    }

    mtype = wgtype(msg, msglen);
    if (mtype == 0) {
        return;
    }

    switch (mtype) {
    case WGM_HANDSHAKE_INITIATION:
        TRACE(&sa, "> HANDSHAKE INITIATION");
        break;
    case WGM_HANDSHAKE_RESPONSE:
        TRACE(&sa, "> HANDSHAKE RESPONSE");
        break;
    case WGM_HANDSHAKE_COOKIE:
        TRACE(&sa, "> HANDSHAKE COOKIE");
        break;
    }

    cc = cclookup(sc, &sa);
    if (!cc) {
        if (mtype != WGM_HANDSHAKE_INITIATION) {
            return;
        }
        cc = cctokick(sc);
        if (!cc) {
            TRACE(&sa, "* REJECT");
            return;
        }
        if (cc->state != CLIENT_STATE_NONE) {
            TRACE(&cc->dnstream, "* KICK (%d seconds idle)", (int)(monotonic() - cc->rx));
        }
        if (ccreset(cc, &sa) == -1) {
            return;
        }
        TRACE(&sa, "* ACCEPT");
    }

    msglen = sendto(cc->fd, msg, msglen, 0, (struct sockaddr*)&sc->upstream,
                    sizeof(struct sockaddr_in));
    if (msglen == -1) {
        perror("sendto");
        return;
    }

    if (cc->state == CLIENT_STATE_NORMAL || mtype == WGM_HANDSHAKE_INITIATION) {
        cc->rx = monotonic();
    }
}

static void ccreceive(struct servercontext* sc, struct clientcontext* cc)
{
    char                    msg[1500];
    ssize_t                 msglen;
    uint32_t                mtype;
    struct sockaddr_in      sa;
    socklen_t               salen = sizeof(struct sockaddr_in);

    msglen = recvfrom(cc->fd, msg, sizeof(msg), 0, (struct sockaddr*)&sa, &salen);
    if (msglen == -1) {
        perror("recvfrom");
        return;
    }

    mtype = wgtype(msg, msglen);
    if (mtype == 0) {
        return;
    }

    msglen = sendto(sc->fd, msg, msglen, 0, (struct sockaddr*)&cc->dnstream,
                    sizeof(struct sockaddr_in));
    if (msglen == -1) {
        perror("send");
        return;
    }

    switch (mtype) {
    case WGM_HANDSHAKE_INITIATION:
        TRACE(&cc->dnstream, "< HANDSHAKE INITIATION");
        break;
    case WGM_HANDSHAKE_RESPONSE:
        TRACE(&cc->dnstream, "< HANDSHAKE RESPONSE");
        break;
    case WGM_HANDSHAKE_COOKIE:
        TRACE(&cc->dnstream, "< HANDSHAKE COOKIE");
        break;
    }

    if (cc->state == CLIENT_STATE_AUTH && mtype == WGM_HANDSHAKE_RESPONSE) {
        cc->state = CLIENT_STATE_NORMAL;
    }
}

static int scpoll(struct servercontext* sc)
{
    struct pollfd           fds[1 + SERVER_MAX_CLIENTS];
    struct pollfd*          fd;
    struct pollfd*          fdend = fds;
    struct clientcontext*   cc;
    struct clientcontext*   ccend = sc->cc + SERVER_MAX_CLIENTS;

    setpollfd(fdend++, sc->fd);
    for (cc = sc->cc; cc != ccend; ++cc) {
        if (cc->fd != -1) {
            setpollfd(fdend++, cc->fd);
        }
    }

    if (poll(fds, fdend - fds, -1) == -1) {
        perror("poll");
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }

    cc = sc->cc;
    for (fd = fds; fd != fdend; ++fd) {
        if (!(fd->revents & POLLIN)) {
            continue;
        }
        if (fd->fd == sc->fd) {
            screceive(sc);
            continue;
        }
        for (; cc != ccend; ++cc) {
            if (cc->fd == fd->fd) {
                ccreceive(sc, cc);
                break;
            }
        }
    }

    return 0;
}

static int scstopped = 0;

static void scstop(int signo)
{
    switch (signo) {
    case STOP_SIGNAL1:
    case STOP_SIGNAL2:
        scstopped = 1;
        break;
    }
}

static int scrun(struct servercontext* sc)
{
    signal(STOP_SIGNAL1, &scstop);
    signal(STOP_SIGNAL2, &scstop);

    while (!scstopped) {
        if (scpoll(sc) == -1) {
            return -1;
        }
    }

    return 0;
}

static int parseaddr(char* string, struct sockaddr_in* sa)
{
    char* colon = strchr(string, ':');
    if (!colon) {
        return -1;
    }
    *colon = '\0';

    struct in_addr addr;
    if (inet_pton(AF_INET, string, &addr) <= 0) {
        return -1;
    }

    int port = atoi(colon + 1);
    if (port <= 0 || port >= 65536) {
        return -1;
    }

    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    sa->sin_addr = addr;

    return 0;
}

static int parseargs(int argc, char** argv, struct args* args)
{
    if (argc < 3) {
        return -1;
    }
    if (parseaddr(argv[1], &args->listen) < 0) {
        return -1;
    }
    if (parseaddr(argv[2], &args->upstream) < 0) {
        return -1;
    }
    return 0;
}

static const char* usage =
    "Usage:\n"
    "  wgproxy <listen> <upstream>\n"
    "\n"
    "Options:\n"
    "  listen    - listen for WireGuard messages on this endpoint\n"
    "  upstream  - proxy WireGuard messages to this endpoint\n"
    "\n"
    "Example:\n"
    "  wgproxy 0.0.0.0:51000 127.0.0.1:51001\n"
;

int main(int argc, char** argv)
{
    struct args             args;
    int                     rv = 1;
    struct servercontext*   sc = NULL;

    if (parseargs(argc, argv, &args) == -1) {
        fprintf(stderr, "%s", usage);
        return 1;
    }

    sc = scinit(&args);
    if (sc) {
        rv = scrun(sc);
        sccleanup(sc);
    }

    return rv;
}
