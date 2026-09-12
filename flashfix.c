/*
 * flashfix.c -- keep Flash Studio ("flash studio.exe") able to see and talk to
 * FlashForge printers that live on a DIFFERENT subnet than this machine
 * (mesh hops, WireGuard, Tailscale, 2+ routers away...).
 *
 * WHY THIS EXISTS
 * ---------------
 * Flash Studio stores known LAN printers in
 *     %APPDATA%\Orca-Flashforge\Orca-Flashforge.conf
 * under the "local_machines" object, as
 *     { "dev_id": "<serial>", "dev_name": ..., "dev_ip": "<ipv4>", ... }
 *
 * The app only ever fills "dev_ip" from its own Layer-2 discovery sweep
 * (UDP probe ~M119 on port 48899/19000, which is link-local broadcast).
 * If the printer is on another subnet -- even one that is perfectly routable --
 * discovery never sees it, so "dev_ip" stays "" ("dev_ip": "").
 * DeviceManager then builds the MachineObject with an empty IP,
 * MachineObject::check_valid_ip() returns false and connect() bails out with -1.
 * Result: the printer may be listed but is dead/unconnectable.
 *
 * THE FIX
 * -------
 * 1. Find the printers ourselves: unicast UDP probe to 48899/19000 on whatever
 *    subnets we can reach (routable remote subnets, WireGuard peer nets,
 *    Tailscale 100.64.0.0/10, whatever). The reply carries the serial number
 *    and the device pid, so we can rebuild a complete "local_machines" entry
 *    without the app's L2 broadcast.
 * 2. Write "dev_ip" (and the access codes) back into the conf, and re-sign it
 *    with the app's own integrity checksum:
 *        md5( body-with-all-CRs-removed then right-trimmed )  upper-case hex
 *    appended as a "# MD5 checksum <HEX>" trailer.
 * 3. Optionally keep watch: re-apply whenever the app rewrites/empties the
 *    field, and re-discover so DHCP moves are picked up automatically.
 *
 * Build (any of these):
 *     zig cc -O2 -o flashfix.exe flashfix.c -lws2_32
 *     cl  /O2 flashfix.c ws2_32.lib
 *     gcc -O2 -o flashfix flashfix.c -lws2_32        (mingw)
 *     cc  -O2 -o flashfix flashfix.c                 (linux/mac, no -lws2_32)
 *
 * Usage:
 *     flashfix status                 show config + reachability
 *     flashfix discover [SUBNET...]   find printers by probing
 *     flashfix sync [SUBNET...]       discover + patch config (the main fix)
 *     flashfix watch [SUBNET...]      run forever, keep the config correct
 *     flashfix route                  print routing help for unreachable nets
 *
 * Options:
 *     --conf PATH     use a different Orca-Flashforge.conf
 *     --subnets LIST  comma separated CIDRs/IPs (same as positional args)
 *     --timeout MS    probe timeout per round (default 1200)
 *     --dry-run       show what would change, don't write
 *     --restart       restart flash studio after patching
 *     --set-type      also fill empty printer_type from the model name
 *     -q / --quiet    less output
 *
 * Public domain / do what you want. No warranty.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <iptypes.h>
#  include <iphlpapi.h>
#  include <tlhelp32.h>
   typedef int socklen_t;
#  ifndef SOCKET
#    define SOCKET int
#  endif
#  define close_sock closesocket
#  define sleep_ms(ms) Sleep((DWORD)(ms))
#  define ioctlsocket_compat(s, nb) ioctlsocket((s), FIONBIO, &(nb))
#  define sock_errno() WSAEWOULDBLOCK
#  define INPROGRESS_ERR WSAEWOULDBLOCK
#  define WOULDBLOCK_ERR WSAEWOULDBLOCK
#else
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <sys/select.h>
#  include <fcntl.h>
#  include <ifaddrs.h>
#  include <net/if.h>
#  define close_sock close
#  define sleep_ms(ms) usleep((useconds_t)(ms) * 1000)
#endif

#define FLASHFIX_VERSION "1.0"

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static void die(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "flashfix: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static int g_quiet = 0;
static void info(const char *fmt, ...)
{
    va_list ap;
    if (g_quiet) return;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory");
    return q;
}

/* growable byte buffer */
typedef struct {
    char  *p;
    size_t len;
    size_t cap;
} Buf;

static void buf_init(Buf *b) { b->p = NULL; b->len = 0; b->cap = 0; }
static void buf_free(Buf *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

/* Copy the *contents* of a JSON string whose opening quote is at p, stopping
 * at the closing quote (handles simple backslash escapes). */
static void copy_json_string(char *dst, size_t cap, const char *p)
{
    size_t i = 0;
    if (!cap) return;
    dst[0] = 0;
    if (p && *p == 0x22) {
        p++;
        while (p[i] && p[i] != 0x22 && i + 1 < cap) {
            if (p[i] == 0x5c && p[i+1]) p++;
            dst[i] = p[i];
            i++;
        }
    }
    dst[i] = 0;
}

static void buf_reserve(Buf *b, size_t extra)
{
    if (b->len + extra + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 1024;
        while (nc < b->len + extra + 1) nc *= 2;
        b->p = (char *)xrealloc(b->p, nc);
        b->cap = nc;
    }
}

static void buf_add(Buf *b, const void *data, size_t n)
{
    if (!n) return;
    buf_reserve(b, n);
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void buf_adds(Buf *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_addf(Buf *b, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) {
        buf_add(b, tmp, (size_t)n);
    } else {
        char *big = (char *)xmalloc((size_t)n + 1);
        va_start(ap, fmt);
        vsnprintf(big, (size_t)n + 1, fmt, ap);
        va_end(ap);
        buf_add(b, big, (size_t)n);
        free(big);
    }
}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    Buf b;
    char chunk[8192];
    size_t n;
    if (!f) return NULL;
    buf_init(&b);
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
        buf_add(&b, chunk, n);
    fclose(f);
    if (out_len) *out_len = b.len;
    if (!b.p) { b.p = (char *)xmalloc(1); b.p[0] = 0; }
    return b.p;
}

static int write_file_atomic(const char *path, const void *data, size_t len)
{
    char tmp[4096];
    FILE *f;
    snprintf(tmp, sizeof(tmp), "%s.flashfix.tmp", path);
    f = fopen(tmp, "wb");
    if (!f) return -1;
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); remove(tmp); return -1; }
    fflush(f);
    fclose(f);
    if (rename(tmp, path) != 0) {
        /* fall back to a plain copy if rename is refused (file locked etc.) */
        FILE *in = fopen(tmp, "rb");
        FILE *out = fopen(path, "wb");
        char chunk2[8192];
        size_t n;
        if (!in || !out) {
            if (in) fclose(in);
            if (out) fclose(out);
            remove(tmp);
            return -1;
        }
        while ((n = fread(chunk2, 1, sizeof(chunk2), in)) > 0) fwrite(chunk2, 1, n, out);
        fclose(in); fclose(out); remove(tmp);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* MD5 (RFC 1321 style, compact)                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[4];
    uint64_t nbits;
    unsigned char buf[64];
    size_t n;
} MD5_CTX;

static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const int MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_init(MD5_CTX *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xefcdab89;
    c->h[2] = 0x98badcfe; c->h[3] = 0x10325476;
    c->nbits = 0; c->n = 0;
}

static void md5_block(MD5_CTX *c, const unsigned char *p)
{
    uint32_t m[16], a, b, d, e, f, g, tmp;
    int i;
    for (i = 0; i < 16; i++)
        m[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
               ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    a = c->h[0]; b = c->h[1]; d = c->h[2]; e = c->h[3];
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & d) | (~b & e);        g = (uint32_t)i; }
        else if (i < 32) { f = (e & b) | (~e & d);        g = (uint32_t)(5*i + 1) & 15; }
        else if (i < 48) { f = b ^ d ^ e;                 g = (uint32_t)(3*i + 5) & 15; }
        else             { f = d ^ (b | ~e);              g = (uint32_t)(7*i) & 15; }
        tmp = e;
        e = d;
        d = b;
        b = b + rol(a + f + MD5_K[i] + m[g], MD5_S[i]);
        a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e;
}

static void md5_update(MD5_CTX *c, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    c->nbits += (uint64_t)len * 8;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) { md5_block(c, c->buf); c->n = 0; }
    }
}

static void md5_final(MD5_CTX *c, unsigned char out[16])
{
    unsigned char pad[72];
    size_t padlen;
    uint64_t bits = c->nbits;
    int i;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    padlen = (c->n < 56) ? (56 - c->n) : (120 - c->n);
    md5_update(c, pad, padlen);
    for (i = 0; i < 8; i++) pad[i] = (unsigned char)((bits >> (8*i)) & 0xff);
    md5_update(c, pad, 8);
    for (i = 0; i < 4; i++) {
        out[i*4+0] = (unsigned char)(c->h[i] & 0xff);
        out[i*4+1] = (unsigned char)((c->h[i] >> 8) & 0xff);
        out[i*4+2] = (unsigned char)((c->h[i] >> 16) & 0xff);
        out[i*4+3] = (unsigned char)((c->h[i] >> 24) & 0xff);
    }
}

/* md5 of a memory range, upper-case hex into out[33] */
static void md5_hex(const void *data, size_t len, char out[33])
{
    MD5_CTX c;
    unsigned char d[16];
    static const char *hex = "0123456789ABCDEF";
    int i;
    md5_init(&c);
    md5_update(&c, data, len);
    md5_final(&c, d);
    for (i = 0; i < 16; i++) {
        out[i*2]   = hex[d[i] >> 4];
        out[i*2+1] = hex[d[i] & 15];
    }
    out[32] = 0;
}

/* ------------------------------------------------------------------ */
/* networking                                                         */
/* ------------------------------------------------------------------ */

static int net_startup(void)
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
#endif
    return 0;
}

static int tcp_probe(const char *ip, int port, int timeout_ms,
                     const char *send_data, size_t send_len,
                     char *reply, size_t reply_cap, size_t *reply_len)
{
    struct sockaddr_in sa;
    SOCKET s;
    int rc;
    fd_set wf, rf;
    struct timeval tv;
    int so_err = 0;
    socklen_t elen = sizeof(so_err);
    u_long nb = 1;

    if (reply) reply[0] = 0;
    if (reply_len) *reply_len = 0;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == (SOCKET)-1) return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close_sock(s); return -1; }

    ioctlsocket_compat(s, nb);   /* non-blocking connect */

    rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rc != 0) {
        int err = sock_errno();
        if (err != INPROGRESS_ERR && err != WOULDBLOCK_ERR) { close_sock(s); return -1; }
        FD_ZERO(&wf); FD_SET(s, &wf);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        rc = select((int)(s + 1), NULL, &wf, NULL, &tv);
        if (rc <= 0) { close_sock(s); return -1; }
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &elen) != 0 || so_err != 0) {
            close_sock(s); return -1;
        }
    }

    if (send_data && send_len) {
        size_t sent = 0;
        while (sent < send_len) {
            int n = send(s, send_data + sent, (int)(send_len - sent), 0);
            if (n <= 0) { close_sock(s); return -1; }
            sent += (size_t)n;
        }
    }

    if (reply && reply_cap > 1) {
        size_t used = 0;
        for (;;) {
            FD_ZERO(&rf); FD_SET(s, &rf);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            rc = select((int)(s + 1), &rf, NULL, NULL, &tv);
            if (rc <= 0) break;
            {
                int n = recv(s, reply + used, (int)(reply_cap - 1 - used), 0);
                if (n <= 0) break;
                used += (size_t)n;
                if (used >= reply_cap - 1) break;
            }
        }
        reply[used] = 0;
        if (reply_len) *reply_len = used;
    }

    close_sock(s);
    return 0;
}

/* ------------------------------------------------------------------ */
/* high-level: rewrite one printer entry                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char serial[64];
    char ip[64];
    char name[128];
    char code[64];
    char pid[16];
} Entry;

/* ------------------------------------------------------------------ */
/* device table                                                       */
/* ------------------------------------------------------------------ */

#define MAX_DEV 128

typedef struct {
    char  ip[64];
    char  name[128];      /* offset 0x00 of the discovery reply  */
    char  serial[64];     /* offset 0x92 of the discovery reply */
    unsigned pid;         /* offset 0x88, big endian u16        */
    unsigned port;        /* offset 0x84, big endian u16 (8899) */
    char  model[64];      /* from HTTP /detail (may be empty)  */
    char  firmware[32];
    int   replied;        /* answered a UDP probe */
    int   http_ok;        /* answered HTTP on 8898 */
} Device;

static Device g_dev[MAX_DEV];
static int    g_ndev = 0;

static Device *dev_get(const char *ip)
{
    int i;
    for (i = 0; i < g_ndev; i++)
        if (strcmp(g_dev[i].ip, ip) == 0) return &g_dev[i];
    if (g_ndev >= MAX_DEV) return NULL;
    memset(&g_dev[g_ndev], 0, sizeof(Device));
    snprintf(g_dev[g_ndev].ip, sizeof(g_dev[g_ndev].ip), "%s", ip);
    return &g_dev[g_ndev++];
}

static void copy_len(char *dst, size_t cap, const char *src, size_t srclen)
{
    size_t i;
    if (!cap) return;
    for (i = 0; i + 1 < cap && i < srclen && src[i]; i++)
        dst[i] = src[i];
    dst[i] = 0;
    /* trim */
    while (i > 0 && isspace((unsigned char)dst[i-1])) dst[--i] = 0;
}

/* Parse a FlashForge discovery reply.
 *
 * Layout of the 280-byte reply, all multi-byte fields big-endian:
 *      0x00  char  dev_name[128]   NUL padded   (the printer's name, or its serial)
 *      0x84  u16   tcp/udp port    (8899 -- the legacy G-code control port)
 *      0x88  u16   dev_pid         model id (the same value the app stores as dev_pid)
 *      0x92  char  serial[64]      NUL padded   (the device serial)
 *
 * dev_pid examples seen in the wild: 36, 40. The value matters because the app
 * uses it to pick the right printer definition, so it is carried straight into
 * the config rather than guessed.
 */
static void parse_reply(const char *ip, const unsigned char *d, size_t len)
{
    Device *dev = dev_get(ip);
    if (!dev) return;
    dev->replied = 1;

    {
        char raw[160];
        copy_len(raw, sizeof(raw), (const char *)d, len < 128 ? len : 128);
        snprintf(dev->name, sizeof(dev->name), "%s", raw);
    }

    if (len >= 0x94) {
        char raw[80];
        dev->pid = (unsigned)((d[0x88] << 8) | d[0x89]);
        if (len >= 0x8a) dev->port = (unsigned)((d[0x84] << 8) | d[0x85]);
        copy_len(raw, sizeof(raw), (const char *)d + 0x92,
                 len - 0x92 > 64 ? 64 : len - 0x92);
        snprintf(dev->serial, sizeof(dev->serial), "%s", raw);
    }
    /* The name field sometimes *is* the serial; keep them distinct. */
    if (dev->serial[0] == 0 && strncmp(dev->name, "SN", 2) == 0)
        snprintf(dev->serial, sizeof(dev->serial), "%s", dev->name);
    if (dev->name[0] == 0)
        snprintf(dev->name, sizeof(dev->name), "%s", dev->serial);
}

/* Broadcast/unicast sweep: send ~M119\n to every target on the discovery ports.
 * Printers only answer when probed (no unsolicited beacons), so we must ask. */
static int udp_sweep(const unsigned char targets[][4], int ntargets,
                     int timeout_ms)
{
    static const int ports[] = { 48899, 19000 };
    static const char probe[] = "~M119\n";
    SOCKET s;
    u_long nb = 1;
    int pi, ti, round;
    int found = 0, i;
    time_t deadline;

    for (i = 0; i < g_ndev; i++) g_dev[i].replied = 0;
    g_ndev = 0;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == (SOCKET)-1) return -1;

    {
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    }
    ioctlsocket_compat(s, nb);

    for (pi = 0; pi < 2; pi++) {
        for (ti = 0; ti < ntargets; ti++) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_port = htons((unsigned short)ports[pi]);
            memcpy(&dst.sin_addr, targets[ti], 4);
            sendto(s, probe, (int)(sizeof(probe) - 1), 0,
                   (struct sockaddr *)&dst, sizeof(dst));
        }
        /* small pacing gap so we don't dump 254 packets in one burst */
        sleep_ms(2);
    }

    deadline = time(NULL) + (timeout_ms + 999) / 1000 + 1;
    for (round = 0; round < 3; round++) {
        fd_set rf;
        struct timeval tv;
        FD_ZERO(&rf); FD_SET(s, &rf);
        tv.tv_sec = 0;
        tv.tv_usec = timeout_ms * 1000 / 3;
        if (select((int)(s + 1), &rf, NULL, NULL, &tv) <= 0) {
            if (time(NULL) >= deadline) break;
            continue;
        }
        for (;;) {
            unsigned char buf[2048];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            char ipstr[64];
            int n;
            fd_set r2;
            struct timeval t2;
            FD_ZERO(&r2); FD_SET(s, &r2);
            t2.tv_sec = 0; t2.tv_usec = 150000;
            if (select((int)(s + 1), &r2, NULL, NULL, &t2) <= 0) break;
            n = recvfrom(s, (char *)buf, (int)sizeof(buf), 0,
                         (struct sockaddr *)&from, &flen);
            if (n <= 0) break;
            if (inet_ntop(AF_INET, &from.sin_addr, ipstr, sizeof(ipstr)) == NULL)
                continue;
            parse_reply(ipstr, buf, (size_t)n);
        }
        if (time(NULL) >= deadline) break;
    }

    close_sock(s);

    for (i = 0; i < g_ndev; i++) if (g_dev[i].replied) found++;
    return found;
}

static void build_entries_from_conf(const char *body, size_t bodylen,
                                     Entry *ents, int *nents);

/* Ask a printer for its JSON status over the plain-HTTP LAN API. */
static int http_detail(const char *ip, int port, const char *serial,
                       const char *code, char *body, size_t body_cap)
{
    char req[1024];
    char payload[512];
    Buf rx;
    int rc;
    size_t i, hdr_end = 0;

    snprintf(payload, sizeof(payload),
             "{\"serialNumber\":\"%s\",\"checkCode\":\"%s\"}",
             serial ? serial : "", code ? code : "");

    snprintf(req, sizeof(req),
             "POST /detail HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             ip, (int)strlen(payload), payload);

    buf_init(&rx);
    buf_reserve(&rx, 8192);
    rc = tcp_probe(ip, port, 3000, req, strlen(req), rx.p, rx.cap, &rx.len);
    if (rc != 0) { buf_free(&rx); return -1; }

    for (i = 0; i + 3 < rx.len; i++) {
        if (rx.p[i] == '\r' && rx.p[i+1] == '\n' &&
            rx.p[i+2] == '\r' && rx.p[i+3] == '\n') { hdr_end = i + 4; break; }
    }
    if (hdr_end == 0) { buf_free(&rx); return -1; }
    if (strstr(rx.p, " 200 ") == NULL) { buf_free(&rx); return -1; }

    {
        size_t blen = rx.len - hdr_end;
        if (blen >= body_cap) blen = body_cap - 1;
        if (blen) memcpy(body, rx.p + hdr_end, blen);
        body[blen] = 0;
    }
    buf_free(&rx);
    return 0;
}

/* minimal "key": "value" extraction from a flat-ish JSON blob */
static int json_str_field(const char *json, const char *key, char *out, size_t cap)
{
    const char *p = json;
    size_t klen = strlen(key);
    if (out && cap) out[0] = 0;
    while ((p = strchr(p, '"')) != NULL) {
        if (strncmp(p + 1, key, klen) == 0 && p[1 + klen] == '"') {
            const char *q = p + 2 + klen;
            while (*q && *q != ':') q++;
            if (!*q) return 0;
            q++;
            while (*q && isspace((unsigned char)*q)) q++;
            if (*q != '"') return 0;      /* q points AT the opening quote */
            copy_json_string(out, cap, q);
            return out[0] != 0;
        }
        p++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* subnet expansion                                                   */
/* ------------------------------------------------------------------ */

static int target_add(unsigned char targets[][4], int *n, int max,
                      unsigned a, unsigned b, unsigned c, unsigned d)
{
    if (*n >= max) return 0;
    targets[*n][0] = (unsigned char)a;
    targets[*n][1] = (unsigned char)b;
    targets[*n][2] = (unsigned char)c;
    targets[*n][3] = (unsigned char)d;
    (*n)++;
    return 1;
}

/* Accept "10.20.0.0/24" (any mask; clamped to the containing /24) or a bare
 * "10.20.0.20". Deliberately caps expansion at a /24 (254 hosts) so a
 * careless /16 or Tailscale 100.64.0.0/10 does not turn into a 4M-packet scan. */
static int expand_target(const char *spec, unsigned char targets[][4], int *n, int max)
{
    char buf[128];
    unsigned a, b, c, d, mask = 32;
    const char *slash, *p;
    int i;

    snprintf(buf, sizeof(buf), "%s", spec);
    slash = strchr(buf, '/');
    if (slash) {
        *((char *)slash) = 0;
        mask = (unsigned)atoi(slash + 1);
    }
    /* trim */
    while (*buf && isspace((unsigned char)*buf)) memmove(buf, buf + 1, strlen(buf));
    for (i = (int)strlen(buf) - 1; i >= 0 && isspace((unsigned char)buf[i]); i--)
        buf[i] = 0;
    if (!*buf) return 0;

    if (sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;

    if (!slash) {
        target_add(targets, n, max, a, b, c, d);
        return 1;
    }
    if (mask >= 31) {                    /* single host / tiny range */
        target_add(targets, n, max, a, b, c, d);
        return 1;
    }
    p = NULL; (void)p;
    for (i = 1; i <= 254; i++)           /* sweep the whole /24 */
        target_add(targets, n, max, a, b, c, i);
    return 1;
}

/* Every /24 this machine is directly attached to. */
static int local_targets(unsigned char targets[][4], int *n, int max)
{
    int before = *n;
#if defined(_WIN32)
    ULONG sz = 16 * 1024;
    IP_ADAPTER_ADDRESSES *aa = (IP_ADAPTER_ADDRESSES *)xmalloc(sz);
    ULONG rc;
    IP_ADAPTER_ADDRESSES *cur;
    rc = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, aa, &sz);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        aa = (IP_ADAPTER_ADDRESSES *)xrealloc(aa, sz);
        rc = GetAdaptersAddresses(AF_INET,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                NULL, aa, &sz);
    }
    if (rc != NO_ERROR) { free(aa); return 0; }
    for (cur = aa; cur; cur = cur->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *ua;
        if (cur->OperStatus != IfOperStatusUp) continue;
        for (ua = cur->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)ua->Address.lpSockaddr;
                unsigned ip = ntohl(sin->sin_addr.s_addr);
                if ((ip >> 24) == 127) continue;
                target_add(targets, n, max,
                           (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, 0);
            }
        }
    }
    free(aa);
#else
    struct ifaddrs *ifa, *cur;
    if (getifaddrs(&ifa) != 0) return 0;
    for (cur = ifa; cur; cur = cur->next) {
        struct sockaddr_in *sin;
        unsigned ip;
        if (!cur->ifa_addr || cur->ifa_addr->sa_family != AF_INET) continue;
        sin = (struct sockaddr_in *)cur->ifa_addr;
        ip = ntohl(sin->sin_addr.s_addr);
        if ((ip >> 24) == 127) continue;
        target_add(targets, n, max, (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, 0);
    }
    freeifaddrs(ifa);
#endif
    return *n - before;
}

/* ------------------------------------------------------------------ */
/* conf: integrity checksum + surgical JSON surgery                   */
/* ------------------------------------------------------------------ */

#define CONF_MARK "# MD5 checksum"

typedef struct {
    char  *text;         /* whole file                                     */
    size_t total;        /* whole file length                              */
    size_t body;         /* length of everything before "# MD5 checksum"   */
    char   stored[64];   /* the checksum string found in the file          */
    int    has_mark;
} Conf;

/* The app signs: md5( body with every '\r' removed, then right-trimmed ) */
static void conf_checksum(const char *body, size_t bodylen, char out[33])
{
    char *tmp = (char *)xmalloc(bodylen + 1);
    size_t i, j = 0;
    for (i = 0; i < bodylen; i++)
        if (body[i] != '\r') tmp[j++] = body[i];
    while (j > 0 && (tmp[j-1] == '\n' || tmp[j-1] == '\t' ||
                     tmp[j-1] == ' '  || tmp[j-1] == '\r'))
        j--;
    md5_hex(tmp, j, out);
    free(tmp);
}

static int conf_load(const char *path, Conf *c)
{
    char *txt;
    size_t len = 0, i;
    memset(c, 0, sizeof(*c));
    txt = read_file(path, &len);
    if (!txt) return -1;
    c->text = txt;
    c->total = len;
    for (i = 0; i + sizeof(CONF_MARK) - 1 < len; i++) {
        if (memcmp(txt + i, CONF_MARK, sizeof(CONF_MARK) - 1) == 0) {
            c->body = i;
            c->has_mark = 1;
            /* grab the hex token after the marker */
            {
                const char *p = txt + i + sizeof(CONF_MARK) - 1;
                const char *end = txt + len;
                while (p < end && !isxdigit((unsigned char)*p)) p++;
                {
                    size_t k = 0;
                    while (p < end && isxdigit((unsigned char)*p) && k < sizeof(c->stored) - 1)
                        c->stored[k++] = (char)toupper((unsigned char)*p++);
                    c->stored[k] = 0;
                }
            }
            break;
        }
    }
    if (!c->has_mark) c->body = len;
    return 0;
}

static int conf_verify(const Conf *c)
{
    char want[33];
    if (!c->has_mark) return 0;
    conf_checksum(c->text, c->body, want);
    return strcmp(want, c->stored) == 0;
}

/*
 * JSON helpers. We edit the document *textually* (not by re-serialising) so
 * every other setting, comment spacing and line ending stays byte-identical.
 * The app rewrites the file in its own format anyway; minimal diffs are just
 * safer and easier to eyeball.
 */

static const char *skip_ws(const char *s, const char *e)
{
    while (s < e && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) s++;
    return s;
}

/* p points at the opening quote; returns pointer just past the closing quote */
static const char *str_end(const char *p, const char *e)
{
    p++;
    while (p < e) {
        if (*p == '\\') { p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return e;
}

/* p points at '{' or '['; returns pointer just past the matching close */
static const char *match_bracket(const char *p, const char *e)
{
    char open = *p, close = (open == '{') ? '}' : ']';
    int depth = 0;
    while (p < e) {
        if (*p == '"') { p = str_end(p, e); continue; }
        if (*p == open) depth++;
        else if (*p == close) {
            depth--;
            if (depth == 0) return p + 1;
        }
        p++;
    }
    return e;
}

/* find "key": <value> inside object [ob,oe); returns pointer to value start.
 * Tolerates ob pointing at the object's opening brace. */
static const char *obj_value(const char *ob, const char *oe, const char *key,
                             int *is_string, const char **val_end)
{
    const char *p = ob;
    size_t klen = strlen(key);
    if (p < oe && (*p == '{' || *p == '[')) p++;
    while (p < oe) {
        const char *ks, *ke;
        p = skip_ws(p, oe);
        if (p >= oe || *p == '}') break;
        if (*p != '"') break;
        ks = p + 1;
        ke = str_end(p, oe);
        if (ke <= ks) break;
        if ((size_t)(ke - 1 - ks) == klen && strncmp(ks, key, klen) == 0) {
            p = skip_ws(ke, oe);
            if (p < oe && *p == ':') p++;
            p = skip_ws(p, oe);
            if (is_string) *is_string = (p < oe && *p == '"');
            if (val_end) {
                if (p < oe && *p == '"') *val_end = str_end(p, oe);
                else if (p < oe && (*p == '{' || *p == '[')) *val_end = match_bracket(p, oe);
                else {
                    const char *q = p;
                    while (q < oe && *q != ',' && *q != '}' && *q != '\n') q++;
                    while (q > p && isspace((unsigned char)q[-1])) q--;
                    *val_end = q;
                }
            }
            return p;
        }
        /* skip this key's value and continue */
        p = skip_ws(ke, oe);
        if (p < oe && *p == ':') p++;
        p = skip_ws(p, oe);
        if (p < oe && *p == '"') p = str_end(p, oe);
        else if (p < oe && (*p == '{' || *p == '[')) p = match_bracket(p, oe);
        else { while (p < oe && *p != ',' && *p != '}') p++; }
        p = skip_ws(p, oe);
        if (p < oe && *p == ',') p++;
    }
    return NULL;
}

/* locate the value object of a top-level "section" key, e.g. "local_machines" */
static const char *section_obj(const char *json, size_t len, const char *name,
                               const char **endp, const char **valstartp,
                               const char **valendp)
{
    const char *e = json + len;
    const char *p = obj_value(json, e, name, NULL, NULL);
    if (!p) return NULL;
    if (*p != '{' && *p != '[') return NULL;
    if (valstartp) *valstartp = p;
    {
        const char *stop = match_bracket(p, e);
        if (endp) *endp = stop;
        if (valendp) *valendp = stop - 1;
        return p;
    }
}

/* find the sub-object for a printer serial inside a section object */
static const char *sub_obj(const char *ob, const char *oe, const char *key,
                           const char **endp)
{
    const char *p = obj_value(ob, oe, key, NULL, NULL);
    if (!p) return NULL;
    if (*p != '{') return NULL;
    {
        const char *stop = match_bracket(p, ob + (oe - ob));
        if (endp) *endp = stop;
        return p;
    }
}




/*
 * Rewrite the whole conf body:
 *   - for each entry, ensure local_machines[serial].dev_ip == entry.ip
 *   - ensure user_access_code[serial] == entry.code (when we know it)
 * Entries are matched by serial; unknown serials are appended.
 * Returns number of changes, or -1 on parse failure.
 */
static int conf_apply(const char *body, size_t bodylen, const Entry *ents, int nents,
                      int set_type, const char *type_value,
                      char **out_body, size_t *out_len)
{
    const char *e = body + bodylen;
    const char *lm_s = NULL, *lm_e = NULL;
    const char *json_end;
    const char *ws_start;
    Buf out;
    int changes = 0;
    int i;

    /* The JSON region is the body minus its trailing whitespace. */
    ws_start = e;
    while (ws_start > body && isspace((unsigned char)ws_start[-1])) ws_start--;
    json_end = ws_start;

    if (!section_obj(body, (size_t)(json_end - body), "local_machines", &lm_e, &lm_s, NULL))
        return -1;

    buf_init(&out);

    /* We rebuild by walking replacements sorted by position. Simple approach:
     * apply edits one at a time on a moving buffer. */
    {
        char *work = (char *)xmalloc((size_t)(json_end - body) + 1);
        memcpy(work, body, (size_t)(json_end - body));
        work[json_end - body] = 0;
        size_t worklen = (size_t)(json_end - body);

        for (i = 0; i < nents; i++) {
            const char *lm_s2 = NULL, *lm_e2 = NULL, *lm_start = NULL;
            const char *devob = NULL, *devobe = NULL;
            /* re-locate local_machines each iteration (offsets may have moved) */
            lm_start = section_obj(work, worklen, "local_machines", &lm_e2, &lm_s2, NULL);
            if (!lm_start) break;
            (void)lm_e; (void)lm_s;

            devob = sub_obj(lm_start, lm_e2 - 1, ents[i].serial, &devobe);
            if (devob) {
                const char *val = NULL;
                int is_str = 0;
                const char *vs = NULL, *ve = NULL;
                val = obj_value(devob, devobe - 1, "dev_ip", &is_str, &ve);
                if (val && is_str) {
                    vs = val + 1;
                    ve = ve - 1;
                    if ((size_t)(ve - vs) == strlen(ents[i].ip) &&
                        strncmp(vs, ents[i].ip, (size_t)(ve - vs)) == 0) {
                        /* already correct */
                    } else {
                        Buf nb;
                        buf_init(&nb);
                        buf_add(&nb, work, (size_t)(vs - work));
                        buf_adds(&nb, ents[i].ip);
                        buf_add(&nb, ve, worklen - (size_t)(ve - work));
                        free(work);
                        work = nb.p;
                        worklen = nb.len;
                        changes++;
                    }
                }
                if (set_type && type_value && *type_value) {
                    const char *tvs = NULL, *tve = NULL;
                    int ts = 0;
                    const char *tv = obj_value(work + 0, work + worklen, "dev_ip", NULL, NULL);
                    (void)tv;
                    /* only patch type when it is currently empty */
                    devob = sub_obj(section_obj(work, worklen, "local_machines", &lm_e2, &lm_s2, NULL),
                                    lm_e2 - 1, ents[i].serial, &devobe);
                    if (devob) {
                        tv = obj_value(devob, devobe - 1, "printer_type", &ts, &tve);
                        if (tv && ts) {
                            tvs = tv + 1;
                            tve = tve - 1;
                            if (tve == tvs) {
                                Buf nb;
                                buf_init(&nb);
                                buf_add(&nb, work, (size_t)(tvs - work));
                                buf_adds(&nb, type_value);
                                buf_add(&nb, tve, worklen - (size_t)(tve - work));
                                free(work);
                                work = nb.p;
                                worklen = nb.len;
                                changes++;
                            }
                        }
                    }
                }
            } else {
                /* append a brand new entry at the front of local_machines */
                const char *insert_at = lm_start + 1;   /* just inside '{' */
                Buf nb;
                buf_init(&nb);
                buf_add(&nb, work, (size_t)(insert_at - work));
                buf_addf(&nb, "\r\n\t\t\"%s\": {\r\n\t\t\t\"dev_ip\": \"%s\",\r\n"
                              "\t\t\t\"dev_name\": \"%s\",\r\n\t\t\t\"dev_pid\": \"%s\",\r\n"
                              "\t\t\t\"dev_placement\": \"Group A\",\r\n\t\t\t\"printer_type\": \"%s\"\r\n\t\t},",
                         ents[i].serial, ents[i].ip,
                         ents[i].name[0] ? ents[i].name : ents[i].serial,
                         ents[i].pid[0] ? ents[i].pid : "0",
                         (set_type && type_value) ? type_value : "");
                buf_add(&nb, insert_at, worklen - (size_t)(insert_at - work));
                free(work);
                work = nb.p;
                worklen = nb.len;
                changes++;
            }
        }

        /* user_access_code section */
        for (i = 0; i < nents; i++) {
            const char *sec = NULL, *secend = NULL, *sec_start = NULL;
            if (!ents[i].code[0]) continue;
            sec_start = section_obj(work, worklen, "user_access_code", &secend, &sec, NULL);
            if (!sec_start) break;
            {
                const char *vs = NULL, *ve = NULL;
                int is_str = 0;
                const char *val = obj_value(sec_start, secend - 1, ents[i].serial, &is_str, &ve);
                if (val && is_str) {
                    vs = val + 1;
                    ve = ve - 1;
                    if ((size_t)(ve - vs) != strlen(ents[i].code) ||
                        strncmp(vs, ents[i].code, (size_t)(ve - vs)) != 0) {
                        Buf nb;
                        buf_init(&nb);
                        buf_add(&nb, work, (size_t)(vs - work));
                        buf_adds(&nb, ents[i].code);
                        buf_add(&nb, ve, worklen - (size_t)(ve - work));
                        free(work);
                        work = nb.p;
                        worklen = nb.len;
                        changes++;
                    }
                } else if (!val) {
                    const char *insert_at = sec_start + 1;
                    Buf nb;
                    buf_init(&nb);
                    buf_add(&nb, work, (size_t)(insert_at - work));
                    buf_addf(&nb, "\r\n\t\t\"%s\": \"%s\",", ents[i].serial, ents[i].code);
                    buf_add(&nb, insert_at, worklen - (size_t)(insert_at - work));
                    free(work);
                    work = nb.p;
                    worklen = nb.len;
                    changes++;
                }
            }
        }

        /* nlohmann/json (what the app uses) rejects a trailing comma before a
         * closing brace/bracket, so remove any we introduced.
         * work[k] == ',' ; scan forward over whitespace to the closer, then
         * drop everything from the comma through the closer-1. */
        {
            size_t k = 0;
            while (k + 1 < worklen) {
                if (work[k] == ',') {
                    size_t m = k + 1;
                    while (m < worklen && isspace((unsigned char)work[m])) m++;
                    if (m < worklen && (work[m] == '}' || work[m] == ']')) {
                        /* delete [k, m) -- the comma and the whitespace after it */
                        size_t span = m - k;
                        memmove(work + k, work + m, worklen - m);
                        worklen -= span;
                        work[worklen] = 0;
                        if (k > 0) k--;      /* re-check the preceding char */
                        continue;
                    }
                }
                k++;
            }
        }

        *out_body = work;
        *out_len = worklen;
        buf_free(&out);
    }

    return changes;
}

/* ------------------------------------------------------------------ */
/* config discovery / app control                                     */
/* ------------------------------------------------------------------ */

static char g_conf_path_global[4096];
static int g_dry_run = 0;
static int g_restart = 0;
static int g_set_type = 0;
static int g_timeout_ms = 1200;

/* Subnets the user has explicitly named, remembered next to the program so
 * `sync`/`watch` can still find the printers after a config rewrite has
 * blanked their dev_ip fields. */
static void sidecar_path(char *out, size_t cap)
{
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (appdata && *appdata)
        snprintf(out, cap, "%s\\Orca-Flashforge\\flashfix.subnets", appdata);
    else
        snprintf(out, cap, "flashfix.subnets");
#else
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/.config/Orca-Flashforge/flashfix.subnets", home ? home : ".");
#endif
}

static void subnets_remember(const char *specs)
{
    char path[4096], merged[8192];
    char old[4096];
    char *tok;
    size_t n = 0;
    FILE *f;
    merged[0] = 0;
    old[0] = 0;
    sidecar_path(path, sizeof(path));
    {
        char *txt = read_file(path, &n);
        if (txt) { snprintf(old, sizeof(old), "%s", txt); free(txt); }
    }
    snprintf(merged, sizeof(merged), "%s", old);
    tok = strtok((char *)specs, ",");
    while (tok) {
        char *p = merged;
        int present = 0;
        while (*p) {
            char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len == strlen(tok) && strncmp(p, tok, len) == 0) { present = 1; break; }
            if (!nl) break;
            p = nl + 1;
        }
        if (!present && strlen(merged) + strlen(tok) + 2 < sizeof(merged)) {
            strncat(merged, tok, sizeof(merged) - strlen(merged) - 1);
            strncat(merged, "\n", sizeof(merged) - strlen(merged) - 1);
        }
        tok = strtok(NULL, ",");
    }
    f = fopen(path, "wb");
    if (!f) return;
    fwrite(merged, 1, strlen(merged), f);
    fclose(f);
}

static void subnets_recall(char *out, size_t cap)
{
    char path[4096];
    size_t n = 0;
    char *txt;
    size_t i, j = 0;
    out[0] = 0;
    sidecar_path(path, sizeof(path));
    txt = read_file(path, &n);
    if (!txt) return;
    for (i = 0; i < n && j + 2 < cap; i++) {
        if (txt[i] == '\n' || txt[i] == '\r') {
            if (j > 0 && out[j-1] != ',') out[j++] = ',';
        } else {
            out[j++] = txt[i];
        }
    }
    out[j] = 0;
    while (j > 0 && out[j-1] == ',') out[--j] = 0;
    free(txt);
}

static void default_conf_path(char *out, size_t cap)
{
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (appdata && *appdata)
        snprintf(out, cap, "%s\\Orca-Flashforge\\Orca-Flashforge.conf", appdata);
    else
        snprintf(out, cap, "Orca-Flashforge.conf");
#else
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/.config/Orca-Flashforge/Orca-Flashforge.conf",
             home ? home : ".");
#endif
}

static int app_is_running(void)
{
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    int found = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "flash studio.exe") == 0 ||
                _stricmp(pe.szExeFile, "flashstudio.exe") == 0) { found = 1; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
#else
    FILE *f = popen("pgrep -f 'flash studio|flashstudio' 2>/dev/null", "r");
    char line[64];
    int found = 0;
    if (f) { if (fgets(line, sizeof(line), f)) found = 1; pclose(f); }
    return found;
#endif
}

static void app_stop(void)
{
#ifdef _WIN32
    system("taskkill /IM \"flash studio.exe\" /F >NUL 2>&1");
#else
    system("pkill -f 'flash studio' >/dev/null 2>&1");
#endif
    sleep_ms(1500);
}

static void app_start(void)
{
#ifdef _WIN32
    system("start \"\" \"C:\\Program Files\\Flashforge\\Flash Studio Desktop\\flash studio.exe\"");
#else
    system("(nohup 'flash studio' >/dev/null 2>&1 &)");
#endif
    sleep_ms(800);
}

/* ------------------------------------------------------------------ */
/* commands                                                           */
/* ------------------------------------------------------------------ */

static int run_discovery(const unsigned char targets[][4], int ntargets)
{
    int n;
    info("probing %d host(s) on udp/48899 + udp/19000 ...", ntargets);
    n = udp_sweep(targets, ntargets, g_timeout_ms);
    printf("found %d printer(s):\n", n);
    {
        int i;
        for (i = 0; i < g_ndev; i++) {
            char body[8192];
            if (!g_dev[i].replied) continue;
            printf("  %-16s serial=%-16s name=%-16s pid=%-4u",
                   g_dev[i].ip, g_dev[i].serial, g_dev[i].name, g_dev[i].pid);
            char code[64];
            code[0] = 0;
            {
                Entry known[MAX_DEV];
                int nk = 0, k;
                Conf cc;
                if (conf_load(g_conf_path_global, &cc) == 0) {
                    build_entries_from_conf(cc.text, cc.body, known, &nk);
                    for (k = 0; k < nk; k++)
                        if (strcmp(known[k].serial, g_dev[i].serial) == 0 && known[k].code[0]) {
                            snprintf(code, sizeof(code), "%s", known[k].code);
                            break;
                        }
                    free(cc.text);
                }
            }
            if (http_detail(g_dev[i].ip, 8898, g_dev[i].serial, code, body, sizeof(body)) == 0) {
                char model[64] = "", fw[32] = "";
                g_dev[i].http_ok = 1;
                json_str_field(body, "model", model, sizeof(model));
                json_str_field(body, "firmwareVersion", fw, sizeof(fw));
                if (!model[0]) json_str_field(body, "name", model, sizeof(model));
                if (model[0]) snprintf(g_dev[i].model, sizeof(g_dev[i].model), "%s", model);
                if (fw[0]) snprintf(g_dev[i].firmware, sizeof(g_dev[i].firmware), "%s", fw);
                printf(" http=ok model=%s fw=%s\n", model[0] ? model : "?", fw[0] ? fw : "?");
            } else {
                printf(" http=FAIL\n");
            }
        }
    }
    return n;
}

static void build_entries_from_conf(const char *body, size_t bodylen, Entry *ents, int *nents)
{
    /* Pull the serials we know about out of local_machines and remember their
     * configured access codes so we can rewrite them intact. */
    const char *lm_s = NULL, *lm_e = NULL, *uc_s = NULL, *uc_e = NULL;
    int n = 0;
    if (!section_obj(body, bodylen, "local_machines", &lm_e, &lm_s, NULL)) return;
    {
        const char *p = lm_s + 1;
        while (p < lm_e - 1 && n < MAX_DEV) {
            const char *ks, *ke, *vs, *ve;
            p = skip_ws(p, lm_e - 1);
            if (p >= lm_e - 1 || *p == '}') break;
            if (*p != '"') break;
            ks = p + 1;
            ke = str_end(p, lm_e - 1);
            vs = skip_ws(ke, lm_e - 1);
            if (vs < lm_e - 1 && *vs == ':') vs++;
            vs = skip_ws(vs, lm_e - 1);
            if (vs >= lm_e - 1 || *vs != '{') break;
            ve = match_bracket(vs, lm_e - 1);
            memset(&ents[n], 0, sizeof(Entry));
            copy_len(ents[n].serial, sizeof(ents[n].serial), ks, (size_t)(ke - 1 - ks));
            {
                const char *ip = obj_value(vs, ve - 1, "dev_ip", NULL, NULL);
                if (ip && *ip == '"') copy_json_string(ents[n].ip, sizeof(ents[n].ip), ip);
                {
                    const char *nm = obj_value(vs, ve - 1, "dev_name", NULL, NULL);
                    if (nm && *nm == '"') copy_json_string(ents[n].name, sizeof(ents[n].name), nm);
                }
                {
                    const char *pd = obj_value(vs, ve - 1, "dev_pid", NULL, NULL);
                    if (pd && *pd == '"') copy_json_string(ents[n].pid, sizeof(ents[n].pid), pd);
                }
            }
            if (ents[n].serial[0]) n++;
            p = ve;
            p = skip_ws(p, lm_e - 1);
            if (p < lm_e - 1 && *p == ',') p++;
        }
    }
    /* access codes */
    if (section_obj(body, bodylen, "user_access_code", &uc_e, &uc_s, NULL)) {
        int i;
        for (i = 0; i < n; i++) {
            const char *code = obj_value(uc_s, uc_e - 1, ents[i].serial, NULL, NULL);
            if (code && *code == '"')
                copy_json_string(ents[i].code, sizeof(ents[i].code), code);
            if (!ents[i].code[0]) {
                /* try the access_code section as a fallback source */
                const char *ac_s = NULL, *ac_e = NULL;
                if (section_obj(body, bodylen, "access_code", &ac_e, &ac_s, NULL)) {
                    const char *c2 = obj_value(ac_s, ac_e - 1, ents[i].serial, NULL, NULL);
                    if (c2 && *c2 == '"')
                        copy_json_string(ents[i].code, sizeof(ents[i].code), c2);
                }
            }
        }
    }
    *nents = n;
}

static int cmd_status(const char *conf_path)
{
    Conf c;
    int rc = conf_load(conf_path, &c);
    char computed[33];
    int nents = 0, i;

    if (rc != 0) {
        printf("config : %s (NOT FOUND)\n", conf_path);
        return 1;
    }
    printf("config : %s\n", conf_path);
    printf("size   : %zu bytes\n", c.total);
    printf("checksum: %s (stored %s)\n",
           c.has_mark ? (conf_verify(&c) ? "OK" : "MISMATCH") : "absent",
           c.has_mark ? c.stored : "-");
    if (c.has_mark && !conf_verify(&c)) {
        conf_checksum(c.text, c.body, computed);
        printf("          expected %s\n", computed);
    }

    {
        Entry ents[MAX_DEV];
        build_entries_from_conf(c.text, c.body, ents, &nents);
        printf("printers: %d configured\n", nents);
        for (i = 0; i < nents; i++) {
            char proto[64] = "";
            char body[1024];
            int reach = tcp_probe(ents[i].ip[0] ? ents[i].ip : "0.0.0.0", 8898, 800,
                                  NULL, 0, NULL, 0, NULL) == 0;
            if (ents[i].ip[0]) snprintf(proto, sizeof(proto), "%s:8898", ents[i].ip);
            printf("   %-16s dev_ip=%-15s name=%-14s pid=%-3s code=%s  tcp=%s\n",
                   ents[i].serial,
                   ents[i].ip[0] ? ents[i].ip : "(EMPTY!)",
                   ents[i].name[0] ? ents[i].name : "-",
                   ents[i].pid[0] ? ents[i].pid : "-",
                   ents[i].code[0] ? ents[i].code : "-",
                   ents[i].ip[0] ? (reach ? "reachable" : "UNREACHABLE") : "n/a");
            if (reach && ents[i].serial[0]) {
                if (http_detail(ents[i].ip, 8898, ents[i].serial, ents[i].code,
                                body, sizeof(body)) == 0)
                    printf("   %-16s   -> printer API answered OK\n", "");
                else
                    printf("   %-16s   -> printer API did NOT answer\n", "");
            }
        }
    }
    printf("app    : %s\n", app_is_running() ? "running" : "not running");
    free(c.text);
    return 0;
}

/* Core: discover printers, then correct the conf. */
static int do_sync(const char *conf_path, unsigned char targets[][4], int ntargets)
{
    Conf c;
    Entry ents[MAX_DEV];
    int nents = 0, i, changed = 0;
    char *newbody = NULL;
    size_t newlen = 0;

    if (conf_load(conf_path, &c) != 0)
        die("cannot read %s", conf_path);

    build_entries_from_conf(c.text, c.body, ents, &nents);
    info("configured printers: %d", nents);

    /* 1. sweep for printers (fills g_dev) */
    udp_sweep(targets, ntargets, g_timeout_ms);

    /* 2. learn access codes for any newly found serial from the conf, and
     *    learn serials for configured-but-IP-less printers from the sweep. */
    for (i = 0; i < g_ndev; i++) {
        Device *d = &g_dev[i];
        int j, known = -1;
        if (!d->replied || !d->serial[0]) continue;
        for (j = 0; j < nents; j++)
            if (strcmp(ents[j].serial, d->serial) == 0) { known = j; break; }
        if (known >= 0) {
            if (strcmp(ents[known].ip, d->ip) != 0) {
                info("  %s: dev_ip %s -> %s", d->serial,
                     ents[known].ip[0] ? ents[known].ip : "(empty)", d->ip);
                snprintf(ents[known].ip, sizeof(ents[known].ip), "%s", d->ip);
            } else {
                info("  %s: dev_ip %s (unchanged)", d->serial, d->ip);
            }
            if (!ents[known].pid[0] && d->pid)
                snprintf(ents[known].pid, sizeof(ents[known].pid), "%u", d->pid);
            if (!ents[known].name[0] && d->name[0])
                snprintf(ents[known].name, sizeof(ents[known].name), "%s", d->name);
        } else if (nents < MAX_DEV) {
            info("  new printer found: %s (%s) at %s", d->serial, d->name, d->ip);
            memset(&ents[nents], 0, sizeof(Entry));
            snprintf(ents[nents].serial, sizeof(ents[nents].serial), "%s", d->serial);
            snprintf(ents[nents].ip, sizeof(ents[nents].ip), "%s", d->ip);
            snprintf(ents[nents].name, sizeof(ents[nents].name), "%s",
                     d->name[0] ? d->name : d->serial);
            if (d->pid) snprintf(ents[nents].pid, sizeof(ents[nents].pid), "%u", d->pid);
            nents++;
        }
    }

    if (nents == 0)
        die("no printers known or discovered -- give me a subnet, e.g. "
            "flashfix discover 10.20.0.0/24");

    /* 3. rewrite */
    {
        int r = conf_apply(c.text, c.body, ents, nents, g_set_type, "Flashforge", &newbody, &newlen);
        if (r < 0) die("could not parse local_machines in %s", conf_path);
        changed = r;
    }

    /* Did discovery actually see anything? If neither the sweep nor a direct
     * probe of the configured printers answered, the subnet is wrong -- fail
     * loudly instead of reporting a hollow "nothing to patch". */
    {
        int replied = 0, reachable = 0, k;
        for (k = 0; k < g_ndev; k++) if (g_dev[k].replied) replied++;
        for (k = 0; k < nents; k++)
            if (ents[k].ip[0] &&
                tcp_probe(ents[k].ip, 8898, 800, NULL, 0, NULL, 0, NULL) == 0)
                reachable++;
        if (replied == 0 && reachable == 0) {
            fprintf(stderr, "flashfix: nothing answered -- discovery found 0 printers\n");
            fprintf(stderr, "          (probed %d host(s) on udp/48899 + udp/19000)\n", ntargets);
            fprintf(stderr, "          check the subnet, e.g.  flashfix sync 10.20.0.0/24\n");
            fprintf(stderr, "          and verify routing first:  flashfix route\n");
            return 2;
        }
        if (replied == 0) {
            /* the printers are still reachable where the conf says they are,
             * but this sweep never found them -- the subnet argument is wrong */
            fprintf(stderr, "flashfix: warning: udp discovery found nothing on the "
                            "subnet(s) given\n");
        }
    }

    if (changed == 0) {
        info("already correct -- nothing to patch");
    }

    /* 4. write it back with a fresh checksum */
    {
        char sum[33];
        Buf file;
        conf_checksum(newbody, newlen, sum);
        buf_init(&file);
        buf_add(&file, newbody, newlen);
        buf_adds(&file, "\r\n");
        buf_addf(&file, "%s %s\r\n", CONF_MARK, sum);

        if (changed == 0) {
            printf("no changes needed (%d printers verified)\n", nents);
        } else if (g_dry_run) {
            printf("--dry-run: would write %zu bytes, checksum %s (%d change(s))\n",
                   file.len, sum, changed);
        } else {
            char bak[4200];
            snprintf(bak, sizeof(bak), "%s.bak", conf_path);
            {
                size_t blen = 0;
                char *b = read_file(conf_path, &blen);
                if (b) { write_file_atomic(bak, b, blen); free(b); }
            }
            if (write_file_atomic(conf_path, file.p, file.len) != 0)
                die("failed writing %s", conf_path);
            printf("patched %s: %d change(s), checksum %s\n", conf_path, changed, sum);
            printf("backup: %s\n", bak);
        }
        buf_free(&file);
    }

    free(newbody);
    free(c.text);

    if (changed && !g_dry_run && g_restart) {
        if (app_is_running()) { info("restarting flash studio ..."); app_stop(); }
        app_start();
    } else if (changed && !g_dry_run && app_is_running()) {
        printf("NOTE: flash studio is running -- restart it to pick up the change\n");
    }
    return 0;
}

static int cmd_watch(const char *conf_path, unsigned char targets[][4], int ntargets)
{
    int last_state = -1;
    time_t last_probe = 0;
    printf("flashfix watch: keeping %s correct. Ctrl-C to stop.\n", conf_path);

    for (;;) {
        time_t now = time(NULL);
        int running = app_is_running();
        int need = 0;

        if (now - last_probe > 60 || last_state < 0) {
            udp_sweep(targets, ntargets, g_timeout_ms);
            last_probe = now;
        }

        {
            Conf c;
            if (conf_load(conf_path, &c) == 0) {
                Entry ents[MAX_DEV];
                int nents = 0, i;
                build_entries_from_conf(c.text, c.body, ents, &nents);
                for (i = 0; i < g_ndev; i++) {
                    int j;
                    if (!g_dev[i].replied || !g_dev[i].serial[0]) continue;
                    for (j = 0; j < nents; j++) {
                        if (strcmp(ents[j].serial, g_dev[i].serial) == 0 &&
                            strcmp(ents[j].ip, g_dev[i].ip) != 0) { need = 1; break; }
                    }
                    if (need) break;
                }
                if (!need) {
                    int j;
                    for (j = 0; j < nents; j++)   /* empty dev_ip also needs fixing */
                        if (!ents[j].ip[0]) { need = 1; break; }
                }
                if (!c.has_mark || !conf_verify(&c)) need = 1;
                free(c.text);
            } else {
                need = 1;
            }
        }

        if (need && !running && now != last_probe) {
            int save = g_quiet;
            g_quiet = 1;
            do_sync(conf_path, targets, ntargets);
            g_quiet = save;
        }
        if (running != last_state) {
            printf("flash studio is %s\n", running ? "running" : "stopped");
            last_state = running;
        }
        sleep_ms(2000);
    }
    return 0;
}

static int cmd_devices(const char *conf_path)
{
    Conf c;
    Entry ents[MAX_DEV];
    int nents = 0, i;

    printf("Flash Studio LAN device reachability + control-path probe\n");
    printf("config: %s\n\n", conf_path);

    if (conf_load(conf_path, &c) != 0) {
        printf("cannot read config\n");
        return 1;
    }
    build_entries_from_conf(c.text, c.body, ents, &nents);

    for (i = 0; i < nents; i++) {
        char body[8192];
        int has8899, has8898, has8080;
        printf("%-16s  %s  (%s)\n", ents[i].serial,
               ents[i].ip[0] ? ents[i].ip : "(no ip)",
               ents[i].name[0] ? ents[i].name : "-");
        if (!ents[i].ip[0]) { printf("    no dev_ip in config\n\n"); continue; }

        has8898 = (tcp_probe(ents[i].ip, 8898, 900, NULL, 0, NULL, 0, NULL) == 0);
        has8899 = (tcp_probe(ents[i].ip, 8899, 900, NULL, 0, NULL, 0, NULL) == 0);
        has8080 = (tcp_probe(ents[i].ip, 8080, 900, NULL, 0, NULL, 0, NULL) == 0);

        printf("    tcp 8898 (HTTP JSON API)   : %s\n", has8898 ? "open" : "closed");
        printf("    tcp 8899 (G-code console)  : %s\n", has8899 ? "open" : "closed");
        printf("    tcp 8080 (camera stream)   : %s\n", has8080 ? "open" : "closed");

        if (has8898 && http_detail(ents[i].ip, 8898, ents[i].serial, ents[i].code,
                                   body, sizeof(body)) == 0) {
            char model[64] = "", fw[32] = "", st[64] = "";
            json_str_field(body, "model", model, sizeof(model));
            json_str_field(body, "firmwareVersion", fw, sizeof(fw));
            json_str_field(body, "machineStatus", st, sizeof(st));
            if (!st[0]) json_str_field(body, "status", st, sizeof(st));
            printf("    HTTP /detail               : OK  model=%s fw=%s status=%s\n",
                   model[0] ? model : "?", fw[0] ? fw : "?", st[0] ? st : "?");
        } else if (has8898) {
            printf("    HTTP /detail               : no valid reply\n");
        }

        if (has8899) {
            char req[64];
            static const char *cmds[] = { "~M601 S1\r\n", "~M119\r\n" };
            int k;
            printf("    G-code console             :");
            for (k = 0; k < 2; k++) {
                char reply[512];
                size_t rl = 0;
                memset(reply, 0, sizeof(reply));
                snprintf(req, sizeof(req), "%s", cmds[k]);
                if (tcp_probe(ents[i].ip, 8899, 1500, req, strlen(req),
                              reply, sizeof(reply), &rl) == 0 && rl) {
                    /* strip CR/LF for a compact one-liner */
                    size_t j, w = 0;
                    char flat[256];
                    for (j = 0; j < rl && w + 1 < sizeof(flat); j++)
                        if (reply[j] != '\r' && reply[j] != '\n') flat[w++] = reply[j];
                    flat[w] = 0;
                    printf(" [%s] %.120s", k ? "~M119" : "~M601 S1", flat);
                } else {
                    printf(" [%s] no reply", k ? "~M119" : "~M601 S1");
                }
            }
            printf("\n");
        }

        if (!has8899 && has8898)
            printf("    NOTE: no console port. This model only exposes the modern\n"
                   "          HTTP API (8898). The Device tab still needs\n"
                   "          FlashNetwork discovery to come Online.\n");
        printf("\n");
    }

    printf("REMINDER: 'Offline' in the Device tab is NOT a routing problem.\n"
           "Flash Studio fills a printer's IP ONLY from its own L2 scan\n"
           "(fnet_getLanDevList); the dev_ip in the config is never read back.\n"
           "See README.md 'Why the Device tab still says Offline'.\n");
    free(c.text);
    return 0;
}

static int cmd_route(void)
{
    printf("If a printer is UNREACHABLE (no ping / no tcp 8898), fix routing first;\n"
           "flashfix only fixes Flash Studio's discovery/config.\n\n"
           "  arp/ping test      : ping <PRINTER-IP>\n"
           "  tcp test           : curl -m 3 http://<PRINTER-IP>:8898/  (any answer = routed)\n\n"
           "A) Windows route via the next hop (temporary):\n"
           "     route add <PRINTER-SUBNET> mask <MASK> <GATEWAY-IP>\n"
           "     route add <PRINTER-SUBNET> mask <MASK> <GATEWAY-IP> -p   (persistent)\n\n"
           "B) WireGuard: add the printer subnet to the peer that bridges to it:\n"
           "     [Peer]\n"
           "     AllowedIPs = <YOUR-SUBNET>, <PRINTER-SUBNET>\n"
           "   and on the far side enable ip forwarding + masquerade:\n"
           "     sysctl -w net.ipv4.ip_forward=1\n"
           "     iptables -t nat -A POSTROUTING -o <lan-if> -j MASQUERADE\n\n"
           "C) Tailscale: advertise the printer subnet from a node on it:\n"
           "     tailscale up --advertise-routes=<PRINTER-SUBNET>\n"
           "   then approve the route in the admin console and enable\n"
           "   \"Allow local network access\" on this machine.\n\n"
           "D) Two-router setups (PC on one subnet, printers behind a second\n"
           "   router on another): make sure the *upstream* router can route back\n"
           "   to this subnet, or that the nearer router's WAN interface NATs it.\n"
           "   If ICMP/TCP to the printers already works from here, routing is\n"
           "   fine -- you only need the `sync` step so Flash Studio learns the\n"
           "   printer IPs.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    printf(
"flashfix %s -- make Flash Studio see FlashForge printers on other subnets\n"
"\n"
"usage: flashfix <command> [options] [SUBNET...]\n"
"\n"
"commands:\n"
"  status            show config contents, checksum and reachability\n"
"  devices           probe each configured printer's control paths\n"
"  discover [SUBNET] probe for printers (udp 48899/19000) and show them\n"
"  sync     [SUBNET] discover + write dev_ip/access codes into the conf  <-- the fix\n"
"  watch    [SUBNET] run forever and keep the conf correct\n"
"  route             print routing help (wireguard / tailscale / static)\n"
"\n"
"options:\n"
"  --conf PATH     path to Orca-Flashforge.conf\n"
"  --subnets LIST  comma separated subnets/IPs to probe\n"
"  --timeout MS    probe timeout per host (default %d)\n"
"  --dry-run       do not write the conf\n"
"  --restart       restart flash studio after patching\n"
"  --set-type      fill empty printer_type with the model name\n"
"  -q, --quiet     quieter output\n"
"\n"
"SUBNET accepts 10.20.0.0/24 or a bare 10.20.0.20.\n"
"When no subnet is given, every /24 this machine is attached to is swept,\n"
"plus the /24s of any printers already in the config.\n",
    FLASHFIX_VERSION, g_timeout_ms);
}

int main(int argc, char **argv)
{
    const char *cmd = NULL;
    char conf_path[4096];
    unsigned char targets[512][4];
    int ntargets = 0;
    char cli_subnets[2048];
    int i;

    conf_path[0] = 0;
    cli_subnets[0] = 0;

    if (net_startup() != 0) die("winsock init failed");

    if (argc < 2) { usage(); return 1; }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] == '-') {
            if (strcmp(a, "--conf") == 0 && i + 1 < argc) {
                snprintf(conf_path, sizeof(conf_path), "%s", argv[++i]);
            } else if (strcmp(a, "--subnets") == 0 && i + 1 < argc) {
                snprintf(cli_subnets, sizeof(cli_subnets), "%s", argv[++i]);
            } else if (strcmp(a, "--timeout") == 0 && i + 1 < argc) {
                g_timeout_ms = atoi(argv[++i]);
                if (g_timeout_ms < 100) g_timeout_ms = 100;
            } else if (strcmp(a, "--dry-run") == 0) {
                g_dry_run = 1;
            } else if (strcmp(a, "--restart") == 0) {
                g_restart = 1;
            } else if (strcmp(a, "--set-type") == 0) {
                g_set_type = 1;
            } else if (strcmp(a, "--quiet") == 0) {
                g_quiet = 1;
            } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
                usage(); return 0;
            } else {
                die("unknown option %s", a);
            }
        } else if (a[0] == '-' && a[1]) {
            if (strcmp(a, "-q") == 0) g_quiet = 1;
            else if (strcmp(a, "-h") == 0) { usage(); return 0; }
            else die("unknown option %s", a);
        } else if (!cmd) {
            cmd = a;
        } else {
            /* positional subnet */
            if (cli_subnets[0]) strncat(cli_subnets, ",",
                                        sizeof(cli_subnets) - strlen(cli_subnets) - 1);
            strncat(cli_subnets, a, sizeof(cli_subnets) - strlen(cli_subnets) - 1);
        }
    }

    if (!cmd) { usage(); return 1; }
    if (!conf_path[0]) default_conf_path(conf_path, sizeof(conf_path));
    snprintf(g_conf_path_global, sizeof(g_conf_path_global), "%s", conf_path);

    /* build the probe list */
    if (cli_subnets[0]) {
        char *tok = strtok(cli_subnets, ",");
        while (tok) {
            if (!expand_target(tok, targets, &ntargets, 512))
                fprintf(stderr, "flashfix: ignoring unparsable subnet '%s'\n", tok);
            tok = strtok(NULL, ",");
        }
        subnets_remember(cli_subnets);
    } else {
        /* default: local /24s + the /24s of printers already configured in the
         * conf + every subnet the user has named before. Remembering matters:
         * once the app rewrites the conf with dev_ip blanked, there is nothing
         * left in the conf to tell us where to look. */
        Conf c;
        char remembered[4096];
        local_targets(targets, &ntargets, 512);
        subnets_recall(remembered, sizeof(remembered));
        if (remembered[0]) {
            char *tok = strtok(remembered, ",");
            while (tok) {
                expand_target(tok, targets, &ntargets, 512);
                tok = strtok(NULL, ",");
            }
        }
        if (conf_load(conf_path, &c) == 0) {
            Entry ents[MAX_DEV];
            int nents = 0, k;
            build_entries_from_conf(c.text, c.body, ents, &nents);
            for (k = 0; k < nents; k++) {
                char spec[64];
                unsigned a, b, cc;
                if (sscanf(ents[k].ip, "%u.%u.%u.", &a, &b, &cc) == 3) {
                    snprintf(spec, sizeof(spec), "%u.%u.%u.0/24", a, b, cc);
                    expand_target(spec, targets, &ntargets, 512);
                }
            }
            free(c.text);
        }
        if (ntargets == 0) {
            /* last resort: sweep a couple of common LANs */
            expand_target("10.20.0.0/24", targets, &ntargets, 512);
            expand_target("192.168.0.0/24", targets, &ntargets, 512);
        }
        /* de-duplicate */
        {
            int a, b;
            for (a = 0; a < ntargets; a++) {
                for (b = a + 1; b < ntargets; ) {
                    if (memcmp(targets[a], targets[b], 4) == 0) {
                        memmove(targets[b], targets[b+1], (size_t)(ntargets - b - 1) * 4);
                        ntargets--;
                    } else b++;
                }
            }
        }
    }

    if (strcmp(cmd, "status") == 0)        return cmd_status(conf_path);
    if (strcmp(cmd, "discover") == 0)      return run_discovery(targets, ntargets) < 0 ? 1 : 0;
    if (strcmp(cmd, "sync") == 0 || strcmp(cmd, "patch") == 0)
        return do_sync(conf_path, targets, ntargets);
    if (strcmp(cmd, "watch") == 0)         return cmd_watch(conf_path, targets, ntargets);
    if (strcmp(cmd, "route") == 0)         return cmd_route();
    if (strcmp(cmd, "devices") == 0)       return cmd_devices(conf_path);

    usage();
    return 1;
}
