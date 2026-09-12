/*
 * flashnet_shim.c -- make Flash Studio honour the printer IPs we wrote into
 * Orca-Flashforge.conf.
 *
 * WHY THIS EXISTS
 * ---------------
 * Flash Studio's Device tab obtains a printer's address from exactly one place:
 *
 *     DeviceData.cpp  DeviceObjectOpr::update_scan_machine()
 *         -> MultiComUtils::getLanDevList()
 *             -> FlashNetwork.dll!fnet_getLanDevList()
 *
 * That call performs a link-local scan (FlashNetwork.dll imports
 * GetIpAddrTable and broadcasts on the local subnet). Across a router it finds
 * nothing, so the printer objects never receive an address. The app parses
 * local_machines out of Orca-Flashforge.conf but keeps only dev_id / dev_name /
 * dev_placement / dev_pid -- dev_ip is dropped on the floor -- so the value we
 * patch in is never read back. Result: printers are listed but permanently
 * "Offline", and set_selected_machine() bails at
 * `get_lan_dev_info() != nullptr`.
 *
 * WHAT THIS DOES
 * --------------
 * Drop-in replacement for FlashNetwork.dll:
 *
 *   * loads the real library from FlashNetwork_orig.dll next to this file
 *   * forwards 129 of the 131 exports to it unchanged (naked trampolines in
 *     flashnet_forwards.asm -- no signature assumptions, all registers and the
 *     stack pass through untouched)
 *   * implements fnet_getLanDevList() itself: calls the real one first (so
 *     same-subnet printers keep working), then appends any printer from the
 *     config that has a usable dev_ip and is not already present
 *   * implements fnet_freeLanDevInfos() to free whichever allocator produced
 *     the array
 *
 * Everything downstream -- getLanDevDetail, temp/fan/light control,
 * lanDevStartJob, gcode transfer -- already receives ip:port as arguments and
 * therefore works through the real DLL with no changes at all.
 *
 * INSTALL (install.ps1, needs admin)
 *   FlashNetwork.dll      -> FlashNetwork_orig.dll   (preserved, once)
 *   flashnet_shim.dll     -> FlashNetwork.dll
 *   restart Flash Studio
 *
 * UNINSTALL (uninstall.ps1): delete the shim, restore the original.
 *
 * Build:
 *   cl /LD /O2 flashnet_shim.c flashnet_forwards.asm /Fe:flashnet_shim.dll \
 *      /link /DEF:flashnet_shim.def
 * or with zig (see build.bat).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define SN_LEN   128
#define NAME_LEN 128

typedef struct fnet_lan_dev_info {
    char           serialNumber[SN_LEN];
    char           name[NAME_LEN];
    char           ip[16];
    unsigned short port;
    unsigned short vid;
    unsigned short pid;
    unsigned short connectMode;   /* 0 = LAN */
    unsigned short bindStatus;    /* 0 = free */
    unsigned short bindType;
} fnet_lan_dev_info_t;

#include "flashnet_forwards.h"

/* ------------------------------------------------------------------ */
/* real library                                                       */
/* ------------------------------------------------------------------ */

static HMODULE g_real = NULL;
static CRITICAL_SECTION g_lock;
static int g_inited = 0;

typedef int  (*fn_getLanDevList)(fnet_lan_dev_info_t **, int *, int);
typedef void (*fn_freeLanDevInfos)(fnet_lan_dev_info_t *);

static fn_getLanDevList   real_getLanDevList   = NULL;
static fn_freeLanDevInfos real_freeLanDevInfos = NULL;

/* Trampoline targets, one per forwarded export (see gen_forwards.py). The
 * array is indexed by the SLOT_* enum in flashnet_forwards.h. */
void *g_real_slot[129];

/* Records we allocated ourselves; the real DLL must never free these. */
#define MAX_TRACK 512
static void *g_ours[MAX_TRACK];
static int   g_oursN = 0;

static void track_add(void *p)
{
    EnterCriticalSection(&g_lock);
    if (g_oursN < MAX_TRACK) g_ours[g_oursN++] = p;
    LeaveCriticalSection(&g_lock);
}

static int track_take(void *p)
{
    int found = 0, i;
    EnterCriticalSection(&g_lock);
    for (i = 0; i < g_oursN; i++) {
        if (g_ours[i] == p) { g_ours[i] = g_ours[--g_oursN]; found = 1; break; }
    }
    LeaveCriticalSection(&g_lock);
    return found;
}

static void shim_init(void)
{
    char self[MAX_PATH], dir[MAX_PATH], orig[MAX_PATH];
    HMODULE hself = NULL;
    int i;

    if (g_inited) return;
    InitializeCriticalSection(&g_lock);
    g_inited = 1;

    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&shim_init, &hself);
    if (!GetModuleFileNameA(hself, self, sizeof(self))) return;

    strcpy(dir, self);
    {
        char *slash = strrchr(dir, '\\');
        if (slash) *(slash + 1) = 0;
    }
    snprintf(orig, sizeof(orig), "%sFlashNetwork_orig.dll", dir);

    g_real = LoadLibraryA(orig);
    if (!g_real) g_real = LoadLibraryA("FlashNetwork_orig.dll");
    if (!g_real) {
        /* Nothing to forward to. Leave the slots NULL: a call would crash, so
         * point them at a trap-free stub instead. */
        return;
    }

    real_getLanDevList   = (fn_getLanDevList)  GetProcAddress(g_real, "fnet_getLanDevList");
    real_freeLanDevInfos = (fn_freeLanDevInfos)GetProcAddress(g_real, "fnet_freeLanDevInfos");

    /* Resolve every forwarded export. The names must match the enum order in
     * flashnet_forwards.h exactly; the generator emits them in the same
     * sorted order used for the .asm, so read them back from the header. */
    {
        static const char *const names[] = {
            FORWARDED_NAMES
        };
        int n = (int)(sizeof(names) / sizeof(names[0]));
        if (n > (int)(sizeof(g_real_slot) / sizeof(g_real_slot[0])))
            n = (int)(sizeof(g_real_slot) / sizeof(g_real_slot[0]));
        for (i = 0; i < n; i++) {
            g_real_slot[i] = (void *)GetProcAddress(g_real, names[i]);
            if (!g_real_slot[i])
                g_real_slot[i] = (void *)GetProcAddress(g_real, names[i] + 0);
        }
    }
}

static void ensure(void) { if (!g_inited) shim_init(); if (g_real) {} }

/* ------------------------------------------------------------------ */
/* config reading                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    char     serial[SN_LEN];
    char     name[NAME_LEN];
    char     ip[64];
    unsigned pid;
    unsigned port;
} CfgDev;

static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0 || n > 64L * 1024 * 1024) { fclose(f); return NULL; }
    buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    buf[n] = 0;
    fclose(f);
    if (len) *len = (size_t)n;
    return buf;
}

static void conf_path_of(char *out, size_t cap)
{
    const char *env = getenv("FLASHFIX_CONF");
    if (env && *env) { snprintf(out, cap, "%s", env); return; }
    env = getenv("APPDATA");
    if (env && *env) { snprintf(out, cap, "%s\\Orca-Flashforge\\Orca-Flashforge.conf", env); return; }
    out[0] = 0;
}

static const char *skip_ws(const char *s, const char *e)
{
    while (s < e && isspace((unsigned char)*s)) s++;
    return s;
}

/* Copy the contents of the JSON string whose opening quote is at p. */
static void jstr(char *dst, size_t cap, const char *p)
{
    size_t i = 0;
    if (!cap) return;
    dst[0] = 0;
    if (p && *p == '"') {
        p++;
        while (*p && *p != '"' && i + 1 < cap) {
            if (*p == '\\' && p[1]) p++;
            dst[i++] = *p++;
        }
    }
    dst[i] = 0;
}

static const char *quote_end(const char *p, const char *e)
{
    p++;
    while (p < e) {
        if (*p == '\\') { p += 2; continue; }
        if (*p == '"') return p;
        p++;
    }
    return e;
}

static const char *match_brace(const char *p, const char *e)
{
    char open = *p, clos = (open == '{') ? '}' : ']';
    int depth = 0;
    while (p < e) {
        if (*p == '"') { p = quote_end(p, e); if (p < e) p++; continue; }
        if (*p == open) depth++;
        else if (*p == clos) { if (--depth == 0) return p + 1; }
        p++;
    }
    return e;
}

/* "key": <string|number> inside [ob,oe) */
static int find_scalar(const char *ob, const char *oe, const char *key,
                       char *out, size_t cap)
{
    const char *p = ob;
    size_t kl = strlen(key);
    if (p < oe && (*p == '{' || *p == '[')) p++;
    while (p < oe) {
        const char *ks, *ke, *v;
        p = skip_ws(p, oe);
        if (p >= oe || *p != '"') break;
        ks = p + 1;
        ke = quote_end(p, oe);
        if (ke >= oe) break;
        v = skip_ws(ke + 1, oe);
        if (v < oe && *v == ':') v++;
        v = skip_ws(v, oe);
        if ((size_t)(ke - ks) == kl && strncmp(ks, key, kl) == 0) {
            if (v < oe && *v == '"') { jstr(out, cap, v); return out[0] != 0; }
            {
                size_t i = 0;
                while (v < oe && *v && *v != ',' && *v != '}' && *v != ']' &&
                       !isspace((unsigned char)*v) && i + 1 < cap)
                    out[i++] = *v++;
                out[i] = 0;
                return out[0] != 0;
            }
        }
        /* advance past this value */
        if (v < oe && (*v == '{' || *v == '[')) p = match_brace(v, oe);
        else if (v < oe && *v == '"') p = quote_end(v, oe) + 1;
        else { while (p < oe && *p != ',' && *p != '}') p++; }
        p = skip_ws(p, oe);
        if (p < oe && *p == ',') p++;
    }
    return 0;
}

/* value of a top-level key */
static const char *top_value(const char *json, size_t len, const char *name,
                             const char **endOut)
{
    const char *e = json + len;
    const char *p = skip_ws(json, e);
    if (p < e && *p == '{') p++;
    while (p < e) {
        const char *ks, *ke, *v;
        p = skip_ws(p, e);
        if (p >= e || *p != '"') break;
        ks = p + 1;
        ke = quote_end(p, e);
        if (ke >= e) break;
        v = skip_ws(ke + 1, e);
        if (v < e && *v == ':') v++;
        v = skip_ws(v, e);
        if ((size_t)(ke - ks) == strlen(name) && strncmp(ks, name, ke - ks) == 0) {
            if (endOut && v < e && (*v == '{' || *v == '[')) *endOut = match_brace(v, e);
            return v;
        }
        if (v < e && (*v == '{' || *v == '[')) p = match_brace(v, e);
        else if (v < e && *v == '"') p = quote_end(v, e) + 1;
        else { while (p < e && *p != ',' && *p != '}') p++; }
        p = skip_ws(p, e);
        if (p < e && *p == ',') p++;
    }
    return NULL;
}

static int load_cfg_devices(CfgDev *out, int max)
{
    char path[1024];
    char *txt;
    size_t len = 0;
    const char *lm, *lmEnd = NULL, *p;
    int n = 0;

    conf_path_of(path, sizeof(path));
    if (!path[0]) return 0;
    txt = slurp(path, &len);
    if (!txt) return 0;
    {
        char *mark = strstr(txt, "# MD5 checksum");
        if (mark) len = (size_t)(mark - txt);
    }

    lm = top_value(txt, len, "local_machines", &lmEnd);
    if (!lm || !lmEnd) { free(txt); return 0; }

    p = lm;
    if (p < lmEnd && *p == '{') p++;
    while (p < lmEnd - 1 && n < max) {
        const char *ks, *ke, *v, *ve;
        char ip[64] = "", name[NAME_LEN] = "", pid[32] = "", port[32] = "";
        p = skip_ws(p, lmEnd - 1);
        if (p >= lmEnd - 1 || *p != '"') break;
        ks = p + 1;
        ke = quote_end(p, lmEnd - 1);
        if (ke >= lmEnd - 1) break;
        v = skip_ws(ke + 1, lmEnd - 1);
        if (v < lmEnd - 1 && *v == ':') v++;
        v = skip_ws(v, lmEnd - 1);
        if (v >= lmEnd - 1 || *v != '{') break;
        ve = match_brace(v, lmEnd - 1);

        find_scalar(v, ve - 1, "dev_ip",   ip,   sizeof(ip));
        find_scalar(v, ve - 1, "dev_name", name, sizeof(name));
        find_scalar(v, ve - 1, "dev_pid",  pid,  sizeof(pid));
        find_scalar(v, ve - 1, "dev_port", port, sizeof(port));

        if (ip[0] && strcmp(ip, "0.0.0.0") != 0) {
            memset(&out[n], 0, sizeof(out[n]));
            {
                size_t sl = (size_t)(ke - ks);
                if (sl >= sizeof(out[n].serial)) sl = sizeof(out[n].serial) - 1;
                memcpy(out[n].serial, ks, sl);
                out[n].serial[sl] = 0;
            }
            snprintf(out[n].name, sizeof(out[n].name), "%s", name[0] ? name : out[n].serial);
            snprintf(out[n].ip,   sizeof(out[n].ip),   "%s", ip);
            out[n].pid  = (unsigned)strtoul(pid, NULL, 10);
            out[n].port = (unsigned)(port[0] ? strtoul(port, NULL, 10) : 8898);
            n++;
        }

        p = skip_ws(ve, lmEnd - 1);
        if (p < lmEnd - 1 && *p == ',') p++;
    }

    free(txt);
    return n;
}

/* ------------------------------------------------------------------ */
/* the interception                                                  */
/* ------------------------------------------------------------------ */

__declspec(dllexport)
int fnet_getLanDevList(fnet_lan_dev_info_t **infos, int *devCnt, int msWaitTime)
{
    fnet_lan_dev_info_t *orig = NULL;
    int origCnt = 0, rc = 0;
    CfgDev cfg[64];
    int cfgN, i, k, addN = 0;
    fnet_lan_dev_info_t *merged;

    ensure();
    if (infos)  *infos = NULL;
    if (devCnt) *devCnt = 0;

    if (real_getLanDevList) {
        rc = real_getLanDevList(&orig, &origCnt, msWaitTime);
        if (rc != 0) { orig = NULL; origCnt = 0; }
    }

    cfgN = load_cfg_devices(cfg, 64);
    if (cfgN == 0) {
        if (infos)  *infos = orig;
        if (devCnt) *devCnt = origCnt;
        return rc;
    }

    merged = (fnet_lan_dev_info_t *)calloc((size_t)origCnt + (size_t)cfgN, sizeof(*merged));
    if (!merged) {
        if (infos)  *infos = orig;
        if (devCnt) *devCnt = origCnt;
        return rc;
    }
    if (origCnt > 0 && orig) memcpy(merged, orig, (size_t)origCnt * sizeof(*merged));

    for (i = 0; i < cfgN; i++) {
        int dup = 0;
        if (!cfg[i].ip[0]) continue;
        for (k = 0; k < origCnt + addN; k++) {
            if (strcmp(merged[k].serialNumber, cfg[i].serial) == 0 ||
                (merged[k].ip[0] && strcmp(merged[k].ip, cfg[i].ip) == 0)) { dup = 1; break; }
        }
        if (dup) continue;
        {
            fnet_lan_dev_info_t *d = &merged[origCnt + addN];
            memset(d, 0, sizeof(*d));
            snprintf(d->serialNumber, sizeof(d->serialNumber), "%s", cfg[i].serial);
            snprintf(d->name,         sizeof(d->name),         "%s", cfg[i].name);
            snprintf(d->ip,           sizeof(d->ip),           "%s", cfg[i].ip);
            d->port        = (unsigned short)(cfg[i].port ? cfg[i].port : 8898);
            d->vid         = 0;
            d->pid         = (unsigned short)cfg[i].pid;
            d->connectMode = 0;
            d->bindStatus  = 0;
            d->bindType    = 0;
            addN++;
        }
    }

    if (real_freeLanDevInfos && orig) real_freeLanDevInfos(orig);
    track_add(merged);

    if (infos)  *infos = merged;
    if (devCnt) *devCnt = origCnt + addN;
    return 0;
}

__declspec(dllexport)
void fnet_freeLanDevInfos(fnet_lan_dev_info_t *infos)
{
    ensure();
    if (!infos) return;
    if (track_take(infos)) { free(infos); return; }
    if (real_freeLanDevInfos) real_freeLanDevInfos(infos);
}

/* ------------------------------------------------------------------ */
/* keep the trampoline table alive across DLL unload                  */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        shim_init();
    }
    return TRUE;
}
