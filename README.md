# flashfix

Make **Flash Studio** (`flash studio.exe`, a.k.a. Orca-Flashforge) work with
FlashForge printers that live on a **different subnet** — across a second
router, WireGuard, Tailscale, or any number of network hops.

> Typical case: `laptop (10.0.0.x) → router → ISP router → printers (10.20.0.x)`

Two parts, and you need both:

| part | what it does |
|------|--------------|
| **`flashfix.exe`** | finds the printers and writes their real IPs into `Orca-Flashforge.conf`, correctly re-signed |
| **`shim/`** | a drop-in `FlashNetwork.dll` that makes the app *read* those IPs |

Then the Device tab works normally: printers Online, status, temps, camera,
upload-and-print.

---

## TL;DR

```cmd
REM 1. locate the printers and patch the config
flashfix.exe sync 10.20.0.0/24

REM 2. install the DLL shim (elevated), then restart Flash Studio
pwsh -File shim\install.ps1
```

Check it any time:

```cmd
flashfix.exe status      :: config + reachability
flashfix.exe devices     :: per-printer control paths (8898 / 8899 / 8080)
pwsh -File shim\verify.ps1
```

---

## Why this is needed

### Part 1 — the config

Flash Studio learns printer addresses **only from its own scan**:

```
DeviceObjectOpr::update_scan_machine()
  └─ MultiComUtils::getLanDevList()
       └─ FlashNetwork.dll!fnet_getLanDevList()    ← link-local broadcast
```

That probe is L2 (the DLL imports `GetIpAddrTable` and broadcasts on the local
subnet). Across a router it finds nothing, so the app saves the devices with an
**empty address**:

```jsonc
// %APPDATA%\Orca-Flashforge\Orca-Flashforge.conf
"local_machines": {
    "SN-AD5X-0001": { "dev_ip": "", ... },   // <-- unusable
    "SN-C5-0002":   { "dev_ip": "", ... }
}
```

and then `connect()` bails out immediately:

```cpp
// DeviceManager.cpp
if (dev_ip.empty()) return -1;
```

`flashfix sync` fixes this by doing the discovery itself — the same `~M119`
probe, but sent as **unicast**, which crosses routers — then writing the IPs
back and re-signing the file with the app's own integrity checksum:

```
md5( body with all CRs removed, then right-trimmed )   →  upper-case hex
appended as:  # MD5 checksum <HEX>
```

### Part 2 — the app still ignores it

Here is the catch that makes the config patch necessary but not sufficient.
The app parses `local_machines` and keeps only some fields — **`dev_ip` is
dropped**:

```cpp
// AppConfig.cpp
} else if (it.key() == SECTION_LOCAL_MACHINES) {
    MacInfoMap info;
    info.emplace(std::make_pair("dev_id",   j_machine["dev_id"].get<std::string>()));
    info.emplace(std::make_pair("dev_name", j_machine["dev_name"].get<std::string>()));
    // dev_placement, dev_pid ... and that's it. No dev_ip.
```

so devices loaded from config get no LAN info, and the only code that connects
requires exactly that:

```cpp
// DeviceData.cpp
DeviceObject *obj = new DeviceObject(dev_id, dev_name);   // m_lan_info = nullptr

if (devObj->get_lan_dev_info() != nullptr) {              // always false
    com_id_t id = MultiComMgr::inst()->addLanDev(...);    // never reached
}
```

A real deadlock: the address exists only where nothing reads it, and the thing
that needs it can only come from a scan that can't reach.

**The shim breaks it open** — see [`shim/`](shim/). It replaces
`FlashNetwork.dll`, forwards 129 of its 131 exports to the real library
untouched, and re-implements `fnet_getLanDevList` to also return the printers
from the config.

---

## flashfix

Single C file, no dependencies.

### Build

```cmd
zig cc -O2 flashfix.c -o flashfix.exe -lws2_32 -liphlpapi   :: zig
cl /O2 flashfix.c ws2_32.lib iphlpapi.lib                   :: MSVC
gcc -O2 flashfix.c -o flashfix.exe -lws2_32 -liphlpapi      :: MinGW
```

Linux/macOS compile too (drop the two `-l` flags) — handy when the printer side
of the link is a Linux box.

### Commands

| command | meaning |
|---------|---------|
| `status` | config contents, checksum state, per-printer reachability |
| `devices` | probe every control path per printer (8898 / 8899 / 8080) |
| `discover [SUBNET]` | find printers by probing, no writes |
| `sync [SUBNET]` | **discover + patch the config** |
| `watch [SUBNET]` | stay resident and keep the config correct |
| `route` | routing help for WireGuard / Tailscale / static routes |

`SUBNET` is `10.20.0.0/24` or a bare `10.20.0.20`. With no subnet it sweeps
every `/24` this machine is attached to, the `/24`s of configured printers, and
anything you named before (remembered in a sidecar file, so it still works
after the app rewrites the config).

| option | meaning |
|--------|---------|
| `--conf PATH` | use a different `Orca-Flashforge.conf` |
| `--subnets LIST` | comma-separated subnets |
| `--timeout MS` | probe timeout (default 1200) |
| `--dry-run` | print the change, write nothing |
| `--restart` | restart Flash Studio after patching |
| `--set-type` | also fill an empty `printer_type` |
| `-q`, `--quiet` | less output |

### Example

```
$ flashfix.exe status
config : %APPDATA%\Orca-Flashforge\Orca-Flashforge.conf
checksum: OK (stored 7F27732469364C39F82573AC0C9089F1)
printers: 2 configured
   SN-AD5X-0001   dev_ip=10.20.0.20  name=SN-AD5X-0001  pid=36  code=a1b2c3d4  tcp=reachable
                    -> printer API answered OK
   SN-C5-0002     dev_ip=10.20.0.21  name=Creator 5     pid=40  code=e5f6a7b8  tcp=reachable
                    -> printer API answered OK
app    : running

$ flashfix.exe devices
SN-AD5X-0001   10.20.0.20  (SN-AD5X-0001)
    tcp 8898 (HTTP JSON API)   : open
    tcp 8899 (G-code console)  : open
    tcp 8080 (camera stream)   : open
    HTTP /detail               : OK  fw=5.1.8 status=printing
    G-code console             : [~M601 S1] Control Success V2.1. ok
```

### How discovery works

Printers do not broadcast — they only answer. `flashfix` sends the same probe
the app uses, as unicast to each host:

```
probe:  "~M119\n"   →   UDP 48899  (and 19000)
reply:  280 bytes
        0x00  name          128 bytes, NUL padded
        0x84  control port  u16 big-endian (8899)
        0x88  dev pid       u16 big-endian (36 = AD5X, 40 = Creator 5)
        0x92  serial        64 bytes, NUL padded
```

The serial and pid from that reply are exactly what the config needs, so a
printer that has never been paired can be added from scratch.

### Safety

- writes a `.bak` next to the config before every change
- `--dry-run` to preview
- only ever touches `dev_ip`, `printer_type` (opt-in) and the access-code
  entries; everything else stays byte-identical
- re-signs with the real MD5 scheme, so the app accepts the file — the output
  is byte-identical to what the app itself writes for the same content
- `watch` refuses to write while Flash Studio is running, so it can never race
  the app mid-save

---

## The shim

See **[shim/README.md](shim/README.md)** for the full writeup. Summary:

```
                    ┌──────────────────────────────┐
  app calls ───────▶│  FlashNetwork.dll  (shim)    │
                    │                              │
                    │  fnet_getLanDevList  ────┐   │
                    │  (ours)                  │   │
                    │                          ▼   │
                    │   read config → merge list   │
                    │                          │   │
                    │  129 trampolines ────────┼──▶│ FlashNetwork_orig.dll
                    │                          │   │ (the real library)
                    └──────────────────────────┴───┘
```

- `fnet_getLanDevList` — calls the real one first (same-subnet printers keep
  working), then appends configured printers that are missing
- `fnet_freeLanDevInfos` — frees with the right allocator
- the other **129 exports forward untouched** via naked trampolines in
  assembly, so no signature is assumed and all registers/stack pass through

Nothing else had to change because every downstream call
(`fnet_getLanDevDetail`, `fnet_ctrlLanDevTemp`, `fnet_lanDevStartJob`, gcode
transfer, camera) already takes `ip:port` as *arguments*.

```powershell
pwsh -File shim\install.ps1              # install (elevated)
pwsh -File shim\install.ps1 -Uninstall   # restore the original
pwsh -File shim\verify.ps1               # status + live connections
cd shim; build.bat                       # rebuild
```

The original DLL is preserved as `FlashNetwork_orig.dll` (loaded by the shim)
plus `FlashNetwork.dll.vanilla` (a spare). **A Flash Studio update will
overwrite `FlashNetwork.dll` — re-run `install.ps1`.**

### Targeted at a specific build

`tools/gen_forwards.py` reads the export table of the *installed*
`FlashNetwork.dll` and regenerates the header, the assembly trampolines and the
`.def`. Verified against **Flash Studio 1.7.17 / FlashNetwork 3.4.3** (131
exports). If a future version changes its exports, `build.bat` regenerates
everything to match.

---

## Other observations from working this out

Both printers expose two independent control paths, which is why nothing here
depends on a single fragile channel:

| | 8898 HTTP JSON | 8899 G-code console | 8080 camera |
|---|---|---|---|
| AD5X | ✅ | ✅ | ✅ |
| Creator 5 | ✅ | ❌ refused | ✅ |

- **8898** — `POST /detail {"serialNumber":..., "checkCode":...}` returns
  status, firmware, nozzle, temperatures, filament, progress and the camera URL
- **8899** — `~M601 S1` → `Control Success V2.1.`; `~M119` → `MachineStatus:`,
  `MoveMode:`, `CurrentFile:`. Used by Flash Studio's built-in *Flashforge*
  print-host backend (`PrintHostUpload` → `~M28` → `~M23`)
- **8080** — `http://<ip>:8080/?action=stream`

The Creator 5 has no console port at all — it is HTTP-API-only.

---

## Troubleshooting

**Printers unreachable (`tcp=UNREACHABLE`)** — that part is routing, and
neither tool fixes it. Check and then `flashfix route`:

```cmd
ping 10.20.0.20
curl -m 3 http://10.20.0.20:8898/     :: any answer means it is routed
```

**`devices` works but the Device tab still says Offline** — the shim isn't
installed or didn't load:

```powershell
pwsh -File shim\verify.ps1
```

Expect to see *both* `FlashNetwork.dll` and `FlashNetwork_orig.dll` in the
loaded modules. If only the original appears, the install didn't take (is the
app in a different directory? pass `-AppDir`).

**App won't start after installing the shim** — restore and report:

```powershell
pwsh -File shim\install.ps1 -Uninstall
```

**Checksum MISMATCH** — something edited the config without re-signing.
`flashfix sync` repairs it.

---

## Layout

```
flashfix.c                 single-file tool (config + discovery)
flashfix.exe               build output (gitignored)
build.bat                  convenience wrapper
shim/
  flashnet_shim.c          the DLL: hooks + config reader
  flashnet_forwards.asm    generated — 129 naked trampolines
  flashnet_forwards.h      generated — decls, slot enum, name table
  flashnet_shim.def        generated — export list (131)
  tools/gen_forwards.py    reads the real DLL's exports, regenerates the three
  build.bat                build the shim
  install.ps1              install / uninstall
  verify.ps1               status + live connections
```

## License

MIT — see [LICENSE](LICENSE). This project interoperates with, but does not
include or redistribute, FlashForge's `FlashNetwork.dll` or Flash Studio. You
supply your own copy of the application.
