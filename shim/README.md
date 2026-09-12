# FlashNetwork shim — makes Flash Studio actually *use* the patched IPs

`flashfix sync` puts the right `dev_ip` into `Orca-Flashforge.conf`. This shim is
what makes the app **read it**.

## The problem it solves

Flash Studio gets a printer's address from exactly one place:

```
DeviceData.cpp   DeviceObjectOpr::update_scan_machine()
    └─ MultiComUtils::getLanDevList()
         └─ FlashNetwork.dll!fnet_getLanDevList()      ← L2 broadcast scan
```

That scan is link-local (the DLL imports `GetIpAddrTable` and broadcasts), so
across a router it returns nothing. Meanwhile the app parses `local_machines`
out of the config but keeps only `dev_id` / `dev_name` / `dev_placement` /
`dev_pid` — **`dev_ip` is dropped**. So the address we patch in is never read,
and `set_selected_machine()` bails at:

```cpp
if (devObj->get_lan_dev_info() != nullptr) {   // always false for config-loaded devices
    com_id_t id = MultiComMgr::inst()->addLanDev(...);
}
```

Printers appear in the Device tab but can never be connected.

## How the shim fixes it

It replaces `FlashNetwork.dll` and changes exactly **two** of the 131 exports:

| export | behaviour |
|--------|-----------|
| `fnet_getLanDevList` | calls the real one first (same-subnet printers unaffected), then **appends every printer from the config that has a usable `dev_ip` and isn't already listed** |
| `fnet_freeLanDevInfos` | frees whichever allocator produced the array |

The other **129 exports forward untouched** to the real DLL via naked
trampolines (`flashnet_forwards.asm`), so no signature is assumed and every
register and the stack pass through exactly as the caller set them up.

Nothing else needed changing: every downstream call — `fnet_getLanDevDetail`,
`fnet_ctrlLanDevTemp`, `fnet_lanDevStartJob`, gcode transfer, camera — already
receives `ip:port` as *arguments*, so it works through the real DLL the moment
the list contains the right address.

```
                     ┌──────────────────────────────┐
   app calls ───────▶│  FlashNetwork.dll  (shim)    │
                     │                              │
                     │  fnet_getLanDevList  ────┐   │
                     │  (our version)           │   │
                     │                          ▼   │
                     │   read Orca-...conf → merge  │
                     │                          │   │
                     │  129 trampolines ────────┼──▶│ FlashNetwork_orig.dll
                     │                          │   │  (the real 4 MB library)
                     └──────────────────────────┴───┘
```

## Install

Needs admin (the app lives in `Program Files`).

```powershell
# from an elevated PowerShell
pwsh -File install.ps1
```

That will:
1. save the pristine DLL as `FlashNetwork.dll.vanilla` **and** `FlashNetwork_orig.dll`
2. copy `flashnet_shim.dll` over `FlashNetwork.dll`
3. stop the app first, and verify the installed hash matches

Then start Flash Studio and open the Device tab. Printers come up **Online**.

Re-running is safe (it detects an up-to-date install and does nothing).

## Uninstall

```powershell
pwsh -File install.ps1 -Uninstall
```

Restores the original DLL and removes `FlashNetwork_orig.dll`.

## Verify

```powershell
pwsh -File verify.ps1
```

```
== FlashNetwork shim status ==
  FlashNetwork.dll             167936 bytes  sha=DC253259A6BA2A27
  FlashNetwork_orig.dll       4020736 bytes  sha=5E4BA0074C135D33
  flashnet_shim.dll            167936 bytes  sha=DC253259A6BA2A27

  shim installed : True
  app running    : pid 19560
  loaded modules : FlashNetwork.dll, FlashNetwork_orig.dll
  printer conns  :
     <PC-IP>:49394 -> <PRINTER-IP>:8080  Established
```

## Build

```cmd
build.bat
```

Needs MSVC (for `ml64` + the x64 CRT) and Python. It runs
`tools/gen_forwards.py`, which reads the export table of the installed
`FlashNetwork.dll` with `llvm-readobj` and regenerates
`flashnet_forwards.h` / `.asm` / `.def` — so if FlashForge ships a new version
with a different export set, just run `build.bat` again.

The generated files are checked in so you can inspect them.

## Files

| file | role |
|------|------|
| `flashnet_shim.c` | the DLL: hooks `fnet_getLanDevList`, loads the real library, config reader |
| `flashnet_forwards.asm` | *generated* — 129 naked trampolines |
| `flashnet_forwards.h` | *generated* — declarations, slot enum, name table |
| `flashnet_shim.def` | *generated* — export list (all 131) |
| `tools/gen_forwards.py` | reads the real DLL's exports and regenerates all three |
| `build.bat` | build the DLL |
| `install.ps1` | install / uninstall |
| `verify.ps1` | show install state, loaded modules, live printer connections |
| `testdir/` | standalone harness used during development |

## Safety notes

- The original DLL is preserved **twice** (`FlashNetwork_orig.dll` is what the
  shim loads; `.vanilla` is a plain backup). Uninstall restores it.
- The shim is ~168 KB vs the original 4 MB — it contains no product logic, only
  the forwarders and the config reader.
- If `FlashNetwork_orig.dll` is missing the shim still loads; forwarded calls
  would then have no target, so uninstall/repair before running the app.
- `FLASHFIX_CONF` overrides which config the shim reads (used by the test
  harness; normally unset so it uses `%APPDATA%\Orca-Flashforge\...`).
- A Flash Studio update will overwrite `FlashNetwork.dll` — re-run
  `install.ps1` afterwards.

## Verified

Test harness (`testdir/`), built against the real DLL:

```
loaded ...\FlashNetwork.dll
fnet_getVersion (forwarded) = <version>
fnet_getLanDevList rc=0 count=2
  [0] sn=SN-PRINTER-0001    ip=10.20.0.20    port=8898   pid=36   mode=0 bind=0
  [1] sn=SN-PRINTER-0002      ip=10.20.0.21    port=8898   pid=40   mode=0 bind=0
freed ok
```

Deeper test calling *into the printers* through the trampolines:

```
version           : <version>
setUserAgent      : ok
getLanDevList     : rc=0 n=2
  product[SN-PRINTER-0001 @ 10.20.0.20] rc=0 ptr=<ptr>
  product[SN-PRINTER-0002 @ 10.20.0.21] rc=0 ptr=<ptr>
```

`fnet_getLanDevProduct` returning `0` means the real DLL successfully fetched
printer data over HTTP using our injected addresses — i.e. the whole chain works.

In the live app: both DLLs load, and Flash Studio holds an established
connection to the printer's camera port (`<PRINTER-IP>:8080`).
