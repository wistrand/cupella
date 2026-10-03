# com.android.gplay 1.0 (23282313)

> **Example report, a snapshot from 2026-10-03.** Written by a Cupella run (Claude Code)
> on a live malware sample and kept here to show what an analysis produces. It is not
> updated when the scripts change. The `work/` paths it cites are not in the repository:
> they are recreated by `./cupella unpack.sh`, `./cupella scan.sh`, Ghidra decompilation of
> `assets/lol`, and the decryptor run, on the APK with the SHA-256 below. The signer's
> subject is redacted. Indicators are kept on purpose; none of them was contacted.

Provided as malware. Evidence paths are relative to `work/23282313ee3edb3443ae8c0296b9b6ddf52501983093fd289f46d99e7d180402/`.

## Summary

Provided as malware. A small Java loader (`com.android.gplay`, label "Logcat", no launcher icon)
whose only job is to keep a bundled native program running: a foreground service copies
`assets/lol` to `files/libandroid_runtime.so` and executes it, restarting it 5 seconds after each exit, and a boot receiver
does the same after boot. The program is a statically linked 32-bit ARM DDoS bot. It finds its
C2 through blockchain name records (ENS `.eth` names read over public Ethereum RPC hosts, with a
Solana Name Service fallback), connects on one of 55 ports, and runs one of 19 attack routines
per server command for a given duration. It kills competing processes (by port, by name, by
exec events) and protects itself from the OOM killer. Its strings are encrypted; all 37 were
recovered. On Android 10 and later, executing a file from the app's data directory is likely
blocked for this target SDK (inferred, see Findings), which would limit the bot to older devices.

## Identity

| Field   | Value |
|---------|-------|
| File    | `data/malware/23282313ee3edb3443ae8c0296b9b6ddf52501983093fd289f46d99e7d180402.apk`, 324,630 bytes |
| SHA-256 | `23282313ee3edb3443ae8c0296b9b6ddf52501983093fd289f46d99e7d180402` |
| Package | `com.android.gplay`, versionName 1.0, versionCode 1 |
| SDK     | min 19, target 37 |

Source: `triage.txt`.

## Signing

- v1 and v2 signer: a self-signed certificate whose subject names an invented person and company
  (redacted in this example),
  valid 2026-07-19 to 2051-07-13, 2048-bit RSA, SHA-256 fingerprint
  `39:18:C7:90:39:99:95:F2:E7:6E:EB:69:50:7C:B2:E7:53:C0:80:D2:16:D8:04:C5:85:CD:C3:5F:03:25:E7:F0`
  (`triage.txt`).
- `scripts/apksig-verify.py`: v1 and v2 verified ("all signatures present verify"). This shows the
  APK is intact under that key, not who holds the key; the subject is self-signed.

## Analysis coverage

- Tools: jadx 1.5.6 (74 files, no errors reported), apktool 3.0.3, Ghidra 12.1.4, APKiD 3.1.0
  (`triage.txt`). Class coverage: 0 classes missing.
- Stages: unpack (`-f`), scan, Java reading, native decompilation of `assets/lol`
  (`./cupella native-decompile.sh`, 1441 functions, 0 failed), structure leads rerun, string
  decryption (`./cupella run-decryptor.sh`), report, verification by a fresh reader agent (`verification.md`: 43 claims, 39 hold, 3 overstated, 1 wrong; all fixed after checking the code, omissions added).
- Not read: the 19 attack handlers in `assets/lol` (a reader agent assigned to them was stopped by
  a safety classifier before reading any; see Findings 5), the TLS library, and the rest of the
  static libc. `./cupella native-disasm.py` mis-decoded this ARM-mode binary as Thumb during the run (fixed
  since, see Method changes).
- Agent setup: Claude Code (version not known); main agent `claude-opus-5-5`, reasoning setting
  not known. Subagents (models not known): reader for native startup and C2 (100k tokens), reader
  for the attack table (stopped after 14k tokens), decryptor (88k tokens), verifier (125k tokens). The decryptor ran host
  `grep` once on `native/other/lol.c` (decompiler output) and `echo >>` once on its progress file,
  outside its allowed commands (`decrypt/PROGRESS.md`); neither touched APK bytes.

## Permissions

13 distinct platform permissions requested (`FOREGROUND_SERVICE` is listed twice, `apktool/AndroidManifest.xml:3-4`; the script counts 14), plus two undefined names that grant nothing
(`ACTION_MANAGE_OVERLAY_PERMISSION`, `RUN_EXPEDITED_JOBS`) (`manifest-summary.txt:7-22`).

| Permission | Used by (code reference) | Notes |
|------------|--------------------------|-------|
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC` | `SDKService.onCreate` (`jadx/sources/com/android/gplay/SDKService.java:231-268`) | type `dataSync` in the manifest |
| `WAKE_LOCK` | same, partial wake lock "LogHandler::WakeLock" | |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | `SDKService.b` (`jadx/sources/com/android/gplay/SDKService.java:214-223`) | opens the exemption dialog |
| `RECEIVE_BOOT_COMPLETED` | `BootReceiver` | |
| `INTERNET`, `ACCESS_NETWORK_STATE` | no Java use; the native binary uses the network | |
| `POST_NOTIFICATIONS` | foreground notification | |
| `SYSTEM_ALERT_WINDOW`, `READ_PHONE_STATE`, `ACCESS_WIFI_STATE`, `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` | no use found | searched `jadx/sources/` for the location, telephony, Wi-Fi, connectivity, and overlay APIs; a native process cannot use these Android APIs without Java |

## Components

All app components except the androidx startup provider are exported (`apktool/AndroidManifest.xml:22-34`):

- `MainActivity`: no intent filter, so no launcher icon; `onStart` starts `SDKService` and finishes
  (`jadx/sources/com/android/gplay/MainActivity.java:12-21`). App label "Logcat".
- `SDKService`: exported, `directBootAware`, foreground type `dataSync`.
- `BootReceiver`: priority 1000, actions `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED`, `USER_UNLOCKED`,
  `PACKAGE_INSTALL`, `TIME_TICK`. The code acts only on the first three
  (`jadx/sources/com/android/gplay/BootReceiver.java:20-48`); `TIME_TICK` is never delivered to
  manifest receivers.
- androidx `ProfileInstallReceiver` (guarded by `DUMP`) and the startup provider.

With no launcher entry, the first start has to come from outside: another app or a user with
adb starting the exported activity or service (inferred). Until then the boot receiver gets
nothing, since apps that were never started are in the stopped state.

## Network

The Java code makes no connections. The network security config permits cleartext for all
hosts (`apktool/res/xml/network_security_config.xml`). Everything below is in the native binary
`assets/lol`; names come from its decrypted string table (`decrypt/out/strings.txt`, method in
`decrypt/NOTES.md`). No host was contacted or looked up.

- **C2 discovery, method 1:** an ENS `text(bytes32,string)` call (selector `0x59d1d43c`,
  `native/other/lol.c:5825-5830`) for name `burrberry.eth`, key `node`, sent as JSON-RPC
  `eth_call` (`native/other/lol.c:5851`) to resolver `0xf29100983e058b709f3d539b0c765937b804ac15`,
  over HTTPS to the first of 8 public Ethereum RPC hosts that answers (strings 7-14; a ninth,
  `cloudflare-eth.com`, string 15, has no direct decrypt call). The record
  holds IPv4 addresses written as `2001:db8:XXXX:XXXX::1` and scrambled with a fixed key
  (`decrypt/out/data.txt`). The bot picks one, requests `/nodes?key=meowmeowmeow` over a plain TCP socket, without TLS
  (`native/other/lol.c:6061-6072`; the port is in `DAT_00011b90`, not resolved), and takes a random quoted IP from the reply as the C2.
- **Method 2:** the same ENS lookup for `ukranianhorseriding.eth`, key `network`, whose record
  decodes directly to C2 addresses.
- **Method 3:** a Solana Name Service lookup of `24carnforth2merseyside.sol` through
  `sdk-proxy.sns.id` or `sns-sdk-proxy.bonfida.workers.dev`, path `/record-v2/<name>/TXT`, JSON
  key `deserialized`, values split on `|` and decoded the same way.
- **C2 connection:** TCP to the chosen IP on one of 55 ports picked at random
  (`native/other/lol.c:4762-4769`; values in `decrypt/out/data.txt`: 12543, 23098, 34567, ...).
  Fixed 78-byte frames for registration, keepalive, and commands.
- **Local:** a listening socket on `127.0.0.1:7612` as a single-instance lock
  (`decrypt/out/data.txt`).
- The C2 addresses themselves live in the ENS and SNS records and are not in the APK.

## Third-party libraries

| Library | Package prefix | Purpose | Notes |
|---------|----------------|---------|-------|
| AndroidX core, lifecycle, startup, profileinstaller, tracing | `androidx.*`, R8-merged into `defpackage` | framework; `q.A` writes the baseline profile | R8 moved most code into one-letter classes (`triage.txt`) |
| Kotlin stdlib | `kotlin` | | |

Trackers: none (`trackers.txt`). No network library in the Java code (`scan.txt` "Network code
anywhere in sources" is empty): all network activity is in the native binary.

## Data handling

- The Java code reads no user data, identifiers, or files beyond its own asset
  (`scan.txt` "Identifiers", "Storage", "Contacts, SMS, calls" are empty).
- It writes the asset to `files/libandroid_runtime.so` and logs the binary's stdout to logcat
  under tag "Util" (`jadx/sources/defpackage/q.java:585-670`).
- Crypto: none in Java. The native binary encrypts its own string table (see Native code).

## Native code

No `lib/` directory. One ELF outside it (`native-summary.txt`):

| File | Group | What it is | How established |
|------|-------|------------|-----------------|
| `assets/lol` | app-specific | 32-bit ARM executable, 485,060 bytes, static, stripped, SHA-256 `071ff332e77bc80d4e43660d73792af2e73e0442c66d74edfec3740b7691b299`; 184 direct `svc 0` system calls; no RELRO, executable stack, no canary | `native-summary.txt`; Ghidra decompilation `native/other/lol.c` (1441 functions, 0 failed) |

- Entry `0x194` passes `FUN_0000f564` as main (`native/other/lol.c:93`). Ghidra's `@ 0x...`
  header comments are file offsets; the image base is 0x8000 (`decrypt/NOTES.md`).
- Strings: 37 entries encrypted with a custom XOR stream cipher, 24-byte key at file offset
  0x6c040; table set up in `FUN_00012f24`; all 37 decrypted by
  `./cupella run-decryptor.sh` (`decrypt/NOTES.md`, `decrypt/out/strings.txt`).
- Read (decompiled C, by a reader agent and spot-checked): startup, lock, process killers,
  watchdog, C2 discovery, protocol, command parsing and dispatch. Not read: the 19 attack
  handlers, the hash `FUN_00012958` (keccak256, inferred), the TLS library, and most libc code.
- `./cupella native-disasm.py` decoded this ARM-mode binary as Thumb during the run, so
  literal-pool values were read from the file by the decryption script (the script is fixed now).

## Findings

Behavior class: loader for a native DDoS bot. `scan.txt` "Known family markers" matched none of
825 strings (`scan.txt:149-150`); the structure (process killers, single-instance port, attack
table with duration child, `"arm7"` default ID) resembles Mirai-derived bots, which is an
inference from the code, not a family match.

### Loader

1. **Runs a bundled executable on a loop** (T1544, T1623.001). `q.i` copies asset `lol` to
   `files/libandroid_runtime.so`, sets it executable (falling back to `chmod 777`), and runs it
   with argument `play`, logging its output (`jadx/sources/defpackage/q.java:585-670`).
   `q.i` blocks until the binary exits (`jadx/sources/defpackage/q.java:657-666`), and `SDKService`
   reposts it 5 s later on a handler thread (`jadx/sources/defpackage/x0.java:17-27`), so the bot
   is restarted 5 s after each exit. On `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED`, or
   `USER_UNLOCKED`, `BootReceiver` starts `SDKService` at once and also runs `q.i` 15 s later on
   the main thread (`jadx/sources/com/android/gplay/BootReceiver.java:33-48`). Confirmed.
   - Boot path on recent Android (inferred from platform rules): Android 15 does not let apps
     targeting 35+ start a `dataSync` foreground service from `BOOT_COMPLETED`, and the files
     directory is not available before unlock on `LOCKED_BOOT_COMPLETED`.
   - Gate: Android 10 and later deny executing files from an app's data directory for apps
     targeting API 29 or higher; this app targets 37 (`triage.txt`), so the exec likely fails there
     and the bot runs only on Android 9 and older (minSdk 19). The binary is 32-bit ARM, so it also
     needs a device with 32-bit support. Both inferred from platform rules, not tested.
2. **Disguise and staying alive** (T1655, T1541). Package `com.android.gplay`, label "Logcat", no
   launcher entry, task excluded from recents (`apktool/AndroidManifest.xml:22`). A foreground
   service titled "Network Service" / "Running" with a partial wake lock
   (`jadx/sources/com/android/gplay/SDKService.java:231-268`), `onStartCommand` returning
   3 (`START_REDELIVER_INTENT`, `jadx/sources/com/android/gplay/SDKService.java:290-293`), and a prompt to ignore battery
   optimizations (`jadx/sources/com/android/gplay/SDKService.java:214-223`). The first start needs
   an outside trigger (see Components). Confirmed.

### Native bot (`assets/lol`)

3. **C2 found through blockchain name records** (T1102, T1568). Three methods in order: ENS name
   `burrberry.eth` (key `node`) then `GET /nodes?key=meowmeowmeow` on a listed node; ENS name
   `ukranianhorseriding.eth` (key `network`); both ENS methods are skipped if TLS setup fails
   (`native/other/lol.c:5685-5697`); SNS name `24carnforth2merseyside.sol` through two
   HTTPS proxies (see Network; `native/other/lol.c:5851`, `native/other/lol.c:6061`). Addresses in
   the records are disguised as documentation-range IPv6 strings and scrambled with a fixed key
   (`decrypt/out/data.txt`). Confirmed for the code; the record contents are not in the APK.
4. **Command protocol and attack dispatch** (T1464). After a 78-byte registration frame carrying
   the bot ID (`play`, the loader's argument; `arm7` only when none is given,
   `native/other/lol.c:4633-4638`), the bot reads 78-byte command frames with a duration, an attack ID, targets
   (IPv4 and netmask), and options (`native/other/lol.c:680-723`). `FUN_00008aa8` forks the
   attack handler from a table of 19 entries and a second child that kills it when the duration
   ends (`native/other/lol.c:609-654`). Confirmed.
5. **Attack routines.** `FUN_00008da0` registers 19 handlers (`native/other/lol.c:784-821`).
   Strings in the binary include HTTP request templates, cookie headers, and 15 browser
   user-agent strings (`native-summary.txt:57-72`), so at least one routine is an HTTP flood (likely).
   The handlers were not read: the reader assigned to them was stopped by a safety classifier.
6. **Kills competing processes** (T1489). A child walks `/proc` and kills `login`
   (`native/other/lol.c:4065-4068`); a netlink process-connector listener (`native/other/lol.c:4078`)
   kills on exec any process named `login`, `nc`, `netcat`, `ftp`, `echo`, `tftp`, or whose exe, name, or busybox applet is in
   `wget|curl|tftp|mount|ftpget|telnet|socat|sh|cp|cat|mv|grep|ps|reboot|kill`
   (`native/other/lol.c:4351`, `decrypt/out/strings.txt`); a watchdog looks at statically linked
   executables outside a skip list of system directories and kills those with more than 5 sockets
   or a start time above 30000 clock ticks (`native/other/lol.c:3451-3511`,
   `native/other/lol.c:3582-3593`); `FUN_00013238` kills whatever holds the lock
   port via `/proc/net/tcp` (`native/other/lol.c:7146`). Confirmed for the code. On Android an app
   can signal only processes of its own UID, so these mostly fail there (inferred); they target
   embedded Linux, as the skip list of directories (`/mnt/mtd/app/`, `/dvr/bin/`, `/system/`) suggests.
7. **Self-protection** (T1564). Renames its process to `libc.so` with `prctl(PR_SET_NAME)` and
   clears its argv (`native/other/lol.c:4612-4621`); writes `-1000` to `/proc/self/oom_score_adj`
   or `-17` to `/proc/self/oom_adj` (lowering these needs privileges an app lacks: inert on
   Android, inferred); prints "Are the chicken and the melon tasty enough" at start.
   Confirmed.
8. **Unused firewall strings.** The table holds `iptables -F`, rules dropping port 2625, and an
   accept-rule template (`decrypt/out/strings.txt`, entries 29-34). No direct decrypt call for
   these entries was found in `native/other/lol.c`, and `iptables` needs root. Present but
   apparently unused (likely).

## Indicators

| Type | Value | Source |
|------|-------|--------|
| SHA-256 APK | `23282313ee3edb3443ae8c0296b9b6ddf52501983093fd289f46d99e7d180402` | `triage.txt` |
| SHA-256 `assets/lol` | `071ff332e77bc80d4e43660d73792af2e73e0442c66d74edfec3740b7691b299` | `native-summary.txt` |
| Signer SHA-256 | `3918c790399995f2e76eeb69507cb2e753c080d216d804c585cdc35f0325e7f0` (self-signed) | `triage.txt` |
| Package, label | `com.android.gplay`, "Logcat" | `triage.txt`, `apktool/AndroidManifest.xml` |
| Dropped file | `files/libandroid_runtime.so`, argument `play`, process name `libc.so` | `jadx/sources/defpackage/q.java:585`, `decrypt/out/strings.txt` |
| ENS names | `burrberry.eth` (key `node`), `ukranianhorseriding.eth` (key `network`) | `decrypt/out/strings.txt` |
| SNS name | `24carnforth2merseyside.sol` | `decrypt/out/strings.txt` |
| ENS resolver | `0xf29100983e058b709f3d539b0c765937b804ac15` | `decrypt/out/strings.txt` |
| Node query | `/nodes?key=meowmeowmeow` | `native/other/lol.c:6061`, `decrypt/out/strings.txt` |
| RPC and proxy hosts (public services the bot uses) | `public-eth.nownodes.io`, `ethereum.publicnode.com`, `ethereum-rpc.publicnode.com`, `eth-mainnet.public.blastapi.io`, `eth.drpc.org`, `rpc.mevblocker.io`, `eth-protect.rpc.blxrbdn.com`, `1rpc.io`, `cloudflare-eth.com`, `sdk-proxy.sns.id`, `sns-sdk-proxy.bonfida.workers.dev` | `decrypt/out/strings.txt` |
| C2 ports | 55 values, starting 12543, 23098, 34567, 45012, 56789 | `decrypt/out/data.txt` |
| Local lock | `127.0.0.1:7612` | `decrypt/out/data.txt` |
| Startup line | "Are the chicken and the melon tasty enough", logged under tag `Util` as `binary: ...` | `decrypt/out/strings.txt`, `jadx/sources/defpackage/q.java:668` |
| Notification | channel `network_sync_channel`, title "Network Service", text "Running" | `jadx/sources/com/android/gplay/SDKService.java:51-58`, `jadx/sources/com/android/gplay/SDKService.java:236` |
| String key | `dec0a7f12f5e3d9b1d8b4a7cb4f9e6a29a7e3f5de7d4b1c8` | `decrypt/NOTES.md` |

## Open questions

- The C2 addresses: they are in the ENS and SNS records, not in the APK. Resolving them means
  contacting the blockchain services, which this analysis does not do.
- The node-query port (`DAT_00011b90`) and the TLS library linked into `assets/lol` were not
  resolved.
- What each of the 19 attack handlers sends (`FUN_00008da0` table); not read.
- Whether the exec in Finding 1 succeeds on any current Android device; needs a device.
- What starts the app the first time (no launcher entry); likely a separate dropper or manual
  install with adb.
- Whether entries 15 and 29-34 of the string table are used through a computed index.

## Method changes

- `scripts/unpack.sh`: `-f` now keeps `work/<name>/progress/` as well as `decrypt/`; it had deleted
  this run's progress log. AGENTS.md and the workflow doc updated. Not gated (no change
  to scan output).
- `scripts/native-disasm.py`: it decoded this binary's 32-bit ARM-mode code as Thumb. It now
  takes the mode from function symbols, else the ELF entry bit, else the share of code words
  with condition AL, and prints the choice per function. Checked on `assets/lol` (ARM, from the
  entry bit) and on the 457ff62c sample's armeabi-v7a library (Thumb, from symbols). Not gated
  (no change to scan output).
