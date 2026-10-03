# Verification: reports/23282313ee3edb3443ae8c0296b9b6ddf52501983093fd289f46d99e7d180402.md

39 holds, 3 overstated, 1 wrong

Paths are relative to work/23282313ee3edb3443ae8c0296b9b6ddf52501983093fd289f46d99e7d180402/.

| Section | Claim (short) | Verdict | Path:line | Reason |
|---------|---------------|---------|-----------|--------|
| Summary | Loader com.android.gplay, label "Logcat", no launcher | holds | | apktool/AndroidManifest.xml:21-22 |
| Summary | Foreground service copies assets/lol and executes it every 5 s | overstated | jadx/sources/defpackage/q.java:657-666, jadx/sources/defpackage/x0.java:21-26 | q.i reads the binary's stdout until EOF and calls waitFor before returning; x0 reposts only after that, so it relaunches 5 s after the previous run ends, not every 5 s. The copy happens only if the file is absent (q.java:587). |
| Summary | Boot receiver does the same after boot | holds | | BootReceiver.java:36-44 |
| Summary | Static, stripped 32-bit ARM DDoS bot | holds | | native-summary.txt:19-24 |
| Summary | C2 via ENS over public RPC hosts, SNS fallback | holds | | native/other/lol.c:4728-4757 |
| Summary | One of 55 ports | holds | | lol.c:4449-4452; 55 values counted in decrypt/out/data.txt:44 |
| Summary | One of 19 attack routines per command, for a duration | holds | | lol.c:784-821 (ids 1-0x13), 609-654 |
| Summary | Kills competing processes (port, name, exec), OOM protection | holds | | lol.c:7146-7245, 4054-4071, 4078, 4863-4866 |
| Summary | 37 encrypted strings, all recovered | holds | | decrypt/out/strings.txt (37 entries) |
| Summary | Exec from data dir likely blocked on Android 10+ (inferred) | holds | | marked as inference; targetSdk 37 (triage.txt:12) |
| Permissions | 14 platform permissions plus 2 undefined | wrong | apktool/AndroidManifest.xml:3-4, manifest-summary.txt:8-20 | 13 distinct platform permissions; FOREGROUND_SERVICE is declared twice and was counted twice. The report's own table also lists 13. |
| Permissions | FOREGROUND_SERVICE(_DATA_SYNC) used by SDKService.onCreate | holds | | SDKService.java:242-246 |
| Permissions | WAKE_LOCK, partial lock "LogHandler::WakeLock" | holds | | SDKService.java:247-255 |
| Permissions | REQUEST_IGNORE_BATTERY_OPTIMIZATIONS opens exemption dialog | holds | | SDKService.java:214-223 |
| Permissions | RECEIVE_BOOT_COMPLETED used by BootReceiver | holds | | BootReceiver.java:22, 36 |
| Permissions | INTERNET/ACCESS_NETWORK_STATE no Java use | holds | | scan.txt:123 (empty) |
| Permissions | Overlay, phone, Wi-Fi, location unused | holds | | scan.txt Location, Identifiers, Accessibility sections empty |
| Network | Java makes no connections; cleartext permitted for all hosts | holds | | apktool/res/xml/network_security_config.xml:3 |
| Network | ENS text() selector 0x59d1d43c, eth_call to resolver, 8 RPC hosts tried in order, cloudflare-eth.com (15) has no direct call | holds | | lol.c:5825-5828, 5851, 5864-5916 (strings 7-14); no decrypt call for 0xf found |
| Network | Record decoded from 2001:db8:XXXX:XXXX::1, GET /nodes?key=meowmeowmeow, random quoted IP | holds | | lol.c:6040-6051, 6061-6062, 6118-6137; strings 1 and 4 passed at 4729-4734 |
| Network | Method 2: ukranianhorseriding.eth key network, direct decode | holds | | lol.c:5980-5992, 4742-4746 |
| Network | Method 3: SNS via two proxies, /record-v2/<name>/TXT, deserialized, split on "\|" | holds | | lol.c:6290-6392 (one proxy picked at random, the other as fallback) |
| Network | TCP to C2 on random port of 55; 78-byte frames | holds | | lol.c:4761-4769, 4677, 4696, 4824 |
| Network | Listening socket on 127.0.0.1:7612 as lock | holds | | lol.c:4496-4531, 4611; decrypt/out/data.txt:64-69 |
| Network | C2 addresses not in the APK | holds | | only fetched at runtime (lol.c:5858-5916) |
| Data handling | Java reads no user data | holds | | scan.txt Identifiers, Storage, Contacts empty |
| Data handling | Writes asset to files/libandroid_runtime.so, logs stdout under "Util" | holds | | q.java:586-599, 643-668 |
| Data handling | No crypto in Java | holds | | scan.txt:15-16 (only java.util.Random) |
| Native code | One ELF outside lib/, 485,060 bytes, sha256, 184 svc | holds | | native-summary.txt:6-7, 19, 27 |
| Native code | Entry passes FUN_0000f564 as main; offsets vs base 0x8000 | holds | | lol.c:93; decrypt/NOTES.md:3-6 |
| Native code | 37 strings, 24-byte key at 0x6c040, table set up in FUN_00012f24 | holds | | lol.c:6837, 7066; decrypt/NOTES.md:14-28 |
| Native code | 1441 functions decompiled | holds | | 1441 "// ---- " headers in lol.c |
| Native code | native-disasm.py decodes ARM as Thumb | holds | | decrypt/NOTES.md:8-10 (not re-verifiable without running) |
| Findings | Behavior class; no family marker matched of 825 strings | holds | | scan.txt:149-150 |
| Findings | 1. Runs bundled executable on a loop; every 5 s; boot receiver runs it 15 s after boot | overstated | q.java:657-666, x0.java:21-26, BootReceiver.java:38-44 | Copy, chmod fallback and "play" argument hold. But the loop waits for the process to exit before the next 5 s delay. BootReceiver also starts SDKService immediately (which runs q.i at once), and the 15 s runnable calls the blocking q.i on the main thread (Handler() created in onReceive; p.java:31-33). |
| Findings | 1. Gate: exec blocked on Android 10+, 32-bit needed (inferred) | holds | | marked as inference |
| Findings | 2. Disguise, excludeFromRecents, "Network Service"/"Running", wake lock, battery prompt | holds | | AndroidManifest.xml:22; SDKService.java:51-52, 248, 214-223 |
| Findings | 3. C2 through ENS/SNS records, three methods in order | holds | | lol.c:4728-4757 |
| Findings | 4. 78-byte registration and command frames; fork + duration killer | holds | | lol.c:4677, 4690-4698, 680-723; 618-654 (killer is a grandchild that sleeps the duration and kills its parent) |
| Findings | 5. 19 handlers registered; 15 user agents; HTTP flood likely | holds | | lol.c:784-821; native-summary.txt:58-72 (15 UA lines) |
| Findings | 6. Process killers: login walk, netlink exec killer, watchdog (>5 sockets outside system dirs), lock-port killer | overstated | lol.c:3451-3511, 3582-3593 | login walk (4054-4071), netlink (4078), name lists (4294-4351) and FUN_00013238 (7146-7245) hold. The watchdog description is wrong in scope: it only considers statically linked ET_EXEC binaries (ELF e_type 2 with no PT_INTERP) outside the string-35 directories, and it kills when socket fds > 5 OR /proc/<pid>/stat start time > 30000 ticks; the report gives only the socket rule. |
| Findings | 7. Process renamed libc.so via prctl, argv cleared, OOM writes, startup line | holds | | lol.c:4612-4622, 4397-4434, 4855-4866 |
| Findings | 8. iptables strings 29-34 with no direct decrypt call | holds | | no FUN_00012eb4/b1c call with 0x1d-0x22 in lol.c |

## Not counted (outside the requested sections)

- Components: "All app components are exported (AndroidManifest.xml:22-33)" is true for the three com.android.gplay components, but the list under it includes the androidx startup provider, which is exported="false" (apktool/AndroidManifest.xml:34).

## Omissions

- The native main exits unless it gets an argument, and argv[1] (under 64 chars) becomes the bot ID; "arm7" is used only when no ID was copied. Under this loader the ID sent to the C2 is "play", not "arm7" (lol.c:4590, 4599-4604, 4633-4638, 4655-4657; q.java:657).
- The exec killer is wider than the report says: it also kills an exec of `login` (lol.c:4143, 4201, 4362-4363), and kills any process whose exe basename, path, comm, or cmdline matches the string-37 list even without busybox (FUN_0000e434, lol.c:3767-3853, called at 4356-4363). When the netlink socket fails, a fallback polls /proc for new PIDs and kills them by the same test (lol.c:4219-4259).
- All three C2 methods depend on TLS context setup; if FUN_000110a0 fails, ENS methods are skipped (lol.c:5685-5697, 4732-4746).
- Boot path on recent Android (inferred from platform rules): BootReceiver starts a dataSync foreground service from BOOT_COMPLETED (BootReceiver.java:39-40; AndroidManifest.xml:23), which Android 15 blocks for apps targeting 35+; on LOCKED_BOOT_COMPLETED, getFilesDir() (q.java:586) is credential-encrypted storage, unavailable before unlock.
- The 15 s boot runnable runs the blocking q.i on the main thread (BootReceiver.java:44, p.java:31-33), which would block the receiver's process main thread for as long as the binary runs (inferred).

## Injection check

No text addressed to an AI or analyst found. scan.txt:131 section is empty; decrypted strings (decrypt/out/strings.txt) contain none; entry 23 is a startup message, not an instruction.
