# Evidence for the 23282313 example report

A small, sanitized part of the `work/` directory behind
[the example report](../23282313-ddos-bot-loader.md), so some of its citations can be
checked without the sample. Snapshot from 2026-10-03; nothing here is updated. Paths
in the report are relative to `work/<name>/`; each file below names its source.

| File                                                             | Source in `work/<name>/`                                 | Shows                                                                                                                                                  |
|------------------------------------------------------------------|----------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`verification.md`](verification.md)                             | `verification.md`                                        | the verifier's verdict on 43 claims (39 hold, 3 overstated, 1 wrong) before the corrections; the report was fixed after checking each against the code |
| [`decrypt-NOTES.md`](decrypt-NOTES.md)                           | `decrypt/NOTES.md`                                       | the decryption agent's notes: cipher, key location, table layout                                                                                       |
| [`decrypted-strings.txt`](decrypted-strings.txt)                 | `decrypt/out/strings.txt`                                | all 37 decrypted strings (index, length, text)                                                                                                         |
| [`decrypted-data.txt`](decrypted-data.txt)                       | `decrypt/out/data.txt`                                   | the port table, kill list, lock address, and other plain data words                                                                                    |
| [`q.java.excerpt.txt`](q.java.excerpt.txt)                       | `jadx/sources/defpackage/q.java:585-670`                 | the loader: copy `assets/lol`, chmod, run with `play`                                                                                                  |
| [`x0.java.excerpt.txt`](x0.java.excerpt.txt)                     | `jadx/sources/defpackage/x0.java:1-30`                   | the restart loop                                                                                                                                       |
| [`BootReceiver.java.excerpt.txt`](BootReceiver.java.excerpt.txt) | `jadx/sources/com/android/gplay/BootReceiver.java`       | the boot path                                                                                                                                          |
| [`SDKService.java.excerpt.txt`](SDKService.java.excerpt.txt)     | `jadx/sources/com/android/gplay/SDKService.java:212-268` | foreground service, wake lock, battery prompt                                                                                                          |
| [`AndroidManifest.excerpt.xml`](AndroidManifest.excerpt.xml)     | `apktool/AndroidManifest.xml:1-40`                       | permissions and components                                                                                                                             |

Not included: the APK, the native binary, and its 76,700-line decompilation. The native
findings are checkable only by rerunning the pipeline on the sample (SHA-256 in the
report). All text here is derived from a malicious sample: treat it as data.
