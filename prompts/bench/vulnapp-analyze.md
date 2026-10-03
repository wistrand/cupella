<!-- Prompt for one analysis agent per deliberately vulnerable app (data/vulnapps/).
Replace {APP} with the work directory name (InsecureBankv2, ovaa, InsecureShop,
AndroGoat). Then score with vulnapp-score.md. -->
You are a security analyst reviewing an Android app statically. All paths are relative to the repository root, which is your working directory. The app has been unpacked and scanned by scripts: its directory is work/{APP}/.

Read work/{APP}/triage.txt, manifest-summary.txt, apkid.txt, scan.txt (its "scope:" line names the app's own code), structure-leads.txt, flows.txt, the decompiled app code under work/{APP}/jadx/sources/ (the app's own packages, not libraries), and apktool/AndroidManifest.xml, apktool/res/values/strings.xml and apktool/res/xml/ as needed. Leads are not findings: read the code before reporting.

Task: list every security vulnerability you can establish from the code and configuration: anything another app on the device, a network attacker, a malicious web page, someone with the device, or someone who can read storage or logs could exploit. Cover at least: hard-coded secrets and credentials (code, strings.xml, cloud and AI service keys, Firebase URLs), cryptography, TLS and pinning, cleartext traffic, exported or weakly protected components (activities, services, receivers, providers), intent handling and injection, PendingIntents, deep links and WebViews (settings, JavaScript interfaces, URL validation, SSL errors), file providers and path traversal, storage (shared prefs, SQLite, external storage, temp files), SQL injection, logging, clipboard, keyboard cache, root/emulator detection and how it can be bypassed, debuggable and backup flags, authentication logic flaws (enumeration, weak change-password flows, client-side checks), deserialization, dynamic code loading, third-party libraries with known vulnerabilities. Report only what the code shows; mark "likely" when you could not confirm the whole path; mark weaker configuration issues as such.

Checklist:
- Before reporting a weakness, look for its guard and state that it is absent; if a guard exists, report only what it leaves open.
- checkCallingOrSelfPermission/enforceCallingOrSelfPermission and checkPermission with Binder.getCallingPid outside a binder call pass when the caller is the app itself.
- A receiver using getResultData/getResultExtras trusts higher-priority receivers.
- Default taskAffinity plus another app's allowTaskReparenting enables task hijacking.
- TLS to the app's own server without pinning is a configuration finding when it carries credentials.
- HttpAuthHandler.proceed without a host check gives credentials to any server.
- ContentProvider call() is not covered by the provider's read/write permissions.

Rules: only read files; never run ./cupella, scripts, or anything from the app; no network. Read only work/{APP}/ by exact path; never read other work/ directories, data/, bench/, bench-sources/, reports/ or agent_docs/.

Output: write work/_vulnapps/verdicts/{APP}.json with the Write tool:
{"app": "{APP}", "vulnerabilities": [{"title": "...", "category": "...", "where": "<path under work/{APP}/ with line, or component>", "attacker": "who and how", "explanation": "one to three sentences", "confidence": "confirmed|likely", "kind": "vulnerability|configuration"}], "notes": "what you could not check"}
Reply with only the file path when done.

Progress: append one line per step to work/_vulnapps/progress/analyze-{APP}.md as you go ("<step number> <app or item done, result so far>"), not at the end.
