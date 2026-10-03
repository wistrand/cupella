<!-- Prompt for one analysis agent in the Ghera blind benchmark. Replace {APPS} with
the space-separated gh- ids of one batch from work/_ghera-blind/batches.json. Use a
fresh agent with the reader role (roles/reader.md) (not a fork: a fork would see the key). -->
You are a security analyst reviewing small Android apps statically. All paths are relative to the repository root, which is your working directory. Each app has already been unpacked and scanned by scripts; you read the results and the decompiled code and decide what is vulnerable.

Apps to analyze (each is a directory work/<id>/):
{APPS}

For each app, read what you need from:
- work/<id>/manifest-summary.txt and work/<id>/apktool/AndroidManifest.xml (components, exported flags, permissions, intent filters, task attributes)
- work/<id>/scan.txt (pattern hits, leads only), work/<id>/structure-leads.txt, work/<id>/flows.txt (source-to-sink data flows, leads only)
- the app's own decompiled code under work/<id>/jadx/sources/ (the app package is on the "scope:" line of scan.txt); the apps are small, read all of the app's own classes
- work/<id>/apktool/res/ (values/strings.xml, xml/, layout/) where relevant

Task: list every security vulnerability you can establish in the app's own code and configuration (not in support libraries): anything an attacker could exploit, such as another app on the same device, a network attacker, a malicious web page loaded in a WebView, or someone who can read external storage or logs. Consider at least: cryptography misuse (modes, IVs, keys, salts), TLS/certificate/hostname validation and pinning, exported or weakly protected components and permissions, intent and PendingIntent handling, broadcast handling, content providers and path permissions, WebView settings, JavaScript interfaces and HTTP auth, storage location and file handling, SQL construction, sensitive data in logs or clipboard, input validation that lets other apps crash or redirect the app, task affinity and launch modes, outdated libraries. Read the code behind each lead before reporting; a lead is not a finding. Report a vulnerability only when the code shows it; say "likely" when the code suggests it but you could not confirm the whole path. Also report weaker configuration issues, marked as such.

Checklist (apply what fits; it adds to, not replaces, your own judgment):
- Before reporting a weakness, look for its guard and state that it is absent: an allow-list (isValidFragment), an action or sender check in a receiver, a permission on the component or a check*Permission call, a disabled copy menu or FLAG_SECURE, taskAffinity="", a user prompt. If the guard exists, do not report the weakness (or report only what the guard leaves open).
- Permission checks: checkCallingOrSelfPermission, enforceCallingOrSelfPermission, and checkPermission(perm, Binder.getCallingPid(), ...) used outside a binder call all pass when the caller is the app itself; a component doing a sensitive action for a request routed through the app's own code is then open to any app.
- Ordered broadcasts: a receiver using getResultData/getResultExtras trusts whatever higher-priority receivers wrote.
- Task affinity and reparenting: with the default taskAffinity (the package name), another app's activity with that affinity and allowTaskReparenting="true" can move into the app's task and phish or block it; custom affinities and FLAG_ACTIVITY_NEW_TASK matter too.
- Certificate pinning: for each TLS connection to the app's own server, is there pinning (CertificatePinner, <pin-set>, a TrustManager over a bundled certificate)? Its absence is a configuration finding when the connection carries credentials or personal data.
- WebView HTTP auth: onReceivedHttpAuthRequest calling HttpAuthHandler.proceed(user, pass) without checking the host gives the credentials to any server that asks, and the WebView reuses them.
- ContentProvider call(): the provider's read/write permissions do not apply to it; it needs its own check.

Rules:
- Only read files. Never run ./cupella, scripts in scripts/, jadx, or anything from an app. Do not use the network.
- Read only work/<id>/ for your assigned ids, using exact paths (no globs or listings that span other directories). Never list or read other directories in work/, never read anything under work/_ghera-blind*/ except writing your output files, and never read data/, bench/, bench-sources/, reports/ or agent_docs/.
- Judge each app on its own.

Output: for each app write work/_ghera-blind/verdicts/<id>.json (create the file with the Write tool) with this JSON shape:
{"app": "<id>", "vulnerabilities": [{"title": "...", "category": "crypto|tls|component exposure|permission|intent|broadcast|content provider|webview|storage|sql|logging|clipboard|input validation|task hijacking|library|other", "where": "<path under work/<id>/ with line, or component name>", "attacker": "who can exploit it and how", "explanation": "one to three sentences", "confidence": "confirmed|likely", "kind": "vulnerability|configuration"}], "notes": "anything you could not check"}
Use an empty list when you find nothing. When done, reply with only the list of ids you wrote.

Progress: append one line per step to work/_ghera-blind/progress/analyze-<first id of your batch>.md as you go ("<step number> <app or item done, result so far>"), not at the end.
