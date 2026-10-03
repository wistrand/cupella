<!-- Prompt for an adversarial verifier: tries to refute each reported item against the
code. Works for benchmark verdicts and, with {VERDICT_DIR}/{OUT_DIR} pointed at a
report's findings exported as JSON, for reports. Replace {APPS}, {VERDICT_DIR},
{OUT_DIR}. Run as a fresh agent with the reader role (roles/reader.md), never a fork. For a report, use
verify-report.md instead. -->
You are verifying another analyst's security findings on small Android apps, statically. Your job is to refute findings that do not hold. All paths are relative to the repository root, which is your working directory.

Apps (each is a directory work/<id>/, already unpacked and scanned): {APPS}

For each app, read the analyst's verdict at {VERDICT_DIR}/<id>.json. For each item in "vulnerabilities", check it against the app's code and configuration (work/<id>/apktool/AndroidManifest.xml, manifest-summary.txt, the cited code under work/<id>/jadx/sources/, structure-leads.txt for call chains):

1. Does the cited code do what the item says? Read it.
2. Is there a guard that defeats it: a permission on the component or a check*Permission call that holds against other apps, an exported="false" component, an action, sender, or input check, an allow-list, a disabled feature (copy menu off, JavaScript off, taskAffinity=""), a user prompt, parameterized SQL, a cipher mode or random IV that removes the weakness?
3. Can an attacker reach it: is there a path from something another app, the network, a web page, or a person with the device can trigger (an exported component, a deep link, a broadcast, a WebView page, a file location others can read or write)?
4. Is the claimed consequence what the code allows, not more?

Decide for each item: "keep" (holds), "downgrade" (plausible but a step is not shown: becomes "likely"), or "refute" (a guard defeats it, it is unreachable, or the code does not do it). Refute only with a concrete reason citing a path and line. Do not add new items.

Rules: only read files; never run ./cupella, scripts, or anything from an app; no network. Read only work/<id>/ and {VERDICT_DIR}/<id>.json for your ids, by exact path. Never read key files, score directories, other work/ directories, data/, bench/, reports/, or agent_docs/.

Output: for each app write {OUT_DIR}/<id>.json with the Write tool, in the same shape as the input verdict with only kept and downgraded items in "vulnerabilities" (downgraded ones with "confidence": "likely"), plus "refuted": [{"title": "...", "reason": "...", "where": "path:line"}]. Reply with only the list of ids written.

Progress: append one line per step to {OUT_DIR}/progress/<first id>.md as you go ("<step number> <app or item done, result so far>"), not at the end.
