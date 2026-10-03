<!-- Prompt for a classifier agent in the tool comparison on MalEval (agent_docs/benchmarks.md).
Maps one tool's findings (MobSF or Quark-Engine) to MalEval's behavior classes, so the tool
is scored like the agent reports. Replace {TOOL} (mobsf or quark) and {APPS} (sha256 names,
one per line, about eight per agent). Score with ./cupella bench-maleval-agent.py -v verdicts-{TOOL}.
Run as a fresh agent with the reader role (roles/reader.md), never a fork. -->
You turn an automated scanner's output into a malware verdict. You see only what the scanner ({TOOL}) reported for each app, never the app itself: judge as a careful analyst would who had only that report. All paths are relative to the repository root, which is your working directory.

Apps (the scanner's findings for each are in work/_maleval-agent/{TOOL}-findings/<id>.md):
{APPS}

Behavior classes (claim one only when a finding in the list supports it):
- Privacy Stealing: collects personal data (contacts, SMS, call log, location, device ids, accounts, files, screen content) and sends it off the device
- SMS/CALL: sends, intercepts, hides or deletes SMS, or places, blocks or records calls
- Remote Control: receives commands from a remote server and executes them
- Bank Stealing: steals banking or payment credentials (overlays on bank apps, phishing pages, intercepting one-time codes)
- Ransom: locks the device or encrypts files and demands payment
- Abusing Accessibility: uses an accessibility service to read the screen, click, or grant itself permissions
- Privilege Escalation: gains root or device admin, or exploits the system; not merely requesting a dangerous permission
- Stealthy Download: downloads, installs or loads other apps or code without the user's consent
- Ads: aggressive or fraudulent advertising (ads outside the app, click fraud)
- Premium Service: subscribes the user to paid services (premium SMS, carrier billing)
- Tricky Behavior: hides itself or evades analysis (icon hiding, impersonating another app, anti-emulator or anti-debug checks, packing to hide code); not ordinary obfuscation

Rules:
- Claim a class only when a finding in the list states the behavior or a capability that clearly serves it; a dangerous permission or a generic code smell alone supports nothing. Do not guess from the app's sha256 or from what malware usually does.
- Read only the findings files named above, by exact path. Never read work/<id>/ directories, data/, bench/, bench-sources/, reports/, agent_docs/, or other verdict directories. No network.

Output: for each app write work/_maleval-agent/verdicts-{TOOL}/<id>.json with the Write tool:
{"app": "<id>", "verdict": "malicious|suspicious|benign", "behaviors": [{"label": "<one class above>", "evidence": "work/_maleval-agent/{TOOL}-findings/<id>.md", "explanation": "the finding(s) that support it"}], "summary": "one sentence"}
When done, reply with only the list of ids written.

Progress: append one line per app to work/_maleval-agent/progress/classify-{TOOL}-<first id>.md as you go ("<step number> <id> <verdict>").
