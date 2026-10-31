# Runbook: vulnerability checklist

Read when the request is a security review (workflow.md request table), or a finding
looks like a weakness rather than a behavior. The rest of the analysis follows
[runbook-analysis.md](runbook-analysis.md); stage order and checkpoints are in
[workflow.md](workflow.md).

For apps where security weaknesses matter (not only behavior), check each item that
applies and say in the report which were checked. From the Ghera benchmark, where the
agent missed these or reported fixed apps as vulnerable:

- Before reporting a weakness, look for its guard and name it as absent: an
  allow-list (`isValidFragment`), an action or sender check in a receiver, a permission
  on the component or a `check*Permission` call, a disabled copy menu or `FLAG_SECURE`,
  `taskAffinity=""`, a user prompt. Most false reports on Ghera's fixed apps missed a
  guard that was there.
- Permission checks: `checkCallingOrSelfPermission`, `enforceCallingOrSelfPermission`,
  and `checkPermission(perm, Binder.getCallingPid(), ...)` outside a binder call all
  pass when the caller is the app itself. A component that does a sensitive action on
  behalf of a request routed through the app's own code is open to any app.
- Ordered broadcasts: a receiver that uses `getResultData`/`getResultExtras` trusts
  whatever higher-priority receivers wrote. Note whose data it acts on.
- Task affinity and reparenting: with the default `taskAffinity` (the package name),
  another app's activity with that affinity and `allowTaskReparenting="true"` can move
  into the app's task and phish or block it. Check `manifest-summary.txt` "Activity task
  attributes" and the app's own affinities; report as a configuration risk with the
  platform caveat (behavior depends on Android version).
- Pinning: for each TLS connection to the app's own server, is there pinning
  (`CertificatePinner`, `<pin-set>` in network security config, a TrustManager over a
  bundled certificate)? Its absence is a configuration finding when the connection
  carries credentials or personal data; the "Pinning" section of `scan.txt` lists the
  candidates.
- WebView HTTP authentication: `onReceivedHttpAuthRequest` calling
  `HttpAuthHandler.proceed(user, pass)` without checking the host sends the credentials
  to any server that asks; the WebView then reuses them for later requests.
- ContentProvider `call()`: the provider's read and write permissions do not apply to
  it; it needs its own check.
