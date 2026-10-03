#!/usr/bin/env python3
"""Summarize a Flutter app from its Dart AOT snapshot (libapp.so) and bundled assets.

The app's logic is compiled Dart, which jadx does not see and which the native
disassembler shows only as raw code. This script reads what the snapshot's string
data exposes: the Dart packages linked in, the app's own source files, URLs and hosts,
platform channel names, API paths, and credential-shaped strings. Strings show what
the code can refer to, not what it does. Static: nothing is executed.

Usage: scripts/flutter-summary.py <name> > work/<name>/flutter-summary.txt
"""
import json
import os
import re
import subprocess
import sys

ABI_ORDER = ["arm64-v8a", "armeabi-v7a", "x86_64"]

# Dart package -> what its presence means. Only packages that matter for an analysis.
PACKAGE_NOTES = {
  "http": "HTTP client", "dio": "HTTP client", "web_socket_channel": "WebSocket client",
  "grpc": "gRPC client", "graphql": "GraphQL client", "chopper": "HTTP client", "retrofit": "HTTP client",
  "firebase_core": "Firebase", "firebase_analytics": "Firebase Analytics (telemetry)",
  "firebase_crashlytics": "Crashlytics (crash reporting)", "firebase_messaging": "FCM push",
  "firebase_auth": "Firebase Auth", "cloud_firestore": "Firestore", "firebase_remote_config": "remote config",
  "sentry": "Sentry (crash reporting)", "sentry_flutter": "Sentry (crash reporting)",
  "google_mobile_ads": "AdMob (advertising)", "facebook_app_events": "Facebook SDK (telemetry)",
  "amplitude_flutter": "Amplitude (telemetry)", "mixpanel_flutter": "Mixpanel (telemetry)",
  "posthog_flutter": "PostHog (telemetry)", "appsflyer_sdk": "AppsFlyer (attribution)",
  "onesignal_flutter": "OneSignal push", "in_app_purchase": "in-app purchases",
  "purchases_flutter": "RevenueCat purchases",
  "shared_preferences": "key-value storage", "flutter_secure_storage": "keystore-backed storage",
  "sqflite": "SQLite", "hive": "Hive database", "isar": "Isar database", "drift": "SQLite (drift)",
  "path_provider": "app directories", "file_picker": "file picker", "image_picker": "camera/gallery picker",
  "camera": "camera", "record": "microphone recording", "speech_to_text": "speech recognition",
  "geolocator": "location", "location": "location", "contacts_service": "contacts",
  "flutter_contacts": "contacts", "telephony": "SMS/phone", "device_info_plus": "device model and OS info",
  "package_info_plus": "own package info", "android_id": "ANDROID_ID", "advertising_id": "advertising id",
  "network_info_plus": "Wi-Fi name/IP info", "connectivity_plus": "connectivity state",
  "lan_scanner": "local network host scan", "dart_ping": "ICMP ping", "nsd": "mDNS discovery",
  "multicast_dns": "mDNS discovery", "permission_handler": "runtime permissions",
  "url_launcher": "opens URLs in other apps", "webview_flutter": "WebView",
  "flutter_inappwebview": "WebView", "receive_sharing_intent": "receives shared content",
  "share_plus": "shares content out", "local_auth": "biometric auth", "crypto": "hashes/HMAC",
  "encrypt": "AES/RSA encryption", "pointycastle": "crypto primitives", "cryptography": "crypto primitives",
  "ffi": "calls native libraries directly", "archive": "zip/tar handling",
  "flutter_background_service": "background service", "workmanager": "background work",
  "openai_dart": "OpenAI API client", "anthropic_sdk_dart": "Anthropic API client",
  "mistralai_dart": "Mistral API client", "ollama_dart": "Ollama API client",
  "googleai_dart": "Google AI API client", "google_generative_ai": "Google AI API client",
}

URL = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>\\]{3,}")
HOST = re.compile(r"^(?:[a-z0-9-]+\.)+(?:com|org|net|io|ai|dev|app|co|cloud|xyz|me|info|de|uk|cn|ru)(?::\d+)?(?:/[^\s]*)?$")
CHANNEL = re.compile(r"^(?:plugins\.flutter\.io|dev\.fluttercommunity\.[\w.]+|flutter|[a-z][\w]*(?:\.[a-z][\w]*){1,4})/[\w./-]+$")
API_PATH = re.compile(r"^/(?:v\d+|api|rest|graphql|oauth|auth|chat|models|messages|completions|embeddings)[\w/{}.:-]*$")
CRED = re.compile(r"api[_-]?key|secret|token|bearer|authorization|x-api-key|password|passwd|credential|client[_-]?id", re.I)
KEY_SHAPED = re.compile(r"^(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{30,}|"
                        r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}.*|-----BEGIN [A-Z ]+-----)")
DART_URI = re.compile(r"package:([A-Za-z0-9_]+)/([\w./-]+\.dart)")
SQL = re.compile(r"^(?:SELECT .+ FROM |INSERT (?:OR \w+ )?INTO |UPDATE \w+ SET |DELETE FROM |CREATE (?:TABLE|INDEX) |PRAGMA )")
NOISE_URL = re.compile(r"schemas\.android\.com|www\.w3\.org|flutter\.dev|dart\.dev|dartbug\.com|github\.com/(?:flutter|dart-lang)|"
                       r"api\.flutter\.dev|pub\.dev|example\.com|goo\.gl/|g\.co/|material\.io|unicode\.org|ietf\.org|"
                       r"developer\.(?:android|apple|mozilla)|stackoverflow\.com|creativecommons|apache\.org|"
                       r"opensource\.org|mozilla\.org|purl\.org|xml\.org|adobe\.com|iptc\.org")


def all_strings(path, minlen=4):
  with open(path, "rb") as f:
    buf = f.read()
  out = set()
  for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, buf):
    out.add(m.group().decode("ascii"))
  for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, buf):
    out.add(m.group().decode("utf-16-le"))
  return out, buf


def limited(items, n):
  items = list(items)
  for it in items[:n]:
    yield it
  if len(items) > n:
    yield "... +%d more" % (len(items) - n)


def section(title, items, n=60):
  items = sorted(items)
  print("\n## %s (%d)" % (title, len(items)))
  for it in limited(items, n):
    print("- %s" % it[:220])


def main():
  name = sys.argv[1]
  root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work", name)
  raw = os.path.join(root, "raw")
  lib = None
  for abi in ABI_ORDER:
    p = os.path.join(raw, "lib", abi, "libapp.so")
    if os.path.exists(p):
      lib = p
      break
  assets = os.path.join(raw, "assets", "flutter_assets")
  print("# Flutter summary: %s" % name)
  if lib is None:
    print("No libapp.so: not a release-mode Flutter app (a debug build ships "
          "assets/flutter_assets/kernel_blob.bin instead)." if os.path.isdir(assets)
          else "Not a Flutter app.")
    return
  print("Strings from the Dart AOT snapshot. They show what the code can refer to, not "
        "what it does or when.\nsource: %s" % os.path.relpath(lib, os.path.join(root, "..", "..")))

  strings, buf = all_strings(lib)
  dump = os.path.join(root, "flutter-strings.txt")
  with open(dump, "w") as f:
    f.write("\n".join(sorted(strings)) + "\n")
  print("all %d strings: %s (grep it for feature names, keys, messages)" % (
    len(strings), os.path.relpath(dump, os.path.join(root, "..", ".."))))

  m = re.search(rb"([0-9a-f]{32})((?:product|release|debug|profile)[ -~]{10,200})", buf)
  print("\n## Snapshot")
  eng = os.path.join(os.path.dirname(lib), "libflutter.so")
  if os.path.exists(eng):
    with open(eng, "rb") as fh:
      mv = re.search(rb"(\d+\.\d+\.\d+[\w.-]* \((?:stable|beta|dev|main)\)[ -~]{0,60})", fh.read())
    if mv:
      print("- Dart SDK in libflutter.so: %s" % mv.group(1).decode())
  if m:
    print("- snapshot hash %s (identifies the Dart SDK build)" % m.group(1).decode())
    print("- features: %s" % m.group(2).decode())
  uris = {}
  for s in strings:
    for pkg, path in DART_URI.findall(s):
      uris.setdefault(pkg, set()).add(path)
  total_uris = sum(len(v) for v in uris.values())
  print("- %d Dart library URIs across %d packages" % (total_uris, len(uris)))
  if total_uris < 20:
    print("- very few library URIs: the build was probably made with --obfuscate; "
          "names below are unreliable or absent")

  pkg_guess = None
  mf = os.path.join(root, "manifest.xml")
  if os.path.exists(mf):
    with open(mf) as f:
      mm = re.search(r' package="([^"]+)"', f.read(4000))
    if mm:
      last = mm.group(1).split(".")[-1]
      pkg_guess = last if last in uris else None

  print("\n## Dart packages (%d)" % len(uris))
  print("count = library files referenced. Notes mark capabilities to follow up.")
  for pkg, paths in sorted(uris.items(), key=lambda kv: (-len(kv[1]), kv[0])):
    note = PACKAGE_NOTES.get(pkg, "")
    if pkg == pkg_guess:
      note = "THE APP'S OWN CODE"
    print("- %-40s %4d  %s" % (pkg, len(paths), note))

  if pkg_guess:
    section("App source files (package:%s)" % pkg_guess, uris[pkg_guess], 200)
  else:
    print("\n## App source files\n- could not tell which package is the app's own; "
          "look for the unfamiliar name in the list above")

  urls = set()
  for s in strings:
    for u in URL.findall(s):
      if not NOISE_URL.search(u):
        urls.add(u.rstrip(".,);"))
  section("URLs", urls, 120)
  section("Bare hosts", {s for s in strings if HOST.match(s) and not NOISE_URL.search(s)
                         and not s.startswith(("plugins.flutter.io/", "flutter.baseflow.com/", "dart.io"))}, 60)
  section("API paths", {s for s in strings if API_PATH.match(s)}, 80)
  section("Platform channels (Dart to Java/Kotlin bridges)",
          {s for s in strings if CHANNEL.match(s) and not s.endswith(".dart")
           and not s.startswith(("package:", "dart:")) and "/" in s and len(s) < 90
           and (s.startswith(("plugins.", "dev.", "flutter/", "com.", "io.", "org.", "net.")))}, 80)
  section("Key-shaped literals (possible embedded credentials)",
          {s for s in strings if KEY_SHAPED.match(s)}, 30)
  section("Credential-related names",
          {s for s in strings if CRED.search(s) and len(s) < 60 and " " not in s.strip()
           and not re.search(r"@\d{5,}|[($&:]|Tokens?(?:Logprob|TopLogprob|sDetails)|[a-z]_tokens|Token(?:izer|ize)", s)}, 80)
  section("SQL", {s for s in strings if SQL.match(s)}, 40)
  section("File paths and extensions of interest",
          {s for s in strings if re.match(r"^(?:/(?:data|sdcard|storage|proc|system)/[\w./-]+|[\w-]+\.(?:gguf|bin|db|sqlite|json|pem|key|p12|jks))$", s)}, 60)

  print("\n## Bundled assets (assets/flutter_assets)")
  if os.path.isdir(assets):
    rows = []
    for dp, _dn, fn in os.walk(assets):
      for f in fn:
        p = os.path.join(dp, f)
        rows.append((os.path.relpath(p, assets), os.path.getsize(p)))
    print("- %d files, %d bytes" % (len(rows), sum(s for _n, s in rows)))
    by_ext = {}
    for n, s in rows:
      by_ext.setdefault(os.path.splitext(n)[1] or "(none)", []).append(s)
    for ext, sizes in sorted(by_ext.items(), key=lambda kv: -sum(kv[1])):
      print("  %-10s %4d files %10d bytes" % (ext, len(sizes), sum(sizes)))
    for n, s in sorted(rows):
      if n.endswith((".json", ".txt", ".yaml", ".yml", ".env", ".pem", ".key", ".db", ".js", ".html")) \
          and not n.startswith(("AssetManifest", "FontManifest", "NativeAssetsManifest")):
        print("- data asset: %s (%d bytes)" % (n, s))
        if n.endswith(".json") and s < 2_000_000:
          try:
            with open(os.path.join(assets, n)) as f:
              text = f.read()
            json.loads(text)
            for u in sorted(set(URL.findall(text)))[:15]:
              print("    url: %s" % u[:200])
          except (ValueError, OSError):
            print("    (not valid JSON)")
    if os.path.exists(os.path.join(assets, "kernel_blob.bin")):
      print("- kernel_blob.bin present: debug build, Dart source is recoverable")
    for n, _s in rows:
      if n.endswith(".env") or os.path.basename(n).startswith(".env"):
        print("- %s: environment file shipped in assets; read it for secrets" % n)

  print("\n## Android side: registered Flutter plugins")
  src = os.path.join(root, "jadx", "sources")
  reg = os.path.join(src, "io", "flutter", "plugins", "GeneratedPluginRegistrant.java")
  if os.path.exists(reg):
    with open(reg) as f:
      text = f.read()
    tags = sorted(set(re.findall(r'"Error registering plugin ([\w.]+), ([\w.$]+)"', text)))
    for plugin, cls in tags:
      print("- %s (%s)" % (plugin, cls))
    if not tags:
      for cls in sorted(set(re.findall(r"new ([\w.]+)\(\)", text))):
        print("- %s" % cls)
  else:
    print("- GeneratedPluginRegistrant not found in jadx output")
  if os.path.isdir(src):
    try:
      out = subprocess.run(["grep", "-rhoE", "-e", r'new [A-Za-z0-9_.]*\((\w+, )?"[a-z][A-Za-z0-9_.]*/[A-Za-z0-9_./-]+"',
                            "--", "."], cwd=src, capture_output=True, text=True, timeout=120).stdout
      chans = sorted(set(re.findall(r'"([^"]+)"', out)))
      print("\n## Android side: channel names in Java code (%d)" % len(chans))
      for c in limited(chans, 60):
        print("- %s" % c)
    except (OSError, subprocess.SubprocessError):
      pass


if __name__ == "__main__":
  main()
