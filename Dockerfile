# Analysis image for Cupella: every external tool the scripts call, at pinned
# versions (downloads checked by sha256; Python packages pinned by version or commit,
# not by hash). The repo itself is not copied in; ./cupella mounts scripts/ and data/
# read-only, work/ read-write, and cache/ read-only to containers that see APK data.
#
# Build:  ./cupella build
# To upgrade a tool, change its version and checksum here and rebuild.
FROM debian:trixie-slim

ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG APKTOOL_VERSION=3.0.3
ARG APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
ARG GHIDRA_VERSION=12.1.4
ARG GHIDRA_DATE=20260921
ARG GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
ARG BLUTTER_COMMIT=4a60ac648bf448c5a7596437243bcd0b9376fdf0
ARG APKID_VERSION=3.1.0
ARG HERMES_DEC_COMMIT=a0f18f97ab661eb8ed659c8c683a0d21ea619e69
# comparison tools for the benchmarks (agent_docs/benchmarks.md), not used by the analysis
ARG QUARK_VERSION=26.9.1
ARG QUARK_RULES_COMMIT=80c902f420cf0b7d70ef9e41a9095e445171d01e

# Runtime for the scripts (python3, unzip, openssl, binutils for strings/c++filt,
# capstone-tool for cstool, JDK for jadx/apktool/Ghidra/jarsigner/keytool) and the
# toolchain blutter needs to build against a Dart runtime (git, cmake, ninja, g++,
# capstone and ICU headers, two Python modules; make, zlib, bison and flex also build
# Ghidra's decompiler on arm64), and pycryptodome (Debian installs it
# as the Cryptodome package) for the agent-written decryptors (scripts/run-decryptor.sh).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip git python3 openssl binutils file grep \
      openjdk-21-jdk-headless fontconfig fonts-dejavu-core \
      capstone-tool libcapstone-dev libicu-dev \
      cmake ninja-build g++ pkg-config make zlib1g-dev bison flex \
      python3-pyelftools python3-requests python3-venv python3-dev \
      python3-pycryptodome \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/tools \
 && curl -fL -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
 && echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c - \
 && unzip -q /tmp/jadx.zip -d /opt/tools/jadx \
 && chmod +x /opt/tools/jadx/bin/jadx \
 && rm /tmp/jadx.zip

RUN curl -fL -o /opt/tools/apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
 && echo "${APKTOOL_SHA256}  /opt/tools/apktool.jar" | sha256sum -c -

RUN curl -fL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
 && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
 && unzip -q /tmp/ghidra.zip -d /opt/tools \
 && mv /opt/tools/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/tools/ghidra \
 && rm /tmp/ghidra.zip

# The Ghidra release ships its native decompiler for linux_x86_64 only. On arm64 (Apple
# Silicon under Docker Desktop, ARM Linux) every function would fail to decompile, so
# build decompile and sleigh there from the C++ sources the release includes. Its
# Makefile knows only x86 and adds -m32 on any other Linux CPU: ARCH_TYPE= drops it. It
# creates its object directories only for a single goal, so one make per binary.
RUN if [ "$(uname -m)" = aarch64 ]; then \
      d=/opt/tools/ghidra/Ghidra/Features/Decompiler \
      && make -C "$d/src/decompile/cpp" -j"$(nproc)" ARCH_TYPE= ghidra_opt \
      && make -C "$d/src/decompile/cpp" -j"$(nproc)" ARCH_TYPE= sleigh_opt \
      && mkdir -p "$d/os/linux_arm_64" \
      && cp "$d/src/decompile/cpp/ghidra_opt" "$d/os/linux_arm_64/decompile" \
      && cp "$d/src/decompile/cpp/sleigh_opt" "$d/os/linux_arm_64/sleigh" \
      && find "$d/src/decompile/cpp" \( -name '*.o' -o -name '*_opt' \) -type f -delete; \
    fi

# blutter sources at a pinned commit. It compiles against the Dart runtime of each
# app's Dart version at first use; those builds go to the cache/ mount (see ./cupella),
# so the copy in the image stays pristine.
RUN git clone https://github.com/worawit/blutter /opt/tools/blutter-src \
 && git -C /opt/tools/blutter-src checkout -q "${BLUTTER_COMMIT}" \
 && rm -rf /opt/tools/blutter-src/.git

# APKiD (packer, protector, obfuscator identification) and hermes-dec (React Native
# Hermes bytecode decompiler) in their own virtualenv, exposed on PATH.
RUN python3 -m venv /opt/tools/pyenv \
 && /opt/tools/pyenv/bin/pip install --no-cache-dir "apkid==${APKID_VERSION}" \
      "git+https://github.com/P1sec/hermes-dec@${HERMES_DEC_COMMIT}" \
 && for t in apkid hbc-decompiler hbc-disassembler hbc-file-parser; do \
      ln -s "/opt/tools/pyenv/bin/$t" "/usr/local/bin/$t"; done \
 && apkid --help > /dev/null \
 && { hbc-file-parser --help > /dev/null 2>&1 || command -v hbc-file-parser > /dev/null; }

# Quark-Engine and its rule set, in their own virtualenv (its androguard pin must not touch
# APKiD's): scan.sh runs Quark on every sample (quark-leads.txt), quark-query.py uses Quark
# Script, callgraph-check.py uses the androguard it brings, and the tool comparison uses
# it too. The rules are part of the image so that Quark never downloads them at run time.
RUN python3 -m venv /opt/tools/quarkenv \
 && /opt/tools/quarkenv/bin/pip install --no-cache-dir "quark-engine==${QUARK_VERSION}" \
 && git clone -q https://github.com/ev-flow/quark-rules /opt/tools/quark-rules \
 && git -C /opt/tools/quark-rules checkout -q "${QUARK_RULES_COMMIT}" \
 && rm -rf /opt/tools/quark-rules/.git \
 && ln -s /opt/tools/quarkenv/bin/quark /usr/local/bin/quark \
 && quark --help > /dev/null

# Exodus Privacy tracker signatures. A snapshot taken at image build: the list changes
# over time, so its date and checksum are recorded in VERSIONS instead of being pinned.
RUN curl -fsSL -o /opt/tools/exodus-trackers.json https://reports.exodus-privacy.eu.org/api/trackers \
 && python3 -c "import json; d=json.load(open('/opt/tools/exodus-trackers.json')); assert len(d['trackers']) > 100"

RUN { printf 'jadx    %s\n' "${JADX_VERSION}"; \
      printf 'apktool %s\n' "${APKTOOL_VERSION}"; \
      printf 'ghidra  %s (%s)\n' "${GHIDRA_VERSION}" "${GHIDRA_DATE}"; \
      printf 'blutter %s\n' "${BLUTTER_COMMIT}"; \
      printf 'apkid   %s\n' "${APKID_VERSION}"; \
      printf 'hermes-dec %s\n' "${HERMES_DEC_COMMIT}"; \
      printf 'quark   %s, rules %s\n' "${QUARK_VERSION}" "${QUARK_RULES_COMMIT}"; \
      printf 'exodus-trackers snapshot %s sha256 %s\n' "$(date -u +%Y-%m-%d)" "$(sha256sum /opt/tools/exodus-trackers.json | cut -c1-16)"; \
      printf 'openssl %s\n' "$(openssl version | cut -d' ' -f2)"; \
      printf 'java    %s\n' "$(java -version 2>&1 | head -n 1)"; \
      printf 'cstool  %s\n' "$(cstool -v 2>&1 | head -n 1)"; \
      printf 'python  %s\n' "$(python3 --version | cut -d' ' -f2)"; \
    } > /opt/tools/VERSIONS

# HOME lives on the container's tmpfs; create it before each command (apktool,
# Ghidra, and the JVM write settings there).
RUN printf '#!/bin/sh\nmkdir -p "$HOME"\nexec "$@"\n' > /usr/local/bin/entry \
 && chmod +x /usr/local/bin/entry
ENTRYPOINT ["/usr/local/bin/entry"]

ENV APK_TOOLS=/opt/tools \
    APK_BLUTTER=/cache/blutter \
    HOME=/tmp/home \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8

WORKDIR /repo
