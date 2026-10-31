# Runbook: samples that are not a plain APK

Read when the sample is a password-protected archive (`data/<sha256>.zip`), a split-APK
bundle (`.apkm`, `.xapk`, `.apks`), or a Parquet file (a dataset with APKs in a binary
column), not an `.apk`. The rest of the analysis follows
[runbook-analysis.md](runbook-analysis.md); stage order and checkpoints are in
[workflow.md](workflow.md).

When the sample is a password-protected archive instead of an APK (malware repositories
hand out `<sha256>.zip`), take the APK out first:

```bash
./cupella sample-archive.py data/<file>.zip        # lists the members; extracts APKs to work/_samples/
./cupella unpack.sh work/_samples/<name>.apk
```

It tries one password, "infected", the convention of those repositories, and handles
ZipCrypto and WinZip AES. For another password use `--password <text>`, given by the
user; never guess passwords, and never extract with host tools or write to `data/`.
Check that the printed sha256 is the one the file is named after, and say in the
report's Identity that the APK came out of an archive.

A split-APK bundle (APKMirror `.apkm`, `.xapk`, `.apks`) is an unencrypted ZIP of a
`base.apk` and `split_config.*.apk` members; the same script takes it out. Each APK is
named after the bundle, so the report is too: `base.apk` becomes `<bundle stem>.apk`,
a split `<bundle stem>.<split>.apk`. The base and the ABI splits come first, and the
eight-member limit drops resource splits.

```bash
./cupella sample-archive.py data/<file>.apkm
./cupella unpack.sh work/_samples/<bundle stem>.apk                        # the app: dex, manifest
./cupella unpack.sh work/_samples/<bundle stem>.split_config.arm64_v8a.apk  # its native libraries
```

The base is the sample and the report; the ABI split is unpacked as a sample of its own
for stage 4 (its `native-summary.txt`), cited by its full `work/` path. Density and
language splits hold only resources. Say in Identity which bundle the APK came from.

When the samples come as a Parquet file (a dataset with one APK per row in a binary
column, often next to a hash, a file name, a package name, or a label), list it first and
extract the rows the user asked for:

```bash
./cupella parquet-samples.py data/<file>.parquet --list          # every APK row: size, sha256, guessed name
./cupella parquet-samples.py data/<file>.parquet --rows 3,7      # those rows to work/_samples/<name>.apk
./cupella unpack.sh work/_samples/<name>.apk
```

- A name comes from a file name column, a package name (and version), or a hash column
  that matches the bytes, else the APK's sha256; the output says which column. A hash
  column that does not match the bytes is reported: say so in the report.
- `work/_samples/<file>.index.tsv` keeps each APK row's other short values (labels,
  families, sources). Cite it in Identity for where the APK came from; a label in a
  dataset is a lead, not a finding.
- When `--list` finds no APK it describes each column instead (type, codec, value sizes,
  a guess at the format from the first bytes, the most common short values);
  `--describe` always does. A dataset of Windows PE files (`MZ`) or other formats is
  not an APK set: say so instead of analyzing it.
- At most 20 APKs per run unless `--max N` or `--all`; never extract a whole dataset
  without the user asking for it. Lists inside rows, LZO, and Hadoop-framed LZ4 are not
  read; the output names the column and the reason.
