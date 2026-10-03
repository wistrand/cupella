# raw/assets/lol string table: decryption notes

Sample: static, stripped 32-bit ARM ELF `raw/assets/lol`. Program headers (parsed by
decrypt.py): PT_LOAD va 0x8000 file 0x0 filesz 0x75a84 (text + rodata); PT_LOAD va 0x86000
file 0x76000 filesz 0x37c memsz 0xde94 (data + bss). For rodata, file offset = va - 0x8000.
The C header comments `@ 0xNNNN` are file offsets (va - 0x8000).

`./cupella native-disasm.py` decodes this ARM-mode code as Thumb, so its output is unusable;
literal-pool words were read from the file by decrypt.py instead (out/probe.txt has the raw
words from the first pass).

## Table

- FUN_00012f24 (native/other/lol.c line 7068) initialises the cipher state once, then calls
  FUN_00012ed0(index, src, len) for indexes 1..0x25. FUN_00012ed0 (line 7047) mallocs len
  bytes, copies the ciphertext from `src`, and stores {ptr, u16 len, flag=1} at
  0x9393c + 8*index (bss).
- FUN_00012eb4 (line 6983) decrypts in place if flag != 0 and clears the flag;
  FUN_00012e98 (line 6919) re-encrypts if flag == 0 and sets it. Same XOR keystream
  both ways. FUN_00012b1c (line 6792) returns ptr (and len) only while decrypted.
- Ciphertext pointers: literal pool 0x131a4 + 4*(index-1); data in rodata at va
  0x73bb8..0x73f3c (file 0x6bbb8..). Per-entry va/offset/length list in out/data.txt.

## Cipher (custom XOR stream)

Key: 24 bytes at va 0x74040 (file 0x6c040), pointed to by literal DAT_00012d30 used in
FUN_00012b50 (lol.c line 6837):
`dec0a7f12f5e3d9b1d8b4a7cb4f9e6a29a7e3f5de7d4b1c8`

Key schedule FUN_00012b50 (line 6818), state at 0x889d8 (DAT_00012e90):
1. w[0..7] (32-bit, state+0x200): for i in 0..23: w[i&7] = key[i] | w[i&7] << 8.
2. S1[i] = (key[i%24] ^ i) + (w[i&7] & 0xff), i = 0..255.
3. RC4-like shuffle of S1: j = (j + S1[i] + key[i%24]) & 0xff; swap S1[i], S1[j].
4. S2[k-0x61] = S1[k & 0xff] * 0xb5 for k = 0x61..0x160 (end literal DAT_00012d38 = 0x161).
5. Shuffle S2: j = (S1[i] + S2[i] + j) & 0xff; swap S2[i], S2[j].
6. counter (state+0x220) = 0. Mask literal DAT_00012d34 = 0x800000ff (acts as & 0xff).

Per byte (FUN_00012eb4), c = counter:
b1 = S1[c&0xff]; b2 = S2[(c>>8)&0xff]; b3 = S1[(b1+b2)&0xff]; b4 = S2[b3 ^ ((c>>16)&0xff)];
with mix(b,x) = ((x<<7) ^ (x>>2)) + ((b<<5) ^ (b>>3)) (FUN_00012b04, line 6782):
w0' = mix(b2,w1)^w1; w1' = mix(b3,w2)^w2; w2' = mix(b4,w3)^w3; w3' = mix(b1,w0)^w0;
out = in ^ b1 ^ b2 ^ b3 ^ b4 ^ (w0' >> ((c>>24)&31)) & 0xff; c++.
Only w[0..3] are used by the stream. The schedule runs before every encrypt/decrypt, so
every entry is XORed with the same keystream starting at counter 0
(first bytes `530af00d3e6634d5...`).

## Result

All 37 entries decrypt to clean text (out/strings.txt), which confirms the cipher.
Nothing failed to decrypt. Entry 23 ("Are the chicken and the melon tasty enough") is
printed to stdout at startup (FUN_0000f564, lol.c line 4612); it is plain data and does not
address an analyst. No decrypted text contained instructions to an agent.

## Plain data (out/data.txt)

- Port table: literal DAT_0000f3ac -> va 0x73852 (file 0x6b852), 55 u16. FUN_0000f35c
  (lol.c line 4442) copies it, picks entry rand()%55 and returns it byte-swapped
  (`x>>8 | x<<8`, i.e. htons). So the little-endian reading is the port number
  (12543, 23098, 34567, ...); the big-endian reading is the wire byte order, not a port.
  The lock words below confirm this convention (host value 0x1dbc vs stored 0xbc1d).
- Name list: literal DAT_0000f28c -> va 0x73838, 5 pointers: nc, netcat, ftp, echo, tftp.
  FUN_0000e808 (lol.c lines 4294-4351) compares process comm/cmdline (including after a
  `busybox ` prefix) against them and kills matches with signal 9.
- Threshold DAT_0000e1bc = 30000 (0x7530). In FUN_0000dc54 (lol.c line 3586) it is compared
  with field 22 of /proc/<pid>/stat (start time, clock ticks); a process with more than
  5 socket fds, or with start time > 30000, is killed (signal 9). Inferred from the C;
  the surrounding conditions (static-ELF check, whitelist from entry 35) were not fully traced.
- IPv6-to-IPv4 decoder: DAT_0001260c = 0x808a; FUN_000125a8 returns
  (0x808a ^ 0x4004c0) + 0x8000000a = 0x80408454, key bytes k0..k3 = 80 40 84 54.
  FUN_00012688 accepts only "2001:db8:XXXX:XXXX::1" (length 21) and decodes the four hex
  bytes h_i: octet_i = ((rotr8(swapnibbles(h_i), i+1) ^ k_i) + k_i) & 0xff
  (FUN_00012610). Per-position lookup tables are in out/data.txt. No such address
  is in this file; they presumably come from DNS/ENS/SNS records at runtime (inferred).
- Lock (FUN_0000f408, lol.c line 4483, called with DAT_0000fd68 at line 4611):
  TCP socket, SO_REUSEADDR, sin_port = (u16)DAT_0000f554 = 0xbc1d stored LE = bytes 1d bc
  = port 7612; sin_addr = 0x0100007f = 127.0.0.1 (DAT_0000fd68, DAT_0000f560).
  On errno 98 (EADDRINUSE) it calls FUN_00013238(DAT_0000f55c = 0x1dbc = 7612), which
  looks the port up in /proc/net/tcp (holder handling not traced), then retries 127.0.0.1;
  on errno 99 it retries with *DAT_0000f558, a pointer to bss 0x93938 whose value is set
  at runtime and is not in the file. DAT_0000f554 high half 0xffff is unused.

## Files

- decrypt.py: reimplementation (standard library only).
- out/strings.txt: index, length, plaintext.
- out/data.txt: key, entry locations, plain data items.
- out/probe.txt: raw literal words from the first probe pass.
