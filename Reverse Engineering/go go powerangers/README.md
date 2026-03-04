# CTF Writeup: go go go powerangers — PNG Steganography + Double AES-CBC

**Flag:** `dCRyp7{d0ubl3_tr0ubl3_f0ll0w3d_by_my_unkn0wn_bubbl3s_734m_r0ck3t}`  
**Category:** Reverse Engineering / Cryptography  
**Tools:** UPX, pwndbg, objdump, Python 3, cryptography library

---

## Overview

We were given a Go binary called `encode` and an output file `enc.png`. The binary reads a plaintext file, encrypts it, and hides the result inside a PNG image using steganography. The goal was to fully reverse engineer the encryption scheme and extract the hidden flag.

This challenge combined multiple layers of obfuscation:
- **UPX packing** to prevent straightforward disassembly
- Steganography (data hidden in PNG pixels)
- Double AES-256-CBC encryption
- XOR obfuscation (index-based)
- A random byte XOR layer

---

## Step 0: Defeating UPX Packing

Before any disassembly was possible, we needed to deal with the binary being packed with **UPX** (Ultimate Packer for eXecutables). Running `file` or `strings` on the binary immediately reveals the signature:

```bash
$ strings encode | grep -i upx
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
```

### Why `upx -d` Failed

The standard approach is:

```bash
upx -d encode
```

But this failed — the UPX headers had been **manually tampered with**. This is a common CTF anti-reversing trick: modify a few bytes in the UPX header so the decompressor rejects it, while the binary still runs fine at execution time (since the OS loads it differently). `upx -d` reads those headers to locate and decompress the payload, so corrupted headers make it abort entirely.

### Extracting the Real Binary from Inside pwndbg

Since static extraction failed, we took a different approach: **let the binary unpack itself at runtime and dump it from memory**.

When a UPX-packed binary runs, the UPX stub decompresses the real binary into memory and jumps to it. At that point the real binary exists fully in process memory, even if we can never get it on disk through normal means. The trick is catching it at the right moment — after decompression but before execution.

**Step 1: Find where the real code lands**

UPX stubs typically decompress to a region starting around `0x400000` (the standard ELF base address for non-PIE x86-64 binaries). We started the binary in pwndbg and used `vmmap` to inspect the memory layout:

```
pwndbg> start
pwndbg> vmmap
   0x400000    0x401000 r--p     1000 0      /home/.../encode   ← packed stub
   0x401000    0x402000 r-xp     1000 1000   /home/.../encode
   ...
```

After the stub runs and decompresses, the memory map changes. A new executable region appears — the real unpacked binary — starting around `0x400000` with `r-xp` (readable + executable) permissions.

**Step 2: Set a hardware breakpoint at the OEP**

Rather than guessing when the stub had finished, we used a **hardware breakpoint** — the same technique we'd later rely on throughout the whole challenge. Software breakpoints (`b` in GDB/pwndbg) work by patching a byte in the instruction stream with `int3`. Hardware breakpoints use the CPU's built-in debug registers (`DR0`–`DR3`) and fire without touching any code. The syntax in pwndbg is:

```
hb *0x<address>
```

We set a hardware breakpoint at the suspected OEP (Original Entry Point) — the address the UPX stub would jump to once decompression was done. Hardware breakpoints were essential here for the same reason they'd be essential later: the Go runtime and the UPX stub both do things that cause software breakpoints to be skipped or misfire. Hardware breakpoints bypass all of that entirely(more on this later).

Once the breakpoint fired inside the unpacked code, `vmmap` showed the real executable region clearly. We used `vis` (pwndbg's visual memory inspector) to confirm we were looking at real Go code — recognizable by its function prologues and Go runtime patterns — rather than the UPX stub:

```
pwndbg> vis
```

**Step 3: Dump the executable region**

With the real binary in memory and its bounds known from `vmmap`, we dumped it straight out of the process:

```
pwndbg> dump binary memory encode_unpacked 0x400000 0x<end_address>
```

This wrote the live memory contents to `encode_unpacked` on disk. We verified it:

```bash
$ file encode_unpacked
encode_unpacked: ELF 64-bit LSB executable, x86-64, Go, not stripped
```

The `not stripped` part is significant — Go binaries compiled without `-ldflags="-s -w"` retain symbol names, which made the subsequent disassembly far more readable.

> **Important:** `encode_unpacked` was used **only for static analysis with objdump**. It couldn't be executed directly — the memory dump captures the binary's code and data as they existed in the running process, but without the correct ELF headers, load addresses, and runtime setup that the OS expects, the dumped file won't run as a standalone binary. For all dynamic analysis (actually running the code and hitting breakpoints), we continued to use the original `encode` binary and let UPX unpack itself in memory each time.

### Why This Technique Works

The key insight is that **packing only protects the binary at rest**. The moment the process starts, the CPU has to execute real instructions — which means the real code has to exist somewhere in memory in plaintext form. No matter how obfuscated the packing stub is, you can always dump the unpacked result if you catch it at the right moment. This is the fundamental limitation of all software-based packing schemes.

With the unpacked binary on disk, objdump could now process it properly.

---

## Step 1: Static Analysis with objdump

With the unpacked binary, we disassembled it:

```bash
objdump -d encode_unpacked > woah.txt
```

### Why objdump Over Ghidra

Ghidra was deliberately skipped for this binary for a few reasons. First, Ghidra operates on the binary at rest — loading the UPX-packed version would have given us a decompilation of the UPX stub, not the real code, so we'd need to unpack it first regardless. Second, Go binaries are notoriously poor targets for Ghidra's decompiler: Go uses a non-standard calling convention that doesn't follow the x86-64 System V ABI (arguments go on the stack in Go's own layout rather than rdi/rsi/rdx), so Ghidra produces function signatures with wrong argument counts and types — often harder to read than the raw assembly. Third, and most importantly, this binary was **not stripped**: symbol names like `crypto/rand.Read` were visible directly in the disassembly, which eliminates Ghidra's main advantage of identifying unknown functions through cross-reference analysis. When you can already read `call 0x476ee0 ; crypto/rand.Read` in objdump output, Ghidra adds friction without adding signal.

The output was nearly 200,000 lines. We focused on identifying key functions by searching for recognizable patterns.

**Key functions identified:**

| Address | Role |
|---------|------|
| `0x4ae780` | Generates a random byte via `crypto/rand.Read`, XORs all data with it |
| `0x4ae860` | Core encryption function (AES + PKCS7 padding) |
| `0x4aec80` | Orchestrates the full encode pipeline |
| `0x4aea60` | Writes encrypted bytes as PNG pixels |

### Identifying the PNG Write Logic

Inside `0x4aea60`, we found calls to image creation and pixel-setting routines:

```asm
mov  $0x64, %ecx          ; 100 (image dimensions)
call 0x497580             ; create 100x100 NRGBA image
...
mov  %sil, 0x2c(rsp)      ; R = data byte
mov  %sil, 0x2d(rsp)      ; G = data byte
mov  %sil, 0x2e(rsp)      ; B = data byte
movb $0xff, 0x2f(rsp)     ; A = 0xff
call 0x4adf20             ; png.Encode → "enc.png"
```

Each encrypted byte was written as a grayscale pixel (R=G=B=byte, A=255) starting at **row 99** of the 100×100 image (pixels 9900–9995).

### Identifying PKCS7 Padding → AES-CBC (not CTR)

A critical observation inside `0x4ae860`:

```asm
and  $0xf, %ebx           ; plaintext_len % 16
sub  %ebx, %rcx           ; round down to block boundary
add  $0x10, %rsi          ; add 16 bytes capacity
neg  %rdx                 ; padding value = 16 - (len % 16)

; padding loop:
mov  %dl, (%rax,%rbx,1)   ; write padding byte repeatedly
inc  %rbx
cmp  %rsi, %rbx
jl   <loop>
```

This is **PKCS7 padding** — AES-CTR doesn't use padding. This confirmed the mode was **AES-256-CBC**.

### Identifying the Random Byte XOR in `0x4ae780`

```asm
movb $0x0, 0x27(rsp)      ; zero out 1-byte buffer
mov  $0x1, %ecx           ; length = 1
lea  0x27(rsp), %rbx      ; destination on stack
call 0x476ee0             ; crypto/rand.Read(1 byte)

; XOR loop:
movzbl (%rdx,%rbx,1), %esi  ; load input[i]
movzbl 0x27(rsp), %edi      ; load random byte
xor    %edi, %esi           ; XOR
mov    %sil, (%rax,%rbx,1)  ; store result
```

A single random byte is generated, used to XOR every byte of the output, then **discarded** — never stored in the PNG. This is the key that makes static analysis alone insufficient.

### Identifying the Index XOR in `0x4aec80`

```asm
; XOR loop at 0x4aeeb9:
movzx  esi, byte ptr [r12 + rcx]   ; load r12[i]
xor    esi, ecx                    ; XOR with index i
mov    byte ptr [rax + rcx], sil   ; store result
inc    rcx
cmp    rdx, rcx                    ; loop 64 times
jg     0x4aeeb9
```

So the final PNG bytes are: `png[i] = r12[i] ^ i ^ rand_byte`

---

## Step 2: Dynamic Analysis with pwndbg

Static analysis gave us the structure, but we needed runtime values. We used **pwndbg** on top of GDB.

### Knowing Where to Breakpoint

After extracting the unpacked binary and running `objdump`, all the key function addresses were in the `0x4ae000`–`0x4aef00` range — well above `0x400000` where the ELF loads. This is normal for Go binaries: the Go runtime, scheduler, and standard library all occupy the low address range, and application code lives higher up.

We identified the most valuable breakpoint locations from the static analysis:

| Address | Why break here |
|---------|---------------|
| `0x4ae7c5` | Immediately after `crypto/rand.Read` — rand_byte is on the stack at `rsp+0x27` |
| `0x4aeeb9` | Start of the index XOR loop — `r12` holds the 64-byte pre-XOR buffer |
| `0x4aeed7` | End of XOR loop — `rax` holds the final output buffer |

The `0x4ae7c5` address was found by reading the disassembly of `0x4ae780` and identifying the instruction immediately after the `call 0x476ee0` (the `crypto/rand.Read` call). At that exact point the random byte has been written to the stack but hasn't been used yet, making it trivially readable.

### The Problem with Software Breakpoints — and the Fix

> **TL;DR:** `b *0x4aeeb9` was silently skipped every time. Switching to `hb *0x4aeeb9` (hardware breakpoint) fixed it instantly. If your breakpoints aren't firing in a Go binary, this is always the first thing to try.

Setting normal breakpoints with `b *0x4aeeb9` caused them to be **silently skipped**. This is a well-known issue with Go binaries in GDB. Go uses a cooperative scheduler — goroutines yield at certain "safe points" in the code. When GDB inserts a software breakpoint (`int3` instruction), it patches one byte of the instruction stream with a trap opcode. The Go runtime scans for these during goroutine scheduling, treats the modified byte as a preemption point, and migrates the goroutine to a different OS thread — jumping straight past the breakpoint. It fires zero times despite being set correctly.

**Hardware breakpoints** use the CPU's dedicated debug registers (`DR0`–`DR3`) instead of patching any code. They are completely invisible to the running process — no bytes are modified, nothing for the Go runtime to detect or react to. In pwndbg the syntax is:

```
hb *0x4aeeb9
```

This fired reliably on every single run. The difference between `b` and `hb` here was the difference between getting no data and cracking the challenge. We used hardware breakpoints for every single breakpoint in this challenge from this point forward.

### Capturing the r12 Buffer

At the XOR loop breakpoint, `r12` pointed to the 64-byte buffer about to be XOR'd with indices. We dumped it:

```
x/64xb $r12
0xc000116000: 0xb0 0x96 0x42 0x85 0x21 0xb5 0x71 0x7e
0xc000116008: 0xd8 0xb5 0x46 0xfb 0x60 0x1f 0x49 0xf1
0xc000116010: 0xa9 0x0e 0x63 0x92 0x91 0xd2 0xd8 0x85
0xc000116018: 0x46 0xa1 0xc4 0x5f 0x98 0xa5 0x82 0x39
0xc000116020: 0x24 0x30 0x2f 0x18 0xa2 0x1f 0x16 0xc8
0xc000116028: 0x2c 0x4e 0x1d 0xc5 0x55 0x68 0x0b 0xd7
0xc000116030: 0x5b 0x15 0x18 0x62 0x32 0xc9 0x6b 0x66
0xc000116038: 0x5a 0xc0 0x66 0xfa 0xe1 0x81 0xef 0x44
```

**The same bytes appeared across every single run.** We re-ran the program 5+ times and r12 never changed. This was the first major insight: **r12 is deterministic**.

### Discovering the Hardcoded Key and IV

By examining the stack at the XOR loop breakpoint, we could read the function arguments that were passed to the AES encryption call at `0x4ae860`:

```
rsp+0x00 → 0xc000018140 → 52 fd fc 07 21 82 65 4f ...  (KEY, 32 bytes)
rsp+0x18 → 0xc00001a120 → 81 85 5a d8 68 1d 0d 86 ...  (IV, 16 bytes)
```

We re-ran the program several times. **Both the key and IV were identical on every run.** With 2¹²⁸ possible IVs, a collision is statistically impossible — these values are **hardcoded in the binary**.

Key: `52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649`  
IV:  `81855ad8681d0d86d1e91e00167939cb`

### Capturing the rand_byte — and Why It Was Always the Same

We set a hardware breakpoint at `0x4ae7c5` (immediately after `crypto/rand.Read` returns in `0x4ae780`), then read the 1-byte buffer at `rsp + 0x27`:

```
hb *0x4ae7c5
...
x/1xb ($rsp + 0x27)
0xc00011ceb7: 0x66
```

**rand_byte = `0x66`** — and this was identical on every single run.

This seems contradictory: the code calls `crypto/rand.Read`, which is supposed to read from the OS's cryptographically secure random source (`/dev/urandom` on Linux). That should produce a different byte every time. So why was it always `0x66`?

The answer is that the binary was using a **deterministically seeded PRNG under the hood rather than true OS randomness**. In Go, if `crypto/rand.Reader` is replaced or wrapped with a custom reader that is seeded with a fixed value — or if the challenge author swapped out the real `crypto/rand` for a fake one backed by `math/rand` with a hardcoded seed — every call produces the same output regardless of when you run it. The binary *looked* like it was calling `crypto/rand.Read` in the disassembly, but the underlying reader had been seeded with a constant, making every "random" value completely predictable.

This is a deliberate challenge design choice and a real-world vulnerability class: **code that appears to use secure randomness but actually uses a fixed seed is cryptographically broken**. The key, IV, and rand_byte being identical across every run meant the entire encryption scheme was deterministic — run the binary once in a debugger, read the values, and you can decrypt any output it ever produced.

### Verifying the Double Encryption

We noticed the function `0x4ae860` was called **twice** in the orchestrator. By stepping through, we confirmed:

1. **Call 1:** Encrypts the file content → produces `ct1`
2. **Call 2:** Encrypts `ct1` → produces `r12`

The flag name `d0ubl3_tr0ubl3` hints at this. The r12 buffer is thus the result of **double AES-CBC encryption**.

---

## Step 3: Extracting Data from the PNG

With the algorithm fully understood, we extracted the pixel data:

```python
from PIL import Image

img = Image.open('enc.png').convert('RGBA')
pixels = list(img.getdata())

# Data is at pixels 9900+, encoded as R=G=B=byte
png_data = bytes([pixels[i][0] for i in range(len(pixels)) if pixels[i][0] != 0])
# → 96 bytes
```

---

## Step 4: Full Decryption

The complete reverse pipeline:

```
PNG pixels  →  undo rand_byte XOR  →  undo index XOR  →  AES-CBC decrypt (×2)  →  strip PKCS7  →  plaintext
```

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = bytes.fromhex('52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649')
iv  = bytes.fromhex('81855ad8681d0d86d1e91e00167939cb')
rand_byte = 0x66

png_data = bytes.fromhex(
    '57fbf53170a37f30b868c2d305e0d17cb4541b4ee504ae2703edb99149abf678'
    'be9fb56ab22012bfd9f94a9105a2a894e3e464bc07b39b42a3e398802afcc80'
    '1b0f3a8051c1cbcc3ebcae1ab7d577bd56e44bfc79c16920bfaac3a2809493eb9'
)

def cbc_decrypt(data, key, iv):
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    return c.decryptor().update(data) + c.decryptor().finalize()

def strip_pkcs7(data):
    pad = data[-1]
    if 1 <= pad <= 16 and all(b == pad for b in data[-pad:]):
        return data[:-pad]
    return data

# Step 1: undo rand_byte XOR
step1 = bytes(b ^ rand_byte for b in png_data)

# Step 2: undo index XOR → recover r12
r12 = bytes(step1[i] ^ i for i in range(len(step1)))

# Step 3: AES-CBC decrypt (outer layer)
layer1 = cbc_decrypt(r12, key, iv)
layer1 = strip_pkcs7(layer1)

# Step 4: AES-CBC decrypt (inner layer)
layer2 = cbc_decrypt(layer1, key, iv)
plaintext = strip_pkcs7(layer2)

print(plaintext.decode('utf-8'))
# → dCRyp7{d0ubl3_tr0ubl3_f0ll0w3d_by_my_unkn0wn_bubbl3s_734m_r0ck3t}
```

---

## Full Encryption Pipeline (Reference)

```
File content
    │
    ▼
[AES-256-CBC encrypt] ←── hardcoded key + hardcoded IV
    │
    ▼  ct1
[AES-256-CBC encrypt] ←── same key + same IV  (double encryption)
    │
    ▼  r12  (64–96 bytes)
[XOR each byte with its index]   output[i] = r12[i] ^ i
    │
    ▼
[XOR each byte with rand_byte]   final[i] = output[i] ^ 0x66
    │
    ▼
[Write as PNG pixels, R=G=B=byte, A=255, starting at pixel 9900 of a 100×100 image]
    │
    ▼
enc.png
```

---

## Key Takeaways

**Why hardware breakpoints were necessary:**  
Go's runtime scheduler preempts goroutines between certain instructions. Software breakpoints (`int3`) can be skipped when the runtime migrates a goroutine to a different OS thread mid-execution. Hardware breakpoints use CPU debug registers and are OS-level — they fire regardless of what the runtime does.

**How we knew the values were hardcoded:**  
Running the binary 5+ times through pwndbg and observing that `r12`, the key, the IV, and `rand_byte` were byte-for-byte identical each time. Cryptographically random values would differ on every execution.

**How we confirmed double encryption:**  
The orchestrator function called `0x4ae860` twice sequentially. After the first call returned `ct1`, the second call received `ct1` as its plaintext input. Decrypting once gave a non-printable 48-byte blob; decrypting that a second time yielded the PKCS7-padded flag.

**Why the flag name fits:**  
`d0ubl3_tr0ubl3` refers to the double AES-CBC encryption. `unkn0wn_bubbl3s` likely references the obfuscated rand_byte XOR. `734m_r0ck3t` is just swagger.

---

---

## Skills Demonstrated

This challenge required chaining together several disciplines that are directly relevant to security engineering roles:

| Skill | Applied Here |
|-------|-------------|
| **Binary unpacking** | Manually defeated tampered UPX headers via ELF carving |
| **Reverse engineering** | Read 200k lines of Go x86-64 disassembly to reconstruct the algorithm |
| **Debugger proficiency** | Used pwndbg hardware breakpoints to overcome Go scheduler limitations |
| **Cryptanalysis** | Identified AES mode from PKCS7 padding patterns in raw assembly |
| **Dynamic analysis** | Proved hardcoded keys by observing identical values across multiple runs |
| **Python scripting** | Wrote a clean multi-step decryption pipeline from scratch |


## Flag

```
dCRyp7{d0ubl3_tr0ubl3_f0ll0w3d_by_my_unkn0wn_bubbl3s_734m_r0ck3t}
```
