This challenge was from picoctf live event 2026 where i was one of the few people who had solved this challenge

# JITFP - Complete CTF Writeup

**Category:** Reverse Engineering  
**Platform:** picoCTF  
**Points:** 500


## Step 1: Getting the Binary from SSH

The challenge provides SSH credentials. Connect:

```bash
ssh ctf-player@dolphin-cove.picoctf.net -p 60214
```

```bash
ssh_host:~$ ls
ad7e550b

ssh_host:~$ ./ad7e550b
Usage: ./ad7e550b <flag>

ssh_host:~$ ./ad7e550b test
================================v
*********************************
Incorrect
```

Takes ~34 seconds, always prints 33 stars, says Incorrect.

Now extract it for local analysis:

```bash
# On your local machine:
scp -P 60214 ctf-player@dolphin-cove.picoctf.net:~/ad7e550b ./
```

---

## Step 2: Analyzing the Binary

```bash
file ad7e550b
# ELF 64-bit LSB pie executable, x86-64,
# interpreter /lib/ld-musl-x86_64.so.1, stripped
```

Key facts:
- Linked against **musl libc** — not standard glibc
- **Stripped** — no debug symbols
- **PIE** — base address randomized by ASLR each run

```bash
strings ad7e550b
# Usage: %s <flag>
# Incorrect
```

### Disassembly

```bash
objdump -d ad7e550b
```

We found three key structures inside:

**Structure 1: 65 tiny checker functions**

Starting at offset `0x11d5`, spaced exactly `0x1d` bytes apart:

```asm
0x11d5:  cmpb $0x61, [rbp-4]   → checks 'a'
0x11f2:  cmpb $0x62, [rbp-4]   → checks 'b'
0x120f:  cmpb $0x63, [rbp-4]   → checks 'c'
...
0x1915:  cmpb $0x7d, [rbp-4]   → checks '}'
```

Each function takes one character as input and returns 1 (match) or 0 (no match). The full charset in order:
```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}
```

Formula: `checker[k]` lives at offset `0x11d5 + k * 0x1d`

**Structure 2: Table1** — hardcoded 33 integers in `.data` at offset `0x4020`:
```
(30,22,11,32,25,4,9,7,19,23,5,26,18,27,16,1,8,15,2,14,3,13,24,21,12,17,6,10,29,28,20,31,0)
```
This is **baked into the binary, never changes.** It maps each flag position to a checker index.

**Structure 3: Table2** — 33 function pointers in `.bss` at offset `0x4120`:
- **Zero in the binary file** (`.bss` is always zero-initialized on disk)
- Gets filled with pointers to checker functions at runtime
- **Reshuffled every second** while running

### Main Loop Logic

```
for j = 0 to 32:
    sleep(1 second)
    reshuffle table2 with new function pointers
    k    = table1[j]        ← which checker to use
    func = table2[k]        ← get that checker function
    if func(flag[j]) == 0:  ← does flag[j] match?
        print Incorrect
        exit
print Correct
```

So at each position `j`, the binary asks:
> *"does flag[j] equal the character that table2[table1[j]] currently points to?"*

---

## Step 3: Why We Couldn't Get the Flag Locally

We tried patching the binary to run on our local machine with glibc instead of musl:
Also tried manually populating the table so it actually has a sequence to crosscheck

```python
# patch interpreter:
# /lib/ld-musl-x86_64.so.1 → /lib64/ld-linux-x86-64.so.2
# patch library:
# libc.musl-x86_64.so.1 → libc.so.6
```

It ran — but gave the completely wrong flag `EwlGzejhtxfAsBqbipcodnyvmrgkDCuFa`.
Expected since we manually populated the table

**Why?** Musl and glibc initialize table2 differently. The shuffle sequence on glibc is completely different from musl. This is exactly what the challenge description warned:

> *"The catch is it only functions properly on the host on which we found it."*

The flag could only be extracted correctly from the **live musl binary running on the remote server.**
I later got to know there was a script in /root which was populating the table which we didnt have access to

---

## Step 4: Discovering the Memory Reading Approach

We read table2 from the live process twice, 1 second apart on the remote:

```
Read at t=5s:
  t2[0] = 0x18be → '9'
  t2[1] = 0x184a → '5'
  t2[2] = 0x1266 → 'f'
  ...

Read at t=6s:
  t2[0] = 0x1915 → '}'
  t2[1] = 0x1884 → '7'
  t2[2] = 0x1314 → 'l'
  ...

WARNING: table changed between reads!
```

**Every single entry changed between reads.** Table2 reshuffles completely every second. This means we need to read `table2[table1[j]]` at **exactly** the right moment for each position `j`.

### The Right Moment

```
t = j+0.0s  ← binary starts sleep(1) for position j
t = j+0.5s  ← table2 is STABLE here → READ NOW ✓
t = j+1.0s  ← binary wakes up, reshuffles table2, checks flag[j]
```

Reading at `t = j + 0.5s` = midpoint of the sleep = table2 is stable and correct.

### How `/proc/pid/mem` Works

On Linux, every running process has a folder at `/proc/<pid>/` containing information about it. Inside is a special file called `mem` — **a direct window into that process's RAM.**

```python
mem = open('/proc/1234/mem', 'rb')  # open child's RAM like a file
mem.seek(some_address)              # go to any address
data = mem.read(8)                  # read bytes directly from RAM
```

A parent process can read its child's memory this way — the same mechanism real debuggers like `gdb` use under the hood.

---

## Step 5: The Exploit

**The plan:**
1. Fork a child process running the binary with dummy input (keeps it alive 34 seconds)
2. Find child's base address via `/proc/pid/maps` (needed because of ASLR)
3. For each position `j`, read `table2[table1[j]]` from child's RAM at `t = j + 0.5s`
4. Convert the pointer to a character
5. Immediately run the binary with the reconstructed flag

**The conversion:**
```
ptr    = 0x7f8b1f811915   ← raw pointer read from RAM
base   = 0x7f8b1f800000   ← where binary loaded (from /proc/pid/maps)
offset = ptr - base       ← = 0x1915 (offset within binary)

0x1915 = 0x11d5 + 64 * 0x1d
→ checker index 64
→ chars[64] = '}'
```

Since no text editor was available on the remote server, we ran everything as a Python one-liner directly in the SSH terminal:

```bash
python3 -c "
import os,time,struct
pid=os.fork()
if pid==0:
 os.execv('./ad7e550b',['./ad7e550b','x'*33])
else:
 time.sleep(0.5)
 maps=open(f'/proc/{pid}/maps').read()
 base=int([l for l in maps.splitlines() if 'ad7e550b' in l][0].split('-')[0],16)
 chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}'
 offmap={0x11d5+i*0x1d:c for i,c in enumerate(chars)}
 t1=(30,22,11,32,25,4,9,7,19,23,5,26,18,27,16,1,8,15,2,14,3,13,24,21,12,17,6,10,29,28,20,31,0)
 flag=[]
 start=time.time()
 for j in range(33):
  while time.time()-start < j: pass
  mem=open(f'/proc/{pid}/mem','rb',0)
  mem.seek(base+0x4120+t1[j]*8)
  ptr=struct.unpack('<Q',mem.read(8))[0]
  mem.close()
  off=ptr-base if ptr else 0
  c=offmap.get(off,'?')
  flag.append(c)
  print(f'[{j}] {c}',flush=True)
 os.kill(pid,9)
 os.waitpid(pid,0)
 f=''.join(flag)
 print('picoCTF{'+f+'}')
 os.execlp('./ad7e550b','./ad7e550b',f)
"
```

---

## Step 6: Output

```
[0]  p
[1]  r
[2]  0
[3]  c
[4]  f
[5]  5
[6]  _
[7]  d
[8]  3
[9]  6
[10] u
[11] g
[12] g
[13] 3
[14] r
[15] _
[16] 1
[17] 6
[18] 8
[19] 7
[20] e
[21] 0
[22] 0
[23] c
...
================================v
*********************************
Correct

picoCTF{pr0cf5_d36ugg3r_1687e00c}
```

---

## Binary Info

The extracted binary `ad7e550b` is the challenge file itself — obtained via:

```bash
scp -P 60214 ctf-player@dolphin-cove.picoctf.net:~/ad7e550b ./
```

- **Format:** ELF 64-bit LSB PIE executable, x86-64
- **Libc:** musl (statically linked style, dynamic via musl loader)
- **Stripped:** yes
- **BuildID SHA1:** `d7a3d6cbf9cf240eb59d0ebba874cd3021be5a3e`

---

## Summary

| Stage | What We Did |
|---|---|
| Got binary | SCP from SSH instance |
| Identified structure | objdump → 65 checkers, table1, table2 |
| Tried local run | Failed — musl vs glibc gives different flag |
| Discovered reshuffling | Two memory reads 1s apart → every entry changed |
| Solution | `/proc/pid/mem` to read child's RAM each second |
| Extraction | Fork child, read table2[table1[j]] at t=j+0.5s for each j |
| Verification | execlp binary with flag → Correct |

## Flag

```
picoCTF{pr0cf5_d36ugg3r_1687e00c}
```
