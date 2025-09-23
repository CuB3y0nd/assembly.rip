---
title: "CHOP Suey: 端上异常处理的攻击盛宴"
published: 2025-09-23
updated: 2025-09-23
description: "异常的刀锋之 Catch Handler Oriented Programming 学习小记。"
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.67xtux8127.avif"
tags: ["Pwn", "CHOP", "Notes"]
category: "Notes"
draft: false
---

# 前言

今天刚复现完 2024 年羊城杯的 [logger](/posts/write-ups/2024-羊城杯/#logger)，一道简单的涉及 C++ 异常处理机制的缓冲区溢出题，感觉还挺有意思，了解了一下发现有一种专门针对于异常处理而发展出来的 ROP 手法，叫做 `CHOP (Catch Handler Oriented Programming)`，也有称其为 `EOP (Exception Oriented Programming)` 的，这里我就直接沿袭原论文中的命名了。我也是参考了多方博客学习的，现在打算自己写一篇，以增强个人理解，因为我发现别人的博客里其实有些地方写的有点小问题，可能作者当时也没怎么理解到位<s>_（虽然我只是个菜鸡，但我认为质疑精神还是很可贵的……）_</s>，但是写的确实很不错，至少让我学明白了哈哈哈。

~_PS: 等有空了我想好好研读一下那篇论文，体验一下搞科研的感觉是什么样的（bushi_~

:::important
本文将主要研究如何通过缓冲区溢出漏洞，利用 Linux 下的 C++ 异常处理机制，跳转到任意 catch 流，执行任意函数。

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

TODO

## 秩序之火：任意调用与自由的幻象

TODO

# References

- [溢出漏洞在异常处理中的攻击利用手法-上](https://rivers.chaitin.cn/blog/cq70jnqp1rhtmlvvdmng)
- [溢出漏洞在异常处理中的攻击手法-下](https://rivers.chaitin.cn/blog/cq70jnqp1rhtmlvvdpng)
- [分享 C++ PWN 出题经历——深入研究异常处理机制](https://zhuanlan.zhihu.com/p/13157062538)
- [Let Me Unwind That For You: Exceptions to Backward-Edge Protection](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s295_paper.pdf)
