---
title: "Notes: Pwn heap fundamental knowledge"
pubDate: "2025-02-06 15:42"
modDate: "2025-02-07 00:10"
categories:
  - "Pwn"
  - "Heap"
  - "Notes"
description: "This notes is for explaining some fundamental knowledge of heap (managed by dynamic allocator). From the easiest things to even harder things."
slug: "pwn-heap-notes"
---

## Table of contents

## 前言

初识 Heap 就要被大量基础知识狠狠地冲击，为了巩固所学，同时秉持开源共享的精神，我决定单独撰写一篇 blog 来系统的整理一下这方面的笔记。说来惭愧，栈我一个字的笔记都没写（日后有空应该大概可能或许会写吧），可见堆的难度……

~_幻想我跨过瓶颈期的那天……一定……会很爽吧？_~

## Terminology

首先让我们了解一下堆 (Heap) 这个 terminology 的由来，注意我们讨论的堆可**不是数据结构中的「堆」**。

Heap 在英语中本义是「堆积物」，表示一块随意堆放、无特定顺序的集合。这个词被借用于计算机内存管理中，是因为堆内存允许程序在运行时根据需要在任何位置动态分配和释放内存块，这会形成一种「堆积」的状态，形象吧？

总之，我们所研究的堆，通常来说就是由动态分配器 (dynamic allocator) 所管理的那个堆。

## What's the different with stack?

让我们先 recap 一下栈。栈一般用于存放局部变量，函数调用信息等内容，当函数作用域结束后，这块空间（栈帧）就自动释放了，因此不适合做长期存储，而且栈空间也有限，不适合存储大量数据。

堆与栈的一大区别在于，堆可以动态分配空间，要多少分多少，并且分配出来的内存全局可用，通过堆指针可以在程序的任何地方访问和修改它。若非手动释放的话，生命周期会维持到程序结束。

## When should we use the heap?

可以粗暴的说堆的存在就是为了解决栈的各种不适合的问题。常见用途有：

- 动态内存需求（在程序运行时，根据实际情况动态分配内存）
- 跨函数作用域共享

栈空间有限，不能全局使用，堆空间大，管理内存灵活……到现在都是在说堆的优点，那它的缺点呢？

- 分配速度慢
- 容易产生内存碎片
- 需要手动分配和释放，容易产生安全问题

不过现在有像 Rust 这样的语言，它们提供了更安全的内存管理就是了。

## Implementations

为了满足这些需求，其实有一个现成的函数可供使用，那就是 `mmap`。

使用 `mmap` 可以解决动态分配/释放的问题，`mmap` 分配的内存生命周期也可以维持到程序结束。但我们最后没有使用它作为动态内存管理手段肯定是有原因的……首先它分配内存不灵活，必须按页分配（如果你的页大小设置为 4096，你就必须分配 4096 的倍数大小，这很浪费），其次，`mmap` 分配内存需要内核参与，which is crazy slow...

更明智的解决方案是写一个库，先 `mmap` 出来一块足够霍霍的空间，然后根据需求在此基础上分出各种小块的内存供使用……

```c
char *firstname = allocate_memory(128);
char *lastname = allocate_memory(256);

scanf("%s %s", firstname, lastname);
printf("Hello %s %s!", firstname, lastname);

free_memory(firstname);
free_memory(lastname);
```

<a href="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Untitled-2024-02-06-132221.svg" data-fancybox data-caption>
  <center>
    <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Untitled-2024-02-06-132221.svg" />
  </center>
</a>

嗯……我们永远不是第一个有想法的人<s>_（真 TM 的令人难过）_</s>，事实上早已存在很多更成熟的解决方案了。

- Doug Lea 在 1987 年发布了 dlmalloc（历史上最具影响力、性能最优的早期实现之一，成为后续 malloc 实现的经典蓝图）
- Linux 一般使用 ptmalloc (Posix Thread aware fork of dlmalloc)
- FreeBSD 的 jemalloc (also used in Firefox, Android)
- Windows 下是 Segment Heap, NT Heap
- Linux kernel 使用 kmalloc
- iOS kernel 使用 kalloc

多吧？可不止这么多……后续做堆漏洞研究你还得去读它们的实现代码呢……动辄几千行，不同版本的代码都需要读，因为很多漏洞只存在于特定版本……

## How to use the heap?

我们主要关注的是 ptmalloc/glibc 的堆管理器实现（其它实现类似），通常可以通过这些函数来管理堆内存：

- `malloc()` allocate some memory
- `free()` free a prior allocated chunk

上面两个是常用的主要函数，还有很多辅助函数：

- `realloc()` change the size of an allocation
- `calloc()` allocate and zero-out memory

## How does the heap work?

事实上 `ptmalloc` 并没有使用 `mmap` 来实现动态内存管理，而是使用了所谓的 `data segment`。通过 ASLR，`data segment` 通常被随机放置在某个靠近但不紧贴 PIE 地址的地方，起始大小为零，所以在没有分配堆内存的时候我们无法通过 `/proc/self/maps` 看到它。

内存的分配通过 `brk` 和 `sbrk` 这两个系统调用来进行：

- `brk(NULL)` returns the end of the data segment
- `brk(addr)` expands the end of the data segment to addr
- `sbrk(NULL)` returns the end of the data segment
- `sbrk(delta)` expands the end of the data segment by delta bytes

ptmalloc 在进行小规模分配时，会切分数据段的若干位，而在进行大规模分配时，则会使用 `mmap`。

> 理论派就是知道原理，却什么都做不出来。<br />
> 实践派就是做出结果，但没人知道为什么。
>
> 我们的实验室则融合了理论与实践：<br />
> 什么都做不出来，也没人知道为什么。

错了哥，为了避免大家成为理论 fw，我写了个程序，可以通过 `strace` 来观察程序进行 `malloc` 时都做了些啥。

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF_SIZE 4096

void mem_maps() {
  int fd = open("/proc/self/maps", O_RDONLY);

  if (fd == -1) {
    perror("open failed");
    return;
  }

  char buffer[BUF_SIZE];
  ssize_t bytes_read;

  while ((bytes_read = read(fd, buffer, BUF_SIZE)) > 0) {
    write(1, buffer, bytes_read);
  }

  fprintf(stderr, "\n");

  if (bytes_read == -1) {
    perror("read failed");
  }

  close(fd);
}

int main(int argc, char *argv[])
{
  mem_maps();
  fprintf(stderr, "About to perform a small malloc()\n");
  malloc(16);
  mem_maps();
  fprintf(stderr, "About to perform a large malloc()\n");
  malloc(0x10000);
  malloc(0x10000);
  malloc(0x10000);
  mem_maps();
  fprintf(stderr, "About to perform a super large malloc()\n");
  malloc(0x100000);
  mem_maps();

  return 0;
}
```

```plaintext wrap=false showLineNumbers=false {43, 77, 112} ins={34-35, 69, 103}
openat(AT_FDCWD, '/proc/self/maps', O_RDONLY) = 3
read(3, 0x00007ffe3d394790, 4096)        = 2104 (0x0000000000000838)
5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e43000-5cce27e44000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e44000-5cce27e45000 rw-p 00003000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
71b642383000-71b642386000 rw-p 00000000 00:00 0
71b642386000-71b6423aa000 r--p 00000000 103:06 10882402                  /usr/lib/libc.so.6
71b6423aa000-71b64251b000 r-xp 00024000 103:06 10882402                  /usr/lib/libc.so.6
71b64251b000-71b64256a000 r--p 00195000 103:06 10882402                  /usr/lib/libc.so.6
71b64256a000-71b64256e000 r--p 001e3000 103:06 10882402                  /usr/lib/libc.so.6
71b64256e000-71b642570000 rw-p 001e7000 103:06 10882402                  /usr/lib/libc.so.6
71b642570000-71b64257a000 rw-p 00000000 00:00 0
71b6425a3000-71b6425a5000 r--p 00000000 00:00 0                          [vvar]
71b6425a5000-71b6425a7000 r--p 00000000 00:00 0                          [vvar_vclock]
71b6425a7000-71b6425a9000 r-xp 00000000 00:00 0                          [vdso]
71b6425a9000-71b6425aa000 r--p 00000000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425aa000-71b6425d3000 r-xp 00001000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425d3000-71b6425de000 r--p 0002a000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425de000-71b6425e0000 r--p 00035000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e0000-71b6425e1000 rw-p 00037000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e1000-71b6425e2000 rw-p 00000000 00:00 0
7ffe3d376000-7ffe3d397000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
write(1, '5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                   '..., 2104) = 2104 (0x0000000000000838)
read(3, 0x00007ffe3d394790, 4096)        = 0

write(2, '\n', 1)                        = 1
close(3)                                 = 0
About to perform a small malloc()
write(2, 'About to perform a small malloc()\n', 34) = 34 (0x0000000000000022)
getrandom(0x000071b642575238, 8, 1)      = 8
brk(0)                                   = 102041435488256 (0x00005cce5f83c000)
brk(102041435623424)                     = 102041435623424 (0x00005cce5f85d000)
openat(AT_FDCWD, '/proc/self/maps', O_RDONLY) = 3
read(3, 0x00007ffe3d394790, 4096)        = 2184 (0x0000000000000888)
5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e43000-5cce27e44000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e44000-5cce27e45000 rw-p 00003000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce5f83c000-5cce5f85d000 rw-p 00000000 00:00 0                          [heap]
71b642383000-71b642386000 rw-p 00000000 00:00 0
71b642386000-71b6423aa000 r--p 00000000 103:06 10882402                  /usr/lib/libc.so.6
71b6423aa000-71b64251b000 r-xp 00024000 103:06 10882402                  /usr/lib/libc.so.6
71b64251b000-71b64256a000 r--p 00195000 103:06 10882402                  /usr/lib/libc.so.6
71b64256a000-71b64256e000 r--p 001e3000 103:06 10882402                  /usr/lib/libc.so.6
71b64256e000-71b642570000 rw-p 001e7000 103:06 10882402                  /usr/lib/libc.so.6
71b642570000-71b64257a000 rw-p 00000000 00:00 0
71b6425a3000-71b6425a5000 r--p 00000000 00:00 0                          [vvar]
71b6425a5000-71b6425a7000 r--p 00000000 00:00 0                          [vvar_vclock]
71b6425a7000-71b6425a9000 r-xp 00000000 00:00 0                          [vdso]
71b6425a9000-71b6425aa000 r--p 00000000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425aa000-71b6425d3000 r-xp 00001000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425d3000-71b6425de000 r--p 0002a000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425de000-71b6425e0000 r--p 00035000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e0000-71b6425e1000 rw-p 00037000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e1000-71b6425e2000 rw-p 00000000 00:00 0
7ffe3d376000-7ffe3d397000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
write(1, '5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                   '..., 2184) = 2184 (0x0000000000000888)
read(3, 0x00007ffe3d394790, 4096)        = 0

write(2, '\n', 1)                        = 1
close(3)                                 = 0
About to perform a large malloc()
write(2, 'About to perform a large malloc()\n', 34) = 34 (0x0000000000000022)
brk(102041435820032)                     = 102041435820032 (0x00005cce5f88d000)
openat(AT_FDCWD, '/proc/self/maps', O_RDONLY) = 3
read(3, 0x00007ffe3d394790, 4096)        = 2184 (0x0000000000000888)
5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e43000-5cce27e44000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e44000-5cce27e45000 rw-p 00003000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce5f83c000-5cce5f88d000 rw-p 00000000 00:00 0                          [heap]
71b642383000-71b642386000 rw-p 00000000 00:00 0
71b642386000-71b6423aa000 r--p 00000000 103:06 10882402                  /usr/lib/libc.so.6
71b6423aa000-71b64251b000 r-xp 00024000 103:06 10882402                  /usr/lib/libc.so.6
71b64251b000-71b64256a000 r--p 00195000 103:06 10882402                  /usr/lib/libc.so.6
71b64256a000-71b64256e000 r--p 001e3000 103:06 10882402                  /usr/lib/libc.so.6
71b64256e000-71b642570000 rw-p 001e7000 103:06 10882402                  /usr/lib/libc.so.6
71b642570000-71b64257a000 rw-p 00000000 00:00 0
71b6425a3000-71b6425a5000 r--p 00000000 00:00 0                          [vvar]
71b6425a5000-71b6425a7000 r--p 00000000 00:00 0                          [vvar_vclock]
71b6425a7000-71b6425a9000 r-xp 00000000 00:00 0                          [vdso]
71b6425a9000-71b6425aa000 r--p 00000000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425aa000-71b6425d3000 r-xp 00001000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425d3000-71b6425de000 r--p 0002a000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425de000-71b6425e0000 r--p 00035000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e0000-71b6425e1000 rw-p 00037000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e1000-71b6425e2000 rw-p 00000000 00:00 0
7ffe3d376000-7ffe3d397000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
write(1, '5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                   '..., 2184) = 2184 (0x0000000000000888)
read(3, 0x00007ffe3d394790, 4096)        = 0

write(2, '\n', 1)                        = 1
close(3)                                 = 0
About to perform a super large malloc()
write(2, 'About to perform a super large malloc()\n', 40) = 40 (0x0000000000000028)
mmap(0, 1052672, <PROT_READ|PROT_WRITE> (3), 34, 4294967295, 0) = 125027607912448 (0x000071b642282000)
openat(AT_FDCWD, '/proc/self/maps', O_RDONLY) = 3
read(3, 0x00007ffe3d394790, 4096)        = 2184 (0x0000000000000888)
5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e43000-5cce27e44000 r--p 00002000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce27e44000-5cce27e45000 rw-p 00003000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap
5cce5f83c000-5cce5f88d000 rw-p 00000000 00:00 0                          [heap]
71b642282000-71b642386000 rw-p 00000000 00:00 0
71b642386000-71b6423aa000 r--p 00000000 103:06 10882402                  /usr/lib/libc.so.6
71b6423aa000-71b64251b000 r-xp 00024000 103:06 10882402                  /usr/lib/libc.so.6
71b64251b000-71b64256a000 r--p 00195000 103:06 10882402                  /usr/lib/libc.so.6
71b64256a000-71b64256e000 r--p 001e3000 103:06 10882402                  /usr/lib/libc.so.6
71b64256e000-71b642570000 rw-p 001e7000 103:06 10882402                  /usr/lib/libc.so.6
71b642570000-71b64257a000 rw-p 00000000 00:00 0
71b6425a3000-71b6425a5000 r--p 00000000 00:00 0                          [vvar]
71b6425a5000-71b6425a7000 r--p 00000000 00:00 0                          [vvar_vclock]
71b6425a7000-71b6425a9000 r-xp 00000000 00:00 0                          [vdso]
71b6425a9000-71b6425aa000 r--p 00000000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425aa000-71b6425d3000 r-xp 00001000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425d3000-71b6425de000 r--p 0002a000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425de000-71b6425e0000 r--p 00035000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e0000-71b6425e1000 rw-p 00037000 103:06 10882358                  /usr/lib/ld-linux-x86-64.so.2
71b6425e1000-71b6425e2000 rw-p 00000000 00:00 0
7ffe3d376000-7ffe3d397000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
write(1, '5cce27e40000-5cce27e41000 r--p 00000000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e41000-5cce27e42000 r-xp 00001000 103:07 131093                    /home/cub3y0nd/Projects/pwn.college/heap\n5cce27e42000-5cce27e43000 r--p 00002000 103:07 131093                   '..., 2184) = 2184 (0x0000000000000888)
read(3, 0x00007ffe3d394790, 4096)        = 0

write(2, '\n', 1)                        = 1
close(3)                                 = 0
exit_group(0)
*** Process 147011 exited normally ***
```

正如理论告诉我们的一样，在还没 malloc 前，程序的内存映射里面是看不到堆的；在第一次 malloc 之后，程序在「靠近」 PIE 的地方分配了 `0x21000` 字节的堆空间，从 `0x5cce5f83c000` 到 `0x5cce5f85d000`；之后进行一个比较大的内存分配，这是在原空间的基础上扩增了 `0x30000` 字节到 `0x5cce5f88d000`；最后进行一个特别大的分配，这次因为太大了所以使用的是 `mmap`，以避免内存碎片的问题。

<s>还有一些理论没有告诉你的，就由我来告诉你。</s>通常情况下，Linux 会在 heap 后面开始映射 mmap 区域，这片区域被称为匿名映射区。

## What can go wrong?

一切问题的产生，究其根本都离不开人类，~_因此只有解决了人类才有可能解决问题 (bushi_~

我们都知道人有各种各样的缺点……对于堆的使用，人们可能：

- humans forget to free memory
- humans forget all the spots where they store pointers to data
- humans forget what they've freed

除了人的问题……库追求极致的性能也会导致问题（还是离不开人）：

- allocation and deallocation needs to be fast, or programs will slow down
- optimizations often leave security as an afterthought

## How to detect issues?

市面上有很多工具都可以用来检测问题，但事实上还不存在检测这方面问题的通用技术。

比如 valgrind 可以检测一些堆误用，如果你的测试用例覆盖到了的话……glibc 本身也提供了很多加固措施，但是其中有些会造成严重的性能损失……人们一直在积极开发各种「更安全」的堆管理器，但它们要么被留在学术 paper 上了，要么因为种种原因根本没部署……
