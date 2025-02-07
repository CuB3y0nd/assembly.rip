---
title: "Notes: Pwn heap fundamental knowledge"
pubDate: "2025-02-06 15:42"
modDate: "2025-02-07 23:40"
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

一切的恐惧来源于经验不足，~_幻想我跨过瓶颈期的那天……一定……会很爽吧？_~

咳咳，先声明一下：因为这本质上算是我的个人笔记，而非对外「教材」，所以我基本上是想写什么，分析什么，就写什么了，尤其是在分析 glibc 源码的时候，写的比较杂，一般并不会只专注于一个有用的核心知识，中间可能会根据心情发散出来很多无关内容的分析。所以整体上内容并不会显得那么循序渐进，可能不太适合新人食用<s>_（虽然我现在就是从零开始学的？应该说和严谨的系统性教学文相比是不行，谁知道我潜意识里消化了多少外部文献的内容……）_</s>。当然，如果你是好学宝宝<s>_/大佬走开，走开～_</s>，我的笔记可能会大大的扩大你的知识面？

~_读 glibc 源码恶补 C 语言真是自虐啊，你别说还挺爽？_~

## Terminology

首先让我们了解一下堆 (Heap) 这个 terminology 的由来，注意我们讨论的堆可**不是数据结构中的「堆」**。

Heap 在英语中本义是「堆积物」，表示一块随意堆放、无特定顺序的集合。这个词被借用于计算机内存管理中，是因为堆内存允许程序在运行时根据需要在任何位置动态分配和释放内存块，这会形成一种「堆积」的状态，形象吧？

总之，我们所研究的堆，通常来说就是由动态分配器 (dynamic allocator) 所管理的那个堆。

## Dynamic Allocator?

动态分配器 (Dynamic Allocator) 也叫做堆管理器，介于用户程序与内核之间，主要做如下工作：

1. 响应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序。同时，为了保证内存管理的高效性，内核一般都会预先分配很大的一块连续的内存，然后让堆管理器通过某种算法管理这块内存。只有当出现了堆空间不足的情况，堆管理器才会再次与操作系统进行交互。
2. 管理用户所释放的内存。一般来说，用户释放的内存并不是直接返还给操作系统的，而是由堆管理器进行管理。这些释放的内存可以用来响应用户的新的申请内存的请求。

Linux 中早期的堆分配与回收由 [Doug Lea](https://gee.cs.oswego.edu/) 实现，叫做 `dlmalloc`，但它在并行处理多个线程时，会共享进程的堆内存空间。因此，为了安全性，一个线程使用堆时，会进行加锁。然而，与此同时，加锁会导致其它线程无法使用堆，降低了内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能影响内存分配和回收的正确性。因此 [Wolfram Gloger](http://www.malloc.de/en/) 在 Doug Lea 实现的 dlmalloc 的基础上进行改进，使其可以支持多线程，这个改进后的堆分配器就是 `ptmalloc`。`glibc 2.1` 开始使用 `ptmalloc`，`glibc 2.3` 开始默认使用 `ptmalloc2`，进一步优化了 arena 管理，使多核环境下的性能得到显著提升。

目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通过 malloc/free 函数来分配和释放内存块。

需要注意的是，在内存分配与使用的过程中，Linux 有这样的一个基本内存管理思想，只有当真正访问一个地址的时候，系统才会建立虚拟页与物理页之间的映射关系。 所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页给用户使用。

## What's the different with stack?

我们先 recap 一下栈。栈由高地址向低地址增长，一般用于存放局部变量，函数调用信息等内容，当函数作用域结束后，这块空间（栈帧）就自动释放了，因此不适合做长期存储，而且栈空间也有限，不适合存储大量数据。

堆与栈的一大区别在于，首先，它由低地址向高地址增长，其次堆可以动态分配空间，要多少分多少，并且分配出来的内存全局可用，通过堆指针可以在程序的任何地方访问和修改它。若非手动释放的话，生命周期会维持到程序结束。

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

可以看到 glibc 在 [malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c#L574) 中对于这两个函数给出的介绍：

```c showLineNumbers=false
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.

  If n is zero, malloc returns a minimum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
```

```c showLineNumbers=false
/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. It can have arbitrary (i.e., bad!)
  effects if p has already been freed.

  Unless disabled (using mallopt), freeing very large spaces will
  when possible, automatically trigger operations that give
  back unused memory to the system, thus reducing program footprint.
*/
```

上面两个是常用的主要函数，还有很多辅助函数：

- `realloc()` change the size of an allocation
- `calloc()` allocate and zero-out memory

## How does the heap work?

事实上 `ptmalloc` 并没有使用 [mmap/munmap](https://man7.org/linux/man-pages/man2/mmap.2.html) 来实现动态内存管理，而是使用了所谓的 `data segment`。通过 ASLR，`data segment` 通常被随机放置在某个靠近但不紧贴 PIE 地址的地方，起始大小为零，所以在没有分配堆内存的时候我们无法通过 `/proc/self/maps` 看到它。

内存的分配通过 [(s)brk](https://man7.org/linux/man-pages/man2/sbrk.2.html) 系统调用来进行：

- `brk(NULL)` returns the end of the data segment
- `brk(addr)` expands the end of the data segment to addr
- `sbrk(NULL)` returns the end of the data segment
- `sbrk(delta)` expands the end of the data segment by delta bytes

`brk` 是内核提供的系统调用，而 `sbrk` 是 `(g)libc` 提供的一个用户空间的封装，底层还是调用了 `brk`。

ptmalloc 在进行小规模分配时，会切分数据段的若干位，而在进行大规模分配时，则会使用 `mmap`。

> 理论派就是知道原理，却什么都做不出来。<br />
> 实践派就是做出结果，但没人知道为什么。
>
> 我们的实验室则融合了理论与实践：<br />
> ~什么都做不出来，也没人知道为什么。~

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

正如理论告诉我们的一样，在还没 malloc 前，程序的内存映射里面是看不到堆的；在第一次 malloc 之后，程序在「靠近」 PIE 的地方分配了 `0x21000` 字节的堆空间，从 `0x5cce5f83c000` 到 `0x5cce5f85d000`。你可能疑惑：我们明明只申请了 16 字节，为什么返回那么大的空间？这是为了避免频繁的内核态与用户态的切换，提高程序的效率。此外，我们称分配下来的这块连续的内存区域为 `arena`，而在多线程程序中，由主线程申请的内存被称为 `main_arena`，子线程申请的内存被称为 `thread_arena`。后续申请的内存会一直从这个 arena 中获取，直到空间不足。当 arena 空间不足时，它可以通过 brk 来增加堆的空间。类似地，也可以通过 brk 来缩小自己的空间；之后进行一个比较大的内存分配，这是在原空间的基础上扩增了 `0x30000` 字节到 `0x5cce5f88d000`；最后进行一个特别大的分配，这次因为太大了所以使用的是 `mmap`，以避免内存碎片的问题。

<s>还有一些理论没有告诉你的，就由我来告诉你。</s>通常情况下，Linux 会在 heap 后面开始映射 mmap 区域，这片区域被称为匿名映射区。当用户请求的内存大于 128 KB，比如 `malloc(132 * 1024)`，并且没有任何 arena 有足够的空间时，那么系统就会调用 mmap 来分配相应的内存空间。这与这个请求来自于主线程还是子线程无关。另外，子线程一般使用 mmap 分配堆内存，而非 brk，这是为了不干扰主线程或其它线程。如果多个线程同时修改 brk 的堆顶，会导致数据竞争，令内存管理变复杂，带来性能和稳定性问题。

[Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/) 演示了一个多线程 malloc 的底层情况分析，感兴趣的可以看看。

## What can go wrong?

一切问题的产生，究其根本都离不开人类，~_因此只有解决了人类才有可能解决问题 (bushi_~

我们都知道人有各种各样的缺点……对于堆的使用：

- humans forget to free memory
- humans forget all the spots where they store pointers to data
- humans forget what they've freed

除了人的问题……库追求极致的性能也会导致问题（还是离不开人）：

- allocation and deallocation needs to be fast, or programs will slow down
- optimizations often leave security as an afterthought

### Security vs Performance

<a href="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Untitled-2024-02-07-132220.svg" data-fancybox data-caption="The lifecycle of allocator security.">
  <center>
    <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Untitled-2024-02-07-132220.svg" />
  </center>
</a>

## How to detect issues?

市面上有很多工具都可以用来检测问题，但事实上还不存在检测这方面问题的通用技术。

比如 valgrind 可以检测一些堆误用，如果你的测试用例覆盖到了的话……glibc 本身也提供了很多加固措施，但是其中有些会造成严重的性能损失……人们一直在积极开发各种「更安全」的堆管理器，但它们要么被留在学术 paper 上了，要么因为种种原因根本没部署……

## Common Dangers

- Forgetting to free memory
  - Leads to resource exhaustion
- Forgetting that we have freed memory
  - Using free memory
  - Freeing free memory
- Corrupting metadata used by the allocator to keep track of heap state
  - Conceptually similar to corruption internal function state on the stack
- Overlapping Allocations
  - Typically, heap metadata corruption is used to confuse the allocator into allocating overlapping memory, this can be extremely dangerous

最早广泛使用的堆漏洞之一，由 Solar Designer 于 2000 年发布：[JPEG COM Marker Processing Vulnerability](https://www.openwall.com/articles/JPEG-COM-Marker-Vulnerability).

很快于 2001 年在黑客文献中被公式化：

- [Vudo malloc tricks, by MaXX](https://phrack.org/issues/57/8)
- [Once upon a free(), by anonymous](https://phrack.org/issues/57/9)

一个全新的流派就此出现在黑客圈……

## The Rise of the Houses

最早的 "The House of XXX" 命名风格可以追溯到 Phantasmal Phantasmagoria 发布的 [The Malloc Maleficarum](https://seclists.org/bugtraq/2005/Oct/118).

这篇文章提出了一些 "Houses"，描述了不同的堆利用方法，就像不同的 "House" 中有不同的陷阱机制。

- The House of Prime
- The House of Mind
- The House of Force
- The House of Lore
- The House of Spirit
- The House of Chaos

令人震惊的是这些最早发布的利用技术中有一些至今仍然有效。

事情很快就失控了……黑客们趋之若鹜纷纷效仿这种「奇怪的」命名风格，公开了一系列新技术：

- House of Underground
- House of Orange
- House of Einherjar
- House of Rabbit
- House of Botcake

## tcache

历史课上完了，是时候讲点不那么轻松的东西了。

线程本地缓存 `tcache (Thread Local Caching)` 是在 glibc 2.26, Ubuntu 17.10 之后引入的一种新技术 ([commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc))，旨在加速在一个线程中的重复的小块内存分配，提升堆管理的性能。但提升性能的同时也舍弃了很多安全检查，因此有了很多新的利用方式。

`tcache` 是通过单链表实现的，每一个线程都有一个 `tcache_perthread_struct`，用于缓存线程中不同大小的一类内存块。

```c
// https://github.com/bminor/glibc/blob/master/malloc/malloc.c

#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS  64
# define MAX_TCACHE_SIZE tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx) (((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7

/* Maximum chunks in tcache bins for tunables.  This value must fit the range
   of tcache->counts[] entries, else they may overflow.  */
# define MAX_TCACHE_COUNT UINT16_MAX
#endif

/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

先解释一下部分宏的定义：

- `TCACHE_MAX_BINS` 设置了 tcache 最大可管理的 bins 数，每个 bin 都负责管理一组特定大小的内存块
- `MAX_TCACHE_SIZE` 通过 `tidx2usize (TCACHE_MAX_BINS-1)` 计算 bin 可存储的最大内存块大小
- `TCACHE_FILL_COUNT` 设置了每条 tcache_entry 链上可以存放多少个 free()ed 的 chunk
- `MAX_TCACHE_COUNT` 限制了每个 bin 中最多允许存储的块数量。`UINT16_MAX` 即 `2^16 - 1` 个。默认情况下，`TCACHE_FILL_COUNT` 为 7，即每个 bin 通常最多缓存 7 个 chunks，但通过 tunables 可以调整这个数量
- `tidx2usize(idx)` 通过 bin 的索引给出这个 bin 存储的内存的大小
- `csize2tidx(x)` 将 chunk 大小转换为 bin 的索引
- `usize2tidx(x)` 将用户请求的内存大小转换为对应 bin 的索引
- `request2size(x)` 将用户请求的大小转换为实际分配的 chunk 大小（包括对齐和元数据）
- `chunksize()` 大小包含元素据
- `MALLOC_ALIGNMENT` 表示内存块的对齐单位，通常为 16 字节 (64-bit)，8 字节 (32-bit)
- `MINSIZE` 表示内存块的最小大小，通常为 32 字节 (64-bit)，16 字节 (32-bit)
- `SIZE_SZ` 表示头部元数据大小，通常为 8 字节 (64-bit)，4 字节 (32-bit)

然后是有关 tcache 的两个结构体：

- `tcache_entry` 用单链表的方式链接了相同大小的 free()ed 的 chunk. `next` 指向同一 bin 中下一个可用的内存块
- `key` 用于检测 `double free`
- `counts[TCACHE_MAX_BINS]` 记录了 `tcache_entry` 链上空闲 chunk 的数目，每条链上最多可以有 `TCACHE_FILL_COUNT` 个 chunk
- `entries[TCACHE_MAX_BINS]` 指向每个 bin 中的链表头
