---
title: "Notes: Pwn heap fundamental knowledge"
published: 2025-02-06
updated: 2025-02-08
description: "This note is for explaining some fundamental knowledge of heap (managed by the dynamic allocator). From the easiest things to even harder things."
image: "https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1apal2wi8c.avif"
tags: ["Pwn", "Heap", "Notes"]
category: "Notes"
draft: false
---

# 前言

初识 Heap 就要被大量基础知识狠狠地冲击，为了巩固所学，同时秉持开源共享的精神，我决定单独撰写一篇 blog 来系统的整理一下这方面的笔记。说来惭愧，栈我一个字的笔记都没写（日后有空应该大概可能或许会写吧），可见堆的难度……

一切的恐惧来源于经验不足，~_幻想我跨过瓶颈期的那天……一定……会很爽吧？_~

咳咳，先声明一下：因为这本质上算是我的个人笔记，而非对外「教材」，所以我基本上是想写什么，分析什么，就写什么了，尤其是在分析 glibc 源码的时候，写的比较杂，有点乱，而且一般并不会只专注于一个有用/相关的核心知识，中间可能会根据心情发散出来很多无关内容的分析。所以整体上内容并不会显得那么循序渐进，可能不太适合新人食用<s>_（虽然我现在就是从零开始学的？应该说和严谨的系统性教学文相比是不行，谁知道我潜意识里消化了多少外部文献的内容……）_</s>。当然，如果你是好学宝宝<s>_/大佬走开，走开～_</s>，我的笔记可能会大大的扩大你的知识面？

~_读 glibc 源码恶补 C 语言真是自虐啊，你别说还挺爽？_~

还有一点就是这份笔记分析的源码基于 [glibc-2.41](https://sourceware.org/git/?p=glibc.git;a=tag;h=refs/tags/glibc-2.41).

# Terminology

首先让我们了解一下堆 (Heap) 这个 terminology 的由来，注意我们讨论的堆可**不是数据结构中的「堆」**。

Heap 在英语中本义是「堆积物」，表示一块随意堆放、无特定顺序的集合。这个词被借用于计算机内存管理中，是因为堆内存允许程序在运行时根据需要在任何位置动态分配和释放内存块，这会形成一种「堆积」的状态，形象吧？

总之，我们所研究的堆，通常来说就是由动态分配器 (dynamic allocator) 所管理的那个堆。

# Dynamic Allocator?

动态分配器 (Dynamic Allocator) 也叫做堆管理器，介于用户程序与内核之间，主要做如下工作：

1. 响应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序。同时，为了保证内存管理的高效性，内核一般都会预先分配很大的一块连续的内存，然后让堆管理器通过某种算法管理这块内存。只有当出现了堆空间不足的情况，堆管理器才会再次与操作系统进行交互。
2. 管理用户所释放的内存。一般来说，用户释放的内存并不是直接返还给操作系统的，而是由堆管理器进行管理。这些释放的内存可以用来响应用户的新的申请内存的请求。

Linux 中早期的堆分配与回收由 [Doug Lea](https://gee.cs.oswego.edu/) 实现，叫做 `dlmalloc`，但它在并行处理多个线程时，会共享进程的堆内存空间。因此，为了安全性，一个线程使用堆时，会进行加锁。然而，与此同时，加锁会导致其它线程无法使用堆，降低了内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能影响内存分配和回收的正确性。因此 [Wolfram Gloger](http://www.malloc.de/en/) 在 Doug Lea 实现的 dlmalloc 的基础上进行改进，使其可以支持多线程，这个改进后的堆分配器就是 `ptmalloc`。`glibc 2.1` 开始使用 `ptmalloc`，`glibc 2.3` 开始默认使用 `ptmalloc2`，进一步优化了 arena 管理，使多核环境下的性能得到显著提升。

目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通过 malloc/free 函数来分配和释放内存块。

需要注意的是，在内存分配与使用的过程中，Linux 有这样的一个基本内存管理思想，只有当真正访问一个地址的时候，系统才会建立虚拟页与物理页之间的映射关系。 所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页给用户使用。

## What's the different with stack?

我们先 recap 一下栈。栈由高地址向低地址增长，一般用于存放局部变量，函数调用信息等内容，当函数作用域结束后，这块空间（栈帧）就自动释放了，因此不适合做长期存储，而且栈空间也有限，不适合存储大量数据。

堆与栈的一大区别在于，首先，它由低地址向高地址增长，其次堆可以动态分配空间，要多少分多少，并且分配出来的内存全局可用，通过堆指针可以在程序的任何地方访问和修改它。若非手动释放的话，生命周期会维持到程序结束。

# When should we use the heap?

可以粗暴的说堆的存在就是为了解决栈的各种不适合的问题。常见用途有：

- 动态内存需求（在程序运行时，根据实际情况动态分配内存）
- 跨函数作用域共享

栈空间有限，不能全局使用，堆空间大，管理内存灵活……到现在都是在说堆的优点，那它的缺点呢？

- 分配速度慢
- 容易产生内存碎片
- 需要手动分配和释放，容易产生安全问题

不过现在有像 Rust 这样的语言，它们提供了更安全的内存管理就是了。

# Implementations

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

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9kgh9atg76.svg)

嗯……我们永远不是第一个有想法的人<s>_（真 TM 的令人难过）_</s>，事实上早已存在很多更成熟的解决方案了。

- Doug Lea 在 1987 年发布了 dlmalloc（历史上最具影响力、性能最优的早期实现之一，成为后续 malloc 实现的经典蓝图）
- Linux 一般使用 ptmalloc (Posix Thread aware fork of dlmalloc)
- FreeBSD 的 jemalloc (also used in Firefox, Android)
- Windows 下是 Segment Heap, NT Heap
- Linux kernel 使用 kmalloc
- iOS kernel 使用 kalloc

多吧？可不止这么多……后续做堆漏洞研究你还得去读它们的实现代码呢……动辄几千行，不同版本的代码都需要读，因为很多漏洞只存在于特定版本……

# How to use the heap?

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

# How does the heap work?

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

# What can go wrong?

一切问题的产生，究其根本都离不开人类，~_因此只有解决了人类才有可能解决问题 (bushi_~

我们都知道人有各种各样的缺点……对于堆的使用：

- humans forget to free memory
- humans forget all the spots where they store pointers to data
- humans forget what they've freed

除了人的问题……库追求极致的性能也会导致问题（还是离不开人）：

- allocation and deallocation needs to be fast, or programs will slow down
- optimizations often leave security as an afterthought

## Security vs Performance

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3rbj006vgd.svg)

# How to detect issues?

市面上有很多工具都可以用来检测问题，但事实上还不存在检测这方面问题的通用技术。

比如 valgrind 可以检测一些堆误用，如果你的测试用例覆盖到了的话……glibc 本身也提供了很多加固措施，但是其中有些会造成严重的性能损失……人们一直在积极开发各种「更安全」的堆管理器，但它们要么被留在学术 paper 上了，要么因为种种原因根本没部署……

# Common Dangers

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

# The Rise of the Houses

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

# glibc 中部分可能需要特别记忆的内容

历史课上完了，是时候讲点不那么轻松的东西了。

```c showLineNumbers=false collapse={1-89}
/* Malloc implementation for multiple threads without lock contention.
   Copyright (C) 1996-2025 Free Software Foundation, Inc.
   Copyright The GNU Toolchain Authors.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <https://www.gnu.org/licenses/>.  */

/*
  This is a version (aka ptmalloc2) of malloc/free/realloc written by
  Doug Lea and adapted to multiple threads/arenas by Wolfram Gloger.

  There have been substantial changes made after the integration into
  glibc in all parts of the code.  Do not look for much commonality
  with the ptmalloc2 version.

* Version ptmalloc2-20011215
  based on:
  VERSION 2.7.0 Sun Mar 11 14:14:06 2001  Doug Lea  (dl at gee)

* Quickstart

  In order to compile this implementation, a Makefile is provided with
  the ptmalloc2 distribution, which has pre-defined targets for some
  popular systems (e.g. "make posix" for Posix threads).  All that is
  typically required with regard to compiler flags is the selection of
  the thread package via defining one out of USE_PTHREADS, USE_THR or
  USE_SPROC.  Check the thread-m.h file for what effects this has.
  Many/most systems will additionally require USE_TSD_DATA_HACK to be
  defined, so this is the default for "make posix".

* Why use this malloc?

  This is not the fastest, most space-conserving, most portable, or
  most tunable malloc ever written. However it is among the fastest
  while also being among the most space-conserving, portable and tunable.
  Consistent balance across these factors results in a good general-purpose
  allocator for malloc-intensive programs.

  The main properties of the algorithms are:
  * For large (>= 512 bytes) requests, it is a pure best-fit allocator,
    with ties normally decided via FIFO (i.e. least recently used).
  * For small (<= 64 bytes by default) requests, it is a caching
    allocator, that maintains pools of quickly recycled chunks.
  * In between, and for combinations of large and small requests, it does
    the best it can trying to meet both goals at once.
  * For very large requests (>= 128KB by default), it relies on system
    memory mapping facilities, if supported.

  For a longer but slightly out of date high-level description, see
     http://gee.cs.oswego.edu/dl/html/malloc.html

  You may already by default be using a C library containing a malloc
  that is  based on some version of this malloc (for example in
  linux). You might still want to use the one in this file in order to
  customize settings or to avoid overheads associated with library
  versions.

* Contents, described in more detail in "description of public routines" below.

  Standard (ANSI/SVID/...)  functions:
    malloc(size_t n);
    calloc(size_t n_elements, size_t element_size);
    free(void* p);
    realloc(void* p, size_t n);
    memalign(size_t alignment, size_t n);
    valloc(size_t n);
    mallinfo()
    mallopt(int parameter_number, int parameter_value)

  Additional functions:
    independent_calloc(size_t n_elements, size_t size, void* chunks[]);
    independent_comalloc(size_t n_elements, size_t sizes[], void* chunks[]);
    pvalloc(size_t n);
    malloc_trim(size_t pad);
    malloc_usable_size(void* p);
    malloc_stats();

* Vital statistics:

  Supported pointer representation:       4 or 8 bytes
  Supported size_t  representation:       4 or 8 bytes
       Note that size_t is allowed to be 4 bytes even if pointers are 8.
       You can adjust this by defining INTERNAL_SIZE_T

  Alignment:                              2 * sizeof(size_t) (default)
       (i.e., 8 byte alignment with 4byte size_t). This suffices for
       nearly all current machines and C compilers. However, you can
       define MALLOC_ALIGNMENT to be wider than this if necessary.

  Minimum overhead per allocated chunk:   4 or 8 bytes
       Each malloced chunk has a hidden word of overhead holding size
       and status information.

  Minimum allocated size: 4-byte ptrs:  16 bytes    (including 4 overhead)
     8-byte ptrs:  24/32 bytes (including, 4/8 overhead)

       When a chunk is freed, 12 (for 4byte ptrs) or 20 (for 8 byte
       ptrs but 4 byte size) or 24 (for 8/8) additional bytes are
       needed; 4 (8) for a trailing size field and 8 (16) bytes for
       free list pointers. Thus, the minimum allocatable size is
       16/24/32 bytes.

       Even a request for zero bytes (i.e., malloc(0)) returns a
       pointer to something of the minimum allocatable size.

       The maximum overhead wastage (i.e., number of extra bytes
       allocated than were requested in malloc) is less than or equal
       to the minimum size, except for requests >= mmap_threshold that
       are serviced via mmap(), where the worst case wastage is 2 *
       sizeof(size_t) bytes plus the remainder from a system page (the
       minimal mmap unit); typically 4096 or 8192 bytes.

  Maximum allocated size:  4-byte size_t: 2^32 minus about two pages
      8-byte size_t: 2^64 minus about two pages

       It is assumed that (possibly signed) size_t values suffice to
       represent chunk sizes. `Possibly signed' is due to the fact
       that `size_t' may be defined on a system as either a signed or
       an unsigned type. The ISO C standard says that it must be
       unsigned, but a few systems are known not to adhere to this.
       Additionally, even when size_t is unsigned, sbrk (which is by
       default used to obtain memory from system) accepts signed
       arguments, and may not be able to handle size_t-wide arguments
       with negative sign bit.  Generally, values that would
       appear as negative after accounting for overhead and alignment
       are supported only via mmap(), which does not have this
       limitation.

       Requests for sizes outside the allowed range will perform an optional
       failure action and then return null. (Requests may also
       also fail because a system is out of memory.)

  Thread-safety: thread-safe

  Compliance: I believe it is compliant with the 1997 Single Unix Specification
       Also SVID/XPG, ANSI C, and probably others as well.

* Synopsis of compile-time options:

    People have reported using previous versions of this malloc on all
    versions of Unix, sometimes by tweaking some of the defines
    below. It has been tested most extensively on Solaris and Linux.
    People also report using it in stand-alone embedded systems.

    The implementation is in straight, hand-tuned ANSI C.  It is not
    at all modular. (Sorry!)  It uses a lot of macros.  To be at all
    usable, this code should be compiled using an optimizing compiler
    (for example gcc -O3) that can simplify expressions and control
    paths. (FAQ: some macros import variables as arguments rather than
    declare locals because people reported that some debuggers
    otherwise get confused.)

    OPTION                     DEFAULT VALUE

    Compilation Environment options:

    HAVE_MREMAP                0

    Changing default word sizes:

    INTERNAL_SIZE_T            size_t

    Configuration and functionality options:

    USE_PUBLIC_MALLOC_WRAPPERS NOT defined
    USE_MALLOC_LOCK            NOT defined
    MALLOC_DEBUG               NOT defined
    REALLOC_ZERO_BYTES_FREES   1
    TRIM_FASTBINS              0

    Options for customizing MORECORE:

    MORECORE                   sbrk
    MORECORE_FAILURE           -1
    MORECORE_CONTIGUOUS        1
    MORECORE_CANNOT_TRIM       NOT defined
    MORECORE_CLEARS            1
    MMAP_AS_MORECORE_SIZE      (1024 * 1024)

    Tuning options that are also dynamically changeable via mallopt:

    DEFAULT_MXFAST             64 (for 32bit), 128 (for 64bit)
    DEFAULT_TRIM_THRESHOLD     128 * 1024
    DEFAULT_TOP_PAD            0
    DEFAULT_MMAP_THRESHOLD     128 * 1024
    DEFAULT_MMAP_MAX           65536

    There are several other #defined constants and macros that you
    probably don't want to touch unless you are extending or adapting malloc.  */
```

- `MALLOC_ALIGNMENT` 表示 chunk 的对齐单位，通常为 16 字节 (64-bit)，8 字节 (32-bit)
- `MINSIZE` 表示我们能 malloc 的最小 chunk 大小（包含 metadata），通常为 32 字节 (64-bit)，16 字节 (32-bit)
- `SIZE_SZ` 表示单个头部字段的大小，通常为 8 字节 (64-bit)，4 字节 (32-bit)

# tcache

线程本地缓存 `tcache (Thread Local Caching)` 是在 glibc 2.26 (Ubuntu 17.10) 之后引入的一种新技术 ([commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc))，旨在加速在一个线程中的重复的小块内存分配，提升堆管理的性能。但提升性能的同时也舍弃了很多安全检查，因此有了很多新的利用方式。

先看看相关的宏定义：

```c
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
```

- `TCACHE_MAX_BINS` 设置了 tcache 最大可管理的 bins 数，每个 bin 都负责管理一组特定大小的 chunks
- `MAX_TCACHE_SIZE` 表示 bin 可存储的最大 chunk 大小（包含 metadata）
- `TCACHE_FILL_COUNT` 设置了每条 tcache_entry 链上可以存放多少个 free()ed 的 chunk，可以通过 tunables 调整这个值
- `MAX_TCACHE_COUNT` 限制了每个 bin 中最多允许存储的 chunks 数量，限制的是 tunables 最大可调整的范围
- `tidx2usize(idx)` 通过 bin 的索引给出这个 bin 可存储的 chunk 的大小
- `csize2tidx(x)` 将给定 chunk 大小转换为对应 bin 的索引
- `usize2tidx(x)` 将用户请求的内存大小转换为对应 bin 的索引
- `request2size(x)` 将用户请求的大小转换为实际分配的 chunk 大小（包含 metadata）
- `chunksize()` chunk 大小，包含 metadata

然后是有关 tcache 的两个结构体：

```c
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

每一个线程都有一个 `tcache_perthread_struct`，位于堆开头的位置。

- `next` 指向同一 bin 中下一个 free()ed 的 chunk，构成单链表
- `key` 用于检测 double free
- `counts` 记录了 tcache_entry 链上空闲 chunks 的数目，默认情况下每条链上最多可以有 7 个 chunks
- `entries` 指向每个 bin 中的链表头

## tcache_init

现在开始分析那些操作 tcache 的函数，就从 `tcache_init` 开始说好了。

```c
static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = NULL;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
```

- `ar_ptr` 用来存储指向 arena 的指针
- `victim` 用来存储分配得到的内存地址
- `bytes` 存储每个线程的 `tcache_perthread_struct` 结构体的大小

整个函数大致上就是做了这么几件事：

1. 初始化检查：通过检查 `tcache_shutting_down` 是否为真，避免在 tcache 正在关闭时进行初始化
2. 内存分配：获取一块 arena，并从这块 arena 分配内存，若失败则重试
3. 内存初始化：分配成功后，将得到的地址赋值给全局的 tcache，将分配到的内存清零，初始化了 `tcache_perthread_struct` 的所有字段

## tcache_thread_shutdown

```c
static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

static void
tcache_thread_shutdown (void)
{
  int i;
  tcache_perthread_struct *tcache_tmp = tcache;

  tcache_shutting_down = true;

  if (!tcache)
    return;

  /* Disable the tcache and prevent it from being reinitialized.  */
  tcache = NULL;

  /* Free all of the entries and the tcache itself back to the arena
     heap for coalescing.  */
  for (i = 0; i < TCACHE_MAX_BINS; ++i)
    {
      while (tcache_tmp->entries[i])
 {
   tcache_entry *e = tcache_tmp->entries[i];
   if (__glibc_unlikely (!aligned_OK (e)))
     malloc_printerr ("tcache_thread_shutdown(): "
        "unaligned tcache chunk detected");
   tcache_tmp->entries[i] = REVEAL_PTR (e->next);
   __libc_free (e);
 }
    }

  __libc_free (tcache_tmp);
}
```

它基本上就是遍历并释放了每一个 entries 并释放了 tcache 本身，实现了清理当前线程的 tcache 资源。

这里有一个检查，用于确保每个 chunk 都正确对齐了：

```c
if (__glibc_unlikely (!aligned_OK (e)))
  malloc_printerr ("tcache_thread_shutdown(): "
        "unaligned tcache chunk detected");
```

## tcache_free

怎么把 free()ed 的 chunk 放到 tcache 应该是我们需要重点关注的一个操作，它的实现如下：

```c
/* Try to free chunk to the tcache, if success return true.
   Caller must ensure that chunk and size are valid.  */
static inline bool
tcache_free (mchunkptr p, INTERNAL_SIZE_T size)
{
  bool done = false;
  size_t tc_idx = csize2tidx (size);
  if (tcache != NULL && tc_idx < mp_.tcache_bins)
    {
      /* Check to see if it's already in the tcache.  */
      tcache_entry *e = (tcache_entry *) chunk2mem (p);

      /* This test succeeds on double free.  However, we don't 100%
  trust it (it also matches random payload data at a 1 in
  2^<size_t> chance), so verify it's not an unlikely
  coincidence before aborting.  */
      if (__glibc_unlikely (e->key == tcache_key))
 tcache_double_free_verify (e, tc_idx);

      if (tcache->counts[tc_idx] < mp_.tcache_count)
 {
   tcache_put (p, tc_idx);
   done = true;
 }
    }
  return done;
}
```

用到了一个没讲过的 `chunk2mem` 宏，定义如下：

```c
/* The chunk header is two SIZE_SZ elements, but this is used widely, so
   we define it here for clarity later.  */
#define CHUNK_HDR_SZ (2 * SIZE_SZ)

/* Convert a chunk address to a user mem pointer without correcting
   the tag.  */
#define chunk2mem(p) ((void*)((char*)(p) + CHUNK_HDR_SZ))
```

简单来讲就是把 chunk 地址转换为了用户可用的指针。

`tcache_free` 的作用是尝试将 chunk `p` 释放到 tcache 中。

首先，根据 chunk size 计算对应的 bin (tc_idx)，然后检查 tcache 是否可用以及 bin 是否有效，之后是检测是否触发了 double free. 如果没啥问题，并且 bin 未满，则调用 `tcache_put` 将其插入链表。

## tcache_double_free_verify

```c
/* Verify if the suspicious tcache_entry is double free.
   It's not expected to execute very often, mark it as noinline.  */
static __attribute__ ((noinline)) void
tcache_double_free_verify (tcache_entry *e, size_t tc_idx)
{
  tcache_entry *tmp;
  size_t cnt = 0;
  LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
  for (tmp = tcache->entries[tc_idx];
       tmp;
       tmp = REVEAL_PTR (tmp->next), ++cnt)
    {
      if (cnt >= mp_.tcache_count)
 malloc_printerr ("free(): too many chunks detected in tcache");
      if (__glibc_unlikely (!aligned_OK (tmp)))
 malloc_printerr ("free(): unaligned chunk detected in tcache 2");
      if (tmp == e)
 malloc_printerr ("free(): double free detected in tcache 2");
      /* If we get here, it was a coincidence.  We've wasted a
  few cycles, but don't abort.  */
    }
}
```

如其名，我不说你也知道这是用来检测 double free 的……

glibc 检测 double free 的核心逻辑是：

每当把一块 free()ed 的 chunk 放到 tcache 中时都会通过 `e->key = tcache_key` 设置它的 key 为 tcache_key. 释放内存时，先判断 `e->key == tcache_key`，如果成立，则说明这块内存还在 tcache 里，没有被重新分配出去，这时候你再释放它就是 double free 了。因为正常情况下当这块内存被重新分配，`e->key` 就会被新的数据覆盖，不再等于 `tcache_key`。

但存在 `1/2^<size_t>` 的几率使得 `e->key` 恰好等于 `tcache_key`，导致误判。所以又通过 `tcache_double_free_verify` 进行二次验证。

`e` 是刚检测到可能 double free 的 chunk. `tc_idx` 是对应的 tcache bin 索引。`tmp` 用于遍历 tcache bin 链表中的各个节点，`cnt` 用于记录已遍历的节点的数量。

如果 `cnt >= mp_.tcache_count`，则说明链表异常，可能 chunk 已损坏或者出现了什么其它问题；如果节点地址不对齐，也说明 chunk 可能已经损坏；`tmp == e` 是检查当前遍历到的节点是否正好等于传入的 `e`。如果相等，说明在该 tcache bin 的链表中已经存在该 chunk，因此再次释放就属于 double free 了。

## tcache_key_initialize

```c
/* Process-wide key to try and catch a double-free in the same thread.  */
static uintptr_t tcache_key;

/* The value of tcache_key does not really have to be a cryptographically
   secure random number.  It only needs to be arbitrary enough so that it does
   not collide with values present in applications.  If a collision does happen
   consistently enough, it could cause a degradation in performance since the
   entire list is checked to check if the block indeed has been freed the
   second time.  The odds of this happening are exceedingly low though, about 1
   in 2^wordsize.  There is probably a higher chance of the performance
   degradation being due to a double free where the first free happened in a
   different thread; that's a case this check does not cover.  */
static void
tcache_key_initialize (void)
{
  /* We need to use the _nostatus version here, see BZ 29624.  */
  if (__getrandom_nocancel_nostatus_direct (&tcache_key, sizeof(tcache_key),
         GRND_NONBLOCK)
      != sizeof (tcache_key))
    {
      tcache_key = random_bits ();
#if __WORDSIZE == 64
      tcache_key = (tcache_key << 32) | random_bits ();
#endif
    }
}
```

`tcache_key` 是一个进程范围内的随机数，用来帮助检测 double free 的情况。

这个函数通过调用 `__getrandom_nocancel_nostatus_direct` 直接从内核中读取随机数，它会返回给 `tcache_key` 一个比较高质量随机数。如果失败，则使用 `random_bits` 生成随机数。64-bit 系统上，通过将两个 32 位随机数拼接为一个完整的 64 位随机数，以提高随机性的强度。

## tcache_put

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

这个函数负责将 chunk 插入到 tcache 的指定 bin (tc_idx) 中。至于位置嘛，是插到了链表头，并更新了 counts.

# Safe-Linking

属于是重点关注对象了，等写完 tcache 再来写这个。

```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```
