---
title: "GLIBC Ptmalloc2 Dynamic Allocator Source Code Analysis"
published: 2025-09-02
updated: 2025-09-04
description: "About how does the malloc / free works, mechanisms inside, and security guards explaintation etc."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.6m47vyn1pe.avif"
tags: ["Pwn", "Heap", "GLIBC", "Notes"]
category: "Notes"
draft: true
---

# 前言

暑假也快结束了，整个假期都被各种事情困扰着，心态一崩再崩，糟糕极了，差点就放弃了一切……不过现在已经好很多，重新打起精神来了。想着在余下的十多天里把 GLIBC 堆分配器的源码读完吧，反正迟早要读的，先把各种机制，流程全部理清楚了，打好基础，开学后再去学习各种攻击手法也不迟。谁知道呢，或许会是一个极好的助力也说不准。

其实老早就像写这篇博客了，但是因为各种原因一直没开工，曾短暂开工了一段时间，也因为基础根基不牢的原因转而去弥补所缺了，反正就是一直拖到现在，不过这次应该是真正的正式开始我的堆利用之旅了吧……期间堆学习方面可以说是没啥长进，不过其它必要的基础倒是补的差不多了，所以我现在基本上还是等于从零开始读源码，从零开始学习哈哈哈。

我原本打算从经典的 GLIBC 2.23 入手，后来一读代码发现这个版本包含的内容有点太少了，故问了下 Civiled，得到了新路线：

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.esuth1g0w.avif" alt="" />
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.lw2owmf84.avif" alt="" />
</center>

那就让我们从 2.29 开始入手好了，因为相比于 2.28 也就新加入了一个 key field protection, 所以变化应该不是很大。

_PS: 哎呀，感觉写的太杂乱无章了……不过也没办法，不能太高的标准要求自己，因为这个东西要写得循序渐进属实有点难度，以后有机会再说吧。反正估计也没什么人看，我自己看着舒服就行了哈哈哈。_

炸了，我觉得还是先以做题为切入点吧，之后慢慢写这篇博客……

## Heap

在研究源码之前，先简单了解一下堆 (Heap) 。

堆是进程虚拟地址空间中一块由低地址向高地址扩展的连续的线性内存区域，由堆管理器负责维护。堆管理器的主要作用是支持动态内存分配——当程序在编译时无法确定需要多少内存时，就可以通过堆管理器在运行时向系统申请所需的空间。

:::note[History]
Linux 中早期的堆分配与回收由 Doug Lea 实现，但它在并行处理多个线程时，会共享进程的堆内存空间。因此，为了安全性，一个线程使用堆时，会进行加锁。然而，与此同时，加锁会导致其它线程无法使用堆，降低了内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能影响内存分配和回收的正确性。Wolfram Gloger 在 Doug Lea 的基础上进行改进使其可以支持多线程，这个堆分配器就是 ptmalloc 。 在 glibc-2.3.x. 之后，glibc 中集成了 ptmalloc2 。

目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2 。ptmalloc2 主要是通过 malloc / free 函数来分配和释放内存块。这里我们的主要研究对象也是 ptmalloc2 。
:::

堆管理器处于用户程序与内核中间，主要做以下工作：

1. 响应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序。同时，为了保持内存管理的高效性，内核一般都会预先分配很大的一块连续的内存，然后让堆管理器通过某种算法管理这块内存。只有当出现了堆空间不足的情况，堆管理器才会再次与操作系统进行交互。
2. 管理用户所释放的内存。一般来说，用户释放的内存并不是直接返还给操作系统的，而是由堆管理器进行管理。这些释放的内存可以重用来响应用户新申请的内存的请求。

:::tip
在内存分配与使用的过程中，Linux 有这样的一个基本内存管理思想：只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系。所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存，只有当用户使用到相应的内存时，系统才会真正分配物理页给用户使用。
:::

### 基本操作

#### malloc

```plaintext showLineNumbers=false
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.

  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/
```

#### free

```plaintext showLineNumbers=false
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

### 内存分配背后的系统调用

malloc 和 free 并不是真正与系统交互的函数，这些函数背后的系统调用主要是 `(s)brk` 函数以及 `mmap`, `munmap` 函数。

#### (s)brk

对于堆的操作，操作系统提供了 `brk` 函数，glibc 库提供了 `sbrk` 函数，我们可以通过增加 brk 的大小来向操作系统申请内存。

初始时，堆的起始地址 `start_brk` 以及堆的当前末尾 `brk` 指向同一地址。根据是否开启 ASLR，两者的具体位置会有所不同：

- 不开启 ASLR 时，**start_brk** 以及 **brk** 会指向 data / bss 段的结尾
- 开启 ASLR 时，**start_brk** 以及 **brk** 也会指向同一位置，只是这个位置是在 data / bss 段结尾后的随机偏移处

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.3k8ctqpino.avif" alt="" />
</center>

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  void *curr_brk, *tmp_brk = NULL;

  printf("Welcome to sbrk example: %d\n", getpid());

  /* sbrk(0) gives current program break location */
  tmp_brk = curr_brk = sbrk(0);
  printf("Program Break Location1: %p\n", curr_brk);
  getchar();

  /* brk(addr) increments/decrements program break location */
  brk(curr_brk + 4096);

  curr_brk = sbrk(0);
  printf("Program Break Location2: %p\n", curr_brk);
  getchar();

  brk(tmp_brk);

  curr_brk = sbrk(0);
  printf("Program Break Location3: %p\n", curr_brk);
  getchar();

  return 0;
}
```

#### mmap

malloc 会使用 mmap 来创建独立的匿名映射段。匿名映射的目的主要是可以申请以 0 填充的内存，并且这块内存仅被调用进程所使用。

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void static inline errExit(const char *msg) {
  printf("%s failed. Exiting the process\n", msg);
  exit(-1);
}

int main() {
  int ret = -1;
  printf("Welcome to private anonymous mapping example::PID:%d\n", getpid());
  printf("Before mmap\n");
  getchar();
  char *addr = NULL;
  addr = mmap(NULL, (size_t)132 * 1024, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED)
    errExit("mmap");
  printf("After mmap\n");
  getchar();

  /* Unmap mapped region. */
  ret = munmap(addr, (size_t)132 * 1024);
  if (ret == -1)
    errExit("munmap");
  printf("After munmap\n");
  getchar();
  return 0;
}
```

### 多线程支持

在原来的 dlmalloc 实现中，当两个线程同时要申请内存时，只有一个线程可以进入临界区申请内存，而另外一个线程则必须等待直到临界区中不再有线程。这是因为所有的线程共享一个堆。在 glibc 的 ptmalloc 实现中，比较好的一点就是支持了多线程的快速访问。在新的实现中，所有的线程共享多个堆。

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void *threadFunc(void *arg) {
  printf("Before malloc in thread 1\n");
  getchar();
  char *addr = (char *)malloc(1000);
  printf("After malloc and before free in thread 1\n");
  getchar();
  free(addr);
  printf("After free in thread 1\n");
  getchar();
}

int main() {
  pthread_t t1;
  void *s;
  int ret;
  char *addr;

  printf("Welcome to per thread arena example::%d\n", getpid());
  printf("Before malloc in main thread\n");
  getchar();
  addr = (char *)malloc(1000);
  printf("After malloc and before free in main thread\n");
  getchar();
  free(addr);
  printf("After free in main thread\n");
  getchar();
  ret = pthread_create(&t1, NULL, threadFunc, NULL);
  if (ret) {
    printf("Thread creation error\n");
    return -1;
  }
  ret = pthread_join(t1, &s);
  if (ret) {
    printf("Thread join error\n");
    return -1;
  }
  return 0;
}
```

最开始主线程申请到的 heap 为 `0x555555559000     0x55555557a000 rw-p    21000      0 [heap]`，一共 0x21000 字节大小，尽管我们只申请了 1000 字节。这说明虽然程序可能只是向操作系统申请很小的内存，但是为了方便，操作系统会把很大的内存分配给程序。这样的话，就避免了多次内核态与用户态的切换，提高了程序的效率。

```asm showLineNumbers=false ins={9} collapse={1-6, 12-33}
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000      0 test
    0x555555555000     0x555555556000 r-xp     1000   1000 test
    0x555555556000     0x555555557000 r--p     1000   2000 test
    0x555555557000     0x555555558000 r--p     1000   2000 test
    0x555555558000     0x555555559000 rw-p     1000   3000 test
    0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
    0x7ffff7de6000     0x7ffff7de9000 rw-p     3000      0 [anon_7ffff7de6]
    0x7ffff7de9000     0x7ffff7e0e000 r--p    25000      0 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7e0e000     0x7ffff7f55000 r-xp   147000  25000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7f55000     0x7ffff7f9e000 r--p    49000 16c000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7f9e000     0x7ffff7fa1000 r--p     3000 1b5000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7fa1000     0x7ffff7fa4000 rw-p     3000 1b8000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7fa4000     0x7ffff7fa8000 rw-p     4000      0 [anon_7ffff7fa4]
    0x7ffff7fa8000     0x7ffff7faf000 r--p     7000      0 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7faf000     0x7ffff7fbe000 r-xp     f000   7000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fbe000     0x7ffff7fc3000 r--p     5000  16000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc3000     0x7ffff7fc4000 r--p     1000  1a000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc4000     0x7ffff7fc5000 rw-p     1000  1b000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc5000     0x7ffff7fcb000 rw-p     6000      0 [anon_7ffff7fc5]
    0x7ffff7fcb000     0x7ffff7fcf000 r--p     4000      0 [vvar]
    0x7ffff7fcf000     0x7ffff7fd1000 r--p     2000      0 [vvar_vclock]
    0x7ffff7fd1000     0x7ffff7fd3000 r-xp     2000      0 [vdso]
    0x7ffff7fd3000     0x7ffff7fd4000 r--p     1000      0 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7fd4000     0x7ffff7ff4000 r-xp    20000   1000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ff4000     0x7ffff7ffc000 r--p     8000  21000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

我们称这一块 0x21000 字节的连续的内存区域为 `arena`。此外，我们称由主线程申请的内存为 `main_arena`。后续的申请的内存会一直从这个 arena 中获取，直到空间不足。当 arena 空间不足时，它可以通过增加 brk 的方式来增加堆的空间。类似地，arena 也可以通过减小 brk 来缩小自己的空间。

进入子线程函数后，我们发现多了一个 `0x7ffff75e6000     0x7ffff7de6000 rw-p   800000      0 [anon_7ffff75e6]`，这 8 MB 空间是子线程的栈空间（使用 `limit` 指令可以知道栈空间默认大小就是 8 MB）。

```asm showLineNumbers=false ins={11} collapse={1-8, 14-35}
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000      0 test
    0x555555555000     0x555555556000 r-xp     1000   1000 test
    0x555555556000     0x555555557000 r--p     1000   2000 test
    0x555555557000     0x555555558000 r--p     1000   2000 test
    0x555555558000     0x555555559000 rw-p     1000   3000 test
    0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
    0x7ffff75e5000     0x7ffff75e6000 ---p     1000      0 [anon_7ffff75e5]
    0x7ffff75e6000     0x7ffff7de6000 rw-p   800000      0 [anon_7ffff75e6]
    0x7ffff7de6000     0x7ffff7de9000 rw-p     3000      0 [anon_7ffff7de6]
    0x7ffff7de9000     0x7ffff7e0e000 r--p    25000      0 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7e0e000     0x7ffff7f55000 r-xp   147000  25000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7f55000     0x7ffff7f9e000 r--p    49000 16c000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7f9e000     0x7ffff7fa1000 r--p     3000 1b5000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7fa1000     0x7ffff7fa4000 rw-p     3000 1b8000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7fa4000     0x7ffff7fa8000 rw-p     4000      0 [anon_7ffff7fa4]
    0x7ffff7fa8000     0x7ffff7faf000 r--p     7000      0 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7faf000     0x7ffff7fbe000 r-xp     f000   7000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fbe000     0x7ffff7fc3000 r--p     5000  16000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc3000     0x7ffff7fc4000 r--p     1000  1a000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc4000     0x7ffff7fc5000 rw-p     1000  1b000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc5000     0x7ffff7fcb000 rw-p     6000      0 [anon_7ffff7fc5]
    0x7ffff7fcb000     0x7ffff7fcf000 r--p     4000      0 [vvar]
    0x7ffff7fcf000     0x7ffff7fd1000 r--p     2000      0 [vvar_vclock]
    0x7ffff7fd1000     0x7ffff7fd3000 r-xp     2000      0 [vdso]
    0x7ffff7fd3000     0x7ffff7fd4000 r--p     1000      0 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7fd4000     0x7ffff7ff4000 r-xp    20000   1000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ff4000     0x7ffff7ffc000 r--p     8000  21000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

:::tip
注意到它前面其实还多了一个 0x1000 (4 KB) 字节的段，权限是 `---p`，用作线程的 guard page 。

在 Linux 的线程栈分配中，通常在栈的起始或末尾会放一个 guard page，用来防止栈溢出（如果访问栈地址超出了分配的范围，就会触发 SIGSEGV）。其大小通常是一个页，权限 `---p` 或 `----`，位于栈的低地址（因为栈向低地址增长）。
:::

在子线程执行完 malloc 后，紧邻着主线程的 heap 段又多了一个 0x21000 字节的匿名段 `0x7ffff0000000     0x7ffff0021000 rw-p    21000      0 [anon_7ffff0000]`，用作子线程的 heap 段，这说明子线程申请堆内存时使用的是 mmap 而不是 brk 。这一段连续的内存被称为 `thread_arena`。

```asm showLineNumbers=false ins={10} collapse={1-7, 13-37}
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000      0 test
    0x555555555000     0x555555556000 r-xp     1000   1000 test
    0x555555556000     0x555555557000 r--p     1000   2000 test
    0x555555557000     0x555555558000 r--p     1000   2000 test
    0x555555558000     0x555555559000 rw-p     1000   3000 test
    0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
    0x7ffff0000000     0x7ffff0021000 rw-p    21000      0 [anon_7ffff0000]
    0x7ffff0021000     0x7ffff4000000 ---p  3fdf000      0 [anon_7ffff0021]
    0x7ffff75e5000     0x7ffff75e6000 ---p     1000      0 [anon_7ffff75e5]
    0x7ffff75e6000     0x7ffff7de6000 rw-p   800000      0 [anon_7ffff75e6]
    0x7ffff7de6000     0x7ffff7de9000 rw-p     3000      0 [anon_7ffff7de6]
    0x7ffff7de9000     0x7ffff7e0e000 r--p    25000      0 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7e0e000     0x7ffff7f55000 r-xp   147000  25000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7f55000     0x7ffff7f9e000 r--p    49000 16c000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7f9e000     0x7ffff7fa1000 r--p     3000 1b5000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7fa1000     0x7ffff7fa4000 rw-p     3000 1b8000 /opt/glibc/2.29/64/lib/libc-2.29.so
    0x7ffff7fa4000     0x7ffff7fa8000 rw-p     4000      0 [anon_7ffff7fa4]
    0x7ffff7fa8000     0x7ffff7faf000 r--p     7000      0 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7faf000     0x7ffff7fbe000 r-xp     f000   7000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fbe000     0x7ffff7fc3000 r--p     5000  16000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc3000     0x7ffff7fc4000 r--p     1000  1a000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc4000     0x7ffff7fc5000 rw-p     1000  1b000 /opt/glibc/2.29/64/lib/libpthread-2.29.so
    0x7ffff7fc5000     0x7ffff7fcb000 rw-p     6000      0 [anon_7ffff7fc5]
    0x7ffff7fcb000     0x7ffff7fcf000 r--p     4000      0 [vvar]
    0x7ffff7fcf000     0x7ffff7fd1000 r--p     2000      0 [vvar_vclock]
    0x7ffff7fd1000     0x7ffff7fd3000 r-xp     2000      0 [vdso]
    0x7ffff7fd3000     0x7ffff7fd4000 r--p     1000      0 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7fd4000     0x7ffff7ff4000 r-xp    20000   1000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ff4000     0x7ffff7ffc000 r--p     8000  21000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /opt/glibc/2.29/64/lib/ld-2.29.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

同样，我们注意到新增的不止有子线程的 heap 区域，下面还有一个差不多 64 MB 的 `anon_7ffff0021`，作为虚拟地址保留区 / heap guard，是未映射物理页。当线程 malloc 更多内存时，会在这片区域里使用 mmap 映射实际的可读写页。

:::important
当用户请求的内存大于 128 KB (mmap_threshold) 时，并且没有任何 arena 有足够的空间时，那么系统就会执行 mmap 函数来分配相应的内存空间。这与这个请求来自于主线程还是从线程无关。

```asm showLineNumbers=false
pwndbg> p/d mp_.mmap_threshold/1024
$1 = 128
```

:::

## GLIBC 2.29

### Core Macro Definitions

这里我把我认为后面经常会遇到的定义写在一起了，它们可能来自不同头文件。

```c
#ifndef _GENERIC_MALLOC_ALIGNMENT_H
#define _GENERIC_MALLOC_ALIGNMENT_H

/* MALLOC_ALIGNMENT is the minimum alignment for malloc'ed chunks.  It
   must be a power of two at least 2 * SIZE_SZ, even on machines for
   which smaller alignments would suffice. It may be defined as larger
   than this though. Note however that code and data structures are
   optimized for the case of 8-byte alignment.  */
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
     ? __alignof__ (long double) : 2 * SIZE_SZ)

#endif /* !defined(_GENERIC_MALLOC_ALIGNMENT_H) */

#ifndef _I386_MALLOC_ALIGNMENT_H
#define _I386_MALLOC_ALIGNMENT_H

#define MALLOC_ALIGNMENT 16

#endif /* !defined(_I386_MALLOC_ALIGNMENT_H) */

/*
   注意上面的 generic 定义会算出 32 位 MALLOC_ALIGNMENT 为 8, 但是 glibc
   针对 i386 的 MALLOC_ALIGNMENT 作了 override 操作，强制为 16。

   如果除了 generic 定义，针对特定架构还有其它定义，那么对于这个特定架构
   应该以其 override 的定义为准，而不是 generic 的定义。

   所以不管是 64-bit 还是 32-bit, MALLOC_ALIGNMENT 都是 16 字节。
 */

#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
```

### malloc_chunk

malloc 申请的内存块被称为 chunk, 用 `malloc_chunk` 结构体表示：

```c
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;                /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize;       /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk* mchunkptr;
```

#### Size and alignment checks and conversions

```c
/* conversion from malloc headers to user pointers, and back */

#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */

/*
   mask = align - 1
   (X + mask) & ~mask 意思是向上取整到某个对齐倍数，这里表示向上对齐到
   MALLOC_ALIGNMENT 的整数倍。

   其中 X + mask 是让值至少增加到超过下一个对齐点。
   (X + mask) & ~mask 把低位清零，相当于取最接近且不小于 X 的 align 倍数。
 */

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

/* Check if m has acceptable alignment */

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)


/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=                                       \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))

/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* Same, except also perform an argument and result check.  First, we check
   that the padding done by request2size didn't result in an integer
   overflow.  Then we check (using REQUEST_OUT_OF_RANGE) that the resulting
   size isn't so large that a later alignment would lead to another integer
   overflow.  */
#define checked_request2size(req, sz) \
({                                  \
  (sz) = request2size (req);        \
  if (((sz) < (req))                \
      || REQUEST_OUT_OF_RANGE (sz)) \
    {                               \
      __set_errno (ENOMEM);         \
      return 0;                     \
    }                               \
})
```

#### Allocated Chunk

```plaintext showLineNumbers=false
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

每个 chunk 开始于 `chunk` 标记的位置，称之为 metadata (overhead)。 它包含了上一个 chunk 的大小 `mchunk_prev_size` 和这个 chunk 自己的大小 `mchunk_size` (metadata size + user data size)。mchunk_size 必须是 `MALLOC_ALIGNMENT` 的整数倍。如果申请的内存大小不是 MALLOC_ALIGNMENT 的整数倍，会被转换满足大小的最小的 MALLOC_ALIGNMENT 的倍数。此外，malloc 返回给用户的地址是跳过 metadata 之后的 `mem` 指向的地址。

:::important
malloc 分配出来的 chunk 之间是物理紧邻的; free 释放后 chunk 会被归类到不同的 bins 中（可能会和物理相邻的前后 free chunk 合并成更大的 free chunk），bins 中保存的是 free chunks 的地址，它们之间只是逻辑相邻，而非物理相邻。
:::

#### Free Chunk

```plaintext showLineNumbers=false
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **P (PREV_INUSE)** 标记前一个 **内存中物理相邻** 的 chunk 是否正在使用，free 为 0, allocated 为 1. 注意最开始分配的第一个 chunk 始终会将此位设置为 1，防止向前访问非法内存。`mchunk_prev_size` 只有当上一个 chunk 是 free 状态时才会保存上一个 chunk 的大小，否则它将用作上一个 chunk 的 data 部分
- **M (IS_MMAPPED)** 标记是否是通过 `mmap` 分配的。如果设置了该位，则另外两个位就被忽略了，因为 mmap 得到的内存既不在 arena 中，也不与 free chunk 物理相邻
- **A (NON_MAIN_ARENA)** 标记 chunk 是否不属于 main arena, 1 表示不属于，0 表示是从 main arena 中分配出来的
- free chunk 独有
  - **fd** 指向当前 bin 中下一个（非物理相邻）free chunk
  - **bk** 指向当前 bin 中上一个（非物理相邻）free chunk

#### Physical chunk operations

AMP 位相关的宏定义如下：

```c
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->mchunk_size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)

/* Mark a chunk as not being on the main arena.  */
#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)


/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

chunk 操作相关的宏定义如下：

```c
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + chunksize (p)))

/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Set the size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))

/* Ptr to previous physical malloc_chunk.  Only valid if !prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - prev_size (p)))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

/* extract p's inuse bit */
#define inuse(p)                                                              \
  ((((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)                                                          \
  ((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size |= PREV_INUSE

#define clear_inuse(p)                                                        \
  ((mchunkptr) (((char *) (p)) + chunksize (p)))->mchunk_size &= ~(PREV_INUSE)


/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)                                             \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)                                         \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)                                       \
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))


/* Set size at head, without disturbing its use bit */
#define set_head_size(p, s)  ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s)       ((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))
```

### arena

一个线程的 arena 可以包含多个 heap（堆段），每个 heap 都有自己的头信息，即 `heap_info`。这个结构体保存了这个 heap 的基本信息。

起初，每个线程 arena 只有 一个 heap。

```c
/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */

typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

每个线程的堆内存是逻辑上互相独立的，每个堆都关联一个 `arena`, 主线程的 arena 称为 `main_arena`, 子线程的 arena 称为 `thread_arena`。

arena 是一个指向 `malloc_state` 结构体的指针：

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};

typedef struct malloc_state *mstate;
```

- 普通 free
  - 当前 chunk 释放
  - 下一个 chunk 的 P 位改为 0，表示前一个 chunk 空闲，可以合并
- fastbin/tcache free
  - 当前 chunk 释放
  - 保留当前 chunk 的 P 位，表示上一个 chunk 仍然 inuse，防止和上一个 chunk 合并
  - 下一个 chunk 的 P 位也依旧保持 1，表示它前一个 chunk 看似 inuse，防止和下一个 chunk 合并
