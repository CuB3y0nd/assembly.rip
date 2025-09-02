---
title: "GLIBC Ptmalloc2 Dynamic Allocator Source Code Analysis"
published: 2025-09-02
updated: 2025-09-02
description: "About how does the malloc / free works, mechanisms inside, and security guards explaintation etc."
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.6m47vyn1pe.avif"
tags: ["Pwn", "Heap", "GLIBC", "Notes"]
category: "Notes"
draft: false
---

# 前言

暑假也快结束了，整个假期都被各种事情困扰着，心态一崩再崩，糟糕极了，差点就放弃了一切……不过现在已经好很多，重新打起精神来了。想着在余下的十多天里把 GLIBC 堆分配器的源码读完吧，反正迟早要读的，先把各种机制，流程全部理清楚了，打好基础，开学后再去学习各种攻击手法也不迟。谁知道呢，或许会是一个极好的助力也说不准。

其实老早就像写这篇博客了，但是因为各种原因一直没开工，曾短暂开工了一段时间，也因为基础根基不牢的原因转而去弥补所缺了，反正就是一直拖到现在，不过这次应该是真正的正式开始我的堆利用之旅了吧……期间堆学习方面可以说是没啥长进，不过其它必要的基础倒是补的差不多了，所以我现在基本上还是等于从零开始读源码，从零开始学习哈哈哈。

我原本打算从经典的 GLIBC 2.23 入手，后来一读代码发现这个版本包含的内容有点太少了，故问了下 Civiled，得到了新路线：

<center>
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.esuth1g0w.avif" alt="" />
  <img src="https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.lw2owmf84.avif" alt="" />
</center>

那就让我们从 2.29 开始入手好了，因为相比于 2.28 也就新加入了一个 key field protection, 所以变化应该不是很大。

_PS: 哎呀，感觉写的太杂乱无章了……不过也没办法，不能用写书的标准要求自己，因为这个东西要写得循序渐进属实有点难度，以后有机会再说吧。反正估计也没什么人看，我自己看着舒服就行了哈哈哈。_

## GLIBC 2.29

### Macro Definitions

```c
# define INTERNAL_SIZE_T size_t
```

### malloc_chunk

下面这个结构体就是一个 chunk 的内存布局了：

```c
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

#### Allocated Chunk

```plaintext
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

每个 chunk 开始于 `chunk` 标记的位置，称之为 chunk header metadata, 我将其简称为 chunk header. 它包含了上一个 chunk 的大小和这个 chunk 自己的大小 (chunk header size + user data size)；malloc 返回给用户的地址是跳过 chunk header 之后的 `mem` 指向的地址。

#### Free Chunk

```plaintext
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

- **P (PREV_INUSE)** 标记前一个 **内存中物理相邻** 的 chunk 是否正在使用，free 为 0, allocated 为 1. 注意最开始分配的第一个 chunk 始终会将此位设置为 1. 如果该位为 1，则我们无法通过 `mchunk_prev_size` 确定前一个 chunk 的大小，否则，我们可以取得前一个 chunk 的大小
- **M (IS_MMAPPED)** 标记是否是通过 `mmap` 分配的。如果设置了该位，则另外两个位就被忽略了，因为 `mmap` 得到的内存既不在 arena 中，也不与 free chunk 相邻
- **A (NON_MAIN_ARENA)** 标记 chunk 是否不属于 main arena, 1 表示不属于，0 表示是从 main arena 中分配出来的

:::important
malloc 分配出来的 chunk 之间是物理紧邻的; free 释放后 chunk 会被归类到不同的 bins 中（可能会和物理相邻的前后 free chunk 合并成更大的 free chunk），bins 中的 chunks 只是逻辑相邻，而非物理相邻。
:::
