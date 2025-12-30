---
title: "Heap by Heap"
published: 2025-08-15
updated: 2025-08-15
description: "This note is for recording my heap exploitation learning journey."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.1apal2wi8c.avif"
tags: ["Pwn", "Heap", "Notes"]
category: "Notes"
draft: true
---

# 前言

初识 Heap 就要被大量基础知识狠狠地冲击，感受到的只有恐惧……为了巩固所学，同时秉持开源共享的精神，我决定单独撰写一篇 blog 来系统的整理一下这方面的笔记。说来惭愧，栈我一个字的笔记都没写（日后有空应该大概可能或许会写吧）。

一切的恐惧来源于经验不足，~_幻想我跨过瓶颈期的那天……一定……会很爽吧？_~

_2025 Aug 15_ umm，好吧，或许今天才算是我正式开始学习堆的第一天……感觉之前的路线有点问题，干脆直接把前面的笔记全部删了，改名换姓，重新开始……

# First-fit

**glibc malloc** 使用 `first-fit` 堆分配算法。即，通过 **malloc** 申请内存时，glibc 的 **ptmalloc** 分配器会在合适的 **bin** 中从低地址到高地址遍历 **free'd chunks**，直接返回第一个大小满足要求的 chunk，而不会继续寻找更优解。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  fprintf(stderr, "This file doesn't demonstrate an attack, but shows the "
                  "nature of glibc's allocator.\n");
  fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
  fprintf(
      stderr,
      "If a chunk is free and large enough, malloc will select this chunk.\n");
  fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

  fprintf(
      stderr,
      "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
  char *a = malloc(0x512);
  char *b = malloc(0x256);
  char *c;

  fprintf(stderr, "1st malloc(0x512): %p\n", a);
  fprintf(stderr, "2nd malloc(0x256): %p\n", b);
  fprintf(stderr, "we could continue mallocing here...\n");
  fprintf(
      stderr,
      "now let's put a string at a that we can read later \"this is A!\"\n");
  strcpy(a, "this is A!");
  fprintf(stderr, "first allocation %p points to %s\n", a, a);

  fprintf(stderr, "Freeing the first one...\n");
  free(a);

  fprintf(stderr,
          "We don't need to free anything again. As long as we allocate "
          "smaller than 0x512, it will end up at %p\n",
          a);

  fprintf(stderr, "So, let's allocate 0x500 bytes\n");
  c = malloc(0x500);
  fprintf(stderr, "3rd malloc(0x500): %p\n", c);
  fprintf(stderr, "And put a different string here, \"this is C!\"\n");
  strcpy(c, "this is C!");
  fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
  fprintf(stderr, "first allocation %p points to %s\n", a, a);
  fprintf(stderr, "If we reuse the first allocation, it now holds the data "
                  "from the third allocation.\n");
}
```
