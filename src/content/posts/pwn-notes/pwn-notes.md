---
title: "Special topic: Tricky tricks summary for Pwn"
pubDate: "2025-02-01 16:01"
modDate: "2025-02-01 17:12"
categories:
  - "Pwn"
  - "Tricks"
description: "This special topic is about some tricky tricks i've learned so far in Pwn field. Keep updating as the mood strikes."
slug: "pwn-notes"
pin: true
---

## Table of contents

## 前言

写这篇博客的起因应该是为了一个即将到来的比赛，而我还有好多 high level tricks 没学过，万一在比赛上碰到了再临场学肯定是很浪费时间的，而且为不同 tricks 都单独写一篇博客显然不是很好，我一般喜欢围绕一个大的系列来写博客，~_这样才能显得不那么水，是吧？_~

好吧，上面说的只是一个最次要的原因罢了。这就不得不提到我 23 年刚推开 Pwn 之门的一条缝后的一个小梦想了……众所不周知 Pwn 方面优秀的系统教程应该可以说是少得可怜，相当于没有。所以我当时的这个小梦想就是写一份有关 Pwn 的详细教程，让有志之士从入门到入坟，少走弯路，不那么痛苦。~_伟大吗？_~

唉，你还能在[我的原博客](https://tailwind-nextjs-starter-blog-ruby.vercel.app/)看到我以前写的系列文章。现在看看写的什么 trash，叫人从哪开始看都不知道，而且当时只是边学边翻译了 [ir0nstone 的笔记](https://ir0nstone.gitbook.io/)，说白了就是搬运，没多少自己的成分在里面……所以这第二次做同样的事嘛，我一定会比第一次做的好 $\infty$ 倍。~_有关这方面，我的字典里面没有，也不允许出现「不行」这个词。_~

其实我本来想用 GitBook 或者建一个类似 wiki 的平台来写这个的，不过最终还是决定放在这里，为啥？我不道啊……

正如我在 Description 上写的：_Keep updating as the mood strikes._ 不论你现在看到的这篇文章有多简陋……未来它一定会成为一本不错的手册！莫欺少年穷，咱顶峰相见。

<p style="text-align: right;">——以上，书于 02/01/2025</p>

## ROP 那些事

### ret2csu

我在 [ROP Emporium - Challenge 8](/posts/rop-emporium-series/#challenge-8) 写的已经很详细了，最近比赛赶时间，等我打完之后再来慢慢完善吧，暂且劳请各位老爷们先凑合着看。
