---
title: "分岔的森林：angr 符号执行札记"
published: 2025-10-01
updated: 2025-10-01
description: "In the Forest of Branches: angr's Predictions"
image: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.26luturh6l.avif"
tags: ["Pwn", "Reverse", "Angr", "Notes"]
category: "Notes"
draft: false
---

# 前言

前几天打了 SunshineCTF 2025，其中有道 MOVfuscated 的 Pwn 题感觉挺有意思，虽然最后也没做出来，但是知道了一个大致的学习方向，或许可以用符号执行来解决这道题。

Anyway，先开个题，至于什么时候写，hmm，我还有好多 heap 没学泪，所以这是一篇札记（
