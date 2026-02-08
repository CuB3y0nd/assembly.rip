---
title: "The Fuzzy Notebook"
published: 2026-02-07
updated: 2026-02-08
description: "AFL++ learning notes."
image: "https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.mldvs2ca.avif"
tags: ["Fuzz", "Notes"]
category: "Notes"
draft: false
---

# Prologue

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.6ikt5mc3b5.avif" alt="" />
</center>

次日，群名从 `Pwn Squad` 变成了 `Lost Squad`。

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.mlder7db.avif" alt="" />
</center>

我们不知道这是否是更好的选择，但我想，我们绝不差尝试的勇气。

:::note
由于是直接上手用 fuzzer，边做边学，所以肯定会漏掉很多重要的概念，算是比较冒险的学习方法了。不过没事，后面慢慢总结。
:::

# Concept

以下概念翻译自 [Frequently asked questions (FAQ)](https://aflplus.plus/docs/faq/)。

- 程序包含 **函数 (Function)**，而函数包含编译后的机器码。
- 函数中的机器码可以由一个或多个 **基本块 (Basic Block)** 组成。
- 基本块是尽可能长的连续机器指令序列，它只有一个 **入口点 (Entry Point)**（可被多个其它基本块进入），且在执行过程中线性运行，除了末尾外，不会发生分支或跳转到其它地址。

下面的 **A**、**B**、**C**、**D**、**E** 都是基本块：

```plaintext showLineNumbers=false
function() {
  A:
    some
    code
  B:
    if (x) goto C; else goto D;
  C:
    some code
    goto E
  D:
    some code
    goto B
  E:
    return
}
```

**边 (Edge)** 则表示两个直接相连的基本块之间的唯一关系，自环也算一条边：

```plaintext showLineNumbers=false
              Block A
                |
                v
              Block B  <------+
            /        \       |
            v          v      |
        Block C    Block D --+
            \
              v
              Block E
```

# Demo

以下面这个程序为例，感受一下 Fuzz 的基本用法及其思想。

```c
#include <stdio.h>
#include <stdlib.h>

int isBigPrime(int n) {
  if (n <= 5)
    return 0;
  for (int i = 2; i * i <= n; i++)
    if (n % i == 0)
      return 0;
  return 1;
}

int main(void) {
  char s[35];
  scanf("%s", s);

  char cnt[300] = {0};

  for (int i = 0; s[i]; i++) {
    cnt[s[i]]++;
    if (s[i] < 'x' || s[i] > 'z') {
      puts("unacceptable");
      return 0;
    }
  }

  if (isBigPrime(cnt['x']) && isBigPrime(cnt['y']) && isBigPrime(cnt['z']))
    abort();

  puts("Nice string");

  return 0;
}
```

程序逻辑为：

- **输入限制**：程序只接受由字符 `x`，`y`，`z` 组成的字符串。如果包含其他字符，程序会输出 unacceptable 并正常退出
- **计数统计**：使用 `cnt` 数组统计输入字符串中 `x`，`y`，`z` 各自出现的次数
- **触发崩溃**：
  - `isBigPrime` 函数检查一个数是否为大于 5 的质数 (e.g. 7, 11, 13, 17 etc.)
  - 只有当 `x`、`y` 以及 `z` 的数量同时都是大于 5 的质数时，程序才会执行 `abort`
- **额外 Bug**：
  - `scanf` 没有限制输入长度，存在栈溢出

根据 [Selecting the best AFL++ compiler for instrumenting the target](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#a-selecting-the-best-afl-compiler-for-instrumenting-the-target) 的指引，我们选择 `afl-clang-lto` 作为 **插桩 (Instrumentation)** 用的编译器。

使用如下指令编译并插桩：

```shellsession
afl-clang-lto ./test.c -o test
```

接下来，只要提供一些初始样本，放入 `inputs` 文件夹，比如我提供了这些样本：

```shellsession
λ ~/Projects/Fuzz/ cat inputs/text/*
aaaabaaacaaadaaaeaaa
helloworld
Hello world!
ahfoer
```

它们本身没有一个会让程序崩溃，我们希望 AFL++ 能自己变异这些样本，寻找到每一个能让程序崩溃的输入。

由于 Arch 默认配置的问题，我需要临时关闭一些选项以确保 fuzzer 高效运行，为了方便，我直接使用如下指令自动修改系统配置（虽然这可能会造成一些安全隐患）：

```shellsession
sudo afl-system-config
```

然后就可以使用以下指令来探索程序了：

```shellsession
afl-fuzz -i inputs -o out/ -- ./test
```

刚跑几秒就出了 6 个 crash，但是全都是栈溢出，之后大概在 1min 左右，把 abort 的 crash 路径也找到了，可以看到是第九个样本：

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.41ykrv2y1c.avif" alt="" />
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.pfuxhp6cy.avif" alt="" />
</center>

可以在 `out/default/crashes` 中找到这 10 个可以触发崩溃的输入。

`check` 脚本如下：

```bash
#!/usr/bin/env bash

for f in out/default/crashes/id:*; do
  echo "==== $f ===="
  # hexdump -C "$f" | head
  ./test <"$f"
done
```

# Fuzzing-Module

[Fuzzing-Module](https://github.com/alex-maleno/Fuzzing-Module) 是 AFL++ 官方[推荐](https://github.com/AFLplusplus/AFLplusplus?tab=readme-ov-file#tutorials)的纯新手练习。一共 3 个 exercises，speedrun 一下。

## Exercise 1

程序源码如下：

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

int main() {

  string str;

  cout << "enter input string: ";
  getline(cin, str);
  cout << str << endl << str[0] << endl;

  if (str[0] == 0 || str[str.length() - 1] == 0) {
    abort();
  } else {
    int count = 0;
    char prev_num = 'x';
    while (count != str.length() - 1) {
      char c = str[count];
      if (c >= 48 && c <= 57) {
        if (c == prev_num + 1) {
          abort();
        }
        prev_num = c;
      }
      count++;
    }
  }

  return 0;
}
```

使用 `CC=afl-clang-lto CXX=afl-clang-lto++ cmake -S . -B build` 生成编译配置，然后通过 `cmake --build build` 编译项目。

简单分析一下几个可以造成 crash 的地方，然后跑一下 fuzz 看看能不能对上：

1. `str[0] == \x00`
2. `str[str.length() -1] == \x00`
3. 下一个读取到的数字比上一个读取到的数字大一
4. `\n`，`EOF`

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.3ns513tseu.avif" alt="" />
</center>

根据 Exercise 1 的要求，我们使用如下脚本生成 5 个 seeds：

```bash
#!/usr/bin/env bash

mkdir seeds
for i in {0..4}; do
  dd if=/dev/urandom of=seeds/seed_"$i" bs=64 count=10
done
```

然后跑 `afl-fuzz -i seeds -o out/ -m none -d -- ./build/simple_crash`，刚跑一秒就把三个 crash 都找到了：

<center>
  <img src="https://cdn.cubeyond.net/gh/CuB3y0nd/picx-images-hosting@master/.et14gm2kg.avif" alt="" />
</center>

可以看到第一个对上了 Case 2，第二个对上了 Case 1，第三个对上了 Case 3。

:::important
第四个 Case 找不到，那时因为当触发的 crash 是由 Undefined Behaviour 导致时，AFL++ 会自动把它剔除掉。因为这些 UB 可能在不同编译 / 优化 / 运行中表现各不相同，从而不能产生一种稳定可复现的 crash 。

既然如此，我们只要增强它的 crash 表现，使其更加可确定即可，比如：

```c showLineNumbers=false
if (str.length() == 0)
  abort();
```

:::
