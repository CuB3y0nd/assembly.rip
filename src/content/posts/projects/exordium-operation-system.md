---
title: "Exordium Operating System Development Notes"
published: 2025-03-09
updated: 2025-03-19
description: "Exordium operating system development notes. Mainly based on the book《操作系统真象还原》"
tags: ["Operating System", "Notes"]
category: "Operating System"
draft: false
---

# 前言

为了提升开发水平和工程能力，同时也是为了深入学习 C 语言……我再次拾起了这项艰巨却让我无比向往的项目<s>_（种子早在两年前就种下了，现在才开始生长，请叫我摆烂 Master）_</s>。

话说今年（确切的说应该是截至九月中旬）我主要功夫都会倾注在学业中，这意味着，我能投身于技术探索的时间将变得稀缺（这怎么行，我怎么能原地踏步！所以，即便当前以学业为主，我也打算在这段时间顺便积淀一下自己的硬实力。待到回归之日，又是一个更哇塞的自己～）……

借口？或许吧……刚开学前两周经受了一个「小小的」挫折，让我有「一点点」崩。唉，说多了都是泪……没死就好 LOL

主要参考书籍是**_《操作系统真象还原》_**，这本书体量和 **_CSAPP_** 有一拼……

记录一下，我是从 _03/09/2025_ 正式开始的，<s>虽然还没写下任何一行代码，但准确来说就是这个点……</s>只是想在最后看看什么时候结束，届时可能会小小的感慨一下下吧。

::github{repo="CuB3y0nd/Exordium"}

<br />

# 计算机启动过程

## 实模式下的 1MB 内存布局

为何是 1MB？这得追溯到 Intel 8086 的时代了。那时候 Intel 8086 只有 20 根地址总线，故其只能访问 $$2^{20} =1048576$$ 字节，也就是 1MB 的内存空间，而这 1MB 又被拆为多个部分分别用于不同的用途。

实模式下的内存布局如下：

| 起始    | 结束    | 大小              | 用途                                                                                                                                             |
| ------- | ------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0xFFFF0 | 0xFFFFF | 16B               | BIOS 入口地址，此地址也属于 BIOS 代码，同样属于顶部的 64KB 字节。只是为了强调其入口地址才单独贴出来。此处 16 字节的内容是跳转指令 jmp F000\:E05B |
| 0xF0000 | 0xFFFEF | 64KB-16B          | 系统 BIOS 范围是 F0000\~FFFFF 共 64B，为了说明入口地址，将最上面的 16 字节从此处去掉了，所以此处终止地址是 0xFFFEF                               |
| 0xC8000 | 0xEFFFF | 160KB             | 映射硬件适配器的 ROM 或内存映射式 I/O                                                                                                            |
| 0xC0000 | 0xC7FFF | 32KB              | 显示适配器 BIOS                                                                                                                                  |
| 0xB8000 | 0xBFFFF | 32KB              | 用于文本模式显示适配器                                                                                                                           |
| 0xB0000 | 0xB7FFF | 32KB              | 用于黑白显示适配器                                                                                                                               |
| 0xA0000 | 0xAFFFF | 64KB              | 用于彩色显示适配器                                                                                                                               |
| 0x9FC00 | 0x9FFFF | 1KB               | EDBA (Extended BIOS Data Area)                                                                                                                   |
| 0x7E00  | 0x9FBFF | 622080B，约 608KB | 可用区域                                                                                                                                         |
| 0x7C00  | 0x7DFF  | 512B              | MBR 被 BIOS 加载到此处                                                                                                                           |
| 0x500   | 0x7BFF  | 30464B，约 30KB   | 可用区域                                                                                                                                         |
| 0x400   | 0x4FF   | 256B              | BIOS Data Area                                                                                                                                   |
| 0x00    | 0x3FF   | 1KB               | Interrupt Vector Table                                                                                                                           |

## 计算机的启动过程

当按下主机上的 Power 键后，CPU 的 CS\:IP 被强制初始化为 0xF000\:0xFFF0。由于刚开机时处于实模式，故段部件将段地址左移四位再加上偏移地址，得到物理地址 0xFFFF0，也就是是 BIOS (Basic Input/Output System) 的入口地址。所以第一个被运行的软件是 BIOS. BIOS 主要负责通过硬件提供的基本调用来检测、初始化硬件，除此之外，它还建立了最基本的中断向量表 (Interrupt Vector Table, IVT)，之所以说是最基本，是因为 BIOS 就 64KB 大，不可能把所有的硬件 I/O 操作都实现得面面俱到，并且也没必要实现那么多，因为这是在实模式，对硬件支持的再丰富也白搭，精彩的世界是从进入保护模式后才开始的，所以它只挑了一些最重要的、保证计算机能运行的那些最基本的硬件 I/O 操作实现。

> [!TIP]
> 因为 BIOS 是计算机上第一个运行的软件，所以它不可能自己加载自己，而是由只读存储器 ROM 这个硬件加载的。
>
> BIOS 存在于主板上的 ROM 中，硬件将这个 ROM 的地址映射到低端 1MB 内存的顶部，也就是 0xF0000~0xFFFFF 处。

因为实模式下只能访问到 1MB 的空间，而 0xFFFF0 距 1MB 只剩可怜的 16 字节了，在这么小的空间里我们着实做不了太多操作，故在此放的是一条跳转指令，通过 `jmp F000:E05B` 跳转到 0xFE05B 处继续执行，也就是说真正的 BIOS 代码是从 0xFE05B 开始的。

接下来 BIOS 便马不停蹄地检测内存、显卡等外设信息，当所有检测通过，并初始化好硬件后，便在 0x00~0x03FF 处建立中断向量表，并向其中填写中断例程。

计算机执行到这份上，BIOS 也即将完成它这短暂的一生的使命了，完成之后，它又将沉沉睡去。想到这里，心里不免一丝忧伤，甚至有些许挽留它的想法。可是，这就是它的使命，它生来被设计成这样，它这短暂的一生已经为后人创造了足够的精彩。何况，在下一次开机时，BIOS 还会重复这段轮回，它并没有消失……多么伟大啊！好了，让伤感停止，让梦想前行！

BIOS 的最后一项工作是去校验启动盘中位于 0 盘 0 道 1 扇区的内容。如果此扇区末尾的两个字节分别为 `0x55` 和 `0xAA`，BIOS 便认为此扇区中存在可执行程序，也就是主引导记录 MBR (Main Boot Record)，随即将其加载到 0x7c00 处，并跳转到该地址继续执行。

为什么一定是 0 盘 0 道 1 扇区，而不是其它地方？对于这个问题，简单来说就是为了方便 BIOS 找到 MBR。想象一下，如果不存在这一规定，BIOS 就只得将所有检测到的存储设备上的的每一个存储单位都翻一遍，挨个对比，如果发现该存储单位的最后两字节为 0x55 和 0xAA，就认为它是 MBR. 几经花开花落，找到 MBR 的那一刻，BIOS 满脸疲惫地说：「你是我找了好久的那个人。」MBR 抬起经不起岁月等待的脸：「难得你还认得我，我等你等的花儿都谢了。」其实 BIOS 的心声是：「看我手忙脚乱的样子，你们这是要闹哪样啊。就这么 512 字节的内容，害我找遍全世界，我们这是在跑接力赛啊，下一棒的选手我都不知道在哪里……以后让它站在固定的位置等我！」

由于 0 盘 0 道 1 扇区是磁盘的第一个扇区，MBR 选择了这个离 BIOS 最近的位置站好了，从此以后再也不用担心被 BIOS 骂了。

总之，计算机中到处都有写死的东西，各种各样的魔数层出不穷，0xAA55 也是其中之一，这个就不解释了，当成规定/协议理解吧……

至于 0x7c00 是怎么来的，倒是可以解释一下。0x7c00 最早出现于 1981 年 8 月，IBM 公司推出的个人计算机 PC 5150 的 ROM BIOS 的 INT 19H 中断处理程序中。PC 5150 是世界上第一台个人计算机，它就是现代 x86 个人计算机兼容机的祖先。

个人计算机肯定要运行操作系统，在这台计算机上，运行的操作系统是 DOS 1.0。不清楚此系统要求的最小内存是 16KB 还是 32KB，反正 PC 5150 BIOS 研发团队就假定其是 32KB 的，所以此 BIOS 是按照最小内存 32KB 研发的。

MBR 不是随便放在哪里都行的，首先它不能覆盖已有数据，其次，它还不能过早的被其它数据覆盖。MBR 的任务是加载某个程序（一般是内核加载器，很少有直接加载内核的）到指定位置，并将控制权交给它。之后，MBR 就没用了，被覆盖也没关系（我指的覆盖是覆盖 0x7c00 处的指令，因为 MBR 本身也是被加载到那个位置执行的，而非硬盘上所保存的 MBR，覆盖了硬盘上保存的 MBR 下次就不能启动了），但在此之前，得确保它的完整性。

重现一下当时的内存使用情况：

8086 CPU 要求 0x00~0x03FF 存放中断向量表，所以此处就不能动了，再选新的地方看看。按 DOS 1.0 要求的最小内存 32KB 来说，MBR 希望给人家尽可能多的预留空间，这样也是保全自己的作法，免得被过早覆盖。所以 MBR 只能放在 32KB 的末尾。

MBR 本身也是程序，是程序就要用到栈，栈也是在内存中的，虽然 MBR 本身只有 512 字节，但还要为其所用的栈分配点空间，所以其实际所用的内存空间要大于 512 字节，估计 1KB 内存够用了。

结合以上几点，选择 32KB 中的最后 1KB 最为合适。32KB 转换为十六进制是 0x8000，减去 1KB (0x400) 的话，正好等于 0x7c00。这就是备受质疑的 0x7c00 的由来！

### 实现一个简单的 MBR

最后，让我们写一个简单的程序来验证一下我们所学到的理论知识的正确性。

项目结构为：

```plaintext
.
├── boot
│   └── mbr.s
└── Makefile

```

```asm title="boot/mbr.asm" wrap=false
.code16
.section .text
.global _start

_start:
  xor %ax, %ax
  mov %ax, %ss
  mov $0x7c00, %sp
  mov $0xb800, %ax
  mov %ax, %es

  mov $0x0600, %ax # clear screen
  mov $0x07, %bh   # color attribute 0x07
  xor %cx, %cx     # upper left corner
  mov $0x184f, %dx # bottom right corner
  int $0x10

  movb $'M', %es:[0x00]
  movb $0x07, %es:[0x01]
  movb $'B', %es:[0x02]
  movb $0x07, %es:[0x03]
  movb $'R', %es:[0x04]
  movb $0x07, %es:[0x05]

  jmp .

  .fill 510-(.-_start), 1, 0
boot_flag:
  .word 0xAA55
```

以上，有关 `int 0x10` 视频中断的用法可以参考 [INT 10 - Video BIOS Services](https://stanislavs.org/helppc/int_10.html).

这里我不得不吐槽一句：AT&T 语法珍尼 🐴 屎……

更有趣的是：

> Intel Syntax Support
>
> Up until v2.10 of binutils, GAS supported only the AT&T syntax for x86 and x86-64, which differs significantly from the Intel syntax used by virtually every other assembler. Today, GAS supports both syntax sets (.intel_syntax and the default .att_syntax), and even allows disabling the otherwise mandatory operand prefixes '%' or '$' (...\_syntax noprefix). There are some pitfalls - several FP opcodes suffer from a reverse operand ordering that is bound to stay in there for compatibility reasons, .intel_syntax generates less optimized opcodes on occasion (try mov'ing to %si...).
>
> It is generally discouraged to use the support for Intel Syntax because it can subtly and surprisingly different than the real Intel Syntax found in other assemblers. A different assembler should be considered if Intel Syntax is desired.

唉算了，忍忍就过去了……

```plaintext title="Makefile" wrap=false
AS = i386-elf-as
LD = i386-elf-ld

boot/mbr: boot/mbr.o
 $(LD) -Ttext 0x7c00 --oformat binary -o $@ $<

boot/mbr.o: boot/mbr.s
 $(AS) -o $@ $<

clean:
 rm -rf boot/mbr
 rm -rf boot/*.o
```

通过 `qemu-img create -f raw hd60M.img 60M` 创建一个硬盘镜像，使用 `make` 来自动编译上述程序，最后，通过 `dd if=boot/mbr of=hd60M.img bs=512 count=1 conv=notrunc` 将我们编译出来的程序写入硬盘镜像的 0 盘 0 道 1 扇区。

最终，通过 `qemu-system-i386 -drive file=hd60M.img,format=raw -s -S` 启动虚拟机，之后你就可以通过 `gdb`，使用 `target remote localhost:1234` 连接到虚拟机进行调试了，直接 `(c) continue`，看到 MBR 三个大字被输出在屏幕上，就意味着我们成功地向 MBR 迈出了第一步，壮举！

> [!TIP]
> 如果你通过 gdb 查看开机后运行的第一条指令，会发现这条指令并不符合我们的预期，这可能是因为 gdb 解析的是 32-bit 指令，而不是 16-bit 指令。
>
> 所以如果你想查看开机后运行的第一条指令的话，可以在启动虚拟机的指令后面加上 `-monitor stdio` 参数，之后在 qemu 控制台使用 `x/10i $cs*16+$eip` 指令来进行查看。
>
> 结果如下：
>
> ```asm showLineNumbers=false wrap=false ins={2}
> (qemu) x/10i $cs*16+$eip
> 0x000ffff0:  ea 5b e0 00 f0           ljmpw    $0xf000:$0xe05b
> 0x000ffff5:  30 36 2f 32              xorb     %dh, 0x322f
> 0x000ffff9:  33 2f                    xorw     (%bx), %bp
> 0x000ffffb:  39 39                    cmpw     %di, (%bx, %di)
> 0x000ffffd:  00 fc                    addb     %bh, %ah
> 0x000fffff:  00 00                    addb     %al, (%bx, %si)
> 0x00100001:  00 00                    addb     %al, (%bx, %si)
> 0x00100003:  00 00                    addb     %al, (%bx, %si)
> 0x00100005:  00 00                    addb     %al, (%bx, %si)
> 0x00100007:  00 00                    addb     %al, (%bx, %si)
> ```

### 向 Loader 迈进

由于 MBR 受限于 512 字节大小的空间，显然，这么点小小的空间肯定不足以我们将内核加载进内存并运行。所以一个很自然的想法就是，实现一个 Loader，用它来初始化环境并加载内核。

Loader 应该被 MBR 从硬盘读取到内存后执行，那我们应该将 Loader 写在硬盘中什么位置呢？我们知道 MBR 已经占据了第 0 扇区（LBA 扇区从 0 开始编号），那我们把它放到第 1 扇区？当然可以，但是离得那么近，心理多少有点不踏实，还是隔开点好了……那就放到第 2 扇区好啦～那么现在的问题是，我们把它加载到哪里好呢？理论上任何一块空闲空间都可以，参考实模式下的 1MB 内存布局可知，0x0500\~0x7BFF 和 0x7E00\~0x9FBFF 都是空闲内存。由于未来 Loader 中需要定义一些数据结构，比如 GDT，这些数据结构将来的内核还需要使用，所以 Loader 加载到内存后不能被覆盖；其次，随着我们不断添加功能，内核必然越来越大，其所在的内存地址也会向越来越高的的地方发展，难免会超过可用区域的上限，所以应该尽量把 Loader 放在低处，多留一些空间给内核。但……我选择效仿 Linux 内核的设计，把它加载到了 0x90000 这个位置，大家随意～

有关硬盘的操作，可以参考 [AT Attachment with Packet Interface](http://ebook.pldworld.com/_eBook/ATA%20spec/ATA7_Spec.pdf).

至于代码嘛……如果我每次新增了什么代码都复制一份贴到博客里显然有点多余，显得过于杂乱了。所以劳烦您自行阅读我提交的 source code. 仓库地址在 [前言](#前言) 底部已经给出。

# 开发日志

Yeeee! 今天，03/12/2025，我终于正式写下了 Exordium 的第一行代码<s>（其实是好几行……）</s>。从此，接力棒由 BIOS 传到了 MBR 之手，真是值得庆祝的一刻呢！

# 书中的勘误

基于 **_《操作系统真象还原》（2022.10 重印）_**。

虽然可能错的是我，但并不妨碍我写出来。欢迎一起讨论～

## 第 0 章：一些你可能正感到迷惑的问题

- **0.2 你想研究到什么程度**

三处 $$4\times 4\times 4$$ 应修改为 $$4+4+4$$。

- **0.15 局部变量和函数参数为什么要放在栈中**

> 栈由于是向下生长的，堆栈框架就是把 esp 指针提前加一个数，原 esp 指针到新 esp 指针之间的栈空间用来存储局部变量。

这里应该说是提前减一个数才对，因为栈是从高地址向低地址生长的，所以创建栈帧是减，清理才是加。

## 第 1 章：部署工作环境

- **1.3 操作系统的宿主环境**

> 在编译中要加 -lpthread 参数。用 vim 编译 makefile，vim 是 Linux 下功能最为强大的文本编辑器。vim Makefile 回车：

此处有个小小的 typo：「用 vim 编译 makefile」应改为「用 vim 编辑 makefile」。

## 第 2 章：编写 MBR 主引导记录，让我们开始掌权

- **2.2 软件接力第一棒，BIOS**

这里存在一个表格内部的 typo，原表格如下：

| 起始  | 结束  | 大小 | 用途                                                                                                                                              |
| ----- | ----- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| FFFF0 | FFFFF | 16B  | BIOS 入口地址，此地址也属于 BIOS 代码，同样属于顶部的 640KB 字节。只是为了强调其入口地址才单独贴出来。此处 16 字节的内容是跳转指令 jmp F000\:E05B |

修改为属于顶部的 64KB 字节而不是 640KB：

| 起始  | 结束  | 大小 | 用途                                                                                                                                             |
| ----- | ----- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| FFFF0 | FFFFF | 16B  | BIOS 入口地址，此地址也属于 BIOS 代码，同样属于顶部的 64KB 字节。只是为了强调其入口地址才单独贴出来。此处 16 字节的内容是跳转指令 jmp F000\:E05B |

## 第 3 章：完善 MBR

- **3.1.3 什么是 vstart**

两处「code.节名.start」应修改为「section.节名.start」。

- **3.2.2 实模式下的寄存器**

还是 typo：「IP 寄存器是不可见寄存器，CS 寄存器是可见寄存器。这两个配合在一起后就是 CPU 的罗盘，它们是给 CPU 导航用的。CPU 执行到何处，完成要听从这两个寄存器的安排。」，「完成」应改成「完全」。

- **3.2.4 实模式下 CPU 内存寻址方式**

直接寻址这里，「第二条指令中，由于使用了段跨越前缀 fs，0x5678 的段基址变成了 gs 寄存器。」这里不应该是 gs 寄存器，而是 fs 寄存器才对。

- **3.2.7 实模式下的 call - 16 位实模式相对近调用**

「指令中的立即数地址可以是被调用的函数名、标号、立即数，函数名同标号一样，它只是地址的人性化表示方法，最终会被编译器转换为一个实际数字地址，如 call near prog_name。」这里「prog_name」应改为同下文一样的「proc_name」。

「这好办，咱们上 bochs 看，让其边执行边反汇编给咱们看结果。下面粗体的文件是我加的注释说明。」这里「文件」应该改成「文字」吧。改成「文字」的话，排版上也存在问题，因为贴出来的额外注释字体并不是呈粗体的。还有一种可能是，作者将 `> (markdown cite syntax)` 引用格式的排版描述为粗体，将引用内容描述成文件，不过这样理解的话也会引出一个争端：引用的内容称为「文件」并不合适，如果一定要用「文件」这个词语的话，我觉得写成「文件内容」更好。

- **3.3.1 CPU 如何与外界设备通信——IO 接口**

「再说，同任何一个设备打交道，CPU 那么速度那么快，它不得嫌弃别人慢吗……」多打了一个「那么」。

- **3.5.3 硬盘控制器端口**

「有些命令需要指定额外参数，这些参数就写在 Fea ture 寄存器中。」这里的问题是「Fea ture」中多打了一个空格，应改成「Feature」。

- **3.6.1 改造 MBR**

「我们的 MBR 受限于 512 字节大小的，在那么小的空间中……」多打了一个「的」。

「在寄存器 eax 中的是待读入的扇区起始地址，赋值后 eax 为定义的宏 LOADER_START\_ SECTOR，即 0x2。」这里「LOADER_START\_ SECTOR」多打了一个空格，应改为「LOADER_START_SECTOR」。

「段内偏移地址正因为是 16 位，只能访问 64KB 的段空间，所以才将段基址乘以 16 来突破这 64KB，从而实现访问低调 1MB 空间的。」这里可能是多打了一个「低调」，也可能是多打了一个「调」。
