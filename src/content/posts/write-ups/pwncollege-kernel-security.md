---
title: "Write-ups: System Security (Kernel Security) series"
published: 2025-12-19
updated: 2025-12-19
description: "Write-ups for pwn.college kernel exploitation series."
image: "https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.pfs8v4jqs.avif"
tags: ["Pwn", "Write-ups", "Kernel"]
category: "Write-ups"
draft: false
---

> 你终于踏入了 Ring 0，那不是权力的开始，而是谦卑的第一步。

# 前言

本来预计 12.1 看完 kernel 的几个讲义，2 号直接开始做题，然后我也不知道我在干什么，讲义看了十几天才看完，一直到 19 号才开始做第一题……

期间花了几天时间写了一个全平台通用的自动化创建 kernel exploitation lab 环境的脚本，~~请务必 star 一下（~~

::github{repo="CuB3y0nd/panix"}

# Level 1.0

## Information

- Category: Pwn

## Description

> Ease into kernel exploitation with this simple crackme level!

## Write-up

经典的 LKM 结构，加载的时候调用 `init_module`，移除的时候调用 `cleanup_module`，`init_module` 里面打开了 `/flag` 并写入内核空间的 buffer，然后通过 `proc_create` 创建了 `/proc/pwncollege`，提供了 `device_open`，`device_write`，`device_read`，`device_release`，我们发现 `device_write` 里面实现了如下状态机：

```c
ssize_t __fastcall device_write(file *file, const char *buffer, size_t length, loff_t *offset)
{
  size_t n16; // rdx
  char password[16]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v8; // [rsp+10h] [rbp-18h]

  v8 = __readgsqword(0x28u);
  printk(&unk_810);
  n16 = 16;
  if ( length <= 0x10 )
    n16 = length;
  copy_from_user(password, buffer, n16);
  device_state[0] = (strncmp(password, "ucihjkpyaybhjjsf", 0x10u) == 0) + 1;
  return length;
}
```

如果我们写入密码 `ucihjkpyaybhjjsf`，`device_write` 就会将 `device_state[0]` 设置为 2，继续看 `device_read` 函数：

```c
ssize_t __fastcall device_read(file *file, char *buffer, size_t length, loff_t *offset)
{
  const char *flag; // rsi
  size_t length_1; // rdx
  unsigned __int64 v8; // kr08_8

  printk(&unk_850);
  flag = flag;
  if ( device_state[0] != 2 )
  {
    flag = "device error: unknown state\n";
    if ( device_state[0] <= 2 )
    {
      flag = "password:\n";
      if ( device_state[0] )
      {
        flag = "device error: unknown state\n";
        if ( device_state[0] == 1 )
        {
          device_state[0] = 0;
          flag = "invalid password\n";
        }
      }
    }
  }
  length_1 = length;
  v8 = strlen(flag) + 1;
  if ( v8 - 1 <= length )
    length_1 = v8 - 1;
  return v8 - 1 - copy_to_user(buffer, flag, length_1);
}
```

如果 `device_state[0] == 2` 就将内核中的 flag 写入到用户态的 buffer 中。

最后庆祝一下人生中第一道 kernel（

<center>
  <img src="https://ghproxy.net/https://raw.githubusercontent.com/CuB3y0nd/picx-images-hosting/master/.lw6yu8lcj.avif" alt="" />
</center>

## Exploit

```c
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define FLAG_LENGTH 0x100

char password[] = "ucihjkpyaybhjjsf";
char flag[FLAG_LENGTH];

int main(int argc, char *argv[]) {
  int fd = open("/proc/pwncollege", O_RDWR);

  write(fd, password, strlen(password));
  read(fd, flag, FLAG_LENGTH);
  write(STDOUT_FILENO, flag, FLAG_LENGTH);

  return 0;
}
```

# Level 2.0

## Information

- Category: Pwn

## Description

> Ease into kernel exploitation with another crackme level.

## Write-up

输密码，密码对了就成了。

## Exploit

```c
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

char password[] = "zcexibhdcclcottw";

int main(int argc, char *argv[]) {
  int fd = open("/proc/pwncollege", O_WRONLY);

  write(fd, password, strlen(password));

  return 0;
}
```

# Level 3.0

## Information

- Category: Pwn

## Description

> Ease into kernel exploitation with another crackme level, this time with some privilege escalation (whoami?).

## Write-up

白给的提权函数，提权后再 `cat /flag` 就好了。

## Exploit

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char password[] = "tzrfzpifnzshksnp";

int main(int argc, char *argv[]) {
  int fd = open("/proc/pwncollege", O_WRONLY);

  printf("Current UID: %d\n", getuid());
  write(fd, password, strlen(password));
  printf("Current UID: %d\n", getuid());
  system("cat /flag");

  return 0;
}
```

# Level 4.0

## Information

- Category: Pwn

## Description

> Ease into kernel exploitation with another crackme level and learn how kernel devices communicate.

## Write-up

这次提供的是 `device_ioctl`，即我们需要通过 `ioctl` 函数来操作设备。

```c
__int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  __int64 result; // rax
  int v5; // r8d
  char password[16]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v7; // [rsp+10h] [rbp-18h]

  v7 = __readgsqword(0x28u);
  printk(&unk_328, file, cmd, arg);
  result = -1;
  if ( cmd == 1337 )
  {
    copy_from_user(password, arg, 16);
    v5 = strncmp(password, "qyikgpxrxvcinxbe", 0x10u);
    result = 0;
    if ( !v5 )
    {
      win();
      return 0;
    }
  }
  return result;
}
```

## Exploit

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define REQUEST 1337

char password[] = "qyikgpxrxvcinxbe";

int main(int argc, char *argv[]) {
  int fd = open("/proc/pwncollege", O_WRONLY);

  printf("Current UID: %d\n", getuid());
  ioctl(fd, REQUEST, password);
  printf("Current UID: %d\n", getuid());
  system("cat /flag");

  return 0;
}
```
