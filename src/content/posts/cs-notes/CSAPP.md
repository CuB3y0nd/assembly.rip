---
title: "The CSAPP Notebook"
published: 2025-07-16
updated: 2025-07-20
description: "CMU 15213/15513 CSAPP learning notes."
image: "./covers/CSAPP.png"
tags: ["CSAPP", "Notes"]
category: "Notes"
draft: false
---

# 前言

不开心，不想说话……让我们直接进入这段有趣的学习之旅吧，试试两个月，甚至更短的时间内解决掉这门又臭又长的课程。

# Bits, Bytes, and Integers

## Representation information as bits

### Everything is bits

### By encoding/interpreting sets of bits in various ways

- Computers determine what to do (instructions)
- ... and represent and manipulate numbers, sets, strings, etc...

### Why bits? Electronic Implementation

- Easy to store with bitsable elements
- Reliably transmitted on noisy and inaccurate wires
- Easy to indicate low level/high level

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-17-001818.png" />
</center>

## Bit-level manipulations

### Representing & Manipulating Sets

#### Representation

We can use bits to determine whether an element belongs to a set. Say each bit have index, which corresponds to a number from zero. If a bit is set to 1, it means the corresponding index (i.e., the element) is in the set. Otherwise, its not.

In a more mathematical representation way:

- Width $w$ bit vector represents subsets subsets of $\{0,\ ...,\ w-1\}$
- $a_{j} =1$ if $j\in A$

#### Sets Operations

- `&` is related to Intersection
- `|` is related to Union
- `~` is related to Complement
- `^` is related to Symmetric difference

#### Shift Operations

- Left Shift: `x << y`

  - Shift bit-vector `x` left `y` positions
    - Throw away extra bits on left
  - Fill with 0's on right

- Right Shift: `x >> y`
  - Shift bit-vector `x` right `y` positions
    - Throw away extra bits on right
  - Logical shift
    - Fill with 0's on left
  - Arithmetic shift
    - Replicate most significant bit on left

#### Undefined Behaviour

- Shift amount $< $ 0
- Shift amount $\geqslant $ word size
- Left shift a signed value

## Integers

### Unsigned

$$\displaystyle B2U( X) =\sum _{i=0}^{w-1} x_{i} \cdot 2^{i}$$

### Two's Complement

$$\displaystyle B2T( X) =-x_{w-1} \cdot 2^{w-1} +\sum _{i=0}^{w-2} x_{i} \cdot 2^{i}$$

#### Invert mappings

- $U2B( x) =B2U^{-1}( x)$
- $T2B( x) =B2T^{-1}( x)$

### Numeric Ranges

- Unsigned Values

  - $\displaystyle UMin\ =\ 0$
  - $\displaystyle UMax\ =\ 2^{w} -1$

- Two's Complement Values
  - $\displaystyle TMin = -2^{w-1}$
  - $\displaystyle TMax\ =\ 2^{w-1} -1$

:::tip
In C, these ranges are declared in `limits.h`. e.g., `ULONG_MAX`, `LONG_MAX`, `LONG_MIN`. Values are platform specific.
:::

#### Observations

- $|TMin|=TMax+1$
  - Asymmetric range (Every positive value can represent as a negative value, but $TMin$ cannot represent as a positive value)
- $UMax\ =\ 2\cdot TMax+1$

### Difference between Unsigned & Signed Numeric Values

The difference between Unsigned & Signed Numeric Values is $2^{w}$.

For example, if you want convert a unsigned numeric value to its signed form, just use this value minus $2^{w}$, or if you want convert a signed numeric value to its unsigned form, you plus $2^{w}$.

### Conversion, casting

Mappings between unsigned and two's complement numbers keep bit representations and reinterpret.

For example, casting a signed value to its unsigned form, the most significant bit from large negative weight becomes to large positive weight and vice versa.

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-012230.png" />
</center>

#### Constants

- By default are considered to be signed integers.
- Unsigned if have "U" as suffix

#### Casting

- Explicit casting between signed & unsigned same as `U2T` and `T2U`
- Implicit casting also occurs via assignments and procedure call (assignments will casting to lhs's type)

#### Expression Evaluation

- If there is a mix of unsigned and signed in single expression, signed values implicitly cast to unsigned
- Including comparison operations `<`, `>`, `==`, `<=`, `>`

| Constants 1    | Constants 2        | Relation | Evaluation |
| -------------- | ------------------ | -------- | ---------- |
| `0`            | `0U`               | ==       | unsigned   |
| `-1`           | `0`                | <        | signed     |
| `-1`           | `0U`               | >        | unsigned   |
| `2147483647`   | `-2147483647-1`    | >        | signed     |
| `2147483647U`  | `-2147483647-1`    | <        | unsigned   |
| `-1`           | `-2`               | >        | signed     |
| `(unsigned)-1` | `-2`               | >        | unsigned   |
| `2147483647`   | `2147483648U`      | <        | unsigned   |
| `2147483647`   | `(int)2147483648U` | >        | signed     |

### Expanding, truncating

#### Sign Extension

- Make $k$ copies of sign bit
- $\displaystyle X\prime =X_{w-1} ,...,X_{w-1} ,X_{w-1} ,X_{w-2} ,...,X_{0}$

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-090746.png" />
</center>

:::note
Converting from smaller to larger integer data type. C automatically performs sign extension.
:::

#### Expanding (e.g., short int to int)

- Unsigned: zeros added
- Signed: sign extension
- Both yield expected result

#### Truncating (e.g., unsigned to unsigned short)

- Unsigned/signed: bits are truncated
- Result reinterpreted
- Unsigned: mod operation
- Signed: similar to mod
- For small numbers yields expected behavior

### Addition, negation, multiplication, shifting

#### Unsigned Addition

- Standard Addition Function
  - Ignore carry output
- Implements Modular Arithmetic
  - $\displaystyle UAdd_{w}( u,v) =( u+v)\bmod 2^{w}$

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-110927.png" />
</center>

##### Visualizing (Mathematical) Integer Addition

- Integer Addition
  - 4-bit integers $u,v$
  - Compute true sum $Add_{4}( u,v)$
  - Values increase linearly with $u$ and $v$
  - Forms planar surface

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-111318.png" />
</center>

##### Visualizing Unsigned Addition

- Wraps Around
  - If true sum $\geqslant 2^{w}$
  - At most once

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-111930.png" />
</center>

#### Two's Complement Addition

- $TAdd$ and $UAdd$ have Identical Bit-level Behaviour

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-112117.png" />
</center>

Signed vs. unsigned addition in C:

```c
int s, t, u, v;

s = (int)((unsigned)u + (unsigned)v);
t = u + v;

// will give s == t
```

##### TAdd Overflow

- Functionality
  - True sum requires $w+1$ bits
  - Drop off MSB
  - Treat remaining bits as two's complement integer

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-113401.png" />
</center>

##### Visualizing Two's Complement Addition

- Values

  - 4-bit two's comp.
  - Range from $-8$ to $+7$

- Wraps Around
  - If sum $\geqslant 2^{w-1}$
    - Becomes negative
    - At most once
  - If sum $< -2^{w-1}$
    - Becomes positive
    - At most once

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-113721.png" />
</center>

#### Multiplication

- Goal: Computing Product of $w$-bit numbers $x,y$
  - Either signed or unsigned
- But, exact results can be bigger than $w$ bits
  - Unsigned: up to $2w$ bits
    - Result range: $0\leqslant x\cdot y\leqslant \left( 2^{w} -1\right)^{2} =2^{2w} -2^{w+1} +1$
  - Two's complement min (negative): Up to $2w-1$ bits
    - Result range: $x\cdot y\geqslant \left( -2^{w-1}\right) \cdot \left( 2^{w-1} -1\right) =-2^{2w-2} +2^{w-1}$
  - Two's complement max (positive): Up to $2w$ bits, but only for $( TMin_{w})^{2}$
    - Result range: $x\cdot y\leqslant \left( -2^{w-1}\right)^{2} =2^{2w-2}$
- So, maintaining exact results...
  - would need to keep expanding word size with each product computed (exhaust memory faster)
  - is done in software, if needed
    - e.g., by "arbitrary precision" arithmetic packages

##### Unsigned Multiplication in C

- Standard Multiplication Function
  - Ignore high order $w$ bits
- Implements Modular Arithmetic
  - $\displaystyle UMult_{w}( u,v) =( u\cdot v)\bmod 2^{w}$

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-115644.png" />
</center>

##### Signed Multiplication in C

- Standard Multiplication Function
  - Ignore high order $w$ bits
  - Some of which are different for signed vs. unsigned multiplication
  - Lower bits are the same

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-120148.png" />
</center>

#### Power-of-2 Multiply with Shift

- Operation
  - `u << k` gives $u\cdot 2^{k}$
  - Both signed and unsigned

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-120935.png" />
</center>

#### Unsigned Power-of-2 Divide with Shift

- Quotient of Unsigned by Power of 2
  - `u >> k` gives $\left\lfloor u/2^{k}\right\rfloor $
  - Uses logical shift

<center>
  <img src="https://cdn.jsdelivr.net/gh/CuB3y0nd/IMAGES@master/assets/Shot-2025-07-20-123020.png" />
</center>

#### Signed Power-of-2 Divide with Shift

- Quotient of Signed by Power of 2
  - `u >> k` gives $u/2^{k} +bias\ ( 1)$
  - Uses arithmetic shift

### Handy tricks

If you want convert a value $u$ to its negative form by hand or in mind, either unsigned or signed.

Just do: $\sim u+1$

### When Should I Use Unsigned?

**Don't use without understanding implications!**

- Do use when performing modular arithmetic
  - Multiplication arithmetic
- Do use when using bits to represent sets
  - Logical right shift, no sign extension

## Representation in memory, pointers, strings

### Byte-Oriented Memory Organization

- Programs refer to data by address
  - Conceptually, envision it as a very large array of bytes
    - In reality, it’s not, but can think of it that way
  - An address is like an index into that array
    - and, a pointer variable stores an address
- System provides private address spaces to each "process"
  - So, a program can clobber its own data, but not that of others

### Machine Words

- Any given computer has a "Word Size"
  - Nominal size of integer-valued data
    - and of addresses
  - Until recently, most machines used 32 bits (4 bytes) as word size
    - Limits addresses to 4GB ($2^{32}$ bytes)
  - Increasingly, machines have 64‐bit word size
    - Potentially, could have 18 EB (exabytes) of addressable memory
    - That's $18.4\times 10^{18}$ bytes
  - Machines still support multiple data formats
    - Fractions or multiples of word size
    - Always integral number of bytes

### Word‐Oriented Memory Organization

- Addresses Specify Byte Locations
  - Address of first byte in word
  - Addresses of successive words differ by 4 (32‐bit) or 8 (64‐bit)

### Byte Ordering

- Big Endian: Sun, PPC Mac, Internet
  - Least significant byte has highest address
- Little Endian: x86, ARM processors running Android, iOS, and Windows
  - Least significant byte has lowest address

### Representation Strings

In C, either LSB or MSB machine, strings in memory represented in same way, because a string is essentially an array of characters ends with `\x00`, each character is one byte encoded in ASCII format and single byte (character) do not obey the LSB or MSB rule.

# References

- [15-213: Intro to Computer Systems: Schedule for Fall 2015](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f15/www/schedule.html)
