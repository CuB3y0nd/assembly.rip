---
title: "The CSAPP Notebook"
published: 2025-07-16
updated: 2025-08-11
description: "CMU 15213/15513 CSAPP learning notes."
image: "https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.23262tnnad.avif"
tags: ["CSAPP", "Notes"]
category: "Notes"
draft: false
---

# 前言

不开心，不想说话……让我们直接进入这段有趣的学习之旅吧，试试两个月，甚至更短的时间内解决掉这门又臭又长的课程。

# Bits, Bytes, and Integers

## Representation information as bits

### Everything is bits

#### Each bit is 0 or 1

#### By encoding/interpreting sets of bits in various ways

- Computers determine what to do (instructions)
- ... and represent and manipulate numbers, sets, strings, etc...

#### Why bits ? Electronic Implementation

- Easy to store with bitsable elements
- Reliably transmitted on noisy and inaccurate wires
- Easy to indicate low level/high level

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1e8wit31ra.avif)

## Bit-level manipulations

### Representing & Manipulating Sets

#### Representing Sets

We can use bits to determine whether an element belongs to a set. Say each bit have index, which corresponds to a number from zero. If a bit is set to 1, it means the corresponding index (i.e., the element) is in the set. Otherwise, its not.

In a more mathematical representation way:

- Width $w$ bit vector represents subsets subsets of $\{0,\ ...,\ w-1\}$
- $a_{j} =1$ if $j\in A$

#### Sets Operations

- `&` is related to Intersection
- `|` is related to Union
- `~` is related to Complement
- `^` is related to Symmetric difference

### Shift Operations

#### Left Shift: `x << y`

- Shift bit-vector `x` left `y` positions
  - Throw away extra bits on left
- Fill with 0's on right

#### Right Shift: `x >> y`

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

### Representation: unsigned and signed

#### Unsigned

$$\displaystyle B2U( X) =\sum _{i=0}^{w-1} x_{i} \cdot 2^{i}$$

#### Two's Complement

$$\displaystyle B2T( X) =-x_{w-1} \cdot 2^{w-1} +\sum _{i=0}^{w-2} x_{i} \cdot 2^{i}$$

#### Invert mappings

- $U2B( x) =B2U^{-1}( x)$
- $T2B( x) =B2T^{-1}( x)$

#### Numeric Ranges

- Unsigned Values

  - $\displaystyle UMin\ =\ 0$
  - $\displaystyle UMax\ =\ 2^{w} -1$

- Two's Complement Values
  - $\displaystyle TMin = -2^{w-1}$
  - $\displaystyle TMax\ =\ 2^{w-1} -1$

:::tip
In C, these ranges are declared in `limits.h`. E.g., `ULONG_MAX`, `LONG_MAX`, `LONG_MIN`. Values are platform specific.
:::

#### Observations

- $|TMin|=TMax+1$
  - Asymmetric range (Every positive value can be represented as a negative value, but $TMin$ cannot be represented as a positive value)
- $UMax\ =\ 2\cdot TMax+1$

#### Difference between Unsigned & Signed Numeric Values

The difference between Unsigned & Signed Numeric Values is $2^{w}$.

For example, if you want convert a unsigned numeric value to its signed form, just use this value minus $2^{w}$, or if you want convert a signed numeric value to its unsigned form, you plus $2^{w}$.

### Conversion, casting

Mappings between unsigned and two's complement numbers keep bit representations and reinterpret.

For example, casting a signed value to its unsigned form, the most significant bit from large negative weight becomes to large positive weight and vice versa.

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.86ty59tug4.avif)

#### Constants

- By default are considered to be signed integers
- Unsigned if have "U" as suffix

#### Casting

- Explicit casting between signed & unsigned same as $U2T$ and $T2U$
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

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5trbo2gghg.avif)

:::warning
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

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.lw112nu4l.avif)

##### Visualizing (Mathematical) Integer Addition

- Integer Addition
  - 4-bit integers $u,v$
  - Compute true sum $Add_{4}( u,v)$
  - Values increase linearly with $u$ and $v$
  - Forms planar surface

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4qrmd6lcsq.avif)

##### Visualizing Unsigned Addition

- Wraps Around
  - If true sum $\geqslant 2^{w}$
  - At most once

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.45hyqvrbgg.avif)

#### Two's Complement Addition

- $TAdd$ and $UAdd$ have Identical Bit-level Behaviour

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1e8wit5juy.avif)

Signed vs. Unsigned Addition in C:

```c
int s, t, u, v;

s = (int)((unsigned)u + (unsigned)v);
t = u + v;

// will give s == t
```

##### TAdd Overflow

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7eh2njfkev.avif)

- Functionality
  - True sum requires $w+1$ bits
  - Drop off MSB
  - Treat remaining bits as two's complement integer

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6wr0yyekf9.avif)

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

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.pfmysj7jj.avif)

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

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5mo3smxcua.avif)

##### Signed Multiplication in C

- Standard Multiplication Function
  - Ignore high order $w$ bits
  - Some of which are different for signed vs. unsigned multiplication
  - Lower bits are the same

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8vn7pal9ub.avif)

#### Power-of-2 Multiply with Shift

- Operation
  - `u << k` gives $u\cdot 2^{k}$ (basically increases each bits weight)
  - Both signed and unsigned

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5c19zhj0ap.avif)

#### Unsigned Power-of-2 Divide with Shift

- Quotient of Unsigned by Power of 2
  - `u >> k` gives $\left\lfloor u/2^{k}\right\rfloor $
  - Uses logical shift

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.102gry07d5.avif)

#### Signed Power-of-2 Divide with Shift

- Quotient of Signed by Power of 2
  - Uses arithmetic shift
  - Want $\lceil x/2^{k} \rceil $ (Round toward 0)
  - Compute as $\left\lfloor \left( x+2^{k} -1\right) /2^{k}\right\rfloor $
    - In C: `(x + (1 << k) - 1) >> k`
    - Biases dividend toward 0

##### Case 1: No rounding

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5trbo2ldaa.avif)

##### Case 2: Rounding

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8adk2zsm1r.avif)

### Handy tricks

If you want convert a value $u$ to its negative form by hand or in mind, either unsigned or signed.

Just do: $\sim u+1$

### When Should I Use Unsigned ?

:::caution
**Don't use without understanding implications!**
:::

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
    - Limits addresses to 4 GB ($2^{32}$ bytes)
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

In C, either little endian or big endian machine, strings in memory represented in the same way, because a string is essentially an array of characters ends with `\x00`, each character is one byte encoded in ASCII format and single byte (character) do not obey the byte ordering rule.

# Floating Point

## Background: Fractional binary numbers

### Representing

- Bits to right of "binary point" represent fractional powers of 2
- Represents rational number: $\displaystyle \sum _{k=-j}^{i} b_{k} \cdot 2^{k}$

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.23262tx92l.avif)

| Value                        | Representation |
| ---------------------------- | -------------- |
| $\displaystyle5\frac{3}{4}$  | $101.11_{2}$   |
| $\displaystyle2\frac{7}{8}$  | $10.111_{2}$   |
| $\displaystyle1\frac{7}{16}$ | $1.0111_{2}$   |

### Observations

- Divide by 2 by shifting right (unsigned)
- Multiply by 2 by shifting left
- Numbers of form $0.111111\dots_{2}$ are just below $1.0$
  - $\displaystyle \frac{1}{2} +\frac{1}{4} +\frac{1}{8} +\dots+\frac{1}{2^{i}} +\dots\rightarrow 1.0$
  - Use notation $1.0−\epsilon $ ($\epsilon $ depends on how many bits you have to the right of the binary point. If it gets smaller the more, the more of those bits you have there, and it gets closer to $1$)

### Limitation 1

- Can only exactly represent numbers of the form $\displaystyle\frac{x}{2^{k}}$
  - Other rational numbers have repeating bit representations, but cause computer system can only hold a finite number of bits, so $0.1+0.2\neq 0.3$

| Value                       | Representation                     |
| --------------------------- | ---------------------------------- |
| $\displaystyle\frac{1}{3}$  | $0.0101010101[ 01] \dots_{2}$      |
| $\displaystyle\frac{1}{5}$  | $0.001100110011[ 0011] \dots_{2}$  |
| $\displaystyle\frac{1}{10}$ | $0.0001100110011[ 0011] \dots_{2}$ |

### Limitation 2

- Just one setting of binary point within the $w$ bits
  - Limited range of numbers (very small values ? very large ? we have to move the binary point to represent sort of wide as wide a range as possible with as much precision given the number of bits)

## Definition: IEEE Floating Point Standard

### IEEE Standard 754

Established in 1985 as uniform standard for floating point arithmetic. Before that, many idiosyncratic formats.

Although it provided nice standards for rounding, overflow, underflow... It is hard to make fast in hardware (Numerical analysts predominated over hardware designers in defining standard)

## Floating Point Representation

Numerical form: $( -1)^{s} \cdot M\cdot 2^{E}$

- Sign bit $s$ determines whether number is negative or positive
- Significand $M$ (Mantissa) normally a fractional value in range $[ 1.0,2.0)$
- Exponent $E$ weights value by power of two

### Encoding

- MSB `s` is sign bit $s$
- `exp` field encodes $E$ (but is not equal to $E$)
- `frac` field encodes $M$ (but is not equal to $M$)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2yynia7gbn.avif)

#### Normalized Values

- Condition: $exp\neq 000\dotsc 0$ and $exp\neq 111\dotsc 1$
- Exponent coded as a biased value: $E=exp-bias$
  - $exp$ is unsigned value of exp field
  - $bias=2^{k-1} -1$, where $k$ is number of exponent bits
    - Single precision: $127$ ($exp\in [ 1,254]$, $E\in [ -126,127]$)
    - Double precision: $1023$ ($exp\in [ 1,2046]$, $E\in [ -1022,1023]$)
- Significand coded with implied leading $1$: $M=1.xxx\dotsc x_{2}$
  - $xxx\dotsc x$ is bits of frac field
  - Minimum when $frac=000\dotsc 0\ ( M=1.0)$
  - Maximum when $frac=111\dotsc 1\ ( M=2.0-\epsilon )$
  - Get extra leading bit for "free"

##### Normalized Encoding Example

- Value: `float F = 15213.0;`
  - $15213_{10} =11101101101101_{2} =1.1101101101101\times 2^{13}$
- Significand
  - $M=( 1.) 1101101101101_{2}$
  - $frac=11011011011010000000000_{2}$
- Exponent
  - $E=13$
  - $bias=127$
  - $exp=140=10001100_{2}$

So the result would be:

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4g4sk1cfjd.avif)

```python
# manually calculate
((-1)**0)*(1+1/2+1/4+1/16+1/32+1/128+1/256+1/1024+1/2048+1/8192)*(2**13) == 15213.0

# by struct package
import struct

bits = 0b01000110011011011011010000000000
f = struct.unpack("f", struct.pack("I", bits))[0]

print(f)
```

#### Denormalized Values

- Condition: $exp=000\dotsc 0$
- Exponent value: $E=1-bias\ ( instead\ of\ E=0-bias)$
- Significand coded with implied leading $0$: $M=0.xxx\dotsc x_{2}$
  - $xxx\dotsc x$ is bits of frac field
- Cases
  - $exp=000\dotsc 0,frac=000\dotsc 0$
    - Represents zero value
    - Note distinct values: $+0$ and $-0$
  - $exp=000\dotsc 0,farc\neq 000\dotsc 0$
    - Numbers closet to $0.0$
    - Equispaced

#### Special Values

- Condition: $exp=111\dotsc 1$
- Case: $exp=111\dotsc 1,frac=000\dotsc 0$

  - Represents value $\infty $
  - Operation that overflows
  - Both positive and negative
  - E.g., $1.0/0.0=-1.0/-0.0=+\infty ,1.0/-0.0=-\infty $

- Case: $exp=111\dotsc 1,frac\neq 000\dotsc 0$
  - Not-a-Number (NaN)
  - Represents case when no numeric value can be determined
  - E.g., $\sqrt{-1} ,\infty -\infty ,\infty \cdot 0$

### Visualization: Floating Point Encodings

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4xuu8me5ea.avif)

### Example and properties

#### Tiny Floating Point Example

Think about this 8-bit Floating Point Representation below, it obeying the same general form as IEEE Format:

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.26ls0jseh0.avif)

#### Dynamic Range (Positive Only)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6pnt3iy9a6.avif)

#### Distribution of Values

Still think about our tiny example, notice how the distribution gets denser toward zero.

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3gop6vb6vl.avif)

Here is a scaled close-up view:

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3gop6vbl8i.avif)

### Special Properties of the IEEE Encoding

- Floating Point Zero Same as Integer Zero
  - All bits = 0
- Can (Almost) Use Unsigned Integer Comparison
  - Must first compare sign bits
  - Must consider $-0=0$
  - NaNs problematic
    - What should comparison yield ?
  - Otherwise OK
    - Denormalized vs. Normalized
    - Normalized vs. Infinity

## Rounding, addition, multiplication

### Floating Point Operations: Basic Idea

$x+_{f} y=round( x+y)$

$x\times _{f} y=round( x\times y)$

#### Basic idea

- First compute exact result
- Make it fit into desired precision
  - Possibly overflow if exponent too large
  - Possibly round to fit into frac

### Rounding

Rounding Modes (illustrate with $ rounding)

|                         | $1.40 | $1.60 | $1.50 | $2.50 | -$1.50 |
| ----------------------- | ----- | ----- | ----- | ----- | ------ |
| Towards Zero            | $1    | $1    | $1    | $2    | -$1    |
| Round Down ($-\infty $) | $1    | $1    | $1    | $2    | -$2    |
| Round Up ($+\infty $)   | $2    | $2    | $2    | $3    | -$1    |
| Nearest Even (default)  | $1    | $2    | $2    | $2    | -$2    |

:::note[Round to Even]
It means, if you have a value that's less than half way then you round down, if more than half way, round up. When you have something that's exactly half way, then what you do is round towards the nearest even number.
:::

#### Closer Look at Round-To-Even

##### Default Rounding Mode

- Hard to get any other kind without dropping into assembly
- All others are statistically biased
  - Sum of set of positive numbers will consistently be over or underestimated

##### Applying to Other Decimal Places / Bit Positions

- When exactly half way between two possible values
  - Round so that least significant digit is even

E.g., round to nearest hundredth:

| Value     | Rounded |                       |
| --------- | ------- | --------------------- |
| 7.8949999 | 7.89    | Less than half way    |
| 7.8950001 | 7.90    | Greater than half way |
| 7.8950000 | 7.90    | Half way (round up)   |
| 7.8850000 | 7.88    | Half way (rond down)  |

##### Rounding Binary Numbers

Binary Fractional Numbers

- "Even" when least significant bit is 0
- "Half way" when bits to right of rounding position is $100\dotsc _{2}$

E.g., round to nearest $\displaystyle \frac{1}{4}$ (2 bits right of binary point)

| Value                         | Binary         | Rounded     | Action                           | Rounded Value                |
| ----------------------------- | -------------- | ----------- | -------------------------------- | ---------------------------- |
| $\displaystyle 2\frac{3}{32}$ | $10.00011_{2}$ | $10.00_{2}$ | Less than half way (round down)  | $2$                          |
| $\displaystyle 2\frac{3}{16}$ | $10.00110_{2}$ | $10.01_{2}$ | Greater than half way (round up) | $\displaystyle 2\frac{1}{4}$ |
| $\displaystyle 2\frac{7}{8}$  | $10.11100_{2}$ | $11.00_{2}$ | Half way (round up)              | $3$                          |
| $\displaystyle 2\frac{5}{8}$  | $10.10100_{2}$ | $10.10_{2}$ | Half way (round down)            | $\displaystyle 2\frac{1}{2}$ |

### Floating Point Multiplication

$( -1)^{s_{1}} \cdot M_{1} \cdot 2^{E_{1}} \cdot ( -1)^{s_{2}} \cdot M_{2} \cdot 2^{E_{2}} =( -1)^{s} \cdot M \cdot 2^{E}$

- Sign $s$ is $s_{1}$^$s_{2}$
- Significand $M$ is $M_{1} \cdot M_{2}$
- Exponent $E$ is $E_{1}+E_{2}$

#### Fixing

- If $M\geqslant 2$, shift $M$ right, increment $E$
- If $E$ out of range, overflow
- Round $M$ to fit frac precision

_Biggest chore in implementation is multiplying significands_

### Floating Point Addition

$( -1)^{s_{1}} \cdot M_{1} \cdot 2^{E_{1}} +( -1)^{s_{2}} \cdot M_{2} \cdot 2^{E_{2}} =( -1)^{s} \cdot M \cdot 2^{E}$ (Assume $E_{1}>E_{2}$)

- Sign $s$, significand $M$
  - Result of signed align & add
- Exponent $E$
  - $E_{1}$

#### Fixing

- If $M\geqslant 2$, shift $M$ right, increment $E$
- If $M<1$, shift $M$ left $k$ positions, decrement $E$ by $k$
- Overflow if $E$ out of range
- Round $M$ to fit frac precision

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9gwvbllly4.avif)

### Mathematical Properties of Floating Point Add

- Compare to those of Abelian Group
  - Closed under addition ? (Yes)
    - But may generate infinity or NaN
  - Commutative ? (Yes)
  - Associative ? (No)
    - Overflow and inexactness of rounding
    - `(3.14+1e10)-1e10 = 0, 3.14+(1e10-1e10) = 3.14`
  - $0$ is additive identity ? (Yes)
  - Every element has additive inverse ? (Almost)
    - Except for infinities & NaNs
- Monotonicity
  - $a\geqslant b\Rightarrow a+c\geqslant b+c$ ? (Almost)
    - Except for infinities & NaNs

### Mathematical Properties of Floating Point Mult

- Compare to Commutative Ring
  - Closed under multiplication ? (Yes)
    - But may generate infinity or NaN
  - Multiplication Commutative ? (Yes)
  - Multiplication is Associative ? (No)
    - Possibility of overflow, inexactness of rounding
    - `(1e20*1e20)*1e-20 = inf, 1e20*(1e20*1e-20) = 1e20`
  - $1$ is multiplicative identity ? (Yes)
  - Multiplication distributes over addition ? (No)
    - Possibility of overflow, inexactness of rounding
    - `1e20*(1e20-1e20) = 0.0, 1e20*1e20-1e20*1e20 = NaN`
- Monotonicity
  - $a\geqslant b\ \&\ c\geqslant 0\Rightarrow a\cdot c\geqslant b\cdot c$ ? (Almost)
    - Except for infinities & NaNs

## Floating Point in C

### Conversions / Casting

:::caution
Casting between `int`, `float`, and `double` changes bit representation!
:::

- `double/float` to `int`
  - Truncates fractional part
  - Like rounding toward zero
  - Not defined when out of range or $NaN$: Generally sets to $TMin$
- `int` to `double`
  - Exact conversion, as long as `int` has $\leqslant 53$ bit word size
- `int` to `float`
  - Will round according to rounding mode

# Machine-Level Programming

## History of Intel processors and architectures

Nobody (at least me), can keep these long history in mind! So I'll just skipping this part to save life~

## C, Assembly, Machine Code

### Definitions

- Architecture: (also ISA: instruction set architecture) The parts of a processor design that one needs to understand or write assembly/machine code
  - Examples: instruction set specification, registers
- Microarchitecture: Implementation of the architecture
  - Examples: cache sizes and core frequency

### Assembly / Machine Code View

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5c19zhouhx.avif)

### Turning C into Object Code

- Code in files `p1.c` `p2.c`
- Compile with command: `gcc -Og p1.c p2.c -o p`
  - Use basic optimizations (`-Og`) [New to recent versions of GCC]
  - Put resulting binary in file `p`

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8z6tn0l05d.avif)

### Assembly Characteristics: Data Types

- "Integer" data of 1, 2, 4 or 8 bytes
  - Data values
  - Address (untyped pointers)
- Floating Point data of 4, 8 or 10 bytes
- Code: Byte sequences encoding series of instructions
- No aggregate types such as arrays or structures
  - Just contiguously allocated bytes in memory

### Assembly Characteristics: Operations

- Perform arithmetic function on register or memory data
- Transfer data between memory and register
  - Load data from memory into register
  - Store register data into memory
- Transfer control
  - Conditional branches
  - Unconditional jumps to/from procedures

### Object Code

- Assembler
  - Translates `.s` into `.o`
  - Binary encoding of each instruction
  - Nearly-complete image of executable code
  - Missing linkages between code in different files
- Linker
  - Resolves references between files
  - Combines with static run-time libraries
    - E.g., code for `malloc`, `printf`
  - Some libraries are dynamically linked
    - Linking occurs when program begins execution

## Assembly Basics: Registers, Operands, Move

### x86‐64 Integer Registers

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7axgptv3ep.avif)

### Moving Data

- `movq src, dst`
- Operand Types
  - Immediate: Constant integer data
    - E.g., `$0x400`, `$-533`
    - Like C constant, but prefixed with `$`
    - Encoded with 1, 2, or 4 bytes
  - Register: One of 16 integer registers
    - E.g., `%rax`, `%r13`
    - But `%rsp` reserved for special use
    - Others have special uses for particular instructions
  - Memory: 8 consecutive bytes of memory at address given by register
    - Simplest example: `(%rax)`
    - Various other "address modes"

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7lkaizapzl.avif)

### Complete Memory Addressing Modes

- `D(Rb, Ri, S)`, `Mem[Reg[Rb] + S * Reg[Ri] + D]`
  - `D`: Constant "displacement" 1, 2, or 4 bytes
  - `Rb`: Base register: Any of 16 integer registers
  - `Ri`: Index register: Any, except for `%rsp`
  - `S`: Scale (1, 2, 4, or 8)
- Special Cases
  - `(Rb, Ri)`: `Mem[Reg[Rb] + Reg[Ri]]`
  - `D(Rb, Ri)`: `Mem[Reg[Rb] + Reg[Ri] + D]`
  - `(Rb, Ri, S)`: `Mem[Reg[Rb] + S * Reg[Ri]]`

## Arithmetic & Logical Operations

### Address Computation Instruction

- `leaq src, dst`
  - `src` is address mode expression
  - Set `dst` to address denoted by expression
- Uses
  - Computing addresses without a memory reference
    - E.g., translation of `p = &x[i];`
  - Computing arithmetic expressions of the form `x + k * y`
    - `k` equals to 1, 2, 4, or 8

Here is an example of computing arithmetic expression with `leaq`:

```c
long m12(long x) {
  return x * 12;
}
```

Converted to ASM by compiler:

```asm
leaq (%rdi, %rdi, 2), %rax # t <- x + x * 2
salq $2, %rax              # return t << 2
```

A bit more complex one:

```c
long arith(long x, long y, long z) {
  long t1 = x + y;
  long t2 = z + t1;
  long t3 = x + 4;
  long t4 = y * 48;
  long t5 = t3 + t4;
  long rval = t2 * t5;

  return rval;
}
```

```asm
arith:
  leaq (%rdi, %rsi), %rax     # t1
  addq %rdx, %rax             # t2
  leaq (%rsi, %rsi, 2), %rdx
  salq $4, %rdx               # t4
  leaq 4(%rdi, %rdx), %rcx    # t5
  imulq $rcx, %rax            # rval
  ret
```

## Control: Condition Codes

### Condition Codes (Implicit Setting)

Think of it as a side effect by arithmetic operations.

`leaq` won't effect flags.

### Condition Codes (Explicit Setting)

- Compare Instrucion
  - `cmpq src2, src1`: computing `src1 - src2` without setting destination
- Test Instruction
  - `testq src2, src1`: computing `src1 & src2` without setting destination
  - Useful to have one of the operands be a mask

### Reading Condition Codes

- `setX` Instructions
  - Set low‐order byte of destination (must one of addressable byte registers) to 0 or 1 based on combinations of
    condition codes
  - Does not alter remaining 7 bytes
    - Typically use `movzbl` (Move with Zero-Extend from Byte to Long) to finish job
      - 32‐bit instructions also set upper 32 bits to 0

:::note
Any computation where the result is a 32-bit result, it will zero out the higher 32-bits of the register. And its different for example the byte level operations only affect the bytes, the word operations only affect two bytes.
:::

| setX    | Condition          | Description               |
| ------- | ------------------ | ------------------------- |
| `sete`  | `ZF`               | Equal / Zero              |
| `setne` | `~ZF`              | Not Equal / Not Zero      |
| `sets`  | `SF`               | Negative                  |
| `setns` | `~SF`              | Nonnegative               |
| `setg`  | `~(SF ^ OF) & ~ZF` | Greater (Signed)          |
| `setge` | `~(SF ^ OF)`       | Greater or Equal (Signed) |
| `setl`  | `(SF ^ OF)`        | Less (Signed)             |
| `setle` | `(SF ^ OF) \| ZF`  | Less or Equal (Signed)    |
| `seta`  | `~CF & ~ZF`        | Above (Unsigned)          |
| `setb`  | `CF`               | Below (Unsigned)          |

:::note
`sil`, `dil`, `spl`, `bpl` are all 1 byte registers.
:::

```c
int gt(long x, long y) {
  return x > y;
}
```

```asm
cmpq   %rsi, %rdi # Compare x:y
setg   %al        # Set %al to 1 when >
movzbl %al, %eax  # Zero rest of %rax
ret
```

## Conditional Branches

### Jumping

- `jX` Instructions
  - Jump to different part of code depending on condition codes

| jX    | Condition          | Description               |
| ----- | ------------------ | ------------------------- |
| `jmp` | `1`                | Unconditional             |
| `je`  | `ZF`               | Equal / Zero              |
| `jne` | `~ZF`              | Not Equal / Not Zero      |
| `js`  | `SF`               | Negative                  |
| `jns` | `~SF`              | Nonnegative               |
| `jg`  | `~(SF ^ OF) & ~ZF` | Greater (Signed)          |
| `jge` | `~(SF ^ OF)`       | Greater or Equal (Signed) |
| `jl`  | `SF ^ OF`          | Less (Signed)             |
| `jle` | `(SF ^ OF) \| ZF`  | Less or Equal (Signed)    |
| `ja`  | `~CF & ~ZF`        | Above (Unsigned)          |
| `jb`  | `CF`               | Below (Unsigned)          |

### Using Conditional Moves

- Conditional Move Instructions
  - Instruction supports: `if (Test) Dest <- Src`
  - Supported in post-1995 x86 processors
  - GCC tries to use them (but, only when known to be safe)
    - Branches are very disruptive to instruction flow through pipelines
    - Conditional moves do not require control transfer

Here is a simple example of conditional move:

```c
long absdiff(long x, long y) {
  long result;
  if (x > y)
    result = x - y;
  else
    result = y - x;
  return result;
}
```

```asm
absdiff:
  movq   %rdi, %rax # x
  subq   %rsi, %rax # result = x - y
  movq   %rsi, %rdx
  subq   %rdi, %rdx # eval = y - x
  cmpq   %rsi, %rdi # x:y
  cmovle %rdx, %rax # if <=, result = eval
  ret
```

#### Bad Cases for Conditional Move

- Expensive Computations: `val = Test(x) ? Hard1(x) : Hard2(x);`
  - Both values get computed
  - Only makes sense when computations are very simple
- Risky Computations: `val = p ? *p : 0;`
  - Both values get computed
  - May have undesirable effects
- Computations with side effects: `val = x > 0 ? x *= 7 : x += 3;`
  - Both values get computed
  - Must be side-effect free

## Loops

:::important
Each kind of loop will convert to their `goto` version and then assembly code.
:::

### "Do-While" Loop

C Code:

```c
long pcount_do(unsigned long x) {
  long result = 0;
  do {
    result += x & 0x1;
    x >>= 1;
  } while (x);
  return result;
}
```

Goto Version:

```c
long pcount_goto(unsigned long x) {
  long result = 0;
loop:
  result += x & 0x1;
  x >>= 1;
  if (x) goto loop;
  return result;
}
```

Assembly Code:

```asm
  movl $0, %eax   # result = 0
.L2:              # loop:
  movq %rdi, %rdx
  andl $1, %edx   # t = x & 0x1
  addq %rdx, %rax # result += t
  shrq %rdi       # x >>= 1
  jne  .L2        # if (x) goto loop
  rep; ret
```

#### General "Do-While" Translation

```c
do {
  Body
} while (Test);
```

```asm
loop:
  Body
  if (Test)
    goto loop
```

### "While" Loop

#### General "While" Translation 1 ("Jump‐to-middle" translation, compiled with `-Og`)

```c
while (Test) {
  Body
}
```

```asm
  goto test
loop:
  Body
test:
  if (Test)
    goto loop
done:
```

#### General "While" Translation 2 (Compiled with `-O1`)

```c
while (Test) {
  Body
}
```

To Do-While Version:

```c
  if (!Test)
    goto done;
  do {
    Body
  } while (Test);
done:
```

Goto Version:

```c
  if (!Test)
    goto done;
loop:
  Body
  if (Test)
    goto loop;
done:
```

The initial conditional guards entrance to loop.

### "For" Loop

#### "For" Loop "While" Conversion

For Version:

```c
for (Init; Test; Update)
  Body
```

While Version:

```c
Init;
while (Test) {
  Body
  Update;
}
```

#### "For" Loop "Do-While" Conversion

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1e8witfdlk.avif)

Initial test can be optimized away.

## Switch Statements

### Switch Statement Example

```c
long switch_eg(long x, long y, long z) {
  long w = 1;
  switch (x) {
    case 1:
      w = y * z;
      break;
    case 2:
      w = y / z;
    /* Fall Through */
    case 3:
      w += z;
      break;
    case 5:
    case 6:
      w -= z;
      break;
    default:
      w = 2;
    }
  return w;
}
```

- Multiple case labels: 5 & 6
- Fall through cases: 2
- Missing cases: 4

### Switch Statement Example in Assembly

```asm
switch_eg:
  movq %rdx, %rcx
  cmpq $6, %rdi        # x:6
  ja   .L8             # use default
  jmp  *.L4(, %rdi, 8) # goto *JTab[x]
```

_Note that `w` not initialized here._

:::tip
`ja .L8` considering the result is unsigned, so its a smart way to tackle negative number.
:::

### Jump Table Structure

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9rjp4r358w.avif)

#### Jump Table

```asm
.section .rodata
  .align 8
.L4:
  .quad .L8 # x = 0
  .quad .L3 # x = 1
  .quad .L5 # x = 2
  .quad .L9 # x = 3
  .quad .L8 # x = 4
  .quad .L7 # x = 5
  .quad .L7 # x = 6
```

- Table Structure
  - Each target requires 8 bytes
  - Base address at `.L4`
- Jumping
  - Direct: `jmp .L8`
    - Jump target is denoted by label `.L8`
  - Indirect: `jmp *.L4(, %rdi, 8)`
    - Start of jump table: `.L4`
    - Must scale by factor of 8 (addresses are 8 bytes)
    - Fetch target from effective address `.L4 + %rdi * 8`
      - Only for `0 <= x <= 6`

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3d5395ln4u.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7p3wgp5cmz.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6f0zadnyrf.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8adk300sp3.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8ojztv9het.avif)

## Procedures

### Stack Structure

#### x86-64 Stack

- Region of memory managed with stack discipline
- Grows toward lower addresses
- Register `%rsp` contains lowest stack address
  - address of "top" element

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6ikl8nrzmw.avif)

##### Push

- `pushq src`
  - Fetch operand at `src`
  - Decrement `%rsp` by 8
  - Write operand at address given by `%rsp`

##### Pop

- `popq dest`
  - Read value at address given by `%rsp`
  - Increment `%rsp` by 8
  - Store value at `dest` (must be register)

### Calling Conventions

#### Procedure Control Flow

- Use stack to support procedure call and return
- Procedure call: `call label`
  - Push return address (address of the next instruction right after call) on stack
  - Jump to label
- Procedure return: `ret`
  - Pop address from stack
  - Jump to address

#### Managing local data

- First 6 arguments are passing by registers: `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`, other more arguments will store in stack
- Only allocate stack space when needed
- Return value store in `%rax`

#### Stack Frames

- Contents
  - Return information
  - Local storage (if needed)
  - Temporary space (if needed)
- Management
  - Space allocated when enter procedure
    - "Set-up" code
    - Includes push by `call` instruction
  - Deallocated when return
    - "Finish" code
    - Includes pop by `ret` instruction

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.39lhc0ris7.avif)

#### x86-64 / Linux Stack Frame

- Current Stack Frame ("Top" to Bottom)
  - Argument build: Parameters for function about to call
- Local variables
  - If can't keep in registers
- Saved register context
- Old frame pointer (optional)

- Caller Stack Frame
  - Return address
  - Arguments for this call

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5q7pqzavmk.avif)

:::note
As we often see the program often allocates more space on the stack than it really needs to, its because some conventions about trying to keep addresses on aligned.
:::

### Register Saving Conventions

- Caller Saved
  - Caller saves temporary values in its frame before the call
- Callee Saved
  - Callee saves temporary values in its frame before using
  - Callee restores them before returning to caller

#### x86-64 Linux Register Usage 1

- `%rax`
  - Return value
  - Also caller-saved
  - Can be modified by procedure
- `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`
  - Arguments
  - Also caller-saved
  - Can be modified by procedure
- `%r10`, `%r11`
  - Caller-saved
  - Can be modified by procedure

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6ikl8s2wb5.avif)

#### x86-64 Linux Register Usage 2

- `%rbx`, `%r12`, `%r13`, `%r14`
  - Callee-saved
  - Callee must save & restore
- `%rbp`
  - Callee-saved
  - Callee must save & restore
  - May be used as frame pointer
  - Can mix & match
- `%rsp`
  - Special form of callee save
  - Restored to original value upon exit from procedure

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3nrx2zr8ta.avif)

### Recursion Example

```c
long pcount_r(unsigned long x) {
  if (x == 0)
    return 0;
  else:
    return (x & 1) + pcount_r(x >> 1);
}
```

```asm
pcount_r:
  movl  $0, %eax
  testq %rdi, %rdi
  je    .L6
  pushq %rbx
  movq  %rdi, %rbx
  andl  $1, %ebx
  shrq  %rdi
  call  pcount_r
  addq  %rbx, %rax
  popq  %rbx
.L6:
  rep; ret
```

- Handled Without Special Consideration (just using normal calling conventions)
  - Stack frames mean that each function call has private storage
    - Saved registers & local variables
    - Saved return pointer
  - Register saving conventions prevent one function call from corrupting another's data
    - Unless the C code explicitly does so
  - Stack discipline follows call / return pattern
    - If P calls Q, then Q returns before P
    - Last-In, First-Out
- Also works for mutual recursion
  - P calls Q; Q calls P

## Arrays

### One-dimensional Array

#### Array Allocation

- `T A[L];`
  - Array of data type `T` and length `L`
  - Contiguously allocated region of `L * sizeof(T)` bytes in memory

#### Array Access

- `T A[L];`
  - Array of data type `T` and length `L`
  - Identifier `A` can be used as a pointer to array element 0: Type `T *`

#### Array Accessing Example

```c
#define ZLEN 5

typedef int zip_dig[ZLEN];

int get_digit(zip_dig z, int digit) {
  return z[digit];
}
```

```asm
movl (%rdi, %rsi, 4), %eax # z[digit]
```

- Register `%rdi` contains starting address of array
- Register `%rsi` contains array index
- Desired digit at `%rdi + 4 * %rsi`

#### Array Loop Example

```c
void zincr(zip_dig z) {
  size_t i;
  for (i = 0; i < ZLEN; i++) {
    z[i]++;
  }
}
```

```asm
  movl $0, %eax            # i = 0
  jmp .L3                  # goto middle
.L4:                       # loop:
  addl $1, (%rdi, %rax, 4) # z[i]++
  addq $1, %rax            # i++
.L3:                       # middle
  cmpq $4, %rax            # i:4
  jbe .L4                  # if <=, goto loop
  rep; ret
```

### Multidimensional (Nested) Arrays

- `T A[R][C]`
  - 2D array of data type `T`
  - `R` rows, `C` columns
  - Type `T` element requires `K` bytes
- Array Size
  - `R * C * K` bytes
- Arrangement
  - Row-Major Ordering

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7plbjvas4.avif" />
</center>

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4cl6nntgbl.avif)

#### Nested Array Example

```c
#define ZLEN 5
#define PCOUNT 4

typedef int zip_dig[ZLEN];

zip_dig pgh[PCOUNT] = {
  {1, 5, 2, 0, 6},
  {1, 5, 2, 1, 3},
  {1, 5, 2, 1, 7},
  {1, 5, 2, 2, 1}
}
```

`zip_dig pgh[4]` is equivalent to `int pgh[4][5]`.

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175ooqal1z.avif)

#### Nested Array Row Access

- Row Vectors
  - `A[i]` is array of `C` elements
  - Each element of type `T` requires `K` bytes
  - Starting address `A + i*(C*K)`

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6wr10b882r.avif)

##### Nested Array Row Access Example

```c
int *get_pgh_zip(int index) {
  return pgh[index];
}
```

```asm
leaq (%rdi, %rdi, 4), %rax # 5*index
leaq pgh(, %rax, 4), %rax  # pgh + (20*index)
```

- Row Vector
  - `pgh[index]` is array of 5 `int`'s
  - Starting address `pgh + 20*index`
- Machine Code
  - Computes and returns address
  - Compute as `pgh + 4*(index + 4*index)`

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9o038eo5qn.avif)

##### Nested Array Element Access Example

- Array Elements
  - `A[i][j]` is element of type `T`, which requires `K` bytes
  - Address `A + i*(C*K) + j*K = A + (i*C + j)*K`

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.41ycuj7kl1.avif)

##### Nested Array Element Access Example

```c
int get_pgh_digit(int index, int dig) {
  return pgh[index][dig];
}
```

```asm
leaq (%rdi, %rdi, 4), %rax # 5*index
addl %rax, %rsi            # 5*index + dig
movl pgh(, %rsi, 4), %eax  # M[pgh + 4*(5*index + dig)]
```

- Array Elements
  - `pgh[index][dig]` is `int`
  - Address: `Mem[pgh + 20*index + 4*dig] = Mem[pgh + 4*(5*index + dig)]`

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175oor97dc.avif)

### Multi-Level Array

```c
zip_dig cmu = {1, 5, 2, 1, 3};
zip_dig mit = {0, 2, 1, 3, 9};
zip_dig ucb = {9, 4, 7, 2, 0};

#define UCOUNT 3

int *univ[UCOUNT] = {mit, cmu, ucb};
```

- Variable `univ` denotes array of 3 elements
- Each element is a pointer (8 bytes)
- Each pointer points to array of `int`'s

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1vyy8s8cdr.avif)

#### Element Access in Multi-Level Array

```c
int get_univ_digit(size_t index, size_t digit) {
  return univ[index][digit];
}
```

```asm
salq $2, %rsi              # 4*digit
addq univ(, %rdi, 8), %rsi # p = univ[index] + 4*digit
movl (%rsi), %eax          # return *p
ret
```

- Element access `Mem[Mem[univ + 8*index] + 4*digit]`
- Must do two memory reads
  - First get pointer to row array
  - Then access element within array

### N x N Matrix

- Fixed dimensions
  - Know value of `N` at compile time

```c
#define N 16

typedef int fix_matrix[N][N];

/* Get element A[i][j] */
int fix_ele(fix_matrix A, size_t i, size_t j) {
  return A[i][j];
}
```

- Variable dimensions, explicit indexing
  - Traditional way to implement dynamic arrays

```c
#define IDX(n, i, j) ((i)*(n)+(j))

/* Get element A[i][j] */
int vec_ele(size_t n, int *A, size_t i, size_t j) {
  return A[IDX(n,i,j)];
}
```

- Variable dimensions, explicit indexing
  - Now supported by gcc

```c
/* Get element A[i][j] */
int var_ele(size_t n, int A[n][n], size_t i, size_t j) {
  return A[i][j];
}
```

#### N x N Matrix Access

- Array Elements
  - `size_t n;`
  - `int A[n][n];`
  - Address `A + i*(C*K) + j*K`
  - `C = n, K = 4`
  - Must perform integer multiplication

```c
/* Get element A[i][j] */
int var_ele(size_t n, int A[n][n], size_t i, size_t j) {
  return A[i][j];
}
```

```asm
imulq %rdx, %rdi           # n*i
leaq (%rsi, %rdi, 4), %rax # A + 4*n*i
movl (%rax, %rcx, 4), %eax # A + 4*n*i + 4*j
ret
```

### Understanding Pointers & Array

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.32i9hg2rcu.avif" />
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.54y25hs26z.avif" />
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.77dutjr9u7.avif" />
</center>

- Cmp: Compiles (Y/N)
- Bad: Possible bad pointer reference (Y/N)
- Size: Value returned by `sizeof`

## Structures

### Allocation

- Structure represented as block of memory
  - Big enough to hold all of the fields
- Fields ordered according to declaration
  - Even if another ordering could yield a more compact representation
- Compiler determines overall size + positions of fields
  - Machine-level program has no understanding of the structures in the source code

### Access

#### Generating Pointer to Structure Member

```c
struct rec {
  int a[4];
  size_t i;
  struct rec *next;
};

int *get_ap(struct rec *r, size_t idx) {
  return &r->a[idx];
}
```

```asm
leaq (%rdi, %rsi, 4), %rax
ret
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.54y26bn705.avif" />
</center>

- Offset of each structure member determined at compile time
- Compute as `r + 4*idx`

#### Following Linked List

```c
struct rec {
  int a[4];
  int i;
  struct rec *next;
};

void set_val(struct rec *r, int val) {
  while (r) {
    int i = r->i;
    r->a[i] = val;
    r = r->next;
  }
}
```

```asm
.L11:                        # loop:
  movslq 16(%rdi), %rax      # i = M[r + 16]
  movl %esi, (%rdi, %rax, 4) # M[r + 4*i] = val
  movq 24(%rdi), %rdi        # r = M[r + 24]
  testq %rdi, %rdi           # Test r
  jne .L11                   # if != 0 goto loop
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3uv500dbuh.avif" />
</center>

### Alignment

```c
struct S1 {
  char c;
  int i[2];
  double v;
} *p;
```

- Unaligned Data

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175opnv4vk.avif" />
</center>

- Aligned Data
  - Primitive data type requires `K` bytes
  - Address must be multiple of `K`
  - Required on some machines; advised on x86-64

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5mo3ux8mbu.avif" />
</center>

- Motivation for Aligning Data

  - Memory accessed by (aligned) chunks of 4 or 8 bytes (system dependent)
    - Inefficient to load or store datum that spans quad word boundaries
    - Virtual memory trickier when datum spans 2 pages

- Compiler
  - Inserts gaps in structure to ensure correct alignment of fields

#### Specific Cases of Alignment (x86-64)

- 1 byte: `char`, ...
  - no restrictions on address
- 2 bytes: `short`, ...
  - lowest 1 bit of address must be $0_{2}$
- 4 bytes: `int`, `float`, ...
  - lowest 2 bits of address must be $00_{2}$
- 8 bytes: `double`, `long`, `char *`, ...
  - lowest 3 bits of address must be $000_{2}$

:::important
If an address requires alignment to $2^{n}$ bytes, then its lowest $n$ bits must be $0$.
:::

#### Satisfying Alignment with Structures

- Within structure
  - Must satisfy each element's alignment requirement
- Overall structure placement

  - Each structure has alignment requirement `K`
    - `K` is largest alignment of any element
  - Initial address & structure length must be multiples of `K`

- Example

```c
struct S2 {
  double v;
  int i[2];
  char c;
} *p;
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8dx6316864.avif" />
</center>

### Arrays of Structures

- Overall structure length multiple of `K`
- Satisfy alignment requirement for every element

```c
struct S2 {
  double v;
  int i[2];
  char c;
} a[10];
```

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6m4784tavb.avif)

### Accessing Array Elements

- Compute array offset `12*idx`
  - `sizeof(S3)`, including alignment spacers
- Element `j` is at offset 8 within structure
- Assembler gives offset `a+8`
  - Resolved during linking

```c
struct S3 {
  short i;
  float v;
  short j;
} a[10];
```

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175opphsk3.avif)

```c
short get_j(int idx) {
  return a[idx].j;
}
```

```asm
leaq   (%rdi, %rdi, 2), %rax # 3*idx
movzwl a+8(, %rax, 4), %eax
```

### Saving Space

- Put large data types first

```c
struct S4 {
  char c;
  int i;
  char d;
} *p;
```

```c
struct S5 {
  int i;
  char c;
  char d;
} *p;
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7i0onl94x5.avif" />
</center>

## Floating Point

### x87 FP

- Legacy, very ugly

### SSE3 FP

#### XMM Registers

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7eh2pxhyar.avif" />
</center>

#### Scalar & SIMD Operations

`SIMD (Single instruction, multiple data)`, there are a ton of usage combinations, e.g.:

- `addss (ADD Scalar Single-Precision Floating-Point Values)`
- `addps (ADD Packed Single-Precision Floating-Point Values)`

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7snigsk2si.avif" />
</center>

#### Basics

- Arguments passed in `%xmm0`, `%xmm1`, ...
- Result returned in `%xmm0`
- All `XMM` registers caller-saved

```c
float fadd(float x, float y) {
  return x + y;
}
```

```asm
addss %xmm1, %xmm0
ret
```

```c
double dadd(double x, double y) {
  return x + y;
}
```

```asm
addsd %xmm1, %xmm0
ret
```

#### Memory Referencing

- Integer (and pointer) arguments passed in regular registers
- Floating Point values passed in `XMM` registers
- Different `mov` instructions to move between `XMM` registers, and between memory and `XMM` registers

```c
double dincr(double *p, double v) {
  double x = *p;
  *p = x + v;
  return x;
}
```

```asm
movapd %xmm0, %xmm1 # Copy v
movsd (%rdi), %xmm0 # x = *p
addsd %xmm0, %xmm1  # t = x + v
movsd %xmm1, (%rdi) # *p = t
ret
```

- `movapd (Move Aligned Packed Double-Precision Floating-Point Values)`

#### Other Aspects of Floating Point Instructions

- Lots of instructions
  - Different operations, different formats, ...
- Floating-point comparisons
  - Instructions `ucomiss (Unordered Compare Scalar Single-Precision)` and `ucomisd (Unordered Compare Scalar Double-Precision)`
  - Set condition codes `CF`, `ZF`, and `PF`
- Using constant values
  - Set `XMM0` register to 0 with instruction `xorpd %xmm0, %xmm0`
  - Others loaded from memory

### AVX FP

- Newest version
- Similar to SSE

Floating Point assembly instruction sets are very nasty, though it's principle thought is simple. So I am just skipping this chapter as TODO. Bro really don't want learn this chapter...

## Memory Layout

### x86-64 Linux Memory Layout

- Stack
  - Runtime stack (8MB limit, check by `limit` command)
  - E.g., local variables
- Heap
  - Dynamically allocated as needed
  - When call `malloc()`, `calloc()`, `new()`
- Data
  - Statically allocated data
  - E.g., global vars, `static` vars, string constants
- Text / Shared Libraries
  - Executable machine instructions
  - Read-only

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7lkalfi3x6.avif" alt="" />
</center>

:::tip
In common, the canonical address range in x86-64 is 47 bits address. That is why the maximum address show as `0x00007FFFFFFFFFFF`.
:::

## Unions

### Allocation

- Allocate according to largest element
- Can only use one field at a time

```c
union U1 {
  char c;
  int i[2];
  double v;
} *up;
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7w74exlpis.avif" alt="" />
</center>

```c
struct S1 {
  char c;
  int i[2];
  double v;
} *sp;
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7lkals7ft7.avif" alt="" />
</center>

# Program Optimization

- There's more to performance than asymptotic complexity

- Must optimize at multiple levels: algorithm, data representations, procedures, and loops

## Optimizing Compilers

- Provide efficient mapping of program to machine
  - register allocation
  - code selection and ordering (scheduling)
  - dead code elimination
  - eliminating minor inefficiencies
- Don't (usually) improve asymptotic efficiency
  - up to programmer to select best overall algorithm
  - Big-O savings are (often) more important than constant factors
    - but constant factors also matter
- Have difficulty overcoming "optimization blockers"
  - potential memory aliasing
  - potential procedure side-effects

### Limitations of Optimizing Compilers

- Operate under fundamental constraint
  - Must not cause any change in program behavior
    - Except, possibly when program making use of nonstandard language features
  - Often prevents it from making optimizations that would only affect behavior under pathological conditions.
- Behavior that may be obvious to the programmer can be obfuscated by languages and coding styles
  - E.g., Data ranges may be more limited than variable types suggest
- Most analysis is performed only within procedures
  - Whole-program analysis is too expensive in most cases
  - Newer versions of GCC do interprocedural analysis within individual files
    - But, not between code in different files
- Most analysis is based only on static information
  - Compiler has difficulty anticipating run-time inputs
- When in doubt, the compiler must be conservative

### Generally Useful Optimizations

Optimizations that you or the compiler should do regardless of processor / compiler

- Code Motion
  - Reduce frequency with which computation performed
    - If it will always produce same result
    - Especially moving code out of loop

```c
void set_row(double *a, double *b, long i, long n) {
  long j;
  for (j = 0; j < n; j++)
    a[n*i+j] = b[j];
}
```

```c
void set_row(double *a, double *b, long i, long n) {
  long j;
  int ni = n*i;
  for (j = 0; j < n; j++)
    a[ni+j] = b[j];
}
```

#### Compiler-Generated Code Motion (-O1)

```c
void set_row(double *a, double *b, long i, long n) {
  long j;
  for (j = 0; j < n; j++)
    a[n*i+j] = b[j];
}
```

```asm
set_row:
  testq %rcx, %rcx             # Test n
  jle .L1                      # If 0, goto done
  imulq %rcx, %rdx             # ni = n*i
  leaq (%rdi , %rdx, 8), %rdx  # rowp = A + ni*8
  movl $0, %eax                # j = 0
.L3:                           # loop:
  movsd (%rsi, %rax, 8), %xmm0 # t = b[j]
  movsd %xmm0, (%rdx, %rax, 8) # M[A + ni*8 + j*8] = t
  addq $1, %rax                # j++
  cmpq %rcx, %rax              # j:n
  jne .L3                      # if !=, goto loop
.L1:                           # done:
  rep ; ret
```

To the C code:

```c
void set_row(double *a, double *b, long i, long n) {
  long j;
  long ni = n*i;
  double *rowp = a+ni;
  for (j = 0; j < n; j++)
    *rowp++ = b[j];
}
```

#### Reduction in Strength

- Replace costly operation with simpler one
- Shift, add instead of multiply or divide
  - Utility machine dependent
  - Depends on cost of multiply or divide instruction
  - Recognize sequence of products

```c
for (i = 0; i < n; i++) {
  int ni = n*i;
  for (j = 0; j < n; j++)
    a[ni + j] = b[j];
}
```

```c
int ni = 0;
for (i = 0; i < n; i++) {
  for (j = 0; j < n; j++)
    a[ni + j] = b[j];
  ni += n;
}
```

#### Share Common Subexpressions

- Reuse portions of expressions
- GCC will do this with `–O1`

```c
up = val[(i-1)*n + j ];
down = val[(i+1)*n + j ];
left = val[i*n + j-1];
right = val[i*n + j+1];
sum = up + down + left + right;
```

```asm
leaq 1(%rsi), %rax # i+1
leaq -1(%rsi), %r8 # i-1
imulq %rcx, %rsi   # i*n
imulq %rcx, %rax   # (i+1)*n
imulq %rcx, %r8    # (i-1)*n
addq %rdx, %rsi    # i*n+j
addq %rdx, %rax    # (i+1)*n+j
addq %rdx, %r8     # (i-1)*n+j
```

- 3 multiplications: `i*n`, `(i–1)*n`, `(i+1)*n`

```c
long inj = i*n + j;
up = val[inj - n];
down = val[inj + n];
left = val[inj - 1];
right = val[inj + 1];
sum = up + down + left + right;
```

```asm
imulq %rcx, %rsi        # i*n
addq %rdx, %rsi         # i*n+j
movq %rsi, %rax         # i*n+j
subq %rcx, %rax         # i*n+j-n
leaq (%rsi, %rcx), %rcx # i*n+j+n
```

- 1 multiplication: `i*n`

## Optimization Blockers

:::note
I'm just skipping this chapter, so the notes are seems disordered. Will retake this chapter later.
:::

### Optimization Blocker: Procedure Calls

```c
void lower(char *s) {
  size_t i;
  for (i = 0; i < strlen(s); i++)
    if (s[i] >= 'A' && s[i] <= 'Z')
      s[i] -= ('A' - 'a');
}
```

- `strlen` executed every iteration
- Time quadruples when double string length
- Quadratic performance

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3yeqz6j6zd.avif" alt="" />
</center>

#### Calling strlen

```c
/* My version of strlen */
size_t strlen(const char *s) {
  size_t length = 0;
  while (*s != '\0') {
    s++;
    length++;
  }
  return length;
}
```

- strlen performance
  - Only way to determine length of string is to scan its entire length, looking for null character
- Overall performance, string of length N
  - N calls to strlen
  - Require times `N`, `N-1`, `N‐2`, ..., `1`
  - Overall $O(N^{2})$ performance

#### Improving Performance

```c
void lower(char *s) {
  size_t i;
  size_t len = strlen(s);
  for (i = 0; i < len; i++)
    if (s[i] >= 'A' && s[i] <= 'Z')
      s[i] -= ('A' - 'a');
}
```

- Move call to `strlen` outside of loop
- Since result does not change from one iteration to another
- Form of code motion

#### Improved Lower Case Conversion Performance

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.67xriorxa3.avif" alt="" />
</center>

### Why couldn't compiler move strlen out of inner loop ?

- Procedure may have side effects
  - Alters global state each time called
- Function may not return same value for given arguments
  - Depends on other parts of global state
  - Procedure lower could interact with `strlen`
- Warning
  - Compiler treats procedure call as a black box
  - Weak optimizations near them
- Remedies
  - Use of inline functions
    - GCC does this with `–O1` within single file
  - Do your own code motion

### Memory Matters

```c
/* Sum rows is of n X n matrix a
   and store in vector b */
void sum_rows1(double *a, double *b, long n) {
  long i, j;
  for (i = 0; i < n; i++) {
    b[i] = 0;
    for (j = 0; j < n; j++)
      b[i] += a[i*n + j];
  }
}
```

```asm
# sum_rows1 inner loop
.L4:
  movsd (%rsi, %rax, 8), %xmm0 # FP load
  addsd (%rdi), %xmm0          # FP add
  movsd %xmm0, (%rsi, %rax, 8) # FP store
  addq $8, %rdi
  cmpq %rcx, %rdi
  jne .L4
```

#### Memory Aliasing

- Code updates `b[i]` on every iteration
- Must consider possibility that these updates will affect program behavior

##### Removing Aliasing

```c
/* Sum rows is of n X n matrix a
   and store in vector b */
void sum_rows2(double *a, double *b, long n) {
  long i, j;
  for (i = 0; i < n; i++) {
    double val = 0;
    for (j = 0; j < n; j++)
      val += a[i*n + j];
    b[i] = val;
  }
}
```

```asm
# sum_rows2 inner loop
.L10:
  addsd (%rdi), %xmm0 # FP load + add
  addq $8, %rdi
  cmpq %rax, %rdi
  jne .L10
```

- No need to store intermediate results

### Optimization Blocker: Memory Aliasing

- Aliasing
  - Two different memory references specify single location
  - Easy to have happen in C
    - Since allowed to do address arithmetic
    - Direct access to storage structures
  - Get in habit of introducing local variables
    - Accumulating within loops
    - Your way of telling compiler not to check for aliasing

## Exploiting Instruction‐Level Parallelism

TODO

## Dealing with Conditionals

TODO

# The Memory Hierarchy

TODO

# Cache Memories

TODO

# Linking

## Static Linking

Programs are translated and linked using a compiler driver: `gcc -Og -o prog main.c sum.c`

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7axguzk7iw.avif" alt="" />
</center>

### Why Linkers ?

- Reason 1: Modularity
  - Program can be written as a collection of smaller source files, rather than one monolithic mass
  - Can build libraries of common functions
    - E.g., Math library, Standard C library
- Reason 2: Efficiency
  - Time: Separate compilation
    - Change one source file, compile, and then relink
    - No need to recompile other source files
  - Space: Libraries
    - Common functions can be aggregated into a single file
    - Yet executable files and running memory images contain only code for the functions they actually use

### What Do Linkers Do ?

- Step 1: Symbol resolution
  - Programs define and reference symbols (global variables and functions)
    - `void swap() { ... } /* define symbol swap */`
    - `swap(); /* reference symbol swap */`
    - `int *xp = &x; /* define symbol xp, reference x */`
  - Symbol definitions are stored in object file (by assembler) in symbol table
    - Symbol table is an array of `structs`
    - Each entry includes name, size, and location of symbol
  - During symbol resolution step, the linker associates each symbol reference with exactly one symbol definition
- Step 2: Relocation
  - Merges separate code and data sections into single sections
  - Relocates symbols from their relative locations in the `.o` files to their final absolute memory locations in the executable
  - Updates all references to these symbols to reflect their new positions

## Three Kinds of Object Files (Modules)

- Relocatable object file (`.o` file)
  - Contains code and data in a form that can be combined with other relocatable object files to form executable object file
    - Each `.o` file is produced from exactly one source (`.c`) file
- Executable object file (`a.out` file)
  - Contains code and data in a form that can be copied directly into memory and then executed
- Shared object file (`.so` file)
  - Special type of relocatable object file that can be loaded into memory and linked dynamically, at either load time or run-time
  - Called Dynamic Link Libraries (DLLs) by Windows

## Executable and Linkable Format (ELF)

- Standard binary format for object files
- One unified format for
  - Relocatable object files (`.o`)
  - Executable object files (`a.out`)
  - Shared object files (`.so`)
- Generic name: ELF binaries

### ELF Object File Format

- ELF header
  - Word size, byte ordering, file type (`.o`, `exec`, `.so`), machine type, etc
- Segment header table (required for executables)
  - Page size, virtual addresses memory segments (sections), segment sizes
- `.text` section
  - Code
- `.rodata` section
  - Read only data: jump tables, ...
- `.data` section
  - Initialized global variables
- `.bss` section
  - Global variables that are uninitialized or initialized to zero
  - Block Started by Symbol
  - "Better Save Space"
  - Has section header but occupies no space
- `.symtab` section
  - Symbol table
  - Procedure and static variable names
  - Section names and locations
- `.rel.text` section
  - Relocation info for `.text` section
  - Addresses of instructions that will need to be modified in the executable
  - Instructions for modifying
- `.debug` section
  - Info for symbolic debugging (`gcc -g`)
- Section header table
  - Offsets and sizes of each section

## Linker Symbols

- Global symbols
  - Symbols defined by module m that can be referenced by other modules
  - E.g.: non-static C functions and non-static global variables
- External symbols
  - Global symbols that are referenced by module m but defined by some other module
- Local symbols
  - Symbols that are defined and referenced exclusively by module m
  - E.g.: C functions and global variables defined with the static attribute
  - Local linker symbols are not local program variables

## Local non-static C variables vs. local static C variables

- Local non-static C variables stored on the stack
- Local static C variables stored in either `.bss`, or `.data`

```c
int f() {
  static int x = 0; /* .bss */
  return x;
}

int g() {
  static int x = 1; /* .data */
  return x;
}
```

In the case above, compiler allocates space in `.data` for each definition of `x` and creates local symbols in the symbol table with unique names, e.g., `x.1` and `x.2`.

:::important
Local static variables are only initialized at first time encountered, calls after won't reinitialize.
:::

## How Linker Resolves Duplicate Symbol Definitions

- Program symbols are either `strong` or `weak`
  - Strong: procedures and initialized globals
  - Weak: uninitialized globals

### Linker's Symbol Rules

- Rule 1: Multiple strong symbols are not allowed
  - Each item can be defined only once
  - Otherwise: Linker error
- Rule 2: Given a strong symbol and multiple weak symbols, choose the strong symbol
  - References to the weak symbol resolve to the strong symbol
- Rule 3: If there are multiple weak symbols, pick an arbitrary one
  - Can override this with `gcc –fno-common`

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2dp07cdtux.avif" alt="" />
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3gopi8muuz.avif" alt="" />
</center>

### Global Variables

- Avoid if you can
- Otherwise
  - Use `static` if you can
  - Initialize if you define a global variable
  - Use `extern` if you reference an external global variable

## Relocation

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3k8bfyl2zl.avif" alt="" />
</center>

### Relocation Entries

```c title="main.c"
int array[2] = {1, 2};

int main() {
  int val = sum(array, 2);
  return val;
}
```

```asm title="main.o" {4,6}
0000000000000020 <main>:
  20: be 02 00 00 00        mov    $0x2,%esi
  25: 48 8d 3d 00 00 00 00  lea    0x0(%rip),%rdi        # 2c <main+0xc>
   28: R_X86_64_PC32 array-0x4
  2c: e8 00 00 00 00        call   31 <main+0x11>
   2d: R_X86_64_PLT32 sum-0x4
  31: c3                    ret
```

### Relocated .text section

```asm
0000000000001120 <sum>:
    1120: ba 00 00 00 00        mov    $0x0,%edx
    1125: b8 00 00 00 00        mov    $0x0,%eax
    112a: eb 0d                 jmp    1139 <sum+0x19>
    112c: 0f 1f 40 00           nopl   0x0(%rax)
    1130: 48 63 c8              movslq %eax,%rcx
    1133: 03 14 8f              add    (%rdi,%rcx,4),%edx
    1136: 83 c0 01              add    $0x1,%eax
    1139: 39 f0                 cmp    %esi,%eax
    113b: 7c f3                 jl     1130 <sum+0x10>
    113d: 89 d0                 mov    %edx,%eax
    113f: c3                    ret

0000000000001140 <main>:
    1140: be 02 00 00 00        mov    $0x2,%esi
    1145: 48 8d 3d c4 2e 00 00  lea    0x2ec4(%rip),%rdi        # 4010 <array>
    114c: e8 cf ff ff ff        call   1120 <sum>
    1151: c3                    ret
```

Using PC-relative addressing for `sum`: `0x1120 = 0x1151 + 0xffffffcf`

## Loading Executable Object Files

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9kghkpo5fp.avif" alt="" />
</center>

## Packaging Commonly Used Functions

- How to package functions commonly used by programmers ?
  - Math, I/O, memory management, string manipulation, etc
- Awkward, given the linker framework so far:
  - Option 1: Put all functions into a single source file
    - Programmers link big object file into their programs
    - Space and time inefficient
  - Option 2: Put each function in a separate source file
    - Programmers explicitly link appropriate binaries into their programs
    - More efficient, but burdensome on the programmer

## Old-fashioned Solution: Static Libraries

- Static libraries (`.a` archive files)
  - Concatenate related relocatable object files into a single file with an index (called an archive)
  - Enhance linker so that it tries to resolve unresolved external references by looking for the symbols in one or more archives
  - If an archive member file resolves reference, link it into the executable

## Creating Static Libraries

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8z6tz68a3z.avif" alt="" />
</center>

- Archiver allows incremental updates
- Recompile function that changes and replace `.o` file in archive

## Linking with Static Libraries

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2326ezwqsn.avif" alt="" />
</center>

## Using Static Libraries

- Linker's algorithm for resolving external references
  - Scan `.o` files and `.a` files in the command line order
  - During the scan, keep a list of the current unresolved references
  - As each new `.o` or `.a` file, obj, is encountered, try to resolve each unresolved reference in the list against the symbols defined in obj
  - If any entries in the unresolved list at end of scan, then error
- Problem
  - Command line order matters!
  - Moral: put libraries at the end of the command line

```bash
unix> gcc -L. libtest.o -lmine
unix> gcc -L. -lmine libtest.o
libtest.o: In function `main':
libtest.o(.text+0x4): undefined reference to `libfun'
```

## Shared Libraries

- Static libraries have the following disadvantages
  - Duplication in the stored executables (every function needs libc)
  - Duplication in the running executables
  - Minor bug fixes of system libraries require each application to explicitly relink
- Modern solution: Shared Libraries

  - Object files that contain code and data that are loaded and linked into an application dynamically, at either load-time or run-time
  - Also called: dynamic link libraries, DLLs, `.so` files

- Dynamic linking can occur when executable is first loaded and run (load-time linking)
  - Common case for Linux, handled automatically by the dynamic linker (`ld-linux.so`)
    Standard C library (`libc.so`) usually dynamically linked
- Dynamic linking can also occur after program has begun (run-time linking)
  - In Linux, this is done by calls to the `dlopen()` interface
    - Distributing software
    - High-performance web servers
    - Runtime library interpositioning
- Shared library routines can be shared by multiple processes

### Dynamic Linking at Load-time

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6wr1b588zg.avif" alt="" />
</center>

### Dynamic Linking at Run-time

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int x[2] = {1, 2};
int y[2] = {3, 4};
int z[2];

int main() {
  void *handle;
  void (*addvec)(int *, int *, int *, int);
  char *error;

  /* Dynamically load the shared library that contains addvec() */
  handle = dlopen("./libvector.so", RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(1);
  }

  /* Get a pointer to the addvec() function we just loaded */
  addvec = dlsym(handle, "addvec");
  if ((error = dlerror()) != NULL) {
    fprintf(stderr, "%s\n", error);
    exit(1);
  }

  /* Now we can call addvec() just like any other function */
  addvec(x, y, z, 2);
  printf("z = [%d %d]\n", z[0], z[1]);

  /* Unload the shared library */
  if (dlclose(handle) < 0) {
    fprintf(stderr, "%s\n", dlerror());
    exit(1);
  }
  return 0;
}
```

## Library Interpositioning

- Its a powerful linking technique that allows programmers to intercept calls to arbitrary functions
- Interpositioning can occur at:
  - Compile time: When the source code is compiled
  - Link time: When the relocatable object files are statically linked to form an executable object file
  - Load/Run time: When an executable object file is loaded into memory, dynamically linked, and then executed

### Example Program

```c title="int.c"
#include <stdio.h>
#include <malloc.h>

int main() {
  int *p = malloc(32);
  free(p);
  return(0);
}
```

- Goal: trace the addresses and sizes of the allocated and freed blocks, without breaking the program, and without modifying the source code
- Three solutions: interpose on the lib `malloc` and `free` functions at compile time, link time, and load/run time

### Compile-time Interpositioning

```c title="mymalloc.c"
#ifdef COMPILETIME
#include <stdio.h>
#include <malloc.h>

/* malloc wrapper function */
void *mymalloc(size_t size) {
  void *ptr = malloc(size);
  printf("malloc(%d)=%p\n", (int)size, ptr);
  return ptr;
}

/* free wrapper function */
void myfree(void *ptr) {
  free(ptr);
  printf("free(%p)\n", ptr);
}
#endif
```

```c title="malloc.h"
#define malloc(size) mymalloc(size)
#define free(ptr) myfree(ptr)

void *mymalloc(size_t size);
void myfree(void *ptr);
```

```bash
linux> make intc
gcc -Wall -DCOMPILETIME -c mymalloc.c
gcc -Wall -I. -o intc int.c mymalloc.o
linux> make runc
./intc
malloc(32)=0x1edc010
free(0x1edc010)
linux>
```

### Link-time Interpositioning

```c title="mymalloc.c"
#ifdef LINKTIME
#include <stdio.h>

void *__real_malloc(size_t size);
void __real_free(void *ptr);

/* malloc wrapper function */
void *__wrap_malloc(size_t size) {
  void *ptr = __real_malloc(size); /* Call libc malloc */
  printf("malloc(%d) = %p\n", (int)size, ptr);
  return ptr;
}

/* free wrapper function */
void __wrap_free(void *ptr) {
  __real_free(ptr); /* Call libc free */
  printf("free(%p)\n", ptr);
}
#endif
```

```bash
linux> make intl
gcc -Wall -DLINKTIME -c mymalloc.c
gcc -Wall -c int.c
gcc -Wall -Wl,--wrap,malloc -Wl,--wrap,free -o intl int.o mymalloc.o
linux> make runl
./intl
malloc(32) = 0x1aa0010
free(0x1aa0010)
linux>
```

- The `-Wl` flag passes argument to linker, replacing each comma with a space
- The `--wrap,malloc` arg instructs linker to resolve references in a special way:
  - Refs to `malloc` should be resolved as `__wrap_malloc`
  - Refs to `__real_malloc` should be resolved as `malloc`

### Load/Run time Interpositioning

```c title="mymalloc.c"
#ifdef RUNTIME
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* malloc wrapper function */
void *malloc(size_t size) {
  void *(*mallocp)(size_t size);
  char *error;

  mallocp = dlsym(RTLD_NEXT, "malloc"); /* Get addr of libc malloc */
  if ((error = dlerror()) != NULL) {
    fputs(error, stderr);
    exit(1);
  }
  char *ptr = mallocp(size); /* Call libc malloc */
  printf("malloc(%d) = %p\n", (int)size, ptr);
  return ptr;
}

/* free wrapper function */
void free(void *ptr) {
  void (*freep)(void *) = NULL;
  char *error;

  if (!ptr)
    return;

  freep = dlsym(RTLD_NEXT, "free"); /* Get address of libc free */
  if ((error = dlerror()) != NULL) {
    fputs(error, stderr);
    exit(1);
  }
  freep(ptr); /* Call libc free */
  printf("free(%p)\n", ptr);
}
#endif
```

```bash
linux> make intr
gcc -Wall -DRUNTIME -shared -fpic -o mymalloc.so mymalloc.c -ldl
gcc -Wall -o intr int.c
linux> make runr
(LD_PRELOAD="./mymalloc.so" ./intr)
malloc(32) = 0xe60010
free(0xe60010)
linux>
```

- The `LD_PRELOAD` environment variable tells the dynamic linker to resolve unresolved refs (e.g., to `malloc`) by looking in `mymalloc.so` first

# Exceptional Control Flow

## Control Flow

- Processors do only one thing:
  - From startup to shutdown, a CPU simply reads and executes (interprets) a sequence of instructions, one at a time
  - This sequence is the CPU's control flow (or flow of control)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3yer7zxizc.avif" alt="" />
</center>

Up to now, we have learned two mechanisms for changing control flow:

- Jumps and branches
- Call and return

They react to changes in program state.

But its insufficient for a useful system: difficult to react to changes in system state:

- Data arrives from a disk or a network adapter
- Instruction divides by zero
- User hits `Ctrl-C` at the keyboard
- System timer expires

That's why we need mechanisms for "exceptional control flow".

## Exceptional Control Flow

- Exists at all levels of a computer system
- Low level mechanisms
  - Exceptions
    - Change in control flow in response to a system event (i.e., change in system state)
    - Implemented using combination of hardware and OS software
- Higher level mechanisms
  - Process context switch
    - Implemented by OS software and hardware timer
  - Signals
    - Implemented by OS software
  - Nonlocal jumps: `setjmp()` and `longjmp()`
    - Implemented by C runtime library

## Exceptions

- An exception is a transfer of control to the OS kernel in response to some event (i.e., change in processor state)
  - Kernel is the memory-resident part of the OS
  - Examples of events: Divide by 0, arithmetic overflow, page fault, I/O request completes, typing `Ctrl‐C`

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8hgsb06g7p.avif" alt="" />
</center>

### Exception Tables

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8ok06fxc1p.avif" alt="" />
</center>

### Synchronous Exceptions

- Caused by events that occur as a result of executing an instruction
  - Traps
    - Intentional (e.g., system calls, breakpoint traps, special instructions)
    - Returns control to "next" instruction
  - Faults
    - Unintentional but possibly recoverable (e.g., page faults (recoverable), protection faults (unrecoverable), floating point exceptions)
    - Either re-executes faulting ("current") instruction or aborts
  - Aborts
    - Unintentional and unrecoverable (e.g., illegal instruction, parity error, machine check)
    - Aborts current program

### Asynchronous Exceptions (Interrupts)

- Caused by events external to the processor
  - Indicated by setting the processor’s interrupt pin
  - Handler returns to "next" instruction
- Examples:
  - Timer interrupt
    - Every few ms, an external timer chip triggers an interrupt
    - Used by the kernel to take back control from user programs
  - I/O interrupt from external device
    - Hitting `Ctrl-C` at the keyboard
    - Arrival of a packet from a network
    - Arrival of data from a disk

## Processes

- Definition: A process is an instance of a running program
  - One of the most profound ideas in computer science
  - Not the same as "program" or "processor"
- Process provides each program with two key abstractions:
  - Logical control flow
    - Each program seems to have exclusive use of the CPU
    - Provided by kernel mechanism called context switching
  - Private address space
    - Each program seems to have exclusive use of main memory
    - Provided by kernel mechanism called virtual memory

### Multiprocessing: The Illusion

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.58hoediwx5.avif" alt="" />
</center>

- Computer runs many processes simultaneously
  - Applications for one or more users
    - Web browsers, email clients, editors, ...
  - Background tasks
    - Monitoring network & I/O devices

### Multiprocessing: The (Traditional) Reality

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3nrxewo9gw.avif" alt="" />
</center>

- Single processor executes multiple processes concurrently
  - Process executions interleaved (multitasking)
  - Address spaces managed by virtual memory system
  - Register values for non-executing processes saved in memory
- Save current registers in memory

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7i0oxvaq6t.avif" alt="" />
</center>

- Schedule next process for execution
- Load saved registers and switch address space (context switch)

### Multiprocessing: The (Modern) Reality

- Multicore processors
  - Multiple CPUs on single chip
  - Share main memory (and some of the caches)
  - Each can execute a separate process
    - Scheduling of processors onto cores done by kernel

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.pfnbf3vjq.avif" alt="" />
</center>

### Concurrent Processes

- Each process is a logical control flow
- Two processes run concurrently (are concurrent) if their flows overlap in time
- Otherwise, they are sequential
- Examples (running on single core):
  - Concurrent: A & B, A & C
  - Sequential: B & C

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7eh3065rhl.avif" alt="" />
</center>

#### User View of Concurrent Processes

- Control flows for concurrent processes are physically disjoint in time
- However, we can think of concurrent processes as running in parallel with each other

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9rjphdkyax.avif" alt="" />
</center>

### Context Switching

- Processes are managed by a shared chunk of memory-resident OS code called the kernel
  - Important: the kernel is not a separate process, but rather runs as part of some existing process
- Control flow passes from one process to another via a context switch

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3d53lsj1f0.avif" alt="" />
</center>

## Process Control

### System Call Error Handling

- On error, Linux system-level functions typically return `‐1` and set global variable `errno` to indicate cause
- Hard and fast rule:
  - You must check the return status of every system-level function
  - Only exception is the handful of functions that return `void`

```c
if ((pid = fork()) < 0) {
  fprintf(stderr, "fork error: %s\n", strerror(errno));
  exit(0);
}
```

#### Error-reporting functions

- Can simplify somewhat using an error-reporting function:

```c
/* Unix-style error */
void unix_error(char *msg) {
  fprintf(stderr, "%s: %s\n", msg, strerror(errno));
  exit(0);
}

if ((pid = fork()) < 0)
  unix_error("fork error");
```

#### Error-handling Wrappers

- Simplify the present code even further by using Stevens-style error-handling wrappers:

```c
pid_t Fork(void) {
  pid_t pid;

  if ((pid = fork()) < 0)
    unix_error("Fork error");
  return pid;
}

pid = Fork();
```

### Processes States

From a programmer's perspective, we can think of a process as being in one of three states:

- Running
  - Process is either executing, or waiting to be executed and will eventually be scheduled (i.e., chosen to execute) by the kernel
- Stopped
  - Process execution is suspended and will not be scheduled until further notice
- Terminated
  - Process is stopped permanently

### Creating Processes

- Parent process creates a new running child process by calling `fork`
- `int fork(void)`
  - Returns `0` to the child process, child's PID to parent process
  - Child is almost identical to parent:
    - Child get an identical (but separate) copy of the parent's virtual address space
    - Child gets identical copies of the parent's open file descriptors
    - Child has a different PID than the parent
- `fork` is interesting (and often confusing) because it is called once but returns twice

#### fork Example

```c
int main() {
  pid_t pid;
  int x = 1;

  pid = Fork();
  if (pid == 0) { /* Child */
    printf("child: x=%d\n", ++x);
    exit(0);
  }

  /* Parent */
  printf("parent: x=%d\n", --x);
  exit(0);
}
```

```bash
linux> ./fork
parent: x=0
child: x=2
```

- Call once, return twice
- Concurrent execution
  - Can’t predict execution order of parent and child
- Duplicate but separate address space
  - `x` has a value of 1 when fork returns in parent and child
  - Subsequent changes to `x` are independent
- Shared open files
  - `stdout` is the same in both parent and child

### Terminating Processes

- Process becomes terminated for one of three reasons:
  - Receiving a signal whose default action is to terminate
  - Returning from the `main` routine
  - Calling the `exit` function
- `void exit(int status)`
  - Terminates with an exit status of status
  - Convention: normal return status is `0`, nonzero on error
  - Another way to explicitly set the exit status is to return an integer value from the main routine
- `exit` is called once but never returns

### Modeling fork with Process Graphs

- A process graph is a useful tool for capturing the partial ordering of statements in a concurrent program:
  - Each vertex is the execution of a statement
  - `a ‐> b` means `a` happens before `b`
  - Edges can be labeled with current value of variables
  - `printf` vertices can be labeled with output
  - Each graph begins with a vertex with no inedges
- Any topological sort of the graph corresponds to a feasible total ordering
  - Total ordering of vertices where all edges point from left to right

#### Process Graph Example

```c
int main() {
  pid_t pid;
  int x = 1;

  pid = Fork();
  if (pid == 0) { /* Child */
    printf("child: x=%d\n", ++x);
    exit(0);
  }

  /* Parent */
  printf("parent: x=%d\n", --x);
  exit(0);
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.361vqf3v66.avif" alt="" />
</center>

#### Interpreting Process Graphs

- Original graph:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.361vqf3v66.avif" alt="" />
</center>

- Relabled graph:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.sz997t4sc.avif" alt="" />
</center>

- Feasible total ordering:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3d53luu0e1.avif" alt="" />
</center>

- Infeasible total ordering:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2obu1u7581.avif" alt="" />
</center>

#### fork Example: Two consecutive forks

```c
void fork2() {
  printf("L0\n");
  fork();
  printf("L1\n");
  fork();
  printf("Bye\n");
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.lw1dsgms3.avif" alt="" />
</center>

#### fork Example: Nested forks in parent

```c
void fork4() {
  printf("L0\n");
  if (fork() != 0) {
    printf("L1\n");
    if (fork() != 0) {
      printf("L2\n");
    }
  }
  printf("Bye\n");
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.sz9984x39.avif" alt="" />
</center>

#### fork Example: Nested forks in children

```c
void fork5() {
  printf("L0\n");
  if (fork() == 0) {
    printf("L1\n");
    if (fork() == 0) {
      printf("L2\n");
    }
  }
  printf("Bye\n");
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.mdrhqki8.avif" alt="" />
</center>

### Reaping Child Processes

- Idea
  - When process terminates, it still consumes system resources (e.g., Exit status, various OS tables)
  - Called a `zombie` (Living corpse, half alive and half dead)
- Reaping
  - Performed by parent on terminated child (using `wait` or `waitpid`)
  - Parent is given exit status information
  - Kernel then deletes zombie child process
- What if parent doesn't reap ?
  - If any parent terminates without reaping a child, then the orphaned child will be reaped by `init` process (`pid == 1`)
  - So, only need explicit reaping in long-running processes (e.g., shells and servers)

#### Zombie Example

```c
void fork7() {
  if (fork() == 0) {
    /* Child */
    printf("Terminating Child, PID = %d\n", getpid());
    exit(0);
  } else {
    printf("Running Parent, PID = %d\n", getpid());
    while (1)
      ; /* Infinite loop */
  }
}
```

```bash
linux> ./forks 7 &
[1] 6639
Running Parent, PID = 6639
Terminating Child, PID = 6640
linux> ps
PID TTY TIME CMD
6585 ttyp9 00:00:00 tcsh
6639 ttyp9 00:00:03 forks
6640 ttyp9 00:00:00 forks <defunct>
6641 ttyp9 00:00:00 ps
linux> kill 6639
[1] Terminated
linux> ps
PID TTY TIME CMD
6585 ttyp9 00:00:00 tcsh
6642 ttyp9 00:00:00 ps
```

- `ps` shows child process as "defunct" (i.e., a zombie)
- Killing parent allows child to be reaped by `init`

#### Non-terminating Child Example

```c
void fork8() {
  if (fork() == 0) {
    /* Child */
    printf("Running Child, PID = %d\n", getpid());
    while (1)
      ; /* Infinite loop */
  } else {
    printf("Terminating Parent, PID = %d\n", getpid());
    exit(0);
  }
}
```

```bash
linux> ./forks 8
Terminating Parent, PID = 6675
Running Child, PID = 6676
linux> ps
PID TTY TIME CMD
6585 ttyp9 00:00:00 tcsh
6676 ttyp9 00:00:06 forks
6677 ttyp9 00:00:00 ps
linux> kill 6676
linux> ps
PID TTY TIME CMD
6585 ttyp9 00:00:00 tcsh
6678 ttyp9 00:00:00 ps
```

- Child process still active even though parent has terminated
- Must kill child explicitly, or else will keep running indefinitely

### wait: Synchronizing with Children

- Parent reaps a child by calling the `wait` function
- `int wait(int *child_status)`
  - Suspends current process until one of its children terminates
  - Return value is the `pid` of the child process that terminated
  - If `child_status != NULL`, then the integer it points to will be set to a value that indicates reason the child terminated and the exit status:
    - Checked using macros defined in `wait.h`
      - `WIFEXITED`, `WEXITSTATUS`, `WIFSIGNALED`, `WTERMSIG`, `WIFSTOPPED`, `WSTOPSIG`, `WIFCONTINUED`

#### wait Example

```c
void fork9() {
  int child_status;

  if (fork() == 0) {
    printf("HC: hello from child\n");
    exit(0);
  } else {
    printf("HP: hello from parent\n");
    wait(&child_status);
    printf("CT: child has terminated\n");
  }
  printf("Bye\n");
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1ovqopl1uh.avif" alt="" />
</center>

#### Another wait Example

- If multiple children completed, will take in arbitrary order
- Can use macros `WIFEXITED` and `WEXITSTATUS` to get information about exit status

```c
void fork10() {
  pid_t pid[N];
  int i, child_status;

  for (i = 0; i < N; i++)
    if ((pid[i] = fork()) == 0)
      exit(100+i); /* Child */
  for (i = 0; i < N; i++) { /* Parent */
    pid_t wpid = wait(&child_status);
  if (WIFEXITED(child_status))
    printf("Child %d terminated with exit status %d\n", wpid, WEXITSTATUS(child_status));
  else
    printf("Child %d terminate abnormally\n", wpid);
  }
}
```

### waitpid: Waiting for a Specific Process

- `pid_t waitpid(pid_t pid, int &status, int options)`
  - Suspends current process until specific process terminates

```c
void fork11() {
  pid_t pid[N];
  int i;
  int child_status;

  for (i = 0; i < N; i++)
    if ((pid[i] = fork()) == 0)
      exit(100+i); /* Child */
  for (i = N-1; i >= 0; i--) {
    pid_t wpid = waitpid(pid[i], &child_status, 0);
    if (WIFEXITED(child_status))
      printf("Child %d terminated with exit status %d\n", wpid, WEXITSTATUS(child_status));
    else
      printf("Child %d terminate abnormally\n", wpid);
    }
}
```

### execve: Loading and Running Programs

- `int execve(char *filename, char *argv[], char *envp[])`
- Loads and runs in the current process:
  - Executable file `filename`
    - Can be object file or script file beginning with `#!interpreter`
  - ...with argument list `argv`
    - By convention `argv[0] == filename`
  - ...and environment variable list `envp`
    - `name=value` strings (e.g., `USER=root`)
    - `getenv`, `putenv`, `printenv`
- Overwrites code, data, and stack
  - Retains PID, open files and signal context
- Called once and never returns
  - ...except if there is an error

#### Structure of the stack when a new program starts

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.102h4pubgz.avif" alt="" />
</center>

## Signals

### Linux Process Hierarchy

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7p3wvr5kt0.avif" alt="" />
</center>

:::tip
You can view the hierarchy using the `pstree` command.
:::

### Shell Programs

- A shell is an application program that runs programs on behalf of the user
  - `sh`: Original Unix shell (Stephen Bourne, AT&T Bell Labs, 1977)
  - `csh/tcsh`: BSD Unix C shell
  - `bash`: "Bourne-Again" Shell (default Linux shell)
- Execution is a sequence of read/evaluate steps

```c
int main() {
  char cmdline[MAXLINE]; /* command line */

  while (1) {
    /* read */
    printf("> ");
    fgets(cmdline, MAXLINE, stdin);

    if (feof(stdin))
      exit(0);

    /* evaluate */
    eval(cmdline);
  }
}
```

```c
void eval(char *cmdline) {
  char *argv[MAXARGS]; /* Argument list execve() */
  char buf[MAXLINE];   /* Holds modified command line */
  int bg;              /* Should the job run in bg or fg? */
  pid_t pid;           /* Process id */

  strcpy(buf, cmdline);
  bg = parseline(buf, argv);

  if (argv[0] == NULL)
    return; /* Ignore empty lines */

  if (!builtin_command(argv)) {
    if ((pid = Fork()) == 0) { /* Child runs user job */
      if (execve(argv[0], argv, environ) < 0) {
        printf("%s: Command not found.\n", argv[0]);
        exit(0);
      }
    }

    /* Parent waits for foreground job to terminate */
    if (!bg) {
      int status;
      if (waitpid(pid, &status, 0) < 0)
        unix_error("waitfg: waitpid error");
    }
    else
      printf("%d %s", pid, cmdline);
  }
  return;
}
```

#### Problem with Simple Shell Example

- Our example shell correctly waits for and reaps foreground jobs
- But what about background jobs ?
  - Will become zombies when they terminate
  - Will never be reaped because shell (typically) will not terminate
  - Will create a memory leak that could run the kernel out of memory

##### Solution: Exceptional Control Flow

- The kernel will interrupt regular processing to alert us when a background process completes
- In Unix, the alert mechanism is called a _signal_

### Signals

- A _signal_ is a small message that notifies a process that an event of some type has occurred in the system
  - Akin to exceptions and interrupts
  - Sent from the kernel (sometimes at the request of another process) to a process
  - Signal type is identified by small integer ID's (1-30)
  - Only information in a signal is its ID and the fact that it arrived

| ID  | Name     | Default Action   | Corresponding Event                      |
| --- | -------- | ---------------- | ---------------------------------------- |
| 2   | SIGINT   | Terminate        | User typed Ctrl-C                        |
| 9   | SIGKILL  | Terminate        | Kill program (cannot override or ignore) |
| 11  | SIGSEGV  | Terminate & Dump | Segmentation violation                   |
| 14  | SIGALARM | Terminate        | Timer signal                             |
| 17  | SIGCHLD  | Ignore           | Child stopped or terminated              |

#### Sending a Signal

- Kernel _sends (delivers)_ a signal to a _destination process_ by updating some state in the context of the destination process
- Kernel sends a signal for one of the following reasons:
  - Kernel has detected a system event such as _divide-by-zero (SIGFPE)_ or the _termination of a child process (SIGCHLD)_
  - Another process has invoked the `kill` system call to explicitly request the kernel to send a signal to the destination process

#### Receiving a Signal

- A destination process _receives_ a signal when it is forced by the kernel to react in some way to the delivery of the signal
- Some possible ways to react:
  - `Ignore` the signal (do nothing)
  - `Terminate` the process (with optional core dump)
  - `Catch` the signal by executing a user-level function called `signal handler`
    - Akin to a hardware exception handler being called in response to an asynchronous interrupt:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6m47kwd250.avif" alt="" />
</center>

#### Pending and Blocked Signals

- A signal is _pending_ if sent but not yet received
  - There can be at most one pending signal of any particular type
  - Signals are not queued
    - For each signal type, one bit indicates whether or not signal is pending
    - Thus at most one pending signal of any particular type
    - Then subsequent signals of the same type that are sent to that process are discarded
- A process can _block_ the receipt of certain signals
  - Blocked signals can be delivered, but will not be received until the signal is unblocked
- A pending signal is received at most once

#### Pending/Blocked Bits

- Kernel maintains pending and blocked bit vectors in the context of each process
  - `pending`: represents the set of pending signals
    - Kernel sets bit $k$ in pending when a signal of type $k$ is delivered
    - Kernel clears bit $k$ in pending when a signal of type $k$ is received
  - `blocked`: represents the set of blocked signals
    - Can be set and cleared by using the `sigprocmask` function
    - Also referred to as the _signal mask_

### Sending Signals

#### Process Groups

- Every process belongs to exactly one process group

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8ok08z1t1v.avif" alt="" />
</center>

- `getpgrp()` Return process group of current process
- `setpgid()` Change process group of a process

#### /bin/kill Program

- `/bin/kill` program sends arbitrary signal to a process or process group
- Examples
  - `/bin/kill –9 24818` Send SIGKILL to process 24818
  - `/bin/kill –9 –24817` Send SIGKILL to every process in process group 24817

```bash
linux> ./forks 16
Child1: pid=24818 pgrp=24817
Child2: pid=24819 pgrp=24817
linux> ps
PID TTY TIME CMD
24788 pts/2 00:00:00 tcsh
24818 pts/2 00:00:02 forks
24819 pts/2 00:00:02 forks
24820 pts/2 00:00:00 ps
linux> /bin/kill -9 -24817
linux> ps
PID TTY TIME CMD
24788 pts/2 00:00:00 tcsh
24823 pts/2 00:00:00 ps
linux>
```

#### From the Keyboard

- Typing `Ctrl-C` (`Ctrl-Z`) causes the kernel to send a SIGINT (SIGTSTP) to every job in the foreground process group
  - SIGINT – default action is to terminate each process
  - SIGTSTP – default action is to stop (suspend) each process

##### Example of Ctrl-C and Ctrl-Z

- STAT (process state) Legend:
  - First letter:
    - `S`: Sleeping
    - `T`: Stopped
    - `R`: Running
  - Second letter:
    - `s`: Session leader
    - `+`: Foreground proc group

```bash
bluefish> ./forks 17
Child: pid=28108 pgrp=28107
Parent: pid=28107 pgrp=28107
<types ctrl-z>
Suspended
bluefish> ps w
PID TTY STAT TIME COMMAND
27699 pts/8 Ss 0:00 -tcsh
28107 pts/8 T 0:01 ./forks 17
28108 pts/8 T 0:01 ./forks 17
28109 pts/8 R+ 0:00 ps w
bluefish> fg
./forks 17
<types ctrl-c>
bluefish> ps w
PID TTY STAT TIME COMMAND
27699 pts/8 Ss 0:00 -tcsh
28110 pts/8 R+ 0:00 ps w
```

#### kill Function

```c
void fork12() {
  pid_t pid[N];
  int i;
  int child_status;

  for (i = 0; i < N; i++)
    if ((pid[i] = fork()) == 0) {
      /* Child: Infinite Loop */
      while(1)
        ;
    }

  for (i = 0; i < N; i++) {
    printf("Killing process %d\n", pid[i]);
    kill(pid[i], SIGINT);
  }

  for (i = 0; i < N; i++) {
    pid_t wpid = wait(&child_status);
    if (WIFEXITED(child_status))
      printf("Child %d terminated with exit status %d\n", wpid, WEXITSTATUS(child_status));
    else
      printf("Child %d terminated abnormally\n", wpid);
  }
}
```

### Receiving Signals

- Suppose kernel is returning from an exception handler and is ready to pass control to process $p$

:::important
All context switches are initiated by calling some exception handler.
:::

- Kernel computes `pnb = pending & ~blocked`
  - The set of pending nonblocked signals for process $p$
- If `pnb == 0`
  - Pass control to next instruction in the logical flow for $p$
- Else
  - Choose least nonzero bit $k$ in `pnb` and force process $p$ to receive signal $k$
  - The receipt of the signal triggers some _action_ by $p$
  - Repeat for all nonzero $k$ in `pnb`
  - Pass control to next instruction in logical flow for $p$

#### Default Actions

- Each signal type has a predefined default ac)on, which is one of:
  - The process terminates
  - The process terminates and dumps core
  - The process stops until restarted by a SIGCONT signal
  - The process ignores the signal

### Installing Signal Handlers

- The signal function modifies the default action associated with the receipt of signal `signum`:
  - `handler_t *signal(int signum, handler_t *handler)`
- Different values for handler:
  - `SIG_IGN`: Ignore signals of type **signum**
  - `SIG_DFL`: Revert to the default action on receipt of signals of type **signum**
  - Otherwise, `handler` is the address of a user-level _signal handler_
    - Called when process receives signal of type **signum**
    - Referred to as _"installing"_ the handler
    - Executing handler is called _"catching"_ or _"handling"_ the signal
    - When the handler executes its return statement, control passes back to instruction in the control flow of the process that was interrupted by receipt of the signal

```c
/* SIGINT handler */
void sigint_handler(int sig) {
  printf("So you think you can stop the bomb with ctrl-c, do you?\n");
  sleep(2);
  printf("Well...");
  fflush(stdout);
  sleep(1);
  printf("OK. :-)\n");
  exit(0);
}

int main() {
  /* Install the SIGINT handler */
  if (signal(SIGINT, sigint_handler) == SIG_ERR)
    unix_error("signal error");

  /* Wait for the receipt of a signal */
  pause();

  return 0;
}
```

### Signals Handlers as Concurrent Flows

- A signal handler is a separate logical flow (not process) that runs concurrently with the main program

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.67xru5q4nt.avif" alt="" />
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwcfa6bb.avif" alt="" />
</center>

### Nested Signal Handlers

- Handlers can be interrupted by other handlers

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6m47l103is.avif" alt="" />
</center>

### Blocking and Unblocking Signals

- Implicit blocking mechanism
  - Kernel blocks any pending signals of type currently being handled
  - E.g., A SIGINT handler can't be interrupted by another SIGINT
- Explicit blocking and unblocking mechanism
  - `sigprocmask` function
- Supporting functions
  - `sigemptyset` – Create empty set
  - `sigfillset` – Add every signal number to set
  - `sigaddset` – Add signal number to set
  - `sigdelset` – Delete signal number from set

#### Temporarily Blocking Signals

```c
sigset_t mask, prev_mask;

sigemptyset(&mask);
sigaddset(&mask, SIGINT);

/* Block SIGINT and save previous blocked set */
sigprocmask(SIG_BLOCK, &mask, &prev_mask);!

/* Code region that will not be interrupted by SIGINT */

/* Restore previous blocked set, unblocking SIGINT */
sigprocmask(SIG_SETMASK, &prev_mask, NULL);
```

### Safe Signal Handling Guidelines

Handlers are tricky because they are concurrent with main program and share the same global data structures. Shared data structures can become corrupted.

- G0: Keep your handlers as simple as possible
  - E.g., Set a global flag and return
- G1: Call only async-signal-safe functions in your handlers
  - `printf`, `sprintf`, `malloc`, and `exit` are not safe !
- G2: Save and restore `errno` on entry and exit
  - So that other handlers don't overwrite your value of **errno**
- G3: Protect accesses to shared data structures by temporarily blocking all signals
  - To prevent possible corruption
- G4: Declare global variables as `volatile`
  - To prevent compiler from storing them in a register
- G5: Declare global flags as `volatile sig_atomic_t`
  - flag: variable that is only read or written (e.g. `flag = 1`, not `flag++`)
  - Flag declared this way does not need to be protected like other globals

#### Async-Signal-Safety

- Function is async-signal-safe if either reentrant (e.g., all variables stored on stack frame) or non-interruptible by signals
- Posix guarantees 117 functions to be async-signal-safe
  - Source: `man 7 signal`
  - Popular functions on the list:
    - `_exit`, `write`, `wait`, `waitpid`, `sleep`, `kill`
  - Popular functions that are not on the list:
    - `printf`, `sprintf`, `malloc`, `exit`
    - Unfortunate fact: `write` is the only async-signal-safe output function

#### Correct Signal Handling Example

You can't use signals to count events, such as children terminating.

```c
#define N 5

int ccount = 0;

void child_handler(int sig) {
  int olderrno = errno;
  pid_t pid;

  if ((pid = wait(NULL)) < 0)
    Sio_error("wait error");

  ccount--;
  Sio_puts("Handler reaped child ");
  Sio_putl((long)pid);
  Sio_puts(" \n");
  sleep(1);
  errno = olderrno;
}

void fork14() {
  pid_t pid[N];
  int i;
  ccount = N;

  signal(SIGCHLD, child_handler);

  for (i = 0; i < N; i++) {
    if ((pid[i] = fork()) == 0) {
      sleep(1);
      exit(0); /* Child exits */
    }
  }

  while (ccount > 0) /* Parent spins */
    ;
}
```

```bash
whaleshark> ./forks 14
Handler reaped child 23240
Handler reaped child 23241
```

Must wait for all terminated child processes. Put `wait` in a loop to reap all terminated children.

```c
void child_handler2(int sig) {
  int olderrno = errno;
  pid_t pid;

  while ((pid = wait(NULL)) > 0) {
    ccount--;
    Sio_puts("Handler reaped child ");
    Sio_putl((long)pid);
    Sio_puts(" \n");
  }
  if (errno != ECHILD)
    Sio_error("wait error");
  errno = olderrno;
}
```

```bash
whaleshark> ./forks 15
Handler reaped child 23246
Handler reaped child 23247
Handler reaped child 23248
Handler reaped child 23249
Handler reaped child 23250
whaleshark>
```

### Portable Signal Handling

- Ugh ! Different versions of Unix can have different signal handling semantics
  - Some older systems restore action to default after catching signal
  - Some interrupted system calls can return with `errno == EINTR`
  - Some systems don't block signals of the type being handled
- Solution: `sigaction`

```c
handler_t *signal(int signum, handler_t *handler) {
  struct sigaction action, old_action;

  action.sa_handler = handler;
  sigemptyset(&action.sa_mask); /* Block sigs of type being handled */
  action.sa_flags = SA_RESTART; /* Restart syscalls if possible */

  if (sigaction(signum, &action, &old_action) < 0)
    unix_error("Signal error");
  return (old_action.sa_handler);
}
```

### Synchronizing Flows to Avoid Races

- Simple shell with a subtle synchronization error because it assumes parent runs before child

```c
int main(int argc, char **argv) {
  int pid;
  sigset_t mask_all, prev_all;

  sigfillset(&mask_all);
  signal(SIGCHLD, handler);
  initjobs(); /* Initialize the job list */

  while (1) {
    if ((pid = Fork()) == 0) { /* Child */
      execve("/bin/date", argv, NULL);
    }
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all); /* Parent */
    addjob(pid); /* Add the child to the job list */
    sigprocmask(SIG_SETMASK, &prev_all, NULL);
  }
  exit(0);
}
```

```c
void handler(int sig) {
  int olderrno = errno;
  sigset_t mask_all, prev_all;
  pid_t pid;

  sigfillset(&mask_all);
  while ((pid = waitpid(-1, NULL, 0)) > 0) { /* Reap child */
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
    deletejob(pid); /* Delete the child from the job list */
    sigprocmask(SIG_SETMASK, &prev_all, NULL);
  }
  if (errno != ECHILD)
    Sio_error("waitpid error");
  errno = olderrno;
}
```

#### Corrected Shell Program without Race

```c
int main(int argc, char **argv) {
  int pid;
  sigset_t mask_all, mask_one, prev_one;

  sigfillset(&mask_all);
  sigemptyset(&mask_one);
  sigaddset(&mask_one, SIGCHLD);
  signal(SIGCHLD, handler);
  initjobs(); /* Initialize the job list */

  while (1) {
    sigprocmask(SIG_BLOCK, &mask_one, &prev_one); /* Block SIGCHLD */
    if ((pid = Fork()) == 0) { /* Child process */
      sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock SIGCHLD */
      execve("/bin/date", argv, NULL);
    }
    sigprocmask(SIG_BLOCK, &mask_all, NULL); /* Parent process */
    addjob(pid); /* Add the child to the job list */
    sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock SIGCHLD */
  }
  exit(0);
}
```

### Explicitly Waiting for Signals

- Handlers for program explicitly waiting for SIGCHLD to arrive

```c
volatile sig_atomic_t pid;

void sigchld_handler(int s) {
  int olderrno = errno;
  pid = waitpid(-1, NULL, 0); /* Main is waiting for nonzero pid */
  errno = olderrno;
}

void sigint_handler(int s) {}
```

Similar to a shell waiting for a foreground job to terminate:

```c
int main(int argc, char **argv) {
  sigset_t mask, prev;

  signal(SIGCHLD, sigchld_handler);
  signal(SIGINT, sigint_handler);
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  while (1) {
    sigprocmask(SIG_BLOCK, &mask, &prev); /* Block SIGCHLD */
    if (fork() == 0) /* Child */
      exit(0);

    /* Parent */
    pid = 0;
    sigprocmask(SIG_SETMASK, &prev, NULL); /* Unblock SIGCHLD */

    /* Wait for SIGCHLD to be received (wasteful!) */
    while (!pid)
      ;

    /* Do some work after receiving SIGCHLD */
    printf(".");
  }
  exit(0);
}
```

- Program is correct, but very wasteful

Other options:

```c
while (!pid) /* Race! */
  pause();
```

```c
while (!pid) /* Too slow! */
  sleep(1);
```

- Solution: `sigsuspend`

### Waiting for Signals with sigsuspend

- `int sigsuspend(const sigset_t *mask)`
  - It'll temporarily use `const sigset_t *mask` instead of currently signal block mask, then hang on program. Once catch signal, revert the signal block mask to original one

```c
int main(int argc, char **argv) {
  sigset_t mask, prev;

  signal(SIGCHLD, sigchld_handler);
  signal(SIGINT, sigint_handler);
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  while (1) {
    sigprocmask(SIG_BLOCK, &mask, &prev); /* Block SIGCHLD */
    if (fork() == 0) /* Child */
      exit(0);

    /* Wait for SIGCHLD to be received */
    pid = 0;
    while (!pid)
      sigsuspend(&prev);

    /* Optionally unblock SIGCHLD */
    sigprocmask(SIG_SETMASK, &prev, NULL);
    /* Do some work after receiving SIGCHLD */
    printf(".");
  }
  exit(0);
}
```

## Nonlocal Jumps

- Powerful (but dangerous) user-level mechanism for transferring control to an arbitrary location

  - Controlled to way to break the procedure call / return discipline
  - Useful for error recovery and signal handling

- `int setjmp(jmp_buf buf)`
  - Must be called before **longjmp**
  - Identifies a return site for a subsequent **longjmp**
  - Called once, returns one or more times
  - Implementation:
    - Remember where you are by storing the current _register context_, _stack pointer_, and _PC_ value in `buf`
    - Return `0`
- `int sigsetjmp(sigjmp_buf buf, int save);`
  - Similar as **setjmp**, `save` indicates whether save signal block mask (can only be `0` (don't save) or `1` (save))
- `void longjmp(jmp_buf buf, int val)`
  - Meaning:
    - return from the **setjmp** remembered by jump buffer `buf` again...
    - ...this time returning `val` instead of `0` (if `val` is `0`, force return `1`)
  - Called after **setjmp**
  - Called once, but never returns
  - Implementation:
    - Restore _register context_, _stack pointer_, _base pointer_, _PC_ value from jump buffer `buf`
    - Set **%eax** to `val`
    - Jump to the location indicated by the _PC_ stored in jump buf `buf`
- `void siglongjmp(sigjmp_buf buf, int val);`
  - Same as **longjmp**, just using with **sigsetjmp**

### setjmp/longjmp Example

- Goal: return directly to original caller from a deeply-nested function

```c
jmp_buf buf;

int error1 = 0;
int error2 = 1;

void foo(void), bar(void);

int main() {
  switch(setjmp(buf)) {
  case 0:
    foo();
    break;
  case 1:
    printf("Detected an error1 condition in foo\n");
    break;
  case 2:
    printf("Detected an error2 condition in foo\n");
    break;
  default:
    printf("Unknown error condition in foo\n");
  }
  exit(0);
}

/* Deeply nested function foo */
void foo(void) {
  if (error1)
    longjmp(buf, 1);
  bar();
}

void bar(void) {
  if (error2)
    longjmp(buf, 2);
}

// Output: Detected an error2 condition in foo
```

### sigsetjmp/siglongjmp Example

This program restarts itself when Ctrl-C'd:

```c
sigjmp_buf buf;

void handler(int sig) {
  siglongjmp(buf, 1);
}

int main() {
  if (!sigsetjmp(buf, 1)) {
    signal(SIGINT, handler);
    Sio_puts("starting\n");
  }
  else
    Sio_puts("restarting\n");

  while(1) {
    sleep(1);
    Sio_puts("processing...\n");
  }
  exit(0); /* Control never reaches here */
}
```

### Limitations of Nonlocal Jumps

- Works within stack discipline
  - Can only long jump to environment of function that has been called but not yet completed

```c
jmp_buf env;

P1() {
  if (setjmp(env)) {
    /* Long Jump to here */
  } else {
    P2();
  }
}
P2() { . . . P2(); . . . P3(); }
P3() {
  longjmp(env, 1);
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1lc4v4zquz.avif" alt="" />
</center>

```c
jmp_buf env;

P1() {
  P2();
  P3();
}

P2() {
  if (setjmp(env)) {
    /* Long Jump to here */
  }
}

P3() {
  longjmp(env, 1);
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5j4ibtsb04.avif" alt="" />
</center>

# Virtual Memory

TODO

# Dynamic Memory Allocation

- Assumptions for following examples:
  - Memory is word addressed
  - Words are int-sized

## Basic Concepts

- Programmers use dynamic memory allocators (such as **malloc**) to acquire virtual memory at runtime
  - For data structures whose size is only known at runtime
- Dynamic memory allocators manage an area of process virtual memory known as the heap

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.99to01ffdl.avif" alt="" />
</center>

- Allocator maintains heap as collection of variable sized blocks, which are either allocated or free
- Types of allocators
  - Explicit allocator: application allocates and frees space
    - E.g., **malloc** and **free** in C
  - Implicit allocator: application allocates, but does not free space
    - E.g. garbage collection in **Java**, **ML**, and **Lisp**

## The malloc Package

- `void *malloc(size_t size)`
  - Successful:
    - Returns a pointer to a memory block of at least size bytes aligned to an 8-byte (x86) or 16-byte (x86-64) boundary
    - If `size == 0`, returns NULL
  - Unsuccessful: returns NULL (0) and sets **errno**
- `void free(void *p)`
  - Returns the block pointed at by **p** to pool of available memory
  - **p** must come from a previous call to **malloc** or **realloc**
- Other functions
  - `calloc`: Version of **malloc** that initializes allocated block to zero
  - `realloc`: Changes the size of a previously allocated block
  - `sbrk`: Used internally by allocators to grow or shrink the heap

```c
#include <stdio.h>
#include <stdlib.h>

void foo(int n) {
  int i, *p;

  /* Allocate a block of n ints */
  p = (int *) malloc(n * sizeof(int));
  if (p == NULL) {
    perror("malloc");
    exit(0);
  }

  /* Initialize allocated block */
  for (i=0; i<n; i++)
    p[i] = i;


  /* Return allocated block to the heap */!
  free(p);
}
```

### Constrains

- Applications
  - Can issue arbitrary sequence of **malloc** and **free** requests
  - **free** request must be to a **malloc**'d block
- Allocators
  - Can't control number or size of allocated blocks
  - Must respond immediately to **malloc** requests
    - i.e., can't reorder or buffer requests
  - Must allocate blocks from free memory
    - i.e., can only place allocated blocks in free memory
  - Must align blocks so they satisfy all alignment requirements
    - 8-byte (x86) or 16-byte (x86-64) alignment on Linux boxes
  - Can manipulate and modify only free memory
  - Can't move the allocated blocks once they are **malloc**'d
    - i.e., compaction is not allowed

## Performance Goal

- Goals: maximize throughput and peak memory utilization
  - These goals are often conflicting

### Throughput

- Given some sequence of **malloc** and **free** requests:
  - $R_{0} ,R_{1} ,...,R_{k} ,...,R_{n-1}$
- Throughput
  - Number of completed requests per unit time
  - Example:
    - 5,000 **malloc** calls and 5,000 **free** calls in 10 seconds
    - Throughput is 1,000 operations/second

### Peak Memory Utilization

- Given some sequence of **malloc** and **free** requests:
  - $R_{0} ,R_{1} ,...,R_{k} ,...,R_{n-1}$
- Def: Aggregate payload $P_{k}$
  - `malloc(p)` results in a block with a _payload_ of **p** bytes
  - After request $R_{k}$ has completed, the _aggregate payload_ $P_{k}$ is the sum of currently allocated payloads
- Def: Current heap size $H_{k}$
  - Assume $H_{k}$ is monotonically nondecreasing
    - i.e., heap only grows when allocator uses **sbrk**
- Def: Peak memory utilization after $k+1$ requests
  - $\displaystyle U_{k} =( max_{i\leqslant k} \ P_{i}) /H_{k}$

## Fragmentation

- Poor memory utilization caused by fragmentation
  - internal fragmentation
  - external fragmentation

### Internal Fragmentation

- For a given block, _internal fragmentation_ occurs if payload is smaller than block size

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5j4iev728s.avif" alt="" />
</center>

- Caused by
  - Overhead of maintaining heap data structures
  - Padding for alignment purposes
  - Explicit policy decisions
    - E.g., to return a big block to satisfy a small request
- Depends only on the pattern of previous requests
  - Thus, easy to measure

### External Fragmentation

- Occurs when there is enough aggregate heap memory, but no single free block is large enough

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8ok0dtbq9w.avif" alt="" />
</center>

- Depends on the pattern of future requests
  - Thus, difficult to measure

## Implementation Issues

- How do we know how much memory to free given just a pointer ?
- How do we keep track of the free blocks ?
- What do we do with the extra space when allocating a structure that is smaller than the free block it is placed in ?
- How do we pick a block to use for allocation -- many might fit ?
- How do we reinsert freed block ?

## Knowing How Much to Free

- Standard method
  - Keep the length of a block in the word preceding the block
    - This word is often called the header field or header
  - Requires an extra word for every allocated block

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.67xryw937x.avif" alt="" />
</center>

## Keeping Track of Free Blocks

- Method 1: _Implicit list_ using length-links all blocks

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7eh37i35k3.avif" alt="" />
</center>

- Method 2: _Explicit list_ among the free blocks using pointers

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.96a22enk2p.avif" alt="" />
</center>

- Method 3: _Segregated free list_
  - Different free lists for different size classes
- Method 4: _Blocks sorted by size_
  - Can use a balanced tree (e.g. Red-Black tree) with pointers within each free block, and the length used as a key

### Implicit List

- For each block we need both size and allocation status
  - Could store this information in two words: wasteful !
- Standard trick
  - If blocks are aligned, some low-order address bits are always 0
  - Instead of storing an always-0 bit, use it as a allocated/free flag
  - When reading size word, must mask out this bit

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.sz9ghda3u.avif" alt="" />
</center>

#### Detailed Implicit Free List Example

- Payload must be double-word aligned

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.51egqb4ltk.avif" alt="" />
</center>

- We have an internal fragmentation in first allocated block because of payload is only 2 words but allocated 4 words

#### Finding a Free Block

- First fit
  - Search list from beginning, choose first free block that fits:

```c
p = start;
while ((p < end) &&  // not passed end
      ((*p & 1) ||   // already allocated
      (*p <= len)))  // too small
  p = p + (*p & -2); // goto next block (word addressed)
```

- Can take linear time in total number of blocks (allocated and free)
- In practice it can cause "splinters" at beginning of list
- Next fit
  - Like first fit, but search list starting where previous search finished
  - Should often be faster than first fit: avoids re-scanning unhelpful blocks
  - Some research suggests that fragmentation is worse
- Best fit
  - Search the list, choose the best free block: fits, with fewest bytes left over
  - Keeps fragments small — usually improves memory utilization
  - Will typically run slower than first fit

#### Allocating in Free Block

- Splitting
  - Since allocated space might be smaller than free space, we might want to split the block

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8z6u7er5p4.avif" alt="" />
</center>

```c
void addblock(ptr p, int len) {
  int newsize = ((len + 1) >> 1) << 1; // round up to even
  int oldsize = *p & -2;               // mask out low bit
  *p = newsize | 1;                    // set new length
  if (newsize < oldsize)
    *(p+newsize) = oldsize - newsize;  // set length in remaining
}
```

#### Freeing a Block

- Simplest implementation
  - Need only clear the _allocated_ flag
    - `void free_block(ptr p) { *p = *p & -2 }`
  - But can lead to "false fragmentation"

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5q7qar6trr.avif" alt="" />
</center>

- There is enough free space, but the allocator won't be able to find it

#### Coalescing

- Join (coalesce) with next/previous blocks, if they are free
  - Coalescing with next block

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.26lsky9ul8.avif" alt="" />
</center>

```c
void free_block(ptr p) {
  *p = *p & -2;         // clear allocated flag
  next = p + *p;        // find next block
  if ((*next & 1) == 0)
    *p = *p + *next;    // add to this block if
}                       // not allocated
```

- But how do we coalesce with previous block ?

#### Bidirectional Coalescing

- _Boundary tags_ [Knuth73]
  - Replicate size/allocated word at "bottom" (end) of free blocks
  - Allows us to traverse the "list" backwards, but requires extra space
  - Important and general technique !

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175p7t1o10.avif" alt="" />
</center>

#### Constant Time Coalescing

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.70anh3q3vv.avif" alt="" />
</center>

##### Case 1

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2obu9k7i8c.avif" alt="" />
</center>

##### Case 2

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.60uk3xpdgb.avif" alt="" />
</center>

##### Case 3

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4xuut1u639.avif" alt="" />
</center>

##### Case 4

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.51egqrns7m.avif" alt="" />
</center>

#### Disadvantages of Boundary Tags

- Internal fragmentation
- **malloc**'d blocks don't need the footer tag

#### Implicit Lists Summary

- Implementation: very simple
- Allocate cost:
  - Linear time worst case
- Free cost:
  - Constant time worst case
  - Even with coalescing
- Memory usage:
  - Will depend on placement policy
  - First-fit, next-fit or best-fit
- Not used in practice for **malloc**/**free** because of linear-time allocation
  - Used in many special purpose applications
- However, the concepts of splitting and boundary tag coalescing are general to all allocators

### Explicit List

#### Explicit Free Lists

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.sz9hl07hh.avif" alt="" />
</center>

- Maintain list(s) of free blocks, not all blocks

  - The "next" free block could be anywhere
    - So we need to store forward/back pointers, not just sizes
  - Still need boundary tags for coalescing
  - Luckily we track only free blocks, so we can use payload area

- Logically

<center>
<img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9rjpptl2pw.avif" alt="" />
</center>

- Physically
  - Blocks can be in any order

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.96a23irl8y.avif" alt="" />
</center>

#### Allocating From Explicit Free Lists

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.96a23iucj4.avif" alt="" />
</center>

#### Freeing With Explicit Free Lists

- Insertion policy
  - LIFO (last-in-first-out) policy
    - Insert freed block at the beginning of the free list
    - Pro: Simple and constant time
    - Con: Studies suggest fragmentation is worse than address ordered
  - Address-ordered policy
    - Insert freed blocks so that free list blocks are always in address order: _addr(prev) < addr(curr) < addr(next)_
    - Pro: Studies suggest fragmentation is lower than LIFO
    - Con: Requires search

##### Freeing With a LIFO Policy (Case 1)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.39lhwikezf.avif" alt="" />
</center>

- Insert the freed block at the root of the list

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8s3mcnt6bl.avif" alt="" />
</center>

##### Freeing With a LIFO Policy (Case 2)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6pntolx1mb.avif" alt="" />
</center>

- Splice out successor block, coalesce both memory blocks and insert the new block at the root of the list

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwiagcfc.avif" alt="" />
</center>

##### Freeing With a LIFO Policy (Case 3)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.45zxljzf4.avif" alt="" />
</center>

- Splice out predecessor block, coalesce both memory blocks, and insert the new block at the root of the list

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6bhdxrgljf.avif" alt="" />
</center>

##### Freeing With a LIFO Policy (Case 4)

<cneter>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.51egrg0by7.avif" alt="" />
</cneter>

- Splice out predecessor and successor blocks, coalesce all 3 memory blocks and insert the new block at the root of the list

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2vf25o9gb5.avif" alt="" />
</center>

#### Explicit List Summary

- Comparison to implicit list:
  - Allocate is linear time in number of free blocks instead of all blocks
    - Much faster when most of the memory is full
  - Slightly more complicated allocate and free since needs to splice blocks in and out of the list
  - Some extra space for the links (2 extra words needed for each block)
- Most common use of linked lists is in conjunction with segregated free lists
  - Keep multiple linked lists of different size classes, or possibly for different types of objects

### Segregated Free List

- Each _size class_ of blocks has its own free list

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.lw1m8ofkw.avif" alt="" />
</center>

- Often have separate classes for each small size
- For larger sizes: One class for each two-power size

#### Seglist Allocator

- Given an array of free lists, each one for some size class
- To allocate a block of size _n_:
  - Search appropriate free list for block of size _m > n_
  - If an appropriate block is found:
    - Split block and place fragment on appropriate list (optional)
  - If no block is found, try next larger class
  - Repeat until block is found
- If no block is found:
  - Request additional heap memory from OS (using `sbrk()`)
  - Allocate block of _n_ bytes from this new memory
  - Place remainder as a single free block in largest size class
- To free a block:
  - Coalesce and place on appropriate list
- Advantages of seglist allocators
  - Higher throughput
    - log time for power-of-two size classes
  - Better memory utilization
    - First-fit search of segregated free list approximates a best-fit search of entire heap
    - Extreme case: Giving each block its own size class is equivalent to best-fit

## Summary of Key Allocator Policies

- Placement policy
  - First-fit, next-fit, best-fit, etc
  - Trades off lower throughput for less fragmentation
  - Interesting observation: segregated free lists
    - Approximate a best fit placement policy without having to search entire free list
- Splitting policy
  - When do we go ahead and split free blocks ?
  - How much internal fragmentation are we willing to tolerate ?
- Coalescing policy
  - Immediate coalescing: Coalesce each time free is called
  - Deferred coalescing: Try to improve performance of free by deferring coalescing until needed. Examples:
    - Coalesce as you scan the free list for **malloc**
    - Coalesce when the amount of external fragmentation reaches some threshold

## Garbage Collection

- Automatic reclamation of heap-allocated storage -- application never has to free

```c
void foo() {
  int *p = malloc(128);
  return; /* p block is now garbage */
}
```

- Common in many dynamic languages:
  - Python, Ruby, Java, Perl, ML, Lisp, Mathematica
- Variants ("conservative" garbage collectors) exist for C and C++

  - However, cannot necessarily collect all garbage

- How does the memory manager know when memory can be freed ?
  - In general we cannot know what is going to be used in the future since it depends on conditionals
  - But we can tell that certain blocks cannot be used if there are no pointers to them
- Must make certain assumptions about pointers
  - Memory manager can distinguish pointers from non-pointers
  - All pointers point to the start of a block
  - Cannot hide pointers (e.g., by coercing them to an **int**, and then back again)

### Classical GC Algorithms

- Mark-and-sweep collection (McCarthy, 1960)
  - Does not move blocks (unless you also "compact")
- Reference counting (Collins, 1960)
  - Does not move blocks
- Copying collection (Minsky, 1963)
  - Moves blocks
- Generational Collectors (Lieberman and Hewitt, 1983)
  - Collection based on lifetimes
    - Most allocations become garbage very soon
    - So focus reclamation work on zones of memory recently allocated

### Memory as a Graph

- We view memory as a directed graph
  - Each block is a node in the graph
  - Each pointer is an edge in the graph
  - Locations not in the heap that contain pointers into the heap are called _root_ nodes (e.g. registers, locations on the stack, global variables)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5mo4du972h.avif" alt="" />
</center>

- A node (block) is _reachable_ if there is a path from any root to that node
- Non-reachable nodes are _garbage_ (cannot be needed by the application)

### Mark and Sweep Collecting

- Can build on top of **malloc**/**free** package
  - Allocate using **malloc** until you "run out of space"
- When out of space:
  - Use extra _mark bit_ in the head of each block
  - Mark: Start at roots and set mark bit on each reachable block
  - Sweep: Scan all blocks and free blocks that are not marked

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.77dvdbc32w.avif" alt="" />
</center>

### Assumptions For a Simple Implementation

- Application
  - `new(n)`: returns pointer to new block with all locations cleared
  - `read(b, i)`: read location `i` of block `b` into register
  - `write(b, i, v)`: write `v` into location `i` of block `b`
- Each block will have a header word
  - Addressed as `b[-1]`, for a block `b`
  - Used for different purposes in different collectors
- Instructions used by the Garbage Collector
  - `is_ptr(p)`: determines whether `p` is a pointer
  - `length(b)`: returns the length of block `b`, not including the header
  - `get_roots()`: returns all the roots

#### Example

- Mark using depth-first traversal of the memory graph

```c
ptr mark(ptr p) {
  if (!is_ptr(p)) return;       // do nothing if not pointer
  if (markBitSet(p)) return;    // check if already marked
  setMarkBit(p);                // set the mark bit
  for (i=0; i < length(p); i++) // call mark on all words
    mark(p[i]);                 // in the block
  return;
}
```

- Sweep using lengths to find next block

```c
ptr sweep(ptr p, ptr end) {
  while (p < end) {
    if markBitSet(p)
      clearMarkBit();
    else if (allocateBitSet(p))
      free(p);
    p += length(p);
}
```

### Conservative Mark & Sweep in C

- A "conservative garbage collector" for C programs
  - `is_ptr()` determines if a word is a pointer by checking if it points to an allocated block of memory
  - But, in C pointers can point to the middle of a block

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5xay70tuij.avif" alt="" />
</center>

- So how to find the beginning of the block ?
  - Can use a balanced binary tree to keep track of all allocated blocks (key is start-of-block)
  - Balanced-tree pointers can be stored in header (use two additional words)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.102hd6hgaj.avif" alt="" />
</center>

# System-Level I/O

## Unix I/O

- A Linux file is a sequence of _m_ bytes
- All I/O devices are represented as files
- Even the kernel is represented as a file
  - `/boot/vmlinuz-3.13.0-55-generic`: kernel image
  - `/proc`: kernel data structures

## File Types

- Each file has a type indicating its role in the system
  - Regular file: Contains arbitrary data
  - Directory: Index for a related group of files
  - Socket: For communicating with a process on another machine
- And more file types...
  - Named pipes (FIFOs)
  - Symbolic links
  - Character and block devices
  - ...

### Regular Files

- A regular file contains arbitrary data
- Applications open distinguish between text files and binary files
  - Text files are regular files with only ASCII or Unicode characters
  - Binary files are everything else
    - e.g., object files, JPEG images
  - Kernel doesn't know the difference !
- Text file is sequence of text lines
  - Text line is sequence of chars terminated by newline char `\n`
    - Newline is `0x0a`, same as ASCII line feed character LF
- End Of Line (EOL) indicators in different systems:
  - Linux and Mac OS: `\n` (`0x0a`)
    - Line Feed (LF)
  - Windows and Internet protocols: `\r\n` (`0x0d` `0x0a`)
    - Carriage return (CR) followed by line feed (LF)

### Directories

- Directory consists of an array of links
  - Each link maps a filename to a file
- Each directory contains at least two entries
  - `.` (dot) is a link to itself
  - `..` (dot dot) is a link to the parent directory

#### Directory Hierarchy

- All files are organized as a hierarchy anchored by root directory named `/` (slash)
- Kernel maintains current working directory (cwd) for each process

### Opening Files

- Opening a file informs the kernel that you are getting ready to access that file

```c
int fd; /* file descriptor */

if ((fd = open("/etc/hosts", O_RDONLY)) < 0) {
  perror("open");
  exit(1);
}
```

- Returns a small identifying integer _file descriptor_
  - `fd == -1` indicates that an error occurred
- Each process created by a linux shell begins life with three open files associated with a terminal:
  - `0`: standard input (`stdin`)
  - `1`: standard output (`stdout`)
  - `2`: standard error (`stderr`)

### Closing Files

- Closing a file informs the kernel that you are finished accessing that file

```c
int fd;     /* file descriptor */
int retval; /* return value */

if ((retval = close(fd)) < 0) {
  perror("close");
  exit(1);
}
```

- Closing an already closed file is a recipe for disaster in threaded programs
- Moral: Always check return codes, even for seemingly benign functions such as `close()`

### Reading Files

- Reading a file copies bytes from the current file position to memory, and then updates file position

```c
char buf[512];
int fd;     /* file descriptor */
int nbytes; /* number of bytes read */

/* Open file fd ... */
/* Then read up to 512 bytes from file fd */
if ((nbytes = read(fd, buf, sizeof(buf))) < 0) {
  perror("read");
  exit(1);
}
```

- Returns number of bytes read from file _fd_ into _buf_

### Writing Files

- Writing a file copies bytes from memory to the current file position, and then updates current file position

```c
char buf[512];
int fd;     /* file descriptor */
int nbytes; /* number of bytes read */

/* Open the file fd ... */
/* Then write up to 512 bytes from buf to file fd */
if ((nbytes = write(fd, buf, sizeof(buf)) < 0) {
  perror("write");
  exit(1);
}
```

- Returns number of bytes written from _buf_ to file _fd_

### Short Counts

- Short counts can occur in these situations:
  - Encountering (end-of-file) EOF on reads
  - Reading text lines from a terminal
  - Reading and writing network sockets
- Short counts never occur in these situations:
  - Reading from disk files (except for EOF)
  - Writing to disk files
- Best practice is to always allow for short counts

```c
ssize_t readn(int fd, void *buf, size_t size) {
  char *ptr = buf;
  size_t nleft = size;
  ssize_t nread;

  while (nleft > 0) {
    nread = read(fd, ptr, nleft);

    if (nread < 0)
      return -1; // error
    if (nread == 0)
      break; // EOF

    nleft -= nread;
    ptr += nread;
  }

  return (size - nleft);
}
```

## Buffered I/O

### Motivation

- Applications open read/write one character at a time
  - Read line of text one character at a time, stopping at newline
- Implementing as Unix I/O calls expensive
  - `read` and `write` require Unix kernel calls
    - $> 10000$ clock cycles
- Solution: Buffered read
  - Use Unix _read_ to grab block of bytes
  - User input functions take one byte at a time from buffer
    - Refill buffer when empty

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.32i9yxiff2.avif" alt="" />
</center>

### Example

- Goal: Copying `stdin` to `stdout`, one byte at a time

#### Without builtin buffer

```c
int main() {
  char c;
  while (read(STDIN_FILENO, &c, sizeof(char)))
    write(STDOUT_FILENO, &c, sizeof(char));

  return 0;
}
```

- To many `read` system calls, wasteful !

#### With builtin buffer

```c
#define BUFFER_SIZE 1024

ssize_t buffered_getchar(int fd, char *c) {
  static char buf[BUFFER_SIZE];
  static size_t size = 0;
  static size_t pos = 0;

  if (pos >= size) {
    size = read(fd, buf, BUFFER_SIZE);

    if (size <= 0) {
      return -1; // EOF or error
    }
    pos = 0;
  }
  *c = buf[pos++];

  return 1; // success got 1 character
}
```

- Only one `read` system call.

## Metadata, Sharing, and Redirection

### File Metadata

- Metadata is data about data, in this case file data
- Per-file metadata maintained by kernel
  - Accessed by users with the `stat` and `fstat` functions

```c
/* Metadata returned by the stat and fstat functions */
struct stat {
  dev_t st_dev;             /* Device */
  ino_t st_ino;             /* inode */
  mode_t st_mode;           /* Protection and file type */
  nlink_t st_nlink;         /* Number of hard links */
  uid_t st_uid;             /* User ID of owner */
  gid_t st_gid;             /* Group ID of owner */
  dev_t st_rdev;            /* Device type (if inode device) */
  off_t st_size;            /* Total size, in bytes */
  unsigned long st_blksize; /* Blocksize for filesystem I/O */
  unsigned long st_blocks;  /* Number of blocks allocated */
  time_t st_atime;          /* Time of last access */
  time_t st_mtime;          /* Time of last modification */
  time_t st_ctime;          /* Time of last change */
};
```

#### Example of Accessing Metadata

```c
int main(int argc, char **argv) {
  struct stat file_stat;
  char *type, *readok;

  stat(argv[1], &file_stat);

  if (S_ISREG(file_stat.st_mode))    /* Determine file type */
    type = "regular";
  else if (S_ISDIR(file_stat.st_mode))
    type = "directory";
  else
    type = "other";
  if ((file_stat.st_mode & S_IRUSR)) /* Check read access */
    readok = "yes";
  else
    readok = "no";

  printf("type: %s, read: %s\n", type, readok);
  exit(0);
}
```

### Represents Open Files

- Two descriptors referencing two distinct open files. Descriptor 1 (stdout) points to terminal, and descriptor 4 points to open disk file

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.77dvalgr0d.avif" alt="" />
</center>

### File Sharing

- Two distinct descriptors sharing the same disk file through two distinct open file table entries
  - E.g., Calling open twice with the same filename argument

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6t7fjqff22.avif" alt="" />
</center>

### Processes Share Files: fork

- A child process inherits its parent's open files
  - Note: situation unchanged by exec functions (use `fcntl` to change)

Before fork call:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwfp776w.avif" alt="" />
</center>

After fork call:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5q7q8unvle.avif" alt="" />
</center>

- Child's table same as parent's, and +1 to each refcnt

### I/O Redirection

- `dup2(oldfd, newfd)`
  - Copies (per-process) descriptor table entry `oldfd` to entry `newfd`

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.b97qg02me.avif" alt="" />
</center>

#### Example

- Open file to which stdout should be redirected
  - Happens in child executing shell code, before `exec`

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwfp776w.avif" alt="" />
</center>

- Call `dup2(4,1)`
  - Cause fd=1 (stdout) to refer to disk file pointed at by fd=4

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.64e5zqr4gh.avif" alt="" />
</center>

## Standard I/O

### Standard I/O Streams

- Standard I/O models open files as streams
  - Abstraction for a file descriptor and a buffer in memory
- C programs begin life with three open streams (defined in `stdio.h`)
  - `stdin`: standard input
  - `stdout`: standard output
  - `stderr`: standard error

```c
#include <stdio.h>

extern FILE *stdin;  /* standard input (descriptor 0) */
extern FILE *stdout; /* standard output (descriptor 1) */
extern FILE *stderr; /* standard error (descriptor 2) */

int main() {
  fprintf(stdout, "Hello, world\n");
}
```

### Buffering in Standard I/O

- Standard I/O functions use buffered I/O

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.86tyo7q78o.avif" alt="" />
</center>

```c
int main() {
  printf("h");
  printf("e");
  printf("l");
  printf("l");
  printf("o");
  printf("\n");
  fflush(stdout);
  exit(0);
}
```

- Buffer flushed to output fd on `\n`, call to `fflush` or `exit`, or `return` from main

# Network Programming

## A Client-Server Transaction

- Most network applications are based on the client-server model:
  - A server process and one or more client processes
  - Server manages some resources
  - Server provides service by manipulating resource for clients
  - Server activated by request from client (vending machine analogy)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.39lhxow3xq.avif" alt="" />
</center>

## Hardware Organization of a Network Host

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6ikluckl12.avif" alt="" />
</center>

## Computer Networks

- A _network_ is a hierarchical system of boxes and wires organized by geographical proximity
  - SAN (System Area Network) spans cluster or machine room
    - Switched Ethernet, Quadrics QSW, ...
  - LAN (Local Area Network) spans a building or campus
    - Ethernet is most prominent example
  - WAN (Wide Area Network) spans country or world
    - Typically high-speed point-to-point phone lines
- An _internetwork (internet)_ is an interconnected set of networks
  - The Global IP Internet (uppercase "I") is the most famous example of an internet (lowercase "i")

### Lowest Level: Ethernet Segment

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2h8mfz4s04.avif" alt="" />
</center>

- Ethernet segment consists of a collection of _hosts_ connected by wires (twisted pairs) to a _hub_
- Spans room or floor in a building
- Operation
  - Each Ethernet adapter has a unique 48-bit address (MAC address)
    - E.g., `00:16:ea:e3:54:e6`
  - Hosts send bits to any other host in chunks called _frames_
  - Hub slavishly copies each bit from each port to every other port
    - Every host sees every bit
    - Note: Hubs are on their way out. Bridges (switches, routers) became cheap enough to replace them

### Next Level: Bridged Ethernet Segment

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3uv5k0i2h2.avif" alt="" />
</center>

- Spans building or campus
- Bridges cleverly learn which hosts are reachable from which ports and then selectively copy frames from port to port

#### Conceptual View of LANs

- For simplicity, hubs, bridges, and wires are often shown as a collection of hosts attached to a single wire:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6t7fnixz7p.avif" alt="" />
</center>

### Next Level: internets (lower case)

- Multiple incompatible LANs can be physically connected by specialized computers called _routers_
- The connected networks are called an _internet (lower case)_

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6f0zwnrlpo.avif" alt="" />
</center>

#### Logical Structure of an internet

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.102he8lxu9.avif" alt="" />
</center>

- Ad hoc interconnection of networks
  - No particular topology
  - Vastly different router & link capacities
- Send packets from source to destination by hopping through networks
  - Router forms bridge from one network to another
  - Different packets may take different routes

## The Notion of an internet Protocol

- How is it possible to send bits across incompatible LANs and WANs ?
- Solution: _protocol_ software running on each host and router
  - Protocol is a set of rules that governs how hosts and routers should cooperate when they transfer data from network to network
  - Smooths out the differences between the different networks

### What Does an internet Protocol Do ?

- Provides a _naming scheme_
  - An internet protocol defines a uniform format for _host addresses_
  - Each host (and router) is assigned at least one of these internet addresses that uniquely identifies it
- Provides a _delivery mechanism_
  - An internet protocol defines a standard transfer unit (_packet_)
  - Packet consists of _header_ and _payload_
    - Header: contains info such as packet size, source and destination addresses
    - Payload: contains data bits sent from source host

## Transferring internet Data Via Encapsulation

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3nrxombk5z.avif" alt="" />
</center>

## Other Issues

- We are glossing over a number of important questions:
  - What if different networks have different maximum frame sizes ? (segmentation)
  - How do routers know where to forward frames ?
  - How are routers informed when the network topology changes ?
  - What if packets get lost ?
- These (and other) questions are addressed by the area of systems known as _computer networking_

## Global IP Internet (upper case)

- Most famous example of an internet
- Based on the TCP/IP protocol family
  - IP (Internet Protocol):
    - Provides basic naming scheme and unreliable delivery capability of packets (datagrams) from host-to-host
  - UDP (Unreliable Datagram Protocol)
    - Uses IP to provide unreliable datagram delivery from process-to-process
  - TCP (Transmission Control Protocol)
    - Uses IP to provide reliable byte streams from process-to-process over connections
- Accessed via a mix of Unix file I/O and functions from the sockets interface

### Hardware and Software Organization of an Internet Application

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.70anj0giea.avif" alt="" />
</center>

## A Programmer's View of the Internet

1. Hosts are mapped to a set of 32-bit _IP addresses_
2. The set of IP addresses is mapped to a set of identifiers called Internet _domain names_
3. A process on one Internet host can communicate with a process on another Internet host over a _connection_

## Aside: IPv4 and IPv6

- The original Internet Protocol, with its 32-bit addresses, is
  known as _Internet Protocol Version 4 (IPv4)_
- 1996: Internet Engineering Task Force (IETF) introduced _Internet Protocol Version 6 (IPv6)_ with 128-bit addresses
  - Intended as the successor to IPv4

## IP Addresses

- 32-bit IP addresses are stored in an _IP address struct_
  - IP addresses are always stored in memory in _network byte order_ (big-endian byte order)
  - True in general for any integer transferred in a packet header from one machine to another
    - E.g., the port number used to identify an Internet connection

```c
/* Internet address structure */
struct in_addr {
  uint32_t s_addr; /* network byte order (big-endian) */
};
```

### Dotted Decimal Notation

- By convention, each byte in a 32-bit IP address is represented by its decimal value and separated by a period
  - IP address: `0x8002C2F2 = 128.2.194.242`
- Use `getaddrinfo` and `getnameinfo` functions to convert between IP addresses and dotted decimal format

### IP Address Structure

- IP (V4) Address space divided into classes:

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.361w0affk7.avif" alt="" />
</center>

- Network ID Written in form `w.x.y.z/n`
  - n = number of bits in network address (Net ID)
  - E.g., CMU written as 128.2.0.0/16
    - Class B address
- Unrouted (private) IP addresses:
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

## Internet Domain Names

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.54y2qeyeg2.avif" alt="" />
</center>

## Domain Naming System (DNS)

- The Internet maintains a mapping between IP addresses and domain names in a huge worldwide distributed database called _DNS_
- Conceptually, programmers can view the DNS database as a collection of millions of _host entries_
  - Each host entry defines the mapping between a set of domain names and IP addresses
  - In a mathematical sense, a host entry is an equivalence class of domain names and IP addresses

## Basic Internet Components

- Internet backbone
  - Collection of routers (nationwide or worldwide) connected by high-speed point-to-point networks
- Internet Exchange Points (IXP)
  - Router that connects multiple backbones (often referred to as peers)
  - Also called Network Access Points (NAP)
- Regional networks
  - Smaller backbones that cover smaller geographical areas (e.g., cities or states)
- Point of presence (POP)
  - Machine that is connected to the Internet
- Internet Service Providers (ISPs)
  - Provide dial-­‐up or direct access to POPs

### Internet Connection Hierarchy

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7axhcdd0ob.avif" alt="" />
</center>

## Internet Connections

- Clients and servers communicate by sending streams of bytes over _connections_. Each connection is:
  - Point-to-point: connects a pair of processes
  - Full-duplex: data can flow in both directions at the same time
  - Reliable: stream of bytes sent by the source is eventually received by the destination in the same order it was sent
- A _socket_ is an endpoint of a connection
  - Socket address is an **IPaddress\:Port** pair
- A _port_ is a 16-bit integer that identifies a process:
  - Ephemeral port: Assigned automatically by client kernel when client makes a connection request
  - Well‐known port: Associated with some _service_ provided by a server (e.g., port 80 is associated with Web servers)

### Well-known Ports and Service Names

- Popular services have permanently assigned _well-known ports_ and corresponding _well-known service names_:
  - echo server: 7/echo
  - ssh servers: 22/ssh
  - email server: 25/smtp
  - web servers: 80/http
- Mappings between well-known ports and service names is contained in the file `/etc/services` on each Linux machine

### Anatomy of a Connection

- A connection is uniquely identified by the socket addresses of its endpoints (_socket pair_)
  - **(cliaddr\:cliport, servaddr\:servport)**

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4cl78pkn70.avif" alt="" />
</center>

### Using Ports to Identify Services

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8dx6n3pxbi.avif" alt="" />
</center>

## Sockets

- What is a socket ?
  - To the kernel, a socket is an endpoint of communication
  - To an application, a socket is a file descriptor that lets the application read/write from/to the network
    - Remember: All Unix I/O devices, including networks, are modeled as files
- Clients and servers communicate with each other by reading from and writing to socket descriptors

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.lw1nh894p.avif" alt="" />
</center>

- The main distinction between regular file I/O and socket I/O is how the application "opens" the socket descriptors

### Socket Address Structures

- Generic socket address:
  - For address arguments to `connect`, `bind`, and `accept`
  - Necessary only because C did not have generic (**void \***) pointers when the sockets interface was designed
  - For casting convenience, we adopt the Stevens convention: `typedef struct sockaddr SA;`

```c
struct sockaddr {
  uint16_t sa_family; /* Protocol family */
  char sa_data[14];   /* Address data */
};
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.60uk5wqkow.avif" alt="" />
</center>

- Internet-specific socket address:
  - Must cast (`struct sockaddr_in *`) to (`struct sockaddr *`) for functions that take socket address arguments

```c
struct sockaddr_in {
  uint16_t sin_family;       /* Protocol family (always AF_INET) */
  uint16_t sin_port;         /* Port num in network byte order */
  struct in_addr sin_addr;   /* IP addr in network byte order */
  unsigned char sin_zero[8]; /* Pad to sizeof(struct sockaddr) */
};
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175p9siabs.avif" alt="" />
</center>

### Sockets Interface

- Set of system-level functions used in conjunction with Unix I/O to build network applications
- Created in the early 80's as part of the original Berkeley distribution of Unix that contained an early version of the Internet protocols
- Available on all modern systems

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.icfpssdsb.avif" alt="" />
</center>

#### socket

- Clients and servers use the `socket` function to create a _socket descriptor_: `int socket(int domain, int type, int protocol)`
- Example: `int clientfd = socket(AF_INET, SOCK_STREAM, 0);`

:::tip
Protocol specific ! Best practice is to use **getaddrinfo** to generate the parameters automatically, so that code is protocol independent.
:::

#### bind

- A server uses bind to ask the kernel to associate the server's socket address with a socket descriptor: `int bind(int sockfd, SA *addr, socklen_t addrlen);`
- The process can read bytes that arrive on the connection whose endpoint is _addr_ by reading from descriptor _sockfd_
- Similarly, writes to _sockfd_ are transferred along connection whose endpoint is _addr_

:::tip
Best practice is to use **getaddrinfo** to supply the arguments _addr_ and _addrlen_.
:::

#### listen

- By default, kernel assumes that descriptor from socket function is an _active socket_ that will be on the client end of a connection
- A server calls the listen function to tell the kernel that a descriptor will be used by a server rather than a client: `int listen(int sockfd, int backlog);`
- Converts _sockfd_ from an _active socket_ to a _listening (passive) socket_ that can accept connection requests from clients
- _backlog_ is a hint about the number of outstanding connection requests that the kernel should queue up before starting to refuse requests

#### accept

- Servers wait for connection requests from clients by calling `accept`: `int accept(int listenfd, SA *addr, int *addrlen);`
- Waits for connection request to arrive on the connection bound to _listenfd_, then fills in client's socket address in _addr_ and size of the socket address in _addrlen_
- Returns a _connected descriptor_ that can be used to communicate with the client via Unix I/O routines

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9rjps6vs6d.avif" alt="" />
</center>

#### connect

- A client establishes a connection with a server by calling connect: `int connect(int clientfd, SA *addr, socklen_t addrlen);`
- Attempts to establish a connection with server at socket address _addr_
  - If successful, then _clientfd_ is now ready for reading and writing
  - Resulting connection is characterized by socket pair `(x:y, addr.sin_addr:addr.sin_port)`
    - `x` is client address
    - `y` is ephemeral port that uniquely identifies client process on client host

:::tip
Best practice is to use **getaddrinfo** to supply the arguments _addr_ and _addrlen_.
:::

#### Connected vs. Listening Descriptors

- Listening descriptor
  - End point for client connection requests
  - Created once and exists for lifetime of the server
- Connected descriptor
  - End point of the connection between client and server
  - A new descriptor is created each time the server accepts a connection request from a client
  - Exists only as long as it takes to service client
- Why the distinction ?
  - Allows for concurrent servers that can communicate over many client connections simultaneously
    - E.g., Each time we receive a new request, we fork a child to handle the request

### Host and Service Conversion

#### getaddrinfo

- `getaddrinfo` is the modern way to convert string representations of hostnames, host addresses, ports, and service names to socket address structures
  - Replaces obsolete `gethostbyname` and `getservbyname` functions
- Advantages:
  - Reentrant (can be safely used by threaded programs)
  - Allows us to write portable protocol-independent code
    - Works with both IPv4 and IPv6
- Disadvantages:
  - Somewhat complex
  - Fortunately, a small number of usage patterns suffice in most cases

```c
int getaddrinfo(const char *host,             /* Hostname or address */
                const char *service,          /* Port or service name */
                const struct addrinfo *hints, /* Input parameters */
                struct addrinfo **result);    /* Output linked list */

void freeaddrinfo(struct addrinfo *result);   /* Free linked list */

const char *gai_strerror(int errcode);        /* Return error msg. */
```

- Given host and service, `getaddrinfo` returns result that points to a linked list of `addrinfo` structs, each of which points to a corresponding socket address struct, and which contains arguments for the sockets interface functions
- Helper functions:
  - `freeadderinfo` frees the entire linked list
  - `gai_strerror` converts error code to an error message

##### Linked List Returned by getaddrinfo

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9gwvy3bd6e.avif" alt="" />
</center>

- Clients: walk this list, trying each socket address in turn, until the calls to `socket` and `connect` succeed
- Servers: walk the list until calls to `socket` and `bind` succeed

##### addrinfo Struct

```c
struct addrinfo {
  int ai_flags;             /* Hints argument flags */
  int ai_family;            /* First arg to socket function */
  int ai_socktype;          /* Second arg to socket function */
  int ai_protocol;          /* Third arg to socket function */
  char *ai_canonname;       /* Canonical host name */
  size_t ai_addrlen;        /* Size of ai_addr struct */
  struct sockaddr *ai_addr; /* Ptr to socket address structure */
  struct addrinfo *ai_next; /* Ptr to next item in linked list */
};
```

- Each addrinfo struct returned by `getaddrinfo` contains arguments that can be passed directly to socket function
- Also points to a socket address struct that can be passed directly to `connect` and `bind` functions

#### getnameinfo

- `getnameinfo` is the inverse of `getaddrinfo`, converting a socket address to the corresponding host and service
  - Replaces obsolete `gethostbyaddr` and `getservbyport` functions
  - Reentrant and protocol independent

```c
int getnameinfo(const SA *sa, socklen_t salen, /* In: socket addr */
                char *host, size_t hostlen,    /* Out: host */
                char *serv, size_t servlen,    /* Out: service */
                int flags);                    /* optional flags */
```

#### Conversion Example

```c
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE NI_MAXHOST

typedef struct addrinfo SA;

int main(int argc, char **argv) {
  SA *p, *listp, hints;
  char buf[MAXLINE];
  int rc, flags;

  /* Get a list of addrinfo records */
  memset(&hints, 0, sizeof(SA));
  hints.ai_family = AF_INET;       /* IPv4 only */
  hints.ai_socktype = SOCK_STREAM; /* Connections only */

  if ((rc = getaddrinfo(argv[1], NULL, &hints, &listp)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(rc));
    exit(1);
  }

  /* Walk the list and display each IP address */
  flags = NI_NUMERICHOST; /* Display address instead of name */
  for (p = listp; p; p = p->ai_next) {
    getnameinfo(p->ai_addr, p->ai_addrlen, buf, MAXLINE, NULL, 0, flags);
    printf("%s\n", buf);
  }

  /* Clean up */
  freeaddrinfo(listp);
  exit(0);
}
```

#### Echo Client Example

##### open_clientfd

- Establish a connection with a server

```c
int open_clientfd(char *hostname, char *port) {
  int clientfd;
  struct addrinfo hints, *listp, *p;

  /* Get a list of potential server addresses */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM; /* Open a connection */
  hints.ai_flags = AI_NUMERICSERV; /* Using numeric port arg. */
  hints.ai_flags |= AI_ADDRCONFIG; /* Recommended for connections */

  getaddrinfo(hostname, port, &hints, &listp);

  /* Walk the list for one that we can successfully connect to */
  for (p = listp; p; p = p->ai_next) {
    /* Create a socket descriptor */
    if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
      continue; /* Socket failed, try the next */

    /* Connect to the server */
    if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1)
      break; /* Success */
    close(clientfd); /* Connect failed, try another */
  }

  /* Clean up */
  freeaddrinfo(listp);

  if (!p) /* All connects failed */
    return -1;
  else    /* The last connect succeeded */
    return clientfd;
}
```

##### open_listenfd

- Create a listening descriptor that can be used to accept connection requests from clients

```c
int open_listenfd(char *port) {
  struct addrinfo hints, *listp, *p;
  int listenfd, optval = 1;

  /* Get a list of potential server addresses */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;             /* Accept connect. */
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* On any IP addr */
  hints.ai_flags |= AI_NUMERICSERV;            /* Using port no. */

  getaddrinfo(NULL, port, &hints, &listp);

  /* Walk the list for one that we can bind to */
  for (p = listp; p; p = p->ai_next) {
    /* Create a socket descriptor */
    if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
      continue; /* Socket failed, try the next */

    /* Eliminates "Address already in use" error from bind */
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

    /* Bind the descriptor to the address */
    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
      break; /* Success */
    close(listenfd); /* Bind failed, try the next */
  }

  /* Clean up */
  freeaddrinfo(listp);

  if (!p) /* No address worked */
    return -1;

  /* Make it a listening socket ready to accept conn. requests */
  if (listen(listenfd, LISTENQ) < 0) {
    close(listenfd);
    return -1;
  }
  return listenfd;
}
```

:::note
**open_clientfd** and **open_listenfd** are both independent of any particular version of IP.
:::

##### Echo Client

```c title="echoclient.c"
#include <csapp.h>

int main(int argc, char **argv) {
  int clientfd;
  char *host, *port, buf[MAXLINE];
  rio_t rio;

  host = argv[1];
  port = argv[2];

  clientfd = open_clientfd(host, port);
  rio_readinitb(&rio, clientfd);

  while (fgets(buf, MAXLINE, stdin) != NULL) {
    rio_writen(clientfd, buf, strlen(buf));
    rio_readlineb(&rio, buf, MAXLINE);
    fputs(buf, stdout);
  }
  close(clientfd);
  exit(0);
}
```

##### Iterative Echo Server

```c title="echoserver.c"
#include <csapp.h>

void echo(int connfd);

int main(int argc, char **argv) {
  int listenfd, connfd;
  socklen_t clientlen;
  struct sockaddr_storage clientaddr; /* Enough room for any addr */
  char client_hostname[MAXLINE], client_port[MAXLINE];

  listenfd = open_listenfd(argv[1]);
  while (1) {
    clientlen = sizeof(struct sockaddr_storage); /* Important! */
    connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
    getnameinfo((SA *)&clientaddr, clientlen, client_hostname, MAXLINE, client_port, MAXLINE, 0);
    printf("Connected to (%s, %s)\n", client_hostname, client_port);
    echo(connfd);
    close(connfd);
  }
  exit(0);
}
```

##### echo

- The server uses RIO to read and echo text lines until EOF (end-of-file) condition is encountered
  - EOF condition caused by client calling **close(clientfd)**

```c title="echo.c"
void echo(int connfd) {
  size_t n;
  char buf[MAXLINE];
  rio_t rio;

  rio_readinitb(&rio, connfd);
  while((n = rio_readlineb(&rio, buf, MAXLINE)) != 0) {
    printf("server received %d bytes\n", (int)n);
    rio_writen(connfd, buf, n);
  }
}
```

## Web Server Basics

- Clients and servers communicate using the **Hyper Text Transfer Protocol (HTTP)**
  - Client and server establish TCP connection
  - Client requests content
  - Server responds with requested content
  - Client and server close connection (eventually)
- HTTP/1.1 RFC 2616, June, 1999
  - <https://www.w3.org/Protocols/rfc2616/rfc2616.html>

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1apb8pv8vn.avif" alt="" />
</center>

### HTTP Versions

- Major differences between HTTP/1.1 and HTTP/1.0
  - HTTP/1.0 uses a new connection for each transaction
  - HTTP/1.1 also supports _persistent connections_
    - Multiple transactions over the same connection
    - `Connection: Keep-Alive`
  - HTTP/1.1 requires `HOST` header
    - `Host: www.cmu.edu`
    - Makes it possible to host multiple websites at single Internet host
  - HTTP/1.1 supports _chunked encoding_
    - `Transfer-Encoding: chunked`
  - HTTP/1.1 adds additional support for caching

### Web Content

- Web servers return _content_ to clients
  - content: a sequence of bytes with an associated **MIME (Multipurpose
    Internet Mail Extensions)** type
- Example MIME types
  - `text/html` -- HTML document
  - `text/plain` -- Unformatted text
  - `image/gif` -- Binary image encoded in GIF format
  - `image/png` -- Binary image encoded in PNG format
  - `image/jpeg` -- Binary image encoded in JPEG format
- The complete list of MIME types: <https://www.iana.org/assignments/media-types/media-types.xhtml>

### Static and Dynamic Content

- The content returned in HTTP responses can be either _static_ or _dynamic_
  - Static content: content stored in files and retrieved in response to an HTTP request
    - E.g., HTML files, images, audio clips
    - Request identifies which content file
  - Dynamic content: content produced on-the-fly in response to an HTTP request
    - E.g., content produced by a program executed by the server on behalf of the client
    - Request identifies file containing executable code
- Bottom line: Web content is associated with a file that is managed by the server

### URLs

- Unique name for a file: **URL (Universal Resource Locator)**
  - Example URL: `http://www.cmu.edu:80/index.html`
- Clients use prefix (`http://www.cmu.edu:80`) to infer:
  - What kind (protocol) of server to contact (`HTTP`)
  - Where the server is (`www.cmu.edu`)
  - What port it is listening on (`80`)
- Servers use suffix (`/index.html`) to:
  - Determine if request is for static or dynamic content
    - No hard and fast rules for this
    - One convention: executables reside in `cgi-bin` directory
  - Find file on file system
    - Initial `/` in suffix denotes home directory for requested content
    - Minimal suffix is `/`, which server expands to configured default filename (usually, `index.html`)

### HTTP Requests

- HTTP request is a _request line_, followed by zero or more _request headers_
- Request line: `<method> <uri> <version>`
  - `<method>` is one of `GET`, `POST`, `OPTIONS`, `HEAD`, `PUT`, `DELETE`, or `TRACE`
  - `<uri>` is typically URL for proxies, URL suffix for servers
    - A URL is a type of **URI (Uniform Resource Identifier)**
    - <https://www.ietf.org/rfc/rfc2396.txt>
  - `<version>` is HTTP version of request (`HTTP/1.0` or `HTTP/1.1`)
- Request headers: `<header name>: <header data>`
  - Provide additional information to the server

### HTTP Responses

- HTTP response is a _response line_ followed by zero or more _response headers_, possibly followed by _content_, with blank line (`\r\n`) separating headers from content
- Response line: `<version> <status code> <status msg>`
  - `<version>` is HTTP version of the response
  - `<status code>` is numeric status
  - `<status msg>` is corresponding English text
    - `200 OK` -- Request was handled without error
    - `301 Moved` -- Provide alternate URL
    - `404 Not found` -- Server couldn't find the file
  - Response headers: `<header name>: <header data>`
    - Provide additional information about response
    - `Content-Type`: MIME type of content in response body
    - `Content-Length`: Length of content in response body

### Data Transfer Mechanisms

- Standard
  - Specify total length with content-length
  - Requires that program buffer entire message
- Chunked
  - Break into blocks
  - Prefix each block with number of bytes (Hex coded)

#### Chunked Encoding Example

```plaintext showLineNumbers=false
HTTP/1.1 200 OK\n
Date: Sun, 31 Oct 2010 20:47:48 GMT\n
Server: Apache/1.3.41 (Unix)\n
Keep-Alive: timeout=15, max=100\n
Connection: Keep-Alive\n
Transfer-Encoding: chunked\n
Content-Type: text/html\n
\r\n
d75\r\n
<html>
<head>
.<link href="http://www.cs.cmu.edu/style/calendar.css" rel="stylesheet" type="text/css">
</head>
<body id="calendar_body">
<div id='calendar'><table width='100%' border='0' cellpadding='0' cellspacing='1' id='cal'>
...
</body>
</html>
\r\n
0\r\n
\r\n
```

- `d75\r\n` -- First Chunk: 0xd75 = 3445 bytes
- `0\r\n` -- Second Chunk: 0 bytes (indicates last chunk)

#### Example HTTP Transaction

```plaintext showLineNumbers=false
whaleshark> telnet www.cmu.edu 80             Client: open connection to server
Trying 128.2.42.52...                         Telnet prints 3 lines to terminal
Connected to WWW-CMU-PROD-VIP.ANDREW.cmu.edu.
Escape character is '^]'.
GET / HTTP/1.1                                Client: request line
Host: www.cmu.edu                             Client: required HTTP/1.1 header
                                              Client: empty line terminates headers
HTTP/1.1 301 Moved Permanently                Server: response line
Date: Wed, 05 Nov 2014 17:05:11 GMT           Server: followed by 5 response headers
Server: Apache/1.3.42 (Unix)                  Server: this is an Apache server
Location: http://www.cmu.edu/index.shtml      Server: page has moved here
Transfer-Encoding: chunked                    Server: response body will be chunked
Content-Type: text/html; charset=...          Server: expect HTML in response body
                                              Server: empty line terminates headers
15c                                           Server: first line in response body
<HTML><HEAD>                                  Server: start of HTML content
...
</BODY></HTML>                                Server: end of HTML content
0                                             Server: last line in response body
Connection closed by foreign host.            Server: closes connection
```

- HTTP standard requires that each text line end with `\r\n`
- Blank line (`\r\n`) terminates request and response headers

### Tiny Web Server

- Tiny Web server described in text
  - Tiny is a sequential Web server
  - Serves static and dynamic content to real browsers
  - 239 lines of commented C code
  - Not as complete or robust as a real Web server
    - You can break it with poorly-formed HTTP requests (e.g., terminate lines with `\n` instead of `\r\n`)

#### Operation

- Accept connection from client
- Read request from client (via connected socket)
- Split into `<method> <uri> <version>`
  - If method not GET, then return error
- If URI contains `cgi-bin` then serve dynamic content
  - Would do wrong thing if had file `abcgi-bingo.html`
  - Fork process to execute program
- Otherwise serve static content
  - Copy file to output

#### Serving Static Content

```c
void serve_static(int fd, char *filename, int filesize) {
  int srcfd;
  char *srcp, filetype[MAXLINE], buf[MAXBUF];

  /* Send response headers to client */
  get_filetype(filename, filetype);
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
  sprintf(buf, "%sConnection: close\r\n", buf);
  sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
  sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);
  rio_writen(fd, buf, strlen(buf));

  /* Send response body to client */
  srcfd = open(filename, O_RDONLY, 0);
  srcp = mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
  close(srcfd);
  rio_writen(fd, srcp, filesize);
  munmap(srcp, filesize);
}
```

#### Serving Dynamic Content

- Client sends request to server
- If request URI contains the string `/cgi-bin`, the Tiny server assumes that the request is for dynamic content

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.73u9i3gtdb.avif" alt="" />
</center>

- The server creates a child process and runs the program identified by the URI in that process

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1hsj48hkw0.avif" alt="" />
</center>

- The child runs and generates the dynamic content
- The server captures the content of the child and forwards it without modification to the client

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7snj247ym0.avif" alt="" />
</center>

##### Issues in Serving Dynamic Content

- How does the client pass program arguments to the server ?
- How does the server pass these arguments to the child ?
- How does the server pass other info relevant to the request to the child ?
- How does the server capture the content produced by the child ?
- These issues are addressed by the **Common Gateway Interface (CGI)** specification

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6pntr8h24a.avif" alt="" />
</center>

#### CGI

- Because the children are written according to the CGI spec, they are often called _CGI programs_
- However, CGI really defines a simple standard for transferring information between the client (browser), the server, and the child process
- CGI is the original standard for generating dynamic content. Has been largely replaced by other, faster techniques:
  - E.g., fastCGI, Apache modules, Java servlets, Rails controllers
  - Avoid having to create process on the fly (expensive and slow)

#### Serving Dynamic Content With GET

- Client pass arguments to the server by appended the arguments to the URI
- Can be encoded directly in a URL typed to a browser or a URL in an HTML link
  - `http://add.com/cgi-bin/adder?15213&18213`
  - `adder` is the CGI program on the server that will do the addition
  - Argument list starts with `?`
  - Arguments separated by `&`
  - Spaces represented by `+` or `%20`
- URL suffix: `cgi-bin/adder?15213&18213`
- Result displayed on browser:

```plaintext showLineNumbers=false
Welcome to add.com: THE Internet addition portal.

The answer is: 15213 + 18213 = 33426

Thanks for visiting!
```

- The server pass these arguments to the child by environment variable in `QUERY_STRING`
  - A single string containing everything after the `?`
  - For add: `QUERY_STRING = 15213&18213`

```c
/* Extract the two arguments */
if ((buf = getenv("QUERY_STRING")) != NULL) {
  p = strchr(buf, '&');
  *p = '\0';
  strcpy(arg1, buf);
  strcpy(arg2, p+1);
  n1 = atoi(arg1);
  n2 = atoi(arg2);
}
```

- The child generates its output on **stdout**. Server uses **dup2** to redirect **stdout** to its connected socket. So the server capture the content produced by the child

```c
void serve_dynamic(int fd, char *filename, char *cgiargs) {
  char buf[MAXLINE], *emptylist[] = { NULL };

  /* Return first part of HTTP response */
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  rio_writen(fd, buf, strlen(buf));
  sprintf(buf, "Server: Tiny Web Server\r\n");
  rio_writen(fd, buf, strlen(buf));

  if (fork() == 0) { /* Child */
    /* Real server would set all CGI vars here */
    setenv("QUERY_STRING", cgiargs, 1);
    dup2(fd, STDOUT_FILENO);              /* Redirect stdout to client */
    execve(filename, emptylist, environ); /* Run CGI program */
  }
  wait(NULL); /* Parent waits for and reaps child */
}
```

- Notice that only the CGI child process knows the content type and length, so it must generate those headers

```c
/* Make the response body */
sprintf(content, "Welcome to add.com: ");
sprintf(content, "%sTHE Internet addition portal.\r\n<p>", content);
sprintf(content, "%sThe answer is: %d + %d = %d\r\n<p>", content, n1, n2, n1 + n2);
sprintf(content, "%sThanks for visiting!\r\n", content);

/* Generate the HTTP response */
printf("Content-length: %d\r\n", (int)strlen(content));
printf("Content-type: text/html\r\n\r\n");
printf("%s", content);
fflush(stdout);
exit(0);
```

## Proxies

- A _proxy_ is an intermediary between a client and an origin server
  - To the client, the proxy acts like a server
  - To the server, the proxy acts like a client

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.73u9i5t2mo.avif" alt="" />
</center>

#### Why Proxies ?

- Can perform useful functions as requests and responses pass by
  - Examples: Caching, logging, anonymization, filtering, transcoding

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3k8bscs4il.avif" alt="" />
</center>

# Concurrent Programming

## Concurrent Programming is Hard

- The human mind tends to be sequential
- The notion of time is often misleading
- Thinking about all possible sequences of events in a computer system is at least error prone and frequently impossible

- Classical problem classes of concurrent programs:
  - Races: outcome depends on arbitrary scheduling decisions elsewhere in the system
    - Example: who gets the last seat on the airplane ?
  - Deadlock: improper resource allocation prevents forward progress
    - Example: traffic gridlock
  - Livelock / Starvation / Fairness: external events and/or system scheduling decisions can prevent sub-task progress
    - Example: people always jump in front of you in line

## Iterative Servers

- Iterative servers process one request at a time

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1e8x710wyz.avif" alt="" />
</center>

- Second client attempts to connect to iterative server
- Call to **connect** returns
  - Even though connection not yet accepted
  - Server side TCP manager queues request
  - Feature known as "TCP listen backlog"
- Call to **rio_writen** returns
  - Server side TCP manager buffers input data
- Call to **rio_readlineb** blocks
  - Server hasn't written anything for it to read yet

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3rbjo7ya1q.avif" alt="" />
</center>

- Solution: use _concurrent servers_ instead
  - Concurrent servers use multiple concurrent flows to serve multiple clients at the same time

## Approaches for Writing Concurrent Servers

- Process-based
  - Kernel automatically interleaves multiple logical flows
  - Each flow has its own private address space
- Event-based
  - Programmer manually interleaves multiple logical flows
  - All flows share the same address space
  - Uses technique called I/O multiplexing
- Thread-based
  - Kernel automatically interleaves multiple logical flows
  - Each flow shares the same address space
  - Hybrid of of process-based and event-based

### Process-based Servers

- Spawn separate process for each client

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3gopv35xfr.avif" alt="" />
</center>

#### Process-Based Concurrent Echo Server

```c
void sigchld_handler(int sig) {
  /* Reap all zombie children */
  while (waitpid(-1, 0, WNOHANG) > 0)
    ;
  return;
}

int main(int argc, char **argv) {
  int listenfd, connfd;
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;

  signal(SIGCHLD, sigchld_handler);
  listenfd = open_listenfd(argv[1]);
  while (1) {
    clientlen = sizeof(struct sockaddr_storage);
    connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);

    if (fork() == 0) {
      close(listenfd); /* Child closes its listening socket */
      echo(connfd);    /* Child services client */
      close(connfd);   /* Child closes connection with client */
      exit(0);         /* Child exits */
    }
    close(connfd); /* Parent closes connected socket (important!) */
  }
}
```

#### Process-based Server Execution Model

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1e8x71ngul.avif" alt="" />
</center>

- Each client handled by independent child process
- No shared state between them
- Both parent & child have copies of _listenfd_ and _connfd_
  - Parent must close _connfd_
  - Child should close _listenfd_

#### Issues with Process-based Servers

- Listening server process must reap zombie children to avoid fatal memory leak
- Parent process must **close** its copy of _connfd_
  - Kernel keeps reference count for each socket/open file
  - After fork, `refcnt(connfd) = 2`
  - Connection will not be closed until `refcnt(connfd) = 0`

#### Pros and Cons of Process-based Servers

- Handle multiple connections concurrently
- Clean sharing model
  - descriptors (no)
  - file tables (yes)
  - global variables (no)
- Simple and straightforward
- Additional overhead for process control
- Nontrivial to share data between processes
  - Requires **IPC (interprocess communication)** mechanisms
    - FIFO's (named pipes), System V shared memory and semaphores

### Event-based Servers

- Server maintains set of active connections
  - Array of _connfd_'s
- Repeat:
  - Determine which descriptors (_connfd_'s or _listenfd_) have pending inputs
    - e.g., using `select` or `epoll` functions
    - arrival of pending input is an _event_
  - If _listenfd_ has input, then **accept** connection and add new _connfd_ to array
  - Service all _connfd_'s with pending inputs

#### I/O Multiplexed Event Processing

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.39lhzoqkql.avif" alt="" />
</center>

#### Pros and Cons of Event-based Servers

- One logical control flow and address space
- Can single-step with a debugger
- No process or thread control overhead
  - Design of choice for high-performance Web servers and search engines
    - E.g., Node.js, Nginx, Tornado
- Significantly more complex to code than process-based or thread-based designs
- Hard to provide fine-grained concurrency
  - E.g., How to deal with partial HTTP request headers
- Cannot take advantage of multi-core
  - Single thread of control

### Thread-based Servers

- Very similar to process-based approach
  - ...but using threads instead of processes

#### Traditional View of a Process

- Process = Process Context + Code, Data, and Stack

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.99to4u73a0.avif" alt="" />
</center>

#### Alternate View of a Process

Process = Thread + Code, Data, and Kernel Context

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2326ria3fm.avif" alt="" />
</center>

#### A Process With Multiple Threads

- Multiple threads can be associated with a process
  - Each thread has its own logical control flow
  - Each thread shares the same code, data, and kernel context
  - Each thread has its own stack for local variables
    - but not protected from other threads
  - Each thread has its own **Thread ID (TID)**

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8adkroasgr.avif" alt="" />
</center>

#### Logical View of Threads

- Threads associated with process form a pool of peers
  - Unlike processes which form a tree hierarchy

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8ok0ijlb4s.avif" alt="" />
</center>

#### Concurrent Threads

- Two threads are concurrent if their flows overlap in time
- Otherwise, they are sequential
- Examples:
  - Concurrent: A & B, A & C
  - Sequential: B & C

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8vn8dza7zb.avif" alt="" />
</center>

#### Concurrent Thread Execution

- Single Core Processor
  - Simulate parallelism by time slicing
- Multi Core Processor
  - Can have true parallelism

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175pc2d71f.avif" alt="" />
</center>

#### Threads vs. Processes

- How threads and processes are similar ?
  - Each has its own logical control flow
  - Each can run concurrently with others (possibly on different cores)
  - Each is context switched
- How threads and processes are different ?
  - Threads share all code and data (except local stacks)
    - Processes (typically) do not
  - Threads are somewhat less expensive than processes
    - Process control (creating and reaping) twice as expensive as thread control
    - Linux numbers:
      - ~20K cycles to create and reap a process
      - ~10K cycles (or less) to create and reap a thread

## Posix Threads (Pthreads) Interface

- Pthreads: Standard interface for ~60 functions that manipulate threads from C programs
  - Creating and reaping threads
    - `pthread_create()`
    - `pthread_join()`
  - Determining your thread ID
    - `pthread_self()`
  - Terminating threads
    - `pthread_cancel()`
    - `pthread_exit()`
    - `exit()` terminates all threads , `ret` terminates current thread
  - Synchronizing access to shared variables
    - `pthread_mutex_init`
    - `pthread_mutex_[un]lock`

### The Pthreads "hello, world" Program

```c
void *thread(void *vargp);

int main() {
  pthread_t tid;

  pthread_create(&tid, NULL, thread, NULL);
  pthread_join(tid, NULL);
  exit(0);
}

void *thread(void *vargp) {
  printf("Hello, world!\n");
  return NULL;
}
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwlxka11.avif" alt="" />
</center>

### Thread-Based Concurrent Echo Server

```c
void *thread(void *vargp);

int main(int argc, char **argv) {
  int listenfd, *connfdp;
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
  pthread_t tid;

  listenfd = open_listenfd(argv[1]);
  while (1) {
    clientlen = sizeof(struct sockaddr_storage);
    connfdp = malloc(sizeof(int));
    *connfdp = accept(listenfd, (SA *)&clientaddr, &clientlen);
    pthread_create(&tid, NULL, thread, connfdp);
  }
}

void *thread(void *vargp) {
  int connfd = *((int *)vargp);

  pthread_detach(pthread_self());
  free(vargp);
  echo(connfd);
  close(connfd);
  return NULL;
}
```

- `malloc` of connected descriptor necessary to avoid deadly race (but still have subtle problem)
- Run thread in `detached` mode
  - Runs independently of other threads
  - Reaped automatically (by kernel) when it terminates
- Free storage allocated to hold _connfd_
- Close _connfd_ (important!)

### Thread-based Server Execution Model

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1apb9tsbn9.avif" alt="" />
</center>

- Each client handled by individual peer thread
- Threads share all process state except TID
- Each thread has a separate stack for local variables

### Issues With Thread-Based Servers

- Must run "detached" to avoid memory leak
  - At any point in time, a thread is either _joinable_ or _detached_
  - Joinable thread can be reaped and killed by other threads
    - must be reaped (with **pthread_join**) to free memory resources
  - Detached thread cannot be reaped or killed by other threads
    - resources are automatically reaped on termination
  - Default state is joinable
    - use `pthread_detach(pthread_self())` to make detached
- Must be careful to avoid unintended sharing
  - For example, passing pointer to main thread's stack
    - `pthread_create(&tid, NULL, thread, (void *)&connfd);`
  - All functions called by a thread must be _thread-safe_

### Pros and Cons of Thread-Based Designs

- Easy to share data structures between threads
  - e.g., logging information, file cache
- Threads are more efficient than processes
- Unintentional sharing can introduce subtle and hard-to-reproduce errors !
  - The ease with which data can be shared is both the greatest strength and the greatest weakness of threads
  - Hard to know which data shared & which private
  - Hard to detect by testing
    - Probability of bad race outcome very low
    - But nonzero !

# Synchronization

## Shared Variables in Threaded C Programs

- Question: Which variables in a threaded C program are shared ?
  - The answer is not as simple as "global variables are shared" and "stack variables are private"
- Def: A variable **x** is shared if and only if multiple threads reference some instance of **x**
- Requires answers to the following questions:
  - What is the memory model for threads ?
  - How are instances of variables mapped to memory ?
  - How many threads might reference each of these instances ?

## Threads Memory Model

- Conceptual model:
  - Multiple threads run within the context of a single process
  - Each thread has its own separate thread context
    - Thread ID, stack, stack pointer, PC, condition codes, and GP registers
  - All threads share the remaining process context
    - Code, data, heap, and shared library segments of the process virtual address space
    - Open files and installed handlers
- Operationally, this model is not strictly enforced:
  - Register values are truly separate and protected, but...
  - Any thread can read and write the stack of any other thread

:::caution
The mismatch between the conceptual and operation model is a source of confusion and errors.
:::

## Example Program to Illustrate Sharing

```c
void *thread(void *vargp);

char **ptr; /* global var */

int main() {
  long i;
  pthread_t tid;
  char *msgs[2] = {
    "Hello from foo",
    "Hello from bar"
  };

  ptr = msgs;
  for (i = 0; i < 2; i++)
    pthread_create(&tid, NULL, thread, (void *)i);
  pthread_exit(NULL);
}

void *thread(void *vargp) {
  long myid = (long)vargp;
  static int cnt = 0;

  printf("[%ld]: %s (cnt=%d)\n", myid, ptr[myid], ++cnt);
  return NULL;
}
```

- Peer threads reference main thread's stack indirectly through global **ptr** variable
- `ptr`, `cnt`, and `msgs` are shared, `i` and `myid` are not shared

## Example for Improper Synchronizing Threads

```c
void *thread(void *vargp);

/* Global shared variable */
volatile long cnt = 0;

int main(int argc, char **argv) {
  long niters;
  pthread_t tid1, tid2;

  niters = atoi(argv[1]);
  pthread_create(&tid1, NULL, thread, &niters);
  pthread_create(&tid2, NULL, thread, &niters);
  pthread_join(tid1, NULL);
  pthread_join(tid2, NULL);

  /* Check result */
  if (cnt != (2 * niters))
    printf("BOOM! cnt=%ld\n", cnt);
  else
    printf("OK cnt=%ld\n", cnt);
  exit(0);
}

void *thread(void *vargp) {
  long i, niters = *((long *)vargp);
  for (i = 0; i < niters; i++)
    cnt++;
  return NULL;
}
```

```bash
linux> ./badcnt 10000
OK cnt=20000
linux> ./badcnt 10000
BOOM! cnt=13051
linux>
```

`cnt` should equal 20,000. What went wrong ?

### Assembly Code for Counter Loop

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4xuuy2hxud.avif" alt="" />
</center>

### Concurrent Execution

- Key idea: In general, any sequentially consistent interleaving is possible, but some give an unexpected result !
  - $I_{i}$ denotes that thread $i$ executes instruction $I$
  - $\%rdx_{i}$ is the content of $\%rdx$ in thread $i$'s context

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7eh3czreim.avif" alt="" />
</center>

- Incorrect ordering: two threads increment the counter, but the result is 1 instead of 2

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4n814xg1sw.avif" alt="" />
</center>

- And the following ordering is still wrong

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175pcu751p.avif" alt="" />
</center>

- We can analyze the behavior using a _progress graph_

## Progress Graphs

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4cl7bsa74r.avif" alt="" />
</center>

- A _progress graph_ depicts the discrete _execution state space_ of concurrent threads
- Each axis corresponds to the sequential order of instructions in a thread
- Each point corresponds to a possible _execution state_ $( I_{1} ,I_{2})$
  - E.g., $( L_{1} ,S_{2})$ denotes state where thread 1 has completed $L_{1}$ and thread 2 has completed $S_{2}$

### Trajectories in Progress Graphs

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.54y2tjvj2j.avif" alt="" />
</center>

- A _trajectory_ is a sequence of legal state transitions that describes one possible concurrent execution of the threads

### Critical Sections and Unsafe Regions

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1sfcz6wzxo.avif" alt="" />
</center>

- $L$, $U$, and $S$ form a _critical section_ with respect to the shared variable **cnt**
- Instructions in critical sections (write some shared variable) should not be interleaved
- Sets of states where such interleaving occurs form _unsafe regions_
- Def: A trajectory is _safe_ iff it does not enter any unsafe region
- Claim: A trajectory is correct (write **cnt**) iff it is safe

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3yerkyvgg9.avif" alt="" />
</center>

## Enforcing Mutual Exclusion

- Question: How can we guarantee a safe trajectory ?
- Answer: We must _synchronize_ the execution of the threads so that they can never have an unsafe trajectory
  - i.e., need to guarantee _mutually exclusive access_ for each critical section
- Classic solution:
  - Semaphores (Edsger Dijkstra)
- Other approaches:
  - Mutex and condition variables (Pthreads)
  - Monitors (Java)

### Semaphores

- Semaphore: non-negative global integer synchronization variable. Manipulated by `P` and `V` operations (**P** and **V** correspond to the dutch words _Proberen_ and _Verhogen_ respectively)
- `P(s)`
  - If _s_ is nonzero, then decrement _s_ by 1 and return immediately
    - Test and decrement operations occur atomically (indivisibly)
  - If _s_ is zero, then suspend thread until _s_ becomes nonzero and the thread is restarted by a _V_ operation
  - After restarting, the _P_ operation decrements _s_ and returns control to the caller
- `V(s)`
  - Increment _s_ by 1
    - Increment operation occurs atomically
  - If there are any threads blocked in a _P_ operation waiting for _s_ to become non-zero, then restart exactly one of those threads, which then completes its _P_ operation by decrementing _s_
- Semaphore invariant: $s\geqslant 0$

#### Using Semaphores for Mutual Exclusion

```c
#include <semaphore.h>

int sem_init(sem_t *s, 0, unsigned int val); /* s = val */
int sem_wait(sem_t *s); /* P(s) */
int sem_post(sem_t *s); /* V(s) */
```

- Basic idea:
  - Associate a unique semaphore _mutex_, initially 1, with each shared variable (or related set of shared variables)
  - Surround corresponding critical sections with `P(mutex)` and `V(mutex)` operations
- Terminology:
  - Binary semaphore: semaphore whose value is always 0 or 1
  - Mutex: binary semaphore used for mutual exclusion
    - P operation: "locking" the mutex
    - V operation: "unlocking" or "releasing" the mutex
    - "Holding" a mutex: locked and not yet unlocked
  - Counting semaphore: used as a counter for set of available resources

## Fix for Improper Synchronizing Threads

- Define and initialize a mutex for the shared variable _cnt_:

```c
volatile long cnt = 0;  /* Counter */
sem_t mutex;            /* Semaphore that protects cnt */
sem_init(&mutex, 0, 1); /* mutex = 1 */
```

- Surround critical section with _P_ and _V_:

```c
for (i = 0; i < niters; i++) {
  sem_wait(&mutex);
  cnt++;
  sem_post(&mutex);
}
```

:::warning
Its orders of magnitude slower than improper one.
:::

## Why Mutexes Work

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7lkb8jafx7.avif" alt="" />
</center>

- Provide mutually exclusive access to shared variable by surrounding critical section with _P_ and _V_ operations on semaphore _s_ (initially set to 1)
- Semaphore invariant creates a _forbidden region_ that encloses unsafe region and that cannot be entered by any trajectory

## Using Semaphores to Coordinate Access to Shared Resources

- Basic idea: Thread uses a semaphore operation to notify another thread that some condition has become true
  - Use counting semaphores to keep track of resource state and to notify other threads
  - Use mutex to protect access to resource
- Two classic examples:
  - The Producer-Consumer Problem
  - The Readers-Writers Problem

### Producer-Consumer Problem

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.4jof8anjlq.avif" alt="" />
</center>

- Common synchronization pattern:
  - Producer waits for empty _slot_, inserts item in buffer, and notifies consumer
  - Consumer waits for _item_, removes it from buffer, and notifies producer
- Examples:
  - Multimedia processing:
    - Producer creates MPEG video frames, consumer renders them
  - Event-driven graphical user interfaces
    - Producer detects mouse clicks, mouse movements, and keyboard hits and inserts corresponding events in buffer
    - Consumer retrieves events from buffer and paints the display

#### Producer-Consumer on an n-element Buffer

- Requires a mutex and two counting semaphores:
  - `mutex`: enforces mutually exclusive access to the buffer
  - `slots`: counts the available slots in the buffer
  - `items`: counts the available items in the buffer
- Implemented using a shared circular (ring) buffer package called _sbuf_

##### sbuf Package

```c title="sbuf.h"
typedef struct {
  int *buf;    /* Buffer array */
  int n;       /* Maximum number of slots */
  int front;   /* buf[(front+1)%n] is first item */
  int rear;    /* buf[rear%n] is last item */
  sem_t mutex; /* Protects accesses to buf */
  sem_t slots; /* Counts available slots */
  sem_t items; /* Counts available items */
} sbuf_t;

void sbuf_init(sbuf_t *sp, int n);
void sbuf_deinit(sbuf_t *sp);
void sbuf_insert(sbuf_t *sp, int item);
int sbuf_remove(sbuf_t *sp);
```

```c title="sbuf.c"
/* Create an empty, bounded, shared FIFO buffer with n slots */
void sbuf_init(sbuf_t *sp, int n) {
  sp->buf = calloc(n, sizeof(int));
  sp->n = n;                  /* Buffer holds max of n items */
  sp->front = sp->rear = 0;   /* Empty buffer iff front == rear */
  sem_init(&sp->mutex, 0, 1); /* Binary semaphore for locking */
  sem_init(&sp->slots, 0, n); /* Initially, buf has n empty slots */
  sem_init(&sp->items, 0, 0); /* Initially, buf has 0 items */
}

/* Clean up buffer sp */
void sbuf_deinit(sbuf_t *sp) {
  free(sp->buf);
}

/* Insert item onto the rear of shared buffer sp */
void sbuf_insert(sbuf_t *sp, int item) {
  P(&sp->slots);                        /* Wait for available slot */
  P(&sp->mutex);                        /* Lock the buffer */
  sp->buf[(++sp->rear)%(sp->n)] = item; /* Insert the item */
  V(&sp->mutex);                        /* Unlock the buffer */
  V(&sp->items);                        /* Announce available item */
}

/* Remove and return the first item from buffer sp */
int sbuf_remove(sbuf_t *sp) {
  int item;
  P(&sp->items);                         /* Wait for available item */
  P(&sp->mutex);                         /* Lock the buffer */
  item = sp->buf[(++sp->front)%(sp->n)]; /* Remove the item */
  V(&sp->mutex);                         /* Unlock the buffer */
  V(&sp->slots);                         /* Announce available slot */
  return item;
}
```

### Readers-Writers Problem

- Generalization of the mutual exclusion problem
- Problem statement:
  - Reader threads only read the object
  - Writer threads modify the object
  - Writers must have exclusive access to the object
  - Unlimited number of readers can access the object
- Occurs frequently in real systems:
  - Online airline reservation system
  - Multithreaded caching Web proxy

#### Variants of Readers-Writers

- First readers-writers problem (favors readers)
  - No reader should be kept waiting unless a writer has already been granted permission to use the object
  - A reader that arrives after a waiting writer gets priority over the writer
- Second readers-writers problem (favors writers)
  - Once a writer is ready to write, it performs its write as soon as possible
  - A reader that arrives after a writer must wait, even if the writer is also waiting
- Starvation (where a thread waits indefinitely) is possible in both cases

#### Solution to First Readers-Writers Problem

```c
int readcnt; /* Initially = 0 */
sem_t mutex, w; /* Initially = 1 */

void reader(void) {
  while (1) {
    P(&mutex);
    readcnt++;
    if (readcnt == 1) /* First in */
      P(&w);
    V(&mutex);

    /* Critical section */
    /* Reading happens */

    P(&mutex);
    readcnt--;
    if (readcnt == 0) /* Last out */
      V(&w);
    V(&mutex);
  }
}

void writer(void) {
  while (1) {
    P(&w);

    /* Critical section */
    /* Writing happens */

    V(&w);
  }
}
```

## Putting It All Together: Prethreaded Concurrent Server

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.51egwy30p4.avif" alt="" />
</center>

### Prethreaded Concurrent Server

```c title="echoservert_pre.c"
void *thread(void *vargp);

sbuf_t sbuf; /* Shared buffer of connected descriptors */

int main(int argc, char **argv) {
  int i, listenfd, connfd;
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
  pthread_t tid;

  listenfd = open_listenfd(argv[1]);
  sbuf_init(&sbuf, SBUFSIZE);
  for (i = 0; i < NTHREADS; i++) /* Create worker threads */
    pthread_create(&tid, NULL, thread, NULL);
  while (1) {
    clientlen = sizeof(struct sockaddr_storage);
    connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
    sbuf_insert(&sbuf, connfd); /* Insert connfd in buffer */
  }
}

void *thread(void *vargp) {
  pthread_detach(pthread_self());
  while (1) {
    int connfd = sbuf_remove(&sbuf); /* Remove connfd from buf */
    echo_cnt(connfd);                /* Service client */
    close(connfd);
  }
}
```

```c title="echo_cnt.c"
/* echo_cnt initialization routine */
static int byte_cnt; /* Byte counter */
static sem_t mutex;  /* and the mutex that protects it */

static void init_echo_cnt(void) {
  sem_init(&mutex, 0, 1);
  byte_cnt = 0;
}

/* Worker thread service routine */
void echo_cnt(int connfd) {
  int n;
  char buf[MAXLINE];
  rio_t rio;
  static pthread_once_t once = PTHREAD_ONCE_INIT;

  pthread_once(&once, init_echo_cnt);
  rio_readinitb(&rio, connfd);
  while((n = rio_readlineb(&rio, buf, MAXLINE)) != 0) {
    P(&mutex);
    byte_cnt += n;
    printf("thread %d received %d (%d total) bytes on fd %d\n", (int)pthread_self(), n, byte_cnt, connfd);
    V(&mutex);
    rio_writen(connfd, buf, n);
  }
}
```

## Crucial concept: Thread Safety

- Functions called from a thread must be _thread‐safe_
- Def: A function is thread-safe iff it will always produce correct results when called repeatedly from multiple concurrent threads
- Classes of thread-unsafe functions:
  - Class 1: Functions that do not protect shared variables
  - Class 2: Functions that keep state across multiple invocations
  - Class 3: Functions that return a pointer to a static variable
  - Class 4: Functions that call thread-unsafe functions

### Thread-Unsafe Functions (Class 1)

- Failing to protect shared variables
  - Fix: Use **P** and **V** semaphore operations
  - Issue: Synchronization operations will slow down code

### Thread-Unsafe Functions (Class 2)

- Relying on persistent state across multiple function invocations
  - Example: Random number generator that relies on static state

```c
static unsigned int next = 1;

/* rand: return pseudo-random integer on 0..32767 */
int rand(void) {
  next = next*1103515245 + 12345;
  return (unsigned int)(next/65536) % 32768;
}

/* srand: set seed for rand() */
void srand(unsigned int seed) {
  next = seed;
}
```

#### Thread-Safe Random Number Generator

- Pass state as part of argument
  - and, thereby, eliminate global state

```c
/* rand_r - return pseudo-random integer on 0..32767 */

int rand_r(int *nextp) {
  *nextp = *nextp * 1103515245 + 12345;
  return (unsigned int)(*nextp/65536) % 32768;
}
```

- Consequence: programmer using **rand_r** must maintain seed

### Thread-Unsafe Functions (Class 3)

- Returning a pointer to a static variable
- Fix 1. Rewrite function so caller passes address of variable to store result
  - Requires changes in caller and callee
- Fix 2. Lock-and‐copy
  - Requires simple changes in caller (and none in callee)
  - However, caller must free memory

```c
/* lock-and-copy version */
char *ctime_ts(const time_t *timep, char *privatep) {
  char *sharedp;

  P(&mutex);
  sharedp = ctime(timep);
  strcpy(privatep, sharedp);
  V(&mutex);
  return privatep;
}
```

### Thread-Unsafe Functions (Class 4)

- Calling thread-unsafe functions
  - Calling one thread-unsafe function makes the entire function that calls it thread-unsafe
  - Fix: Modify the function so it calls only thread-safe functions

## Reentrant Functions

- Def: A function is _reentrant_ iff it accesses no shared variables when called by multiple threads
  - Important subset of thread-safe functions
    - Require no synchronization operations
    - Only way to make a Class 2 function thread-safe is to make it reetnrant (e.g., **rand_r**)

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3gopxkdcbi.avif" alt="" />
</center>

## Thread-Safe Library Functions

- All functions in the Standard C Library (at the back of your K&R text) are thread-safe
  - Examples: **malloc**, **free**, **printf**, **scanf**
- Most Unix system calls are thread-safe, with a few exceptions:

| Thread-unsafe function | Class | Reentrant version |
| ---------------------- | ----- | ----------------- |
| `asctime`              | 3     | `asctime_r`       |
| `ctime`                | 3     | `ctime_r`         |
| `gethostbyaddr`        | 3     | `gethostbyaddr_r` |
| `gethostbyname`        | 3     | `gethostbyname_r` |
| `inet_ntoa`            | 3     | (none)            |
| `localtime`            | 3     | `localtime_r`     |
| `rand`                 | 2     | `rand_r`          |

## Races

- A _race_ occurs when correctness of the program depends on one thread reaching point _x_ before another thread reaches point _y_

```c
void *thread(void *vargp);

/* A threaded program with a race */
int main() {
  pthread_t tid[N];
  int i;

  for (i = 0; i < N; i++)
    pthread_create(&tid[i], NULL, thread, &i);
  for (i = 0; i < N; i++)
    pthread_join(tid[i], NULL);
  exit(0);
}

/* Thread routine */
void *thread(void *vargp) {
  int myid = *((int *)vargp);
  printf("Hello from thread %d\n", myid);
  return NULL;
}
```

### Race Illustration

```c
for (i = 0; i < N; i++)
  pthread_create(&tid[i], NULL, thread, &i);
```

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.96a295pdt6.avif" alt="" />
</center>

- Race between increment of _i_ in main thread and deref of _vargp_ in peer thread:
  - If deref happens while `i = 0`, then OK
  - Otherwise, peer thread gets wrong id value

### Could this race really occur ?

Main thread:

```c
int i;
for (i = 0; i < 100; i++) {
  pthread_create(&tid, NULL, thread, &i);
}
```

Peer thread:

```c
void *thread(void *vargp) {
  pthread_detach(pthread_self());
  int i = *((int *)vargp);
  save_value(i);
  return NULL;
}
```

- Race Test
  - If no race, then each thread would get different value of _i_
  - Set of saved values would consist of one copy each of 0 through 99

#### Experimental Results

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.102hintuxg.avif" alt="" />
</center>

### Race Elimination

```c
/* Threaded program without the race */
int main() {
  pthread_t tid[N];
  int i, *ptr;

  for (i = 0; i < N; i++) {
    ptr = malloc(sizeof(int));
    *ptr = i;
    pthread_create(&tid[i], NULL, thread, ptr);
  }
  for (i = 0; i < N; i++)
    pthread_join(tid[i], NULL);
  exit(0);
}

/* Thread routine */
void *thread(void *vargp) {
  int myid = *((int *)vargp);
  free(vargp);
  printf("Hello from thread %d\n", myid);
  return NULL;
}
```

## Deadlock

- Def: A process is deadlocked iff it is waiting for a condition that will never be true
- Typical Scenario:
  - Processes 1 and 2 needs two resources (A and B) to proceed
  - Process 1 acquires A, waits for B
  - Process 2 acquires B, waits for A
  - Both will wait forever !

### Deadlocking With Semaphores

```c
void *count(void *vargp);

int main() {
  pthread_t tid[2];
  sem_init(&mutex[0], 0, 1); /* mutex[0] = 1 */
  sem_init(&mutex[1], 0, 1); /* mutex[1] = 1 */
  pthread_create(&tid[0], NULL, count, (void*)0);
  pthread_create(&tid[1], NULL, count, (void*)1);
  pthread_join(tid[0], NULL);
  pthread_join(tid[1], NULL);
  printf("cnt=%d\n", cnt);
  exit(0);
}

void *count(void *vargp) {
  int i;
  int id = (int)vargp;
  for (i = 0; i < NITERS; i++) {
    P(&mutex[id]); P(&mutex[1-id]);
    cnt++;
    V(&mutex[id]); V(&mutex[1-id]);
  }
  return NULL;
}
```

#### Deadlock Visualized in Progress Graph

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.b97yq3ac7.avif" alt="" />
</center>

- Locking introduces the potential for _deadlock_
- Any trajectory that enters the _deadlock region_ will eventually reach the _deadlock state_, waiting for either $S_{0}$ or $S_{1}$ to become nonzero
- Other trajectories luck out and skirt the deadlock region
- Unfortunate fact: deadlock is often nondeterministic (race)

### Avoiding Deadlock: Acquire shared resources in same order

```c
int main() {
  pthread_t tid[2];
  sem_init(&mutex[0], 0, 1); /* mutex[0] = 1 */
  sem_init(&mutex[1], 0, 1); /* mutex[1] = 1 */
  pthread_create(&tid[0], NULL, count, (void*) 0);
  pthread_create(&tid[1], NULL, count, (void*) 1);
  pthread_join(tid[0], NULL);
  pthread_join(tid[1], NULL);
  printf("cnt=%d\n", cnt);
  exit(0);
}

void *count(void *vargp) {
  int i;
  int id = (int) vargp;
  for (i = 0; i < NITERS; i++) {
    P(&mutex[0]); P(&mutex[1]);
    cnt++;
    V(&mutex[id]); V(&mutex[1-id]);
  }
  return NULL;
}
```

#### Avoided Deadlock in Progress Graph

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.9kgi04fb70.avif" alt="" />
</center>

- No way for trajectory to get stuck
- Processes acquire locks in same order
- Order in which locks released immaterial

# Thread-Level Parallelism

- Parallel Computing Hardware
  - Multicore
    - Multiple separate processors on single chip
  - Hyperthreading
    - Efficient execution of multiple threads on single core

## Typical Multicore Processor

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8vn8gw7tpk.avif" alt="" />
</center>

- Multiple processors operating with coherent view of memory

## Out-of-Order Processor Structure

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6f101z48kj.avif" alt="" />
</center>

- Instruction control dynamically converts program into stream of operations
- Operations mapped onto functional units to execute in parallel

## Hyperthreading Implementation

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2obugqgy9n.avif" alt="" />
</center>

- Replicate enough instruction control to process K instruction streams
- K copies of all registers
- Share functional units

## Example: Parallel Summation

- Sum numbers $0,...,n-1$
  - Should add up to $\displaystyle \frac{n( n-1)}{2}$
- Partition values $0,...,n-1$ into _t_ ranges
  - $\lfloor n/t\rfloor $ values in each range
  - Each of _t_ threads processes 1 range
  - For simplicity, assume _n_ is a multiple of _t_

### First attempt: psum-mutex

- Simplest approach: Threads sum into a global variable protected by a semaphore mutex

```c
void *sum_mutex(void *vargp);

long gsum = 0;          /* Global sum */
long nelems_per_thread; /* Number of elements to sum */
sem_t mutex;            /* Mutex to protect global sum */

int main(int argc, char **argv) {
  long i, nelems, log_nelems, nthreads, myid[MAXTHREADS];
  pthread_t tid[MAXTHREADS];
  /* Get input arguments */
  nthreads = atoi(argv[1]);
  log_nelems = atoi(argv[2]);
  nelems = (1L << log_nelems);
  nelems_per_thread = nelems / nthreads;
  sem_init(&mutex, 0, 1);

  /* Create peer threads and wait for them to finish */
  for (i = 0; i < nthreads; i++) {
    myid[i] = i;
    pthread_create(&tid[i], NULL, sum_mutex, &myid[i]);
  }

  for (i = 0; i < nthreads; i++)
    pthread_join(tid[i], NULL);

  /* Check final answer */
  if (gsum != (nelems * (nelems-1))/2)
    printf("Error: result=%ld\n", gsum);
  exit(0);
}

void *sum_mutex(void *vargp) {
  long myid = *((long *)vargp);          /* Extract thread ID */
  long start = myid * nelems_per_thread; /* Start element index */
  long end = start + nelems_per_thread;  /* End element index */
  long i;

  for (i = start; i < end; i++) {
    P(&mutex);
    gsum += i;
    V(&mutex);
  }
  return NULL;
}
```

#### psum-mutex Performance

- Shark machine with 8 cores, $n=2^{31}$

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1hsj867jxo.avif" alt="" />
</center>

- Nasty surprise:
  - Single thread is very slow
  - Gets slower as we use more cores

### Next Attempt: psum-array

- Peer thread _i_ sums into global array element _psum[i]_
- Main waits for threads to finish, then sums elements of _psum_
- Eliminates need for mutex synchronization

```c
void *sum_array(void *vargp) {
  long myid = *((long *)vargp);          /* Extract thread ID */
  long start = myid * nelems_per_thread; /* Start element index */
  long end = start + nelems_per_thread;  /* End element index */
  long i;

  for (i = start; i < end; i++) {
    psum[myid] += i;
  }
  return NULL;
}
```

#### psum-array Performance

- Orders of magnitude faster than **psum-mutex**

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8s3mj82urh.avif" alt="" />
</center>

### Next Attempt: psum-local

- Reduce memory references by having peer thread _i_ sum into a local variable (register)

```c
void *sum_local(void *vargp) {
  long myid = *((long *)vargp);          /* Extract thread ID */
  long start = myid * nelems_per_thread; /* Start element index */
  long end = start + nelems_per_thread;  /* End element index */
  long i, sum = 0;

  for (i = start; i < end; i++) {
    sum += i;
  }
  psum[myid] = sum;
  return NULL;
}
```

#### psum-local Performance

- Significantly faster than **psum-array**

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7snj6299lj.avif" alt="" />
</center>

## Characterizing Parallel Program Performance

- $p$ processor cores, $T_{k}$ is the running time using $k$ cores
- Def. Speedup: $\displaystyle S_{p} =\frac{T_{1}}{T_{p}}$
  - $S_{p}$ is relative speedup if $T_{1}$ is running time of parallel version of the code running on 1 core
  - $S_{p}$ is absolute speedup if $T_{1}$ is running time of sequential version of code running on 1 core
  - Absolute speedup is a much truer measure of the benefits of parallelism
- Def. Efficiency: $\displaystyle E_{p} =\frac{S_{p}}{p} =\frac{T_{1}}{pT_{p}}$
  - Reported as a percentage in the range $( 0,100]$
  - Measures the overhead due to parallelization

### Performance of psum-local

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.83acz862f4.avif" alt="" />
</center>

- Efficiencies OK, not great
- Our example is easily parallelizable
- Real codes are often much harder to parallelize

## Amdahl's Law

- Gene Amdahl (Nov. 16, 1922 – Nov. 10, 2015)
- Captures the difficulty of using parallelism to speed things up
- Overall problem
  - $T$ - Total sequential time required
  - $p$ - Fraction of total that can be sped up ($0\leqslant p\leqslant 1$)
  - $k$ - Speedup factor
- Resulting Performance
  - $\displaystyle T_{k} =\frac{pT}{k} +( 1-p) \cdot T$
    - Portion which can be sped up runs $k$ times faster
    - Portion which cannot be sped up stays the same
  - Least possible running time:
    - $k=\infty $
    - $T_{\infty } =( 1-p) \cdot T$

### Amdahl's Law Example

- Overall problem
  - $T=10$
  - $p=0.9$
  - $k=9$
- Resulting Performance
  - $\displaystyle T_{9} =0.9\cdot \frac{10}{9} +0.1\cdot 10=1.0+1.0=2.0$
  - Least possible running time:
    - $T_{\infty } =0.1\cdot 10.0=1.0$

## A More Substantial Example: Sort

- Sort set of $N$ random numbers
- Multiple possible algorithms
  - Use parallel version of quicksort
- Sequential quicksort of set of values $X$
  - Choose "pivot" $p$ from $X$
  - Rearrange $X$ into
    - $L$: Values $\leqslant p$
    - $R$: Values $\geqslant p$
  - Recursively sort $L$ to get $\displaystyle L^{\prime }$
  - Recursively sort $R$ to get $\displaystyle R^{\prime }$
  - Return $\displaystyle L^{\prime } :p:R^{\prime }$

### Sequential Quicksort Visualized

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.99to7v3zp2.avif" alt="" />
  <br />
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwowmozi.avif" alt="" />
</center>

### Sequential Quicksort Code

```c
void qsort_serial(data_t *base, size_t nele) {
  if (nele <= 1)
    return;
  if (nele == 2) {
    if (base[0] > base[1])
      swap(base, base+1);
    return;
  }

  /* Partition returns index of pivot */
  size_t m = partition(base, nele);
  if (m > 1)
    qsort_serial(base, m);
  if (nele-1 > m+1)
    qsort_serial(base+m+1, nele-m-1);
}
```

- Sort _nele_ elements starting at _base_
  - Recursively sort $L$ or $R$ if has more than one element

### Parallel Quicksort

- Parallel quicksort of set of values $X$
  - If $N\leqslant Nthresh$, do sequential quicksort
  - Else
    - Choose "pivot" $p$ from $X$
    - Rearrange $X$ into
      - $L$: Values $\leqslant p$
      - $R$: Values $\geqslant p$
    - Recursively spawn separate threads
      - Sort $L$ to get $\displaystyle L^{\prime }$
      - Sort $R$ to get $\displaystyle R^{\prime }$
  - Return $\displaystyle L^{\prime } :p:R^{\prime }$

#### Parallel Quicksort Visualized

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.3d540v0iic.avif" alt="" />
</center>

#### Thread Structure: Sorting Tasks

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.2a5epz84ec.avif" alt="" />
</center>

- Task: Sort subrange of data
  - Specify as:
    - _base_: Starting address
    - _nele_: Number of elements in subrange
- Run as separate thread

#### Small Sort Task Operation

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5fkwox4jmq.avif" alt="" />
</center>

- Sort subrange using serial quicksort

#### Large Sort Task Operation

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.96a2a5u9cs.avif" alt="" />
</center>

#### Top-Level Function (Simplified)

```c
void tqsort(data_t *base, size_t nele) {
  init_task(nele);
  global_base = base;
  global_end = global_base + nele - 1;
  task_queue_ptr tq = new_task_queue();
  tqsort_helper(base, nele, tq);
  join_tasks(tq);
  free_task_queue(tq);
}
```

- Sets up data structures
- Calls recursive sort routine
- Keeps joining threads until none left
- Frees data structures

#### Recursive sort routine (Simplified)

```c
/* Multi-threaded quicksort */
static void tqsort_helper(data_t *base, size_t nele, task_queue_ptr tq) {
  if (nele <= nele_max_sort_serial) {
    /* Use sequential sort */
    qsort_serial(base, nele);
    return;
  }
  sort_task_t *t = new_task(base, nele, tq);
  spawn_task(tq, sort_thread, (void *) t);
}
```

- Small partition: Sort serially
- Large partition: Spawn new sort task

#### Sort task thread (Simplified)

```c
/* Thread routine for many-threaded quicksort */
static void *sort_thread(void *vargp) {
  sort_task_t *t = (sort_task_t *) vargp;
  data_t *base = t->base;
  size_t nele = t->nele;
  task_queue_ptr tq = t->tq;
  free(vargp);
  size_t m = partition(base, nele);
  if (m > 1)
    tqsort_helper(base, m, tq);
  if (nele-1 > m+1)
    tqsort_helper(base+m+1, nele-m-1, tq);
  return NULL;
}
```

- Get task parameters
- Perform partitioning step
- Call recursive sort routine on each partition

#### Parallel Quicksort Performance

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.70anoekfdi.avif" alt="" />
</center>

- Serial fraction: Fraction of input at which do serial sort
- Sort $2^{27}$ (134,217,728) random values
- Best speedup = 6.84X
- Good performance over wide range of fraction values
  - F too small: Not enough parallelism
  - F too large: Thread overhead + run out of thread memory

#### Amdahl's Law & Parallel Quicksort

- Sequential bottleneck
  - Top-level partition: No speedup
  - Second level: $\leqslant 2X$ speedup
  - $k^{th}$ level: $\leqslant 2^{k-1} X$ speedup
- Implications
  - Good performance for small-scale parallelism
  - Would need to parallelize partitioning step to get large-scale parallelism
    - Parallel Sorting by Regular Sampling (H. Shi & J. Schaeffer, J. Parallel & Distributed Computing, 1992)

#### Parallelizing Partitioning Step

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.83aczat3uo.avif" alt="" />
</center>

#### Experience with Parallel Partitioning

- Could not obtain speedup
- Speculate: Too much data copying
  - Could not do everything within source array
  - Set up temporary space for reassembling partition

#### Lessons Learned

- Must have parallelization strategy
  - Partition into _k_ independent parts
  - Divide-and-conquer
- Inner loops must be synchronization free
  - Synchronization operations very expensive
- Beware of Amdahl's Law
  - Serial code can become bottleneck

## Memory Consistency

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.8adkuqke98.avif" alt="" />
</center>

- What are the possible values printed ?
  - Depends on memory consistency model
  - Abstract model of how hardware handles concurrent accesses
- Sequential consistency
  - Overall effect consistent with each individual thread
  - Otherwise, arbitrary interleaving

### Sequential Consistency Example

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.45hzimw23z.avif" alt="" />
</center>

- Impossible outputs
  - 100, 1 and 1, 100
  - Would require reaching both **Ra** and **Rb** before **Wa** and **Wb**

### Non-Coherent Cache Scenario

- Write-back caches, without coordination between them

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7lkbaqah0b.avif" alt="" />
</center>

### Snoopy Caches

- Tag each cache block with state
  - `Invalid` - Cannot use value
  - `Shared` - Readable copy
  - `Exclusive` - Writeable copy

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.1e8xakhfbo.avif" alt="" />
</center>

- When cache sees request for one of its E-tagged blocks
  - Supply value from cache
  - Set tag to S

<center>
  <img src="https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.26lssazxce.avif" alt="" />
</center>

# References

- [Computer Systems: A Programmer's Perspective, 3/E (CS:APP3e)](http://csapp.cs.cmu.edu/3e/home.html)
- [15-213: Intro to Computer Systems: Schedule for Fall 2015](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f15/www/schedule.html)
