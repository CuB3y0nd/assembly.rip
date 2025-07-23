---
title: "The CSAPP Notebook"
published: 2025-07-16
updated: 2025-07-23
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

#### Why bits? Electronic Implementation

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

### When Should I Use Unsigned?

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
  - Limited range of numbers (very small values? very large? we have to move the binary point to represent sort of wide as wide a range as possible with as much precision given the number of bits)

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
    - What should comparison yield?
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
  - Closed under addition? (Yes)
    - But may generate infinity or NaN
  - Commutative? (Yes)
  - Associative? (No)
    - Overflow and inexactness of rounding
    - `(3.14+1e10)-1e10 = 0, 3.14+(1e10-1e10) = 3.14`
  - $0$ is additive identity? (Yes)
  - Every element has additive inverse? (Almost)
    - Except for infinities & NaNs
- Monotonicity
  - $a\geqslant b\Rightarrow a+c\geqslant b+c$ ? (Almost)
    - Except for infinities & NaNs

### Mathematical Properties of Floating Point Mult

- Compare to Commutative Ring
  - Closed under multiplication? (Yes)
    - But may generate infinity or NaN
  - Multiplication Commutative? (Yes)
  - Multiplication is Associative? (No)
    - Possibility of overflow, inexactness of rounding
    - `(1e20*1e20)*1e-20 = inf, 1e20*(1e20*1e-20) = 1e20`
  - $1$ is multiplicative identity? (Yes)
  - Multiplication distributes over addition? (No)
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

### Assembly/Machine Code View

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

# References

- [Computer Systems: A Programmer's Perspective, 3/E (CS:APP3e)](http://csapp.cs.cmu.edu/3e/home.html)
- [15-213: Intro to Computer Systems: Schedule for Fall 2015](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f15/www/schedule.html)
