---
title: "The CSAPP Notebook"
published: 2025-07-16
updated: 2025-08-03
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

### Why couldn't compiler move strlen out of inner loop?

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

### Why Linkers?

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

### What Do Linkers Do?

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
  - Uninitialized global variables
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
  static int x = 0;
  return x;
}

int g() {
  static int x = 1;
  return x;
}
```

In the case above, compiler allocates space in `.data` for each definition of `x` and creates local symbols in the symbol table with unique names, e.g., `x.1` and `x.2`.

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

- How to package functions commonly used by programmers?
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
- What if parent doesn't reap?
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

## Signals and Nonlocal Jumps

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
- But what about background jobs?
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

Equivalent to atomic (uninterruptable) version of:

```c
sigprocmask(SIG_BLOCK, &mask, &prev);
pause();
sigprocmask(SIG_SETMASK, &prev, NULL);
```

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

# References

- [Computer Systems: A Programmer's Perspective, 3/E (CS:APP3e)](http://csapp.cs.cmu.edu/3e/home.html)
- [15-213: Intro to Computer Systems: Schedule for Fall 2015](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f15/www/schedule.html)
