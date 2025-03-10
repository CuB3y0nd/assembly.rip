---
title: "微积分笔记"
published: 2024-03-31
updated: 2024-08-26
description: "微积分学习笔记——从 1 到无穷大。主要记录各种公式定理的推导过程。"
image: "./covers/calculus-notes.jpg"
tags: ["Mathematices", "Notes"]
category: "Mathematices"
draft: false
---

# 极限和连续性

## 何为极限？

假设对于函数 $f$ 有：

$\displaystyle \lim _{x\to c} f(x)=L$

即：只要 $x$ 无限接近于 $c$, 则 $f(x)$ 必然无限接近于 $L$。

用 $\varepsilon -\delta$ 语言来描述就是：

$$
\displaystyle \forall \varepsilon  >0,\ \exists \delta  >0,\ s.t.\ 0<|x−c|< \delta \Longrightarrow |f(x)-L|< \varepsilon
$$

说白了就是：无论给定任何一个数字 $\varepsilon (\varepsilon  >0)$，总能找到一个数 $\delta ( \delta  >0)$。使当 $x$ 在 $c$ 的 $\delta$ 范围内时，$f(x)$ 在极限 $L$ 的 $\varepsilon$ 范围内。

---

例：已知 $
f( x) =\begin{cases}
2x & x\neq 5\\
x & x=5
\end{cases}，
$ 证明 $\displaystyle \lim _{x\rightarrow 5} f( x) =10$

根据定义，给定任意 $\varepsilon (\varepsilon  >0)$，有 $\delta ( \delta  >0)$。因此，我们本质上是要找到一个 $\delta =function\ of\ \varepsilon $ 的函数。

$\mathnormal{Proof.}$

$$
\begin{aligned}
& |x-5| < \delta \Longrightarrow |2x-10|< \varepsilon \\
& |2x-10| < 2\delta \\
& 2\delta =\varepsilon \Rightarrow \delta =\frac{\varepsilon }{2}\\
& |2x-10| < \varepsilon \\
& \forall \varepsilon  >0,\ \exists \delta  >0 ,\ s.t.\ |x-5|< \delta \Longrightarrow |2x-10|< \varepsilon \ \quad Q.E.D.
\end{aligned}
$$

---

## 夹逼定理

设 $I$ 为包含某点 $c$ 的区间，$f, g, h$ 为定义在 $I$ 上的函数。若对于所有属于 $I$ 而不等于 $c$ 的 $x$，有：

- $g( x) \leqslant f( x) \leqslant h( x)$
- $\displaystyle \lim _{x\rightarrow c} g( x) =\lim _{x\rightarrow c} h( x) =L$

则，$\displaystyle \lim _{x\rightarrow c} f( x) =L$。

$g(x)$ 和 $h(x)$ 分别被称为 $f(x)$ 的下界和上界。

### Proof: $\displaystyle \lim _{\theta \rightarrow 0}\frac{\sin \theta }{\theta } =1$

<center>
  <img src="https://pic.imgdb.cn/item/66094d699f345e8d03de6f44.png" />
</center>

### Proof: $\displaystyle \lim _{\theta \rightarrow 0}\frac{1-\cos \theta }{\theta } =0$

$\mathnormal{Proof.}$

$$
\begin{aligned}
\lim _{\theta \rightarrow 0}\frac{1-\cos \theta }{\theta } & =\lim _{\theta \rightarrow 0}\frac{( 1-\cos \theta )( 1+\cos \theta )}{\theta ( 1+\cos \theta )}\\
 & =\lim _{\theta \rightarrow 0}\frac{\sin^{2} \theta }{\theta ( 1+\cos \theta )}\\
 & =\lim _{\theta \rightarrow 0}\frac{\sin \theta }{\theta } \cdot \lim _{\theta \rightarrow 0}\frac{\sin \theta }{1+\cos \theta }\\
 & =1\cdot 0\\
 & =0
 & Q.E.D.
\end{aligned}
$$

## 连续性的定义

函数在某一点处连续：$f$ is continuous at $x=c\Longleftrightarrow \displaystyle \lim _{x\rightarrow c} f( x) =f( c)$

函数在开区间连续：$f$ is continuous over $( a,\ b) \Longleftrightarrow f$ is continuous over every point in the interval

函数在闭区间连续：$f$ is continuous over $[ a,\ b] \Longleftrightarrow f$ is continuous over $( a,\ b)$ and $\displaystyle \lim _{x\rightarrow a^{+}} f( x) =f( a)$, $\displaystyle \lim _{x\rightarrow b^{-}} f( x) =f( b)$

## Intermediate Value Theorem

Suppose $f$ is a continuous function at every point of the interval $[ a,\ b]$

- $f$ will take on every value between $f( a)$ and $f( b)$ over the interval
- For any $L$ between the values $f( a)$ and $f( b)$ , there exists a number $c$ in $[ a,\ b]$ for which $f( c) =L$

怎么会有这么简单的定理…

# 导数

## 导数的两种定义形式

$\displaystyle f^{\prime }( x) =\lim _{h\rightarrow 0}\frac{f( x+h) -f( x)}{h}$

$\displaystyle f^{\prime }( c) =\lim _{x\rightarrow c}\frac{f( x) -f( c)}{x-c}$

## 可微性

- $f$ is differentiability at $x=c\Longrightarrow f$ is continuous at $x=c$
- $f$ is not continuous at $x=c\Longrightarrow f$ is not differentiability at $x=c$

不可微的三种情况：

1. **not continuous**
2. **vertical tangent**
3. **"sharp turn"**

## Proof: Differentiability implies continuity

$\mathnormal{Proof.}$

Assume: $f$ differentiability at $x=c$

$
\begin{array}{l}
\because f\ differentiability\ at\ x=c\\
\therefore \displaystyle f^{\prime }( c) = \lim _{x\rightarrow c}\frac{f( x) -f( c)}{x-c}
\end{array}
$

$$
\begin{aligned}
\lim _{x\rightarrow c}[ f( x) -f( c)] & =\lim _{x\rightarrow c}( x-c) \cdot \frac{f( x) -f( c)}{x-c}\\
 & =\lim _{x\rightarrow c}( x-c) \cdot \lim _{x\rightarrow c}\frac{f( x) -f( c)}{x-c}\\
 & =0\cdot f^{\prime }( c)\\
 & =0\\
 & \\
\lim _{x\rightarrow c}[ f( x) -f( c)] & =0\\
\lim _{x\rightarrow c} f( x) -\lim _{x\rightarrow c} f( c) & =0\\
\lim _{x\rightarrow c} f( x) -f( c) & =0\\
\lim _{x\rightarrow c} f( x) & =f( c)
 & Q.E.D.
\end{aligned}
$$

## Justifying the power rule

### Proof: $\displaystyle \frac{d}{dx}\left( x^{n}\right) =nx^{n-1}$

$\mathnormal{Proof.}$

$\displaystyle \frac{d}{dx}\left( x^{n}\right) =\lim _{\Delta x\rightarrow 0}\frac{( x+\Delta x)^{n} -x^{n}}{\Delta x}$

According to Binomial theorem:

$$
\begin{aligned}
\displaystyle \lim _{\Delta x\rightarrow 0}\frac{( x+\Delta x)^{n} -x^{n}}{\Delta x} & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\cancel{x^{n}} +\binom{n}{1} x^{n-1} \Delta x+\binom{n}{2} x^{n-2} \Delta x^{2} +...+\binom{n}{n} x^{0} \Delta x^{n}\cancel{-x^{n}}}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\binom{n}{1} x^{n-1} +\cancel{\binom{n}{2} x^{n-2} \Delta x} +...+\cancel{\binom{n}{n} \Delta x^{n-1}}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\binom{n}{1} x^{n-1}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{n!}{\cancel{1!}( n-1) !} x^{n-1}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0} nx^{n-1}
 & Q.E.D.
\end{aligned}
$$

### Proof: $\displaystyle \frac{d}{dx}\left(\sqrt{x}\right) =\frac{1}{2} x^{-\frac{1}{2}}$

$\mathnormal{Proof.}$

$$
\begin{aligned}
\frac{d}{dx}\left(\sqrt{x}\right) & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\sqrt{x+\Delta x} -\sqrt{x}}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\left(\sqrt{x+\Delta x} -\sqrt{x}\right)\left(\sqrt{x+\Delta x} +\sqrt{x}\right)}{\Delta x\left(\sqrt{x+\Delta x} +\sqrt{x}\right)}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{1}{\sqrt{x+\Delta x} +\sqrt{x}}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{1}{2\sqrt{x}}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{1}{2} x^{-\frac{1}{2}}
 & Q.E.D.
\end{aligned}
$$

## Justifying the basic derivative rules

### Proof: Constant rule ($\displaystyle \frac{d}{dx} k=0$)

$\mathnormal{Proof.}$

$$
\begin{array}{l}
\because k\ is\ constant\\
\therefore y\ does\ not\ change\ as\ x\ changes\\
\therefore f( x+h) -f( x) =0\\
\therefore \displaystyle \frac{d}{dx} k= \lim _{h\rightarrow 0}\frac{f( x+h) -f( x)}{h} =\lim _{h\rightarrow 0}\frac{0}{h} =0
\end{array}
$$

### Proof: Constant multiple and sum/difference rules

**Constant multiple rule:** $\displaystyle \dfrac{d}{dx}[k\cdot f(x)]=k\cdot\dfrac{d}{dx}f(x)$

**Sum rule:** $\displaystyle \dfrac{d}{dx}[f(x)+g(x)]=\dfrac{d}{dx}f(x)+\dfrac{d}{dx}g(x)$

**Difference rule:** $\displaystyle \dfrac{d}{dx}[f(x)-g(x)]=\dfrac{d}{dx}f(x)-\dfrac{d}{dx}g(x)$

$\mathnormal{Proof.}$

$\displaystyle 1.\ f( x) =kg( x) \Longrightarrow f^{\prime }( x) =kg^{\prime }( x)$

$$
\begin{aligned}
f^{\prime }( x) & =\displaystyle \lim _{h\rightarrow 0}\frac{f( x+h) -f( x)}{h}\\
 & =\displaystyle \lim _{h\rightarrow 0}\frac{kg( x+h) -kg( x)}{h}\\
 & =\displaystyle \lim _{h\rightarrow 0} k\left(\frac{g( x+h) -g( x)}{h}\right)\\
 & =k\displaystyle \lim _{h\rightarrow 0}\frac{g( x+h) -g( x)}{h}\\
 & =kg^{\prime }( x)
 & Q.E.D.
\end{aligned}
$$

$\displaystyle 2.\ f( x) =g( x) \pm j( x) \Longrightarrow f^{\prime }( x) =g^{\prime }( x) \pm j^{\prime }( x)$

$$
\begin{aligned}
f^{\prime }( x) & =\displaystyle \lim _{h\rightarrow 0}\frac{g( x+h) \pm j( x+h) -( g( x) \pm j( x))}{h}\\
 & =\displaystyle \lim _{h\rightarrow 0}\left(\frac{g( x+h) -g( x)}{h} \pm \frac{j( x+h) -j( x)}{h}\right)\\
 & =\displaystyle \lim _{h\rightarrow 0}\frac{g( x+h) -g( x)}{h} \pm \lim _{h\rightarrow 0}\frac{j( x+h) -j( x)}{h}\\
 & =g^{\prime }( x) \pm j^{\prime }( x)
 & Q.E.D.
\end{aligned}
$$

## Proof: The derivatives of sin(x) and cos(x)

Known $\displaystyle \lim _{x\rightarrow 0}\frac{\sin x}{x} =1$ and $\displaystyle \lim _{x\rightarrow 0}\frac{1-\cos x}{x} =0$

$\mathnormal{Proof.}$

$\displaystyle 1.\ \frac{d}{dx}[\sin x] =\cos x$

$$
\begin{aligned}
\frac{d}{dx}[\sin x] & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\sin( x+\Delta x) -\sin( x)}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\cos x\sin \Delta x+\sin x\cos \Delta x-\sin x}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\left(\frac{\cos x\sin \Delta x}{\Delta x} +\frac{\sin x\cos \Delta x-\sin x}{\Delta x}\right)\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\cos x\left(\frac{\sin \Delta x}{\Delta x}\right) +\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\sin x(\cos \Delta x-1)}{\Delta x}\\
 & =\cos x\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\sin \Delta x}{\Delta x} -\sin x\displaystyle \lim _{\Delta x\rightarrow 0}\frac{1-\cos \Delta x}{\Delta x}\\
 & =\cos x\cdot 1-\sin x\cdot 0\\
 & =\cos x
 & Q.E.D.
\end{aligned}
$$

$\displaystyle 2.\ \frac{d}{dx}[\cos x] =-\sin x$

<center>
  <Image alt="1" src="https://pic.imgdb.cn/item/66122e7268eb935713987d7f.png" width={1920} height={1080} />
</center>

## Proof: The derivative of $e^{x}$ is $e^{x}$

Know the limit definition of $\mathbb{e}$ is $e=\displaystyle \lim _{n\rightarrow \infty }\left( 1+\frac{1}{n}\right)^{n} =\displaystyle \lim _{n\rightarrow 0}( 1+n)^{\frac{1}{n}}$

$\mathnormal{Proof.}$

$$
\begin{aligned}
\frac{d}{dx}\left( e^{x}\right) & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{e^{x+\Delta x} -e^{x}}{\Delta x}\\
 & =e^{x}\displaystyle \lim _{\Delta x\rightarrow 0}\frac{e^{\Delta x} -1}{\Delta x}
\end{aligned}
$$

$\displaystyle Let\ n=e^{\Delta x} -1,\ we\ can\ get\ n+1=e^{\Delta x} ,\ such\ that\ \Delta x=\ln( n+1) \ and\ as\ \Delta x\rightarrow 0=n\rightarrow 0$

$We\ can\ rewrite\ to:$

$$
\begin{aligned}
\frac{d}{dx}\left( e^{x}\right) & =e^{x}\displaystyle \lim _{n\rightarrow 0}\frac{n}{\ln( n+1)}\\
 & =e^{x}\displaystyle \lim _{n\rightarrow 0}\frac{\frac{1}{n} n}{\frac{1}{n}\ln( n+1)}\\
 & =e^{x}\displaystyle \lim _{n\rightarrow 0}\frac{1}{\ln\left[( 1+n)^{\frac{1}{n}}\right]}\\
 & =e^{x}\frac{1}{\ln\left[\displaystyle \lim _{n\rightarrow 0}( 1+n)^{\frac{1}{n}}\right]}\\
 & =e^{x}
 & Q.E.D.
\end{aligned}
$$

## Proof: The derivative of $\ln( x)$ is $\frac{1}{x}$

### Method 1 (Directly from the definition of the derivative as a limit)

$\mathnormal{Proof.}$

$$
\begin{aligned}
\frac{d}{dx}(\ln x) & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\ln( x+\Delta x) -\ln( x)}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\ln\left(\frac{x+\Delta x}{x}\right)}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\ln\left( 1+\frac{\Delta x}{x}\right)}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{1}{\Delta x}\ln\left( 1+\frac{\Delta x}{x}\right)\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\ln\left[\left( 1+\frac{\Delta x}{x}\right)^{\frac{1}{\Delta x}}\right]
\end{aligned}
$$

$\displaystyle Let\ n=\frac{\Delta x}{x} ,\ \Delta x=nx,\ \frac{1}{\Delta x} =\frac{1}{n} \cdot \frac{1}{x} \ and\ as\ \Delta x\rightarrow 0=n\rightarrow 0$

$We\ can\ rewrite\ to:$

$$
\begin{aligned}
\displaystyle \lim _{\Delta x\rightarrow 0}\ln\left[\left( 1+\frac{\Delta x}{x}\right)^{\frac{1}{\Delta x}}\right] & =\frac{1}{x}\displaystyle \lim _{n\rightarrow 0}\ln\left[( 1+n)^{\frac{1}{n}}\right]\\
 & =\frac{1}{x}\ln\left[\displaystyle \lim _{n\rightarrow 0}( 1+n)^{\frac{1}{n}}\right]\\
 & =\frac{1}{x}
 & Q.E.D.
\end{aligned}
$$

### Method 2 (Using the fact that $\displaystyle \frac{d}{dx}\left( e^{x}\right) =e^{x}$ and applying implicit differentiation)

$\mathnormal{Proof.}$

$\displaystyle Known\ \frac{d}{dx}\left( e^{x}\right) =e^{x}$

$\displaystyle Let\ y=\ln( x) ,\ we\ can\ get:$

$$
\begin{aligned}
\frac{d}{dx}\left( e^{y}\right) & =\frac{d}{dx}( x)\\
e^{y} \cdot \frac{dy}{dx} & =1\\
\frac{dy}{dx} & =\frac{1}{e^{y}}\\
 & =\frac{1}{e^{\ln x}}\\
 & =\frac{1}{x}
 & Q.E.D.
\end{aligned}
$$

## Proof: The product rule

$\mathnormal{Proof.}$

$$
\begin{aligned}
\frac{d}{dx}[ f( x) g( x)] & =\displaystyle \lim _{h\rightarrow 0}\frac{f( x+h) g( x+h) -f( x+h) g( x) +f( x+h) g( x) -f( x) g( x)}{h}\\
 & =\displaystyle \lim _{h\rightarrow 0}\left[ f( x+h)\frac{g( x+h) -g( x)}{h} +g( x)\frac{f( x+h) -f( x)}{h}\right]\\
 & =\left[\displaystyle \lim _{h\rightarrow 0} f( x+h)\right]\left[\displaystyle \lim _{h\rightarrow 0}\frac{g( x+h) -g( x)}{h}\right] +\left[\displaystyle \lim _{h\rightarrow 0} g( x)\right]\left[\displaystyle \lim _{h\rightarrow 0}\frac{f( x+h) -f( x)}{h}\right]\\
 & =f( x) g^{\prime }( x) +g( x) f^{\prime }( x)
 & Q.E.D.
\end{aligned}
$$

## Proof: The derivatives of $\tan( x)$、$\cos( x)$、$\sec( x)$ and $\csc( x)$

$\mathnormal{Proof.}$

$$
\begin{aligned}
\frac{d}{dx}(\tan x) & =\frac{d}{dx}\left(\frac{\sin x}{\cos x}\right) & \frac{d}{dx}(\cot x) & =\frac{d}{dx}\left(\frac{\cos x}{\sin x}\right)\\
 & =\frac{\cos^{2} x+\sin^{2} x}{\cos^{2} x} &  & =\frac{-\left(\sin^{2} x+\cos^{2} x\right)}{\sin^{2} x}\\
 & =\frac{1}{\cos^{2} x} &  & =-\frac{1}{\sin^{2} x}\\
 & =\sec^{2} x &  & =-\csc^{2} x\\
\frac{d}{dx}(\sec x) & =\frac{d}{dx}\left(\frac{1}{\cos x}\right) & \frac{d}{dx}(\csc x) & =\frac{d}{dx}\left(\frac{1}{\sin x}\right)\\
 & =\frac{0\cdot \cos x+1\cdot \sin x}{\cos^{2} x} &  & =\frac{0\cdot \sin x-1\cdot \cos x}{\sin^{2} x}\\
 & =\frac{\sin x}{\cos^{2} x} &  & =-\frac{\cos x}{\sin^{2} x}\\
 & =\tan x\cdot \sec x &  & =-\cot x\cdot \csc x
 & Q.E.D.
\end{aligned}
$$

## Proof: The derivatives of $a^{x}$ (For any positive base a)

$\mathnormal{Proof.}$

$\displaystyle Known\ \frac{d}{dx}\left( e^{x}\right) =e^{x}$

$\displaystyle Let\ a=e^{\ln a}$

$$
\begin{aligned}
\frac{d}{dx}\left( a^{x}\right) & =\frac{d}{dx}\left[\left( e^{\ln a}\right)^{x}\right]\\
 & =\frac{d}{dx}\left[ e^{(\ln a) x}\right]\\
 & =e^{(\ln a) x} \cdot \ln a\\
 & =a^{x} \cdot \ln a
 & Q.E.D.
\end{aligned}
$$

## Proof: The derivatives of $\log_{a} x$ (For any positive base $a\neq 1$)

$\mathnormal{Proof.}$

$\displaystyle Known\ \frac{d}{dx}(\ln x) =\frac{1}{x}$

$$
\begin{aligned}
\frac{d}{dx}(\log_{a} x) & =\frac{d}{dx}\left(\frac{1}{\ln a} \cdot \ln x\right)\\
 & =\frac{1}{x\ln a}
 & Q.E.D.
\end{aligned}
$$

## Proof: Chain Rule and Quotient Rule

$\mathnormal{Chain\ Rule\ Proof.}$

$$
\begin{aligned}
Known:\  & 1.\ If\ a\ function\ is\ differentiable,\ then\ it\ is\ also\ continuous.\\
 & 2.\ If\ function\ u\ is\ continuous\ at\ x,\ then\ \Delta u\rightarrow 0\ as\ \Delta x\rightarrow 0
\end{aligned}
$$

For why if function $u$ is continuous at $x$, then $\Delta u\rightarrow 0$ as $\Delta x\rightarrow 0$:

<center>
  <img src="https://pic.imgdb.cn/item/661a87a868eb935713971ab1.png" />
</center>

$\displaystyle The\ chain\ rule\ tell\ us:\ \frac{d}{dx}[ y( u( x))] =\frac{dy}{dx} =\frac{dy}{du} \cdot \frac{du}{dx}$

Assuming $y$, $u$ differentiable at $x$. We can get:

$$
\begin{aligned}
\frac{dy}{dx} & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\Delta y}{\Delta x}\\
 & =\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\Delta y}{\Delta u} \cdot \frac{\Delta u}{\Delta x}\\
 & =\left(\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\Delta y}{\Delta u}\right)\left(\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\Delta u}{\Delta x}\right)\\
 & =\left(\displaystyle \lim _{\Delta u\rightarrow 0}\frac{\Delta y}{\Delta u}\right)\left(\displaystyle \lim _{\Delta x\rightarrow 0}\frac{\Delta u}{\Delta x}\right)\\
 & =\frac{dy}{du} \cdot \frac{du}{dx}
 & Q.E.D.
\end{aligned}
$$

$\mathnormal{Quotient\ Rule\ Proof.}$

$$
\begin{aligned}
\frac{d}{dx}\left[\frac{f( x)}{g( x)}\right] & =\frac{d}{dx}\left[ f( x) \cdot [ g( x)]^{-1}\right]\\
 & =f^{\prime }[ x]( g( x))^{-1} -f[ x]( g( x))^{-2} g^{\prime }( x)\\
 & =\frac{f^{\prime }( x)}{g( x)} -\frac{f( x) g^{\prime }( x)}{[ g( x)]^{2}}\\
 & =\frac{f^{\prime }( x) g( x) -f( x) g^{\prime }( x)}{[ g( x)]^{2}}
 & Q.E.D.
\end{aligned}
$$

# Proof: L'Hôpital's rule

> [!NOTE]
> This isn't full proof of L'Hôpital's rule, just a special case. But it should give some intuition for why it works.

$$
f( a) =0,\ g( a) =0;\ f^{\prime} ( a) \ exists,\ g^{\prime} ( a) \ exists\ \Longleftrightarrow \ \displaystyle \lim _{x\rightarrow a}\frac{f( x)}{g( x)} =\frac{f^{\prime} ( a)}{g^{\prime} ( a)}
$$

$$
\begin{aligned}
\frac{f^{\prime }( a)}{g^{\prime }( a)} & =\frac{\displaystyle \lim _{x\rightarrow a}\frac{f( x) -f( a)}{x-a}}{\displaystyle \lim _{x\rightarrow a}\frac{g( x) -g( a)}{x-a}} & \\
 & =\displaystyle \lim _{x\rightarrow a}\frac{f( x) -f( a)}{g( x) -g( a)} & \\
 & =\displaystyle \lim _{x\rightarrow a}\frac{f( x)}{g( x)} & We\ know\ f( a) \ and\ g( a) \ both\ equal\ to\ zero \\
 & & Q.E.D
\end{aligned}
$$

# Mean Value Theorem

If $f$ is continuous over $[ a,\ b]$ and every point over $( a,\ b)$ is differentiable. Then there exists some $c\in ( a,\ b)$ where $\displaystyle \frac{\Delta y}{\Delta x} =\frac{f( b) -f( a)}{b-a} =f^{\prime }( c)$

# Extreme Value Theorem

$f$ continuous over $[ a,\ b] \Longrightarrow \exists \ c,\ d\in [ a,\ b] :f( c) \leqslant f( x) \leqslant f( d)$ for all $x\in [ a,\ b]$

critical points exists when non endpoint point at $$x=a\ \begin{cases} f^{\prime }( a) =0\\ f^{\prime }( a) \ undefined \end{cases}$$

# Definite Integral & Riemann Sum

The definite integral of a continuous function $f$ over the interval $[ a,\ b]$, denoted by $\displaystyle \int _{a}^{b} f( x) dx$, is the limit of a Riemann sum as the number of subdivisions approaches infinity.

$$
\displaystyle \int _{a}^{b} f( x) dx=\lim _{n\rightarrow \infty }\sum _{i=1}^{n} f( x_{i}) \Delta x
$$

Where $\displaystyle \Delta x=\frac{b-a}{n}$ and $x_{i} =a+\Delta x\cdot i$

# Definite integrals properties

**Sum/Difference:**

$$\displaystyle \int _{a}^{b}[ f( x) \pm g( x)] dx=\int _{a}^{b} f( x) dx\pm \int _{a}^{b} g( x) dx$$

**Constant multiple:**

$$\displaystyle \int _{a}^{b} k\cdot f( x) dx=k\int _{a}^{b} f( x) dx$$

**Reverse interval:**

$$\displaystyle \int _{a}^{b} f( x) dx=-\int _{b}^{a} f( x) dx$$

**Zero-length interval:**

$$\displaystyle \int _{a}^{a} f( x) dx=0$$

**Adding intervals:**

$$\displaystyle \int _{a}^{b} f( x) dx+\int _{b}^{c} f( x) dx=\int _{a}^{c} f( x) dx$$

这么简单的东西相信你一定也知道怎么证。~~那证明就略略略了吧～~~

# First fundamental theorem of calculus

Let $f$ be a continuous real−valued function defined on $[ a,\ b]$. And $F$ be the function defined, for all $x$ in $[ a,\ b]$, by $\displaystyle F( x) =\int _{a}^{x} f( t) dt$

Then $F$ is uniformly continuous on $[ a,\ b]$ and differentiable on the open interval $( a,\ b)$, and $\displaystyle F^{\prime }( x) =f( x)$ for all $x$ in $( a,\ b)$ so $F$ is an antiderivative of $f$.

<center>
  <img src="https://s21.ax1x.com/2024/08/18/pACxH78.jpg" />
</center>

# Second fundamental theorem of calculus / Newton–Leibniz theorem

Let $f$ be a continuous real−valued function defined on $[ a,\ b]$ and $F$ is a continuous function on $[ a,\ b]$ which is an antiderivative of $f$ in $( a,\ b)$: $\displaystyle F^{\prime }( x) =f( x)$

If $f$ is Riemann integrable on $[ a,\ b]$ then $\displaystyle \int _{a}^{b} f( x) dx=F( b) -F( a)$

<center>
  <img src="https://s21.ax1x.com/2024/08/18/pACzG3d.jpg" />
</center>

# Reverse power rule

$$\displaystyle \int x^{n} dx=\frac{x^{n+1}}{n+1} +C,\ n\neq -1$$

Yes that just simple!

# Indefinite integration rules

**Polynomials**

$$\displaystyle \int x^{n} dx=\frac{x^{n+1}}{n+1} +C$$

**Radicals**

$$\displaystyle \int \sqrt[m]{x^{n}} dx=\frac{x^{\frac{n}{m} +1}}{\frac{n}{m} +1} +C$$

**Trigonometric functions**

$$\displaystyle \int \sin( x) dx=-\cos( x) +C$$

$$\displaystyle \int \cos( x) dx=\sin( x) +C$$

$$\displaystyle \int \sec^{2}( x) dx=\tan( x) +C$$

$$\displaystyle \int \csc^{2}( x) dx=-\cot( x) +C$$

$$\displaystyle \int \sec( x)\tan( x) dx=\sec( x) +C$$

$$\displaystyle \int \csc( x)\cot( x) dx=-\csc( x) +C$$

$$\displaystyle \int \sec xdx=\ln| \sec x+\tan x| +C$$（分子分母同乘 $\sec x+\tan x$）

$$\displaystyle \int \csc xdx=\ln| \csc x-\cot x| +C$$（分子分母同乘 $\csc x-\cot x$）

下面是另一种方法求这两个不定积分：

$$
\begin{array}{ l l l }
\displaystyle \int \sec xdx & =\displaystyle \int \frac{1}{\cos x} dx & \\
 & =\displaystyle \int \frac{\cos x}{\cos^{2} x} dx & \\
 & =\displaystyle \int \frac{1}{1-\sin^{2} x}\cos xdx & Let\ u=\sin x\\
 & =\displaystyle \int \frac{1}{( 1+u)( 1-u)} du & \\
 & =\displaystyle \frac{1}{2}\int \left(\frac{1}{1+u} +\frac{1}{1-u}\right) du & Partial\ fractions\\
 & =\displaystyle \frac{1}{2}\ln\left| \frac{1+u}{1-u}\right| +C & \\
 & =\displaystyle \frac{1}{2}\ln\left| \frac{1+\sin x}{1-\sin x}\right| +C &
\end{array}
$$

$$
\begin{array}{ l l l }
\displaystyle \int \csc xdx & =\displaystyle \int \frac{1}{\sin x} dx & \\
 & =\displaystyle \int \frac{\sin x}{\sin^{2} x} dx & \\
 & =\displaystyle \int \frac{1}{1-\cos^{2} x}\sin xdx & Let\ u=\cos x\\
 & =\displaystyle -\int \frac{1}{( 1+u)( 1-u)} du & \\
 & =\displaystyle -\frac{1}{2}\int \left(\frac{1}{1+u} +\frac{1}{1-u}\right) du & Partial\ fractions\\
 & =\displaystyle -\frac{1}{2}\ln\left| \frac{1+u}{1-u}\right| +C & \\
 & =\displaystyle -\frac{1}{2}\ln\left| \frac{1+\cos x}{1-\cos x}\right| +C &
\end{array}
$$

**Exponential functions**

$$\displaystyle \int e^{x} dx=e^{x} +C$$

$$\displaystyle \int a^{x} dx=\frac{a^{x}}{\ln( a)} +C$$

**Logarithmic functions**

$$\displaystyle \int \frac{1}{x} dx=\ln |x|+C$$

**Inverse trigonometric functions**

$$\displaystyle \int \frac{1}{\sqrt{a^{2} -x^{2}}} dx=\arcsin\left(\frac{x}{a}\right) +C$$

$$\displaystyle \int \frac{1}{a^{2} +x^{2}} dx=\frac{1}{a}\arctan\left(\frac{x}{a}\right) +C$$

# Integration by parts

$$\displaystyle \int uvdx=u\int vdx-\int \left( u^{\prime }\int vdx\right) dx$$

# Integration by reduction formulae

$$\displaystyle \int \sin^{n} xdx=-\frac{1}{n}\sin^{n-1} x\cos x+\frac{n-1}{n}\int \sin^{n-2} xdx$$

$$\displaystyle \int \cos^{n} xdx=\frac{1}{n}\cos^{n-1} x\sin x+\frac{n-1}{n}\int \cos^{n-2} xdx$$

$$\displaystyle \int \tan^{n} xdx=\frac{1}{n-1}\tan^{n-1} x-\int \tan^{n-2} xdx$$

$$\displaystyle \int (\ln x)^{n} dx=x(\ln x)^{n} -n\int (\ln x)^{n-1} dx$$
