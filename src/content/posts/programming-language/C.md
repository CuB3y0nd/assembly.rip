---
title: "The C Notebook"
published: 2025-07-17
updated: 2025-08-06
description: "The C Programming Language learning notes."
tags: ["C", "Notes"]
category: "Notes"
draft: false
---

# 前言

炸炸炸，不想说话！

# Pragma Once and Header Guards

## Pragma Once

If the same header file gets included more than once, you can end up with some nasty errors caused by redefining things like functions or structs.

One simple solution is `#pragma once`. Adding this line to the top of a header file tells the compiler to include the file only once, even if it's referenced multiple times across your program.

```c title="my_header.h"
#pragma once

struct Point {
  int x;
  int y;
  int z;
};
```

## Header Guards

Another common way to avoid multiple inclusions is with include guards, which use preprocessor directives like this:

```c
#ifndef MY_HEADER_H
#define MY_HEADER_H

// some cool code

#endif
```

# Structs

## Define

```c
struct Coordinate {
  int x;
  int y;
  int z;
};
```

## Initializers

Say we have a struct defined like this:

```c
struct City {
  char *name;
  int lon;
  int lat;
};
```

There are a few different ways to initialize a struct.

### Zero Initializer

```c
struct City c = {0};
```

### Positonal Initializer

```c
struct City c = {"San Francisco", -122, 37};
```

### Designated Initializer

```c
struct City c = {
  .name = "San Francisco",
  .lon = -122,
  .lat = 37
};
```

## Accessing Fields

```c
struct City c;

c.lat = 41;

printf("Latitude: %d\n", c.lat);
```

# Typedef

If you give a name to the struct while using `typedef`, you'd have 2 ways refer to this type:

```c
typedef struct Coordinate {
  int x;
  int y;
  int z;
} cood_t;

struct Coordinate way_1;
coord_t way_2;
```

We can optionally skip giving the struct a name:

```c
typedef struct {
  int x;
  int y;
  int z;
} coord_t;

coord_t coord;
```

In this case, you'd only be able to refer the type as `coord_t`.

# Sizeof Struct

Structs are stored contiguously in memory one field after another. Take this struct:

```c
typedef struct {
  int x;
  int y;
  int z;
} coord_t;
```

Assuming `int` is 4 bytes, the total size of `coord_t` would be 12 bytes.

```c
typedef struct {
  char first_initial;
  int age;
  double height;
} human_t;
```

Assuming `char` is 1 byte, `int` is 4 bytes, and `double` is 8 bytes, the total size of `human_t` would be 16 bytes.

- Each member of a struct must be aligned to its own alignment requirement
- The overall size of a struct must be a multiple of the largest alignment requirement among its members
- $padding=( alignment-( address\ \%\ alignment)) \ \%\ alignment$

:::tip
As a rule of thumb, ordering your fields from largest to smallest will help the compiler minimize padding.
:::

For example:

```c
typedef struct {
  char a;
  double b;
  char c;
  char d;
  long e;
  char f;
} poorly_aligned_t;

typedef struct {
  double b;
  long e;
  char a;
  char c;
  char d;
  char f;
} better_t;
```

`poorly_aligned_t` will insert 20 paddings, total size would be 40 bytes. But `better_t` only add 4 paddings, its size would be 24 bytes only.

# Pointers

A pointer is declared with an asterisk (`*`) after the type. For example, `int *`.

To get the address of a variable so that we can store it in a pointer variable, we can use the address-of operator (`&`).

```c
int age = 28;
int *p_int = &age;
```

Oftentimes we have a pointer, but we want to get access to the data that it points to. Not the address itself, but the value stored at that address.

We can use an asterisk (`*`) to do it. The `*` operator dereferences a pointer.

```c
int meaning_of_life = 42;
int *pointer_to_mol = &meaning_of_life;
int value_at_pointer = *pointer_to_mol;
// value_at_pointer = 42
```

It can be a touch confusing, but remember that the asterisk symbol is used for two different things:

1. Declaring a pointer type: `int *pointer_to_thing;`
2. Dereferencing a pointer value: `int value = *pointer_to_thing;` (retrieving the value) or `*pointer_to_thing = 20;` (modifying the value)

## Important things related to structs

- In C, structs are passed-by-value. Updating a field in the struct does not change the original struct
- To get the change to "persist", we can return the updated struct from the function (a new copy) or just pass struct's pointer, and dereference the pointer to modify the original struct

As you know, when you have a struct, you can access the fields with the dot (`.`) operator:

```c
coord_t point = {10, 20, 30};

printf("X: %d\n", point.x);
```

However, when you're working with a pointer to a struct, you need to use the arrow (`->`) operator:

```c
coord_t point = {10, 20, 30};
coord_t *ptrToPoint = &point;

printf("X: %d\n", ptrToPoint->x);
```

It effectively dereferences the pointer and accesses the field in one step. To be fair, you can also use the dereference and dot operator (`*` and `.`) to achieve the same result (it's just more verbose and less common):

```c
coord_t point = {10, 20, 30};
coord_t *ptrToPoint = &point;

printf("X: %d\n", (*ptrToPoint).x);
```

### Order of Operations

The `.` operator has a higher precedence than the `*` operator, so parentheses are necessary when using `*` to dereference a pointer before accessing a member... which is another reason why the arrow operator is so much more common.

## Void Pointers

A `void *` "void pointer" tells the compiler that this pointer could point to anything. This is why void pointers are also known as a "generic pointer".

Since void pointers do not have a specific data type, they cannot be directly dereferenced or used in pointer arithmetic without casting them to another pointer type first.

```c
int number = 42;
void *generic_ptr = &number;

// This doesn't work
printf("Value of number: %d\n", *generic_ptr);

// This works: Cast to appropriate type before dereferencing
printf("Value of number: %d\n", *(int *)generic_ptr);
```

A common pattern is to store generic data in one variable, and the type of that data in another variable. This is useful when you need to pass data around without knowing its type at compile time.

```c
typedef enum DATA_TYPE {
  INT,
  FLOAT
} data_type_t;

void printValue(void *ptr, data_type_t type) {
  if (type == INT) {
    printf("Value: %d\n", *(int *)ptr);
  } else if (type == FLOAT) {
    printf("Value: %f\n", *(float *)ptr);
  }
}

int number = 42;
printValue(&number, INT);

float decimal = 3.14;
printValue(&decimal, FLOAT);
```

# Arrays

## Declaration

```c
int numbers[5] = {1, 2, 3, 4, 5};
```

## Array as Pointer

```c
int *way_1 = numbers;
int *way_2 = &numbers[0];
```

## Accessing Elements via Indexing

```c
// Access the third element (index 2)
int way_1 = numbers[2];
int way_2 = *(numbers + 2);
```

## Array Casting

```c
#include <stdio.h>

typedef struct {
  int x;
  int y;
  int z;
} coord_t;

int main() {
  coord_t arr[3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};

  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
      printf("%d\n", *(int *)&arr[i] + j);
    }
  }

  return 0;
}
```

Because arrays are basically just pointers, and we know that structs are contiguous in memory, we can cast the array of structs to an array of integers:

```c
#include <stdio.h>

typedef struct {
  int x;
  int y;
  int z;
} coord_t;

int main() {
  coord_t arr[3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
  int *ptr = (int *)arr;

  for (int i = 0; i < 9; i++) {
    printf("%d\n", ptr[i]);
    // printf("%d\n", *(int *)&arr + i);
  }

  return 0;
}
```

## Array Decay to Pointers

So we know that arrays are like pointers, but they're not exactly the same. Arrays allocate memory for all their elements, whereas pointers just hold the address of a memory location. In many contexts, arrays decay to pointers, meaning the array name becomes "just" a pointer to the first element of the array.

### When Arrays Decay

Arrays decay when used in expressions containing pointers:

```c
int arr[5];
int *ptr = arr;          // 'arr' decays to 'int *'
int value = *(arr + 2);  // 'arr' decays to 'int *'
```

And also when they're passed to functions... so they actually decay quite often in practice. That's why you can't pass an array to a function by value like you do with a struct; instead, the array name decays to a pointer.

### When Arrays Don't Decay

- `sizeof` **Operator**: Returns the size of the entire array (e.g., `sizeof(arr)`), not just the size of a pointer
- `&` **Operator**: Taking the address of an array with `&arr` gives you a pointer to the whole array, not just the first element. The type of `&arr` is a pointer to the array type, e.g., `int (*)[5]` for an int array with 5 elements
- `Initialization`: When an array is declared and initialized, it is fully allocated in memory and does not decay to a pointer

# Enumerations

You can define a new enum type like this:

```c
typedef enum DaysOfWeek {
  MONDAY,
  TUESDAY,
  WEDNESDAY,
  THURSDAY,
  FRIDAY,
  SATURDAY,
  SUNDAY,
} days_of_week_t;
```

The `typedef` and its alias `days_of_week_t` are optional, but like with structs, they make the enum easier to use.

In the example above, `days_of_week_t` is a new type that can only have one of the values defined in the `enum`:

- `MONDAY`, which is 0
- `TUESDAY`, which is 1
- `WEDNESDAY`, which is 2
- `THURSDAY`, which is 3
- `FRIDAY`, which is 4
- `SATURDAY`, which is 5
- `SUNDAY`, which is 6

An enum is not a collection type like a struct or an array. It's just a list of integers constrained to a new type, where each is given an explicit name.

You can use the enum type like this:

```c
typedef struct Event {
  char *title;
  days_of_week_t day;
} event_t;

typedef struct Event {
  char *title;
  enum DaysOfWeek day;
} event_t;
```

## Non-Default Values

Sometimes, you want to set those enumerations to specific values. For example, you might want to define a program's exit status codes:

```c
typedef enum {
  EXIT_SUCCESS = 0,
  EXIT_FAILURE = 1,
  EXIT_COMMAND_NOT_FOUND = 127,
} ExitStatus;
```

Alternatively, you can define the first value and let the compiler fill in the rest (incrementing by 1):

```c
typedef enum {
  LANE_WPM = 200,
  PRIME_WPM, // 201
  CUBEY_WPM,  // 202
} WordsPerMinute;
```

## Switch Case

One of the best features of `enums` is that it can be used in switch statements.

- Avoid "magic numbers"
- Use descriptive names
- With modern tooling, will give you an error/warning that you haven't handled all the cases in your switch

```c
switch (logLevel) {
case LOG_DEBUG:
  printf("Debug logging enabled\n");
  break;
case LOG_INFO:
  printf("Info logging enabled\n");
  break;
case LOG_WARN:
  printf("Warning logging enabled\n");
  break;
case LOG_ERROR:
  printf("Error logging enabled\n");
  break;
default:
  printf("Unknown log level: %d\n", logLevel);
  break;
}
```

You'll notice that we have a `break` after each case. If you do not have a `break` (or `return`), the next case will still execute: it "falls through" to the next case.

In some rare cases, you might want the fallthrough:

```c
switch (errorCode) {
case 1:
case 2:
case 3:
  printf("Minor error occurred. Please try again.\n");
  break;
case 4:
case 5:
  printf("Major error occurred. Restart required.\n");
  break;
default:
  printf("Unknown error.\n");
  break;
}
```

## Sizeof Enum

Generally, enums in C are the same size as an `int`. However, if an enum value exceeds the range of an `int`, the C compiler will use a larger integer type to accommodate the value, such as an `unsigned int` or a `long`.

# Union

`union` is just a combination of the two concepts with `struct` and `enum`.

```c
typedef union AgeOrName {
  int age;
  char *name;
} age_or_name_t;
```

The `age_or_name_t` type can hold either an `int` or a `char *`, but not both at the same time (that would be a `struct`). We provide the list of possible types so that the C compiler knows the maximum potential memory requirement, and can account for that. This is how the union is used:

```c
age_or_name_t lane = { .age = 29 };
printf("age: %d\n", lane.age);
// age: 29
```

Here's where it gets interesting. What happens if we try to access the `name` field (even though we set the `age` field)?

```c
printf("name: %s\n", lane.name);
```

A `union` only reserves enough space to hold the largest type in the union and then all of the fields use the same memory.

Then if we try to access `.name`, we read from the same block of memory but try to interpret the bytes as a `char *`, which is undefined behavior. Put simply, setting the value of `.age` overwrites the value of `.name` and vice versa, and you should only access the field that you set.

## Memory Layout

Unions store their value in the same memory location, no matter which field or type is actively being used. That means that accessing any field apart from the one you set is generally a bad idea.

## Union Size

A downside of unions is that the size of the union is the size of the largest field in the union. Take this example:

```c
typedef union IntOrErrMessage {
  int data;
  char err[256];
} int_or_err_message_t;
```

The `int_or_err_message_t` union will take 256 bytes whether it use `err` or not.

## Helper Fields

One interesting (albeit not commonly used) trick is to use unions to create "helpers" for accessing different parts of a piece of memory. Consider the following:

```c
typedef union Color {
  struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
  } components;
  uint32_t rgba;
} color_t;
```

Only 4 bytes are used. And, unlike in 99% of scenarios, it makes sense to both set and get values from this union through both the `components` and `rgba` fields! Both fields in the union are exactly 32 bits in size, which means that we can "safely" (?) access the entire set of colors through the `.rgba` field, or get a single color component through the `.components` field.

The convenience of additional fields, with the efficiency of a single memory location!

# Memory-Related Perils and Pitfalls

- Dereferencing bad pointers
- Reading uninitialized memory
- Overwriting memory
- Referencing nonexistent variables
- Freeing blocks multiple times
- Referencing freed blocks
- Failing to free blocks

## Operators Precedence

| Operators                                                          | Associativity |
| ------------------------------------------------------------------ | ------------- |
| `()`, `[]`, `->`, `.`                                              | left to right |
| `!`, `~`, `++`, `--`, `+`, `-`, `*`, `&`, `(type)`, `sizeof`       | right to left |
| `*` `/`, `%`                                                       | left to right |
| `+`, `-`                                                           | left to right |
| `<<`, `>>`                                                         | left to right |
| `<`, `<=`, `>`, `>=`                                               | left to right |
| `==`, `!=`                                                         | left to right |
| `&`                                                                | left to right |
| `^`                                                                | left to right |
| `\|`                                                               | left to right |
| `&&`                                                               | left to right |
| `\|\|`                                                             | left to right |
| `?:`                                                               | right to left |
| `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `^=`, `\|=`, `<<=`, `>>=` | right to left |
| `,`                                                                | left to right |

:::important
Unary `+`, `-`, and `*` have higher precedence than binary forms.
:::

## Pointer Declarations Quiz

- `int *p`: **p** is a pointer to **int**
- `int *p[13]`: **p** is an **array[13]** of pointer to **int**
- `int *(p[13])`: **p** is an **array[13]** of pointer to **int**
- `int **p`: **p** is a pointer to a pointer to an **int**
- `int (*p)[13]`: **p** is a pointer to an **array[13]** of **int**
- `int *f()`: **f** is a function returning a pointer to **int**
- `int (*f)()`: **f** is a pointer to a function returning **int**
- `int (*(*f())[13])()`: **f** is a function returning pointer to an **array[13]** of pointers to functions returning **int**
- `int (*(*x[3])())[5]`: **x** is an **array[3]** of pointers to functions returning pointers to **array[5]** of **int**s
