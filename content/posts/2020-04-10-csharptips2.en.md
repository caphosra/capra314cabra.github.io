---
title: "[C# tips] #2 Access private members"
date: 2020-05-02T17:58:27+09:00
description: "I will tell you how to use System.Reflection to access private members."
keyword: "C#,tips,today,reflection,system"
author: "caphosra"
tags: ["CSharp"]
series: ["CSharp tips"]
draft: false
---

I introduced C# Linq on the previous article [#1](https://caphosra.github.io/en/posts/2020-03-20-onepoint-csharp/).  
Today's theme is "Access private members".

## Attention

This article will show you how to use `System.Reflection` to access private members. However, please do so at your own risk. (It's not a dangerous operation, but if you do it for codes other people wrote, it can be a copyright infringement.)

## I'll show give a quiz to you!

You have been given a variable of the following class.  
Apparently there is a float variable in this class, which is initialized with a secret value.  
Mr. Capra wants to know the secret value because he loves to reveal secrets.  
How can he get a secret value?

``` C#
public class HasSecret
{
    private float ????? = ?????;
    public float dummy1 = 3.14f;
    private int dummy2 = 314;
}
```

## It's easy! We just use disassemble tools!

Certainly. You can do it instantly by using dnSpy, a disassembler which is extremely powerful in C#. But do so, this article goes meaningless...

[GitHub - 0xd4d/dnSpy](https://github.com/0xd4d/dnSpy)

So let's access the variables in `HasSecret` from the C# code without disassemblers.

## Access straight

First, try accessing `dummy2` without thinking.

``` C#
var secret = new HasSecret();
Console.WriteLine(secert.dummy2);
```

```
error CS0122: 'HasSecret.dummy2' is inaccessible due to its protection level
```

Of course an error occurred. If you can access it by this way, there is no point hiding implementation.

You don't even know the variable name. Do you want to find the name by enumeration ? It's non sense.  
So what should we do?

## Use System.Reflection

Use `System.Reflection` to solve this problems.  
`System.Reflection` is a namespace with classes that provide a way to handle things dynamically using meta information.

Let's use them to access private variables !

Use the `GetType` function to get the type dynamically. You can also use `typeof` keyword, which do statically.  
Note that they give back a type as `System.Type`.

``` C#
// using System.Reflection;

var secret = new HasSecret();

var type = secret.GetType();
```

After you receive the type as a variable, call `GetFields`. As you can imagine from the name, it is a function that gets the information of all the fields that satisfy the specific conditions. By the way, the return value's type is `System.Reflection.FieldInfo[]`.

``` C#
var members = type.GetFields(
    BindingFlags.Instance |
    BindingFlags.Public |
    BindingFlags.NonPublic
); // FieldInfo[]

// Show each field names
foreach(var member in members)
{
    Console.WriteLine(member.Name);
}
```

```
$ dotnet run
password
dummy1
dummy2
```

We get the names of all the fields contained in `HasSecret`.  
There is a variable called `password` in that output. It's so strange, isn't it? Next, let's read the value of it.

## Access private members

Use `GetFields` and handle the result with calling `Where` and `FirstOrDefault`.
As result, we get the `FieldInfo` of the Field whose name is `password`.

Then call `GetValue`. It is a function that gets the value of the variable from the instance based on the information in `FieldInfo`.  
Note that `GetValue` returns the value as `System.Object`.
``` C#
// using System.Linq;

var passwordVal = members // FieldInfo[]
    .Where(info => info.Name == "password") // IEnumerable<FieldInfo>
    .FirstOrDefault() // FieldInfo
    .GetValue(secret); // Object

Console.WriteLine((float)passwordVal); // Cast to float
```

(Note: Strictly speaking, the return value of `GetValue` is `object?` but not `object`. I will introduce how `?` works later.)

```
$ dotnet run
2.71828
```

This is the value of `password`. It seems that it is the number of Napier. Now that we have the full picture of `HasSecret`, we have achieved our goal!

``` C#
public class HasSecret
{
    private float password = 2.71828f;
    public float dummy1 = 3.14f;
    private int dummy2 = 314;
}
```

## Change the value of a private variable

However, Mr. Capra, who doesn't like the answer being the number of Napiers, wants to change `password` to the pi.

This can also be done by a similar operation as above.  
Just get the variable `FieldInfo` with the name `password` and call the function `SetValue` in the same way as when you got the value.

``` C#
members
    .Where(info => info.Name == "password")
    .FirstOrDefault()
    .SetValue(secret, 3.1415f);
```

## Memo

Except for some situations, the heavy use of `System.Reflection` is an evil road and its performance is much worse than accessing directly. (Although speeding up using `Delegate` or using `GetValueDirect` will be somewhat faster.)  
If you really want to access private members, or if you want to analyze a library whose source code has been lost, please use it. (~~ In that case, dnSpy is overwhelmingly convenient.~~)