---
title: "[C# tips] #3 Run C# in interactive ways"
date: 2020-05-24T06:35:55+09:00
description: "You may use Python to do simple calculations. It's very convenient to run interactively. But the same thing can be done with C#."
keyword: "C#,tips,today,interactive,interpret"
author: "caphosra"
tags: ["CSharp"]
series: ["CSharp tips"]
draft: false
---

You may use Python to do simple calculations. It's very convenient to run interactively. But the same thing can be done with C#.  
I will introduce how to do that.

## What is an interactive form?

When a user inputs a statement or expression, the tool evaluates it.  
That is the simplest introduction I think.  
In Python, it looks like this:

``` python
>>> a = 10
>>> a * a * 3.14
314.0
```

It's calculated on the spot, so it's very useful as a way to execute a temporary code. (I use it when I want to judge whether the number is a prime number or not.)

## C# cannot be run interactively because it's a static language. Isn't it?

While Python executes dynamically, C# is a static language, which we have to compile for execution.  
And you may think the need to compile is too time consuming and therefore fatal to run interactively...

[Wikipedia Dynamic programming language](https://en.wikipedia.org/wiki/Dynamic_programming_language)

But it's not true.

## Extensions to run C# interactively

You can't run C# interactively by default.  
However there are a lot of people who want to run C# interactively and you can do that by using extensions which they developed!  
I will introduce some extensions.

### C# REPL

It is provided by the Mono project, which is famous for its C# runtime implementation and open source.  
[C# REPL](https://www.mono-project.com/docs/tools+libraries/tools/repl/).

Usage is very simple. Install Mono and just execute:

```bash
$ csharp
csharp> using System;
csharp> var a = 10;
csharp> a * a * Math.PI;
314.159265358979
```

If you are using Mono C#, try it now.

### dotnet script

This can be used on .NET Core while C# REPL runs on Mono.  
[dotnet script](https://github.com/filipw/dotnet-script)

You can install it as a .NET global tool by executing:

``` bash
$ dotnet tool install -g dotnet-script
```

Once installed, you can run it with the `dotnet script` command.

```
$ dotnet script
> var a = 10;
> a * a * Math.PI
314.1592653589793
```

Also dotnet script can dynamically execute C# files whose extension `csx` and let us to use unique commands such as `#r`.  
It's so convenient.

Note that .NET Core 2.1 or higher is required.

### dotnet interactive

This is an official extension for interactive execution.
[dotnet interactive](https://github.com/dotnet/interactive)

With this extension, you will be able to run C# on a Jupyter notebook.

You can install it by using the following commands.

``` bash
$ dotnet tool install -g Microsoft.dotnet-interactive
$ dotnet interactive jupyter installation
```

~~I know that when you open the Jupyter notebook, your body will move freely and start to type Python codes not C# codes.~~

## Summary

If you create a C# project file for each trivial calculation, switch to interactive C# now. It saves your time.  
~~Normally, to use Python is the best way.~~
