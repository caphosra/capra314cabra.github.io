---
title: "Install lli, a tool of LLVM, to Windows"
date: 2020-03-08T09:12:43+09:00
description: "I had missed to install lli, a tool of LLVM, to Windows so I want you not to miss it like me."
draft: false
author: caphosra
tags: ["CPlusPlus", "LLVM"]
keyword: "LLVM,Windows,lli,llc,llvm-as"
---

<img src="https://llvm.org/img/LLVM-Logo-Derivative-1.png" alt="LLVM logo" class="center" width="256" height="256" />

Good morning! I'm capra314cabra, who am under making new language.  
On this article, I will tell you how to get tools of LLVM. You might think it should be easy but I felt not.
I hope you read this and save huge amount of time from reading heap of documents.

## TL;DR

At last, I downloaded and built all the code of LLVM on my PC.
And I got tools of LLVM, including `lli`.

## So, what is LLVM?

> The LLVM compiler infrastructure project is a set of compiler and toolchain technologies, which can be used to develop a front end for any programming language and a back end for any instruction set architecture.

[wikipedia LLVM](https://en.wikipedia.org/wiki/LLVM)

That is all. I won't describe more. If you want to know more, ~~please google them~~.

## My first trial (Failed)

I had believed that I could get it from the LLVM official site easily.  
I went to [LLVM release page](http://releases.llvm.org/download.html) and
tapped `Windows (64bits)` on LLVM9.0.0 section.  
After a munite, I found a windows installer in the Download folder and ran it.

...It seemed to succeed, but I got nothing tools but Clang. I just wanted to get `lli`, `llc` and `llvm-as`! not Clang!

## My second trial (Failed)

Next, I thought that I could get binaries from other people who built LLVM.  
I searched sites but I didn't find binaries of LLVM 9.0. (There are many of older version.)

## At last...

At last, I downloaded and built all the code of LLVM.  
These were five steps:

1. Get `llvm-9.0.1.src.tar.xz` from [LLVM Project(Github)](https://github.com/llvm/llvm-project/releases).
2. Extract it. (I used 7zip.)
3. Run CMake to get a solution file. It also works fine with the default values.
4. Open it with Visual Studio and build a solution file. I recommend to set the configuration as "Release".
5. You can find many tools of LLVM in `Release` directory.
6. (Optional) Add the directory to PATH.

On my case, it requires only 2.8GB space.  
See you later on LLVM world!
