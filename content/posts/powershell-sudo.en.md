---
title: "How to use 'sudo' in Powershell"
date: 2019-12-12T10:47:01+09:00
description: "We know that sudo command on bash is so useful and there is no command like that on Powershell. I will explain how to implement a command like sudo."
draft: false
author: caphosra
tags: ["Powershell"]
keyword: "sudo,powershell"
---

In this article, I will explain how to implement a command like `sudo` on Powershell.

On Powershell, there are no command with which you can run other commands as a administrator. And if you want to do something as a administrator, you have to open a administrator's Powershell by GUI.  
It's troublesome! I wish we always want to do everything on CUI!

I hope this article helps many people.

## Plan

Implement a function that is similar to `sudo` and set it as a Powershell alias.

## How to do so

First, start Powershell and open the file whose path is `$profile`. By the way, I have opened it by Visual Studio Code.

``` powershell
pwsh
# PowerShell 6.2.3
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# https://aka.ms/pscore6-docs
# Type 'help' to get help.

code $profile
# notepad $profile
# vim $profile
# emacs $profile
# etc..
```

I'm using Powershell that depends not on .NET Framework but on .NET Core. So, if you want to do so on the other, you have to replace "pwsh" with "powershell" before running it.

Second, you write a following code on it and save the file.

``` powershell
# A function that runs some commands with administrator rights.
function SudoRun
{
    # Set commands to $program.
    foreach($arg in $args)
    {
        $program = "$program $arg"
    }

    # Run it by Powershell with administrator rights.
    pwsh -command "Start-Process -Verb runas $program"
}

# Set the function as an new alias.
Set-Alias -Name sudo -Value SudoRun
```

That's all.  
You can now use `sudo` command on Powershell! (Reopening Powershell windows requried.)

## Problems

As this alias simply executes the command in a different process, there are no outputs that will be shown.  
For example: 

``` powershell
sudo pwd
# There is no outputs...
```

I'm thinking a solution.  
If you have any good ideas, please tell me that through the comment field.
