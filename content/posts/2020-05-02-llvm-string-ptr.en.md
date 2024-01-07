---
title: "[LLVM] How to solve CreateGlobalStringPtr crash"
date: 2020-05-02T07:51:32+09:00
description: "I encountered the situaton that CreateGlobalStringPtr failed in the block of if statement, so I will introduce the way to solve it."
keyword: "CreateGlobalStringPtr,LLVM,crash,failed,error"
author: "caphosra"
tags: ["LLVM", "CPlusPlus"]
draft: false
---

I encountered the situaton that CreateGlobalStringPtr failed in the block of if statement, so I will introduce the way to solve it. (Also I found it had been my fault, but you can be.)

## The error that occurred

First, let's implement if statements frankly.

``` C++
auto ifblock = llvm::BasicBlock::Create(module->getContext(), "then");

auto mergeblock = llvm::BasicBlock::Create(module->getContext(), "merged");
```

This is the part where we declare two Basic Blocks, one will be the inside of the if statement and the other will be the bottom of the end of the if statement.

``` C++
builder->CreateCondBr(match, ifblock, mergeblock);

builder->SetInsertPoint(ifblock);

auto strptr = builder->CreateGlobalStringPtr("Hello World"); // ERROR !

builder->CreateBr(mergeblock);
```

If it behaves as we expected, it will create a branch, do `SetInsertPoint` to the block named "then", allocate the character string" Hello World" in the global space and get its pointer.

Assuming that you have done this operation in a function, it should be almost equivalent to the code below.

``` C++
const char* str = "Hello World";

void somefunc() {
    bool match;

    if (match) {
        // Create global string poiter and it points "HelloWorld".
        auto strptr = str;
    }
}
```

But this code fails. Why.

## Pay attention to the parent function of BasicBlock!

You may have realized. (I'm not bright at all so it took me two hours to solve it...)
The parent functions of `ifblock` and `mergeblock` are not specified. The function, `BasicBlock::Create` can be used without specifying the parent function, so I wasn't noticed.

``` C++
BasicBlock::Create(LLVMContext &Context, const Twine &Name="", Function *Parent=nullptr, BasicBlock *InsertBefore=nullptr);
```

[llvm::BasicBlock Class Reference](https://llvm.org/doxygen/classllvm_1_1BasicBlock.html)

Some operations can be performed without specifying the parent function, but calling `CreateGlobalStringPtr` requires the parent function and BasicBlock.

In summary, it means that you cannot call `CreateGlobalStringPtr` without specifying the parent function.

## [Tips] Get the currently inserted function

It can be done by getting the current BasicBlock and then its parent function.

``` C++
auto parent = builder->GetInsertBlock()->getParent();
```

Now, we found that just rewriting like this fix the error.

``` C++
auto ifblock = llvm::BasicBlock::Create(module->getContext(), "then", parent);

auto mergeblock = llvm::BasicBlock::Create(module->getContext(), "merged", parent);
```