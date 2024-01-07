---
title: "[LLVM] How to show a float value by using printf"
date: 2020-05-02T11:39:02+09:00
description: "Generate LLVM IR that displays the float type variable by using LLVM's C++ API."
keyword: "llvm,printf,float,ir,c++"
author: "caphosra"
tags: ["CPlusPlus", "LLVM"]
draft: false
---

I will introduce how to generate LLVM IR that displays the float type variable by using LLVM's C++ API.

## My environment

- LLVM: LLVM 9.0.1
- Compiler: cl.exe (included in Visual Studio 2019)

## What we want

The goal of this time is to output an LLVM IR that behaves the same as the following C program.
Add two float values together and do printf.

``` c
#include <stdio.h>

int main() {
    float f1 = 3.5;
    float f2 = 6.4;
    printf("%f + %f = %f\n", f1, f2, f1 + f2);
    return 0;
}
```

## 1. Define printf

Let's implement C++ code which generates LLVM IR !
First, prepare to use the LLVM API like this.

``` C++
llvm::LLVMContext context;
llvm::IRBuilder<> Builder(context);
llvm::Module* module;

module = new llvm::Module("test.ll", context);
```

It is tired to define basic types, such as `int`, `float` each times we use them. So I made macros which do.
Don't assume that it's common to define this macros. It's just that I don't want to write too long code.

``` C++
#define LLVM_INT8_PTR_TY llvm::Type::getInt8PtrTy(context)
#define LLVM_INT32_TY llvm::Type::getInt32Ty(context)
#define LLVM_FLOAT_TY llvm::Type::getFloatTy(context)
#define LLVM_DOUBLE_TY llvm::Type::getDoubleTy(context)
```

Now, we move on the implementation phase.
Recall the definition of `printf`.
The function, `printf` uses a format string and some values as arguments.
Also it returns Int32 value. (I've rarely used it because `printf` seldom fails.)

``` c
int printf(const char* format, ...);
```

Keep reminding the definition and create a "FunctionType", which has information about the functions, by throwing the types of the arguments and the return type into `llvm :: FunctionType :: get`.
Note that `char*` is also represented as `Int8Ptr` on LLVM.

``` C++
std::vector<llvm::Type*> printfFuncArgs;
printfFuncArgs.push_back(LLVM_INT8_PTR_TY);

auto printfFuncType = llvm::FunctionType::get(
    LLVM_INT32_TY,
    printfFuncArgs,
    true
);
```

Next, let's create the main body of printf. It will be as follows.  
Note that this code is on the basis of that `printf` will be linked by linker.
So, we don't have to implement `printf` from mass of instructions.

``` C++
auto printfFunc = llvm::Function::Create(
    printfFuncType,
    llvm::GlobalValue::ExternalLinkage,
    "printf",
    module);

printfFunc->setCallingConv(llvm::CallingConv::C);
```

## 2. Define main (Abbreviated)

This is not what I want to describe. So, I make this section shorter.  
Please copy and paste the code or read between the lines.  
Basically, it is the same as printf, so it should be easy to understand.

``` C++
std::vector<llvm::Type*> mainFuncArgs;

auto mainFuncType = llvm::FunctionType::get(
    LLVM_INT32_TY,
    mainFuncArgs,
    false
);

auto mainFunc = llvm::Function::Create(
    mainFuncType,
    llvm::GlobalValue::ExternalLinkage,
    "main",
    module);

mainFunc->setCallingConv(llvm::CallingConv::C);
```

Next, prepare to put the instructions into `main`. This is not the essence either, so it omitted too.  
After running `SetInsertPoint`, we can put instructions by calling functions which are formatted like `Builder.CreateSomething`.

``` C++
auto mainBlock = llvm::BasicBlock::Create(
    context,
    "entry",
    mainFunc
);
Builder.SetInsertPoint(mainBlock);
```

## 3. Allocate two float variables and add them

let's prepare a value to be used for addition.

In the first line, we allocate the memory which is as large as `float`.  
In the second line, we initialize the variable by setting a constant value to.

``` C++
auto f1PtrVal = Builder.CreateAlloca(
    LLVM_FLOAT_TY,
    llvm::ConstantInt::get(LLVM_INT32_TY, 1)
);

Builder.CreateStore(
    llvm::ConstantFP::get(LLVM_FLOAT_TY, 3.5),
    f1PtrVal
);
```

Define `f2` like `f1`. (If you already forget what f1 and f2 are, please scroll up and read the C code we targeted.)

``` C++
auto f2PtrVal = Builder.CreateAlloca(
    LLVM_FLOAT_TY,
    llvm::ConstantInt::get(LLVM_INT32_TY, 1)
);

Builder.CreateStore(
    llvm::ConstantFP::get(LLVM_FLOAT_TY, 6.4),
    f2PtrVal
);
```

Addition is not possible between pointers, so load two values and implement with the FAdd instruction.

``` C++
auto f1Val = Builder.CreateLoad(f1PtrVal);
auto f2Val = Builder.CreateLoad(f2PtrVal);
auto calcVal = Builder.CreateFAdd(f1Val1, f2Val2);
```

Now, we have a answer of the addition in `calcVal`.

## 4. It's time to call printf but ...

Before calling `printf`, we have to define the format string. It is easy. Just call `CreateGlobalStringPtr` with a constant character string. The return value represents `Int8Ptr`, which is equivalent to `char*`.

``` C++
auto formatVal = Builder.CreateGlobalStringPtr("%f + %f = %f");
```

It's time to call printf. I think all the people who read this article wait this time.   
Pack the arguments into `vector` and serve it to `printf`. It's easy too. Thanks to LLVM !

``` C++
std::vector<llvm::Value*> args;
args.push_back(formatVal);
args.push_back(f1Val);
args.push_back(f2Val);
args.push_back(calcVal);

Builder.CreateCall(printfFunc, args);
```

Don't forget to add a `RET` instruction for the main function. This is, you know, equivalent to `return 0;`.  
And also to write lines for generating LLVM IR.

``` C++
Builder.CreateRet(llvm::Constant::getNullValue(LLVM_INT32_TY));

//
// The followings are required to emit LLVM IR file.
//
llvm::verifyModule(*module);

std::error_code errorcode;
auto stream = new llvm::raw_fd_ostream("test.ll", errorcode);

module->print(*stream, nullptr);
```

You can check [full code](#full-code) if you want.

## Execute it and encountere the problem

After running this C++ code, you should get an LLVM IR file named `test.ll` in the same directory.  
Now let's run the LLVM IR file using `lli`.

(If you haven't installed `lli` yet, please read [Install lli, a tool of LLVM, to Windows]({{< ref "/posts/llvm-lli-install" >}}).)

``` bash
# Real

$ lli test.ll
0.000000 + 0.000000 = 0.000000
```

Oh my gosh! It is not what we expected. We want to see:

``` bash
# Expected

$ lli test.ll
3.500000 + 6.400000 = 9.900000
```

## Why it shows zeros

The formatter `%f` in `printf` actually outputs a variable as a double type, and in many cases, casting a `float` value to a `double` is automatically done.  
But on this way, it hadn't been done.

## All we have to do is to cast manually

Use the `FPEXT` instruction. This can be used to change the floating point type to a larger one. (I don't think it's strictly doing cast ...)

``` C++
auto f1DoubleVal = Builder.CreateFPExt(f1Val, LLVM_DOUBLE_TY)
auto f2DoubleVal = Builder.CreateFPExt(f2Val, LLVM_DOUBLE_TY)
```

After that, call `printf` as follows instead of the previous way.

``` C++
std::vector<llvm::Value*> args;
args.push_back(formatVal);
args.push_back(f1DoubleVal);
args.push_back(f2DoubleVal);
args.push_back(calcDoubleVal);

Builder.CreateCall(printfFunc, args);
```

I'm so excited. It works right...?

``` bash
$ lli test.ll
3.500000 + 6.400000 = 9.900000
```

``` c
#include <stdio.h>

int main() {
    float f1 = 3.5;
    float f2 = 6.4;
    printf("%f + %f = %f\n", f1, f2, f1 + f2);
    return 0;
}
```

Oh! Yes! We got the same output as the target C code!

In conclusion, all we have to do is to remember this sentence:

> If you want to display a `float` value with `printf`, let's cast it to `double` first.

## Full code

https://gist.github.com/caphosra/9cd38e8658bb2d07cb9306b73435fada
