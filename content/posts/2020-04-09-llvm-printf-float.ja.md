---
title: "[LLVM] printfでFloat型の足し算の結果を表示する"
date: 2020-04-09T13:06:28+09:00
description: "LLVMのC++ APIを使用し、printfを呼び出してfloat型の変数を表示するLLVM IRを出力するまで行います。"
keyword: "llvm,printf,float,ir,c++"
author: "caphosra"
tags: ["CPlusPlus", "LLVM"]
draft: false
---

LLVMのC++ APIを使用して、printfでFloat同士の足し算の結果を表示するLLVM IRを表示するまでを行いたいと思います。

## 筆者の環境

- LLVM: LLVM 9.0.1
- Compiler: Visual Studio付属のcl.exe

## こんなコードを出力したい

以下のC言語のプログラムと同じ動きをするLLVM IRを出力するのが今回の目標です。  
floatの値を2つ足し算をしてprintfですね。

``` c
#include <stdio.h>

int main() {
    float f1 = 3.5;
    float f2 = 6.4;
    printf("%f + %f = %f\n", f1, f2, f1 + f2);
    return 0;
}
```

## まずはprintfを定義しよう

まず、printfの定義について思い出してみましょう。  
printfは関数の引数として、フォーマットの文字列と、複数の値をとることができます。  
戻り値はInt32型で帰ってきます。(私は戻り値を使ったことがあまりないです。)

``` c
int printf(const char* format, ...);
```

それではC++のコードで実装していきます。  
まず、LLVMのサポートClassを初期化していきましょう。  
Builderが大文字なのは、LLVMの公式Tutorialで大文字になっていたので、それに慣れてしまったからです。変数名は勿論変えていただいて問題ありません。

``` C++
llvm::LLVMContext context;
llvm::IRBuilder<> Builder(context);
llvm::Module* module;

module = new llvm::Module("test.ll", context);
```

これからいちいち型を定義するのは大変なので、基本的な型はマクロとして簡単にかける様にしておきます。これは本当に我流なのでこのマクロを定義するのが一般的だと思い込まないでください...

``` C++
#define LLVM_INT8_PTR_TY llvm::Type::getInt8PtrTy(context)
#define LLVM_INT32_TY llvm::Type::getInt32Ty(context)
#define LLVM_FLOAT_TY llvm::Type::getFloatTy(context)
#define LLVM_DOUBLE_TY llvm::Type::getDoubleTy(context)
```

これで前準備は終了です。printfの定義に移っていきましょう。  
まずは関数の"型"を定義します。戻り値の型とvectorに詰めた引数の型を`llvm::FunctionType::get`に投げて、関数の型を受け取ります。  
Int8型(Char型)のポインターを引数にして、戻り値をInt32型で返します。

``` C++
std::vector<llvm::Type*> printfFuncArgs;
printfFuncArgs.push_back(LLVM_INT8_PTR_TY);

auto printfFuncType = llvm::FunctionType::get(
    LLVM_INT32_TY,
    printfFuncArgs,
    true
);
```

続けてprintf本体を作成しましょう。以下のようになります。

``` C++
auto printfFunc = llvm::Function::Create(
    printfFuncType,
    llvm::GlobalValue::ExternalLinkage,
    "printf",
    module);

printfFunc->setCallingConv(llvm::CallingConv::C);
```

## main関数を定義しよう(省略気味)

ここは本質ではないのでコードを書きます。  
コピペするか、コードの内容を察してください。  
基本、printfの時と同じなので比べるとわかりやすいかもしれません。

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

## main関数の中へ(省略気味)

main関数の中に命令を並べる準備をしましょう。これも本質ではないので省略気味です。  
これ以降、`Builder.CreateSomething`みたいな関数を呼ぶと、main関数内に挿入されるようになります。

``` C++
auto mainBlock = llvm::BasicBlock::Create(
    context,
    "entry",
    mainFunc
);
Builder.SetInsertPoint(mainBlock);
```

## floatで足し算をしよう

やっと本題です。まずは、足し算に使用する値を用意しましょう。

1行目ではFloatのサイズだけメモリをAllocateしています。この時の戻り値が表現している型はポインターなので注意です。  
2行目では値を初期化しています。定数値を定義してStoreするという形で実現します。

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

f1と同じようにf2を定義したものとします。(f1, f2って何ぞや、とおもった人は上にある目標のC言語コードを読んでください。)  
足し算はポインター同士ではできないので、二つの値をLoadしてあげてFAdd命令で実現します。  

``` C++
auto f1Val = Builder.CreateLoad(f1PtrVal);
auto f2Val = Builder.CreateLoad(f2PtrVal);
auto calcVal = Builder.CreateFAdd(f1Val1, f2Val2);
```

## printfをいよいよ呼び出そう しかし...

まずformatの文字列を定義します。Constantな文字列でやっていくので、`CreateGlobalStringPtr`に投げます。戻り値は、Int8型のポインターを表現したものです。

``` C++
auto formatVal = Builder.CreateGlobalStringPtr("%f + %f = %f");
```

皆さんお待ちかね、遂にprintfを呼び出します。  
printfを呼び出す命令に引数たちをvectorに詰めたものを渡します。

``` C++
std::vector<llvm::Value*> args;
args.push_back(formatVal);
args.push_back(f1Val);
args.push_back(f2Val);
args.push_back(calcVal);

Builder.CreateCall(printfFunc, args);
```

main関数に対するRet命令を加えましょう。Int32の0を戻り値として返しています。

``` C++
Builder.CreateRet(llvm::Constant::getNullValue(LLVM_INT32_TY));
```

これまでに定義した命令たちをLLVM IRとして書き込んで出力しましょう。  
この出力方法なんですが、それっぽい名前の関数をドキュメントから探して動かしてみたら動いた、というものなので、正しい方法を知っている方、ぜひコメントで教えてください。

``` C++
llvm::verifyModule(*module);

std::error_code errorcode;
auto stream = new llvm::raw_fd_ostream("test.ll", errorcode);

module->print(*stream, nullptr);
```

## 実行すると...

このC++のコードを実行すると、同じディレクトリ内に`test.ll`というLLVM IRのファイルができているはずです。  
続けてLLVM IRのファイルを実行してみましょう。`lli`を使用します。

`lli`がインストールされていない方は、以下を参考にしてください。

[LLVMをWindowsで使いたくて入れたらlliなかった話]({{< ref "/posts/llvm-lli-install" >}})

``` bash
$ lli test.ll
0.000000 + 0.000000 = 0.000000
```

実行結果はこんな感じになったと思います。  
なんということでしょう。出力の値が0になってしまいました。

## なぜ0になってしまったのか

この理由は実は私も最初全く分かりませんでした。  
printfに原因があるのではないか、と思い、調べてみると気になる記事を見つけました。

[Qitta - printf() に float/double を渡したときの挙動と %lf の意義 @lo48576](https://qiita.com/lo48576/items/9901f7d52692567b931c)

printfにおける`%f`は実はdouble型を出力するもので、float型を投げるとdouble型にCastされるようです。  
LLVM IRによってこのCastが行われずに、Float型がDouble型として読まれて0になってしまった、という仮説が頭に浮かびます。(結果的に正しかったみたいです。)

## 表示する前にDouble型にCastする

自動でDouble型にしてくれないのであれば、自分でDouble型にしたいと思います。  
FPExt命令を利用しましょう。これを使うと、浮動小数点数の型をより大きいものへ変更できます。(厳密にはCastではない気がしますが...)

``` C++
auto f1DoubleVal = Builder.CreateFPExt(f1Val, LLVM_DOUBLE_TY)
```

後は、先ほどのprintfを呼び出した部分の値を以下のように置き換えます。

``` C++
std::vector<llvm::Value*> args;
args.push_back(formatVal);
args.push_back(f1DoubleVal);
args.push_back(f2DoubleVal);
args.push_back(calcDoubleVal);

Builder.CreateCall(printfFunc, args);
```

この変更を加えた後、実行してLLVM IRのファイルを入手し、それを実行すると...

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

遂に目標のC言語のコードと同じ出力を得ました。

ソースコード全文と出力されたLLVM IRは以下から見ることができます。

[コード全文](https://gist.github.com/caphosra/9cd38e8658bb2d07cb9306b73435fada)

## まとめ

printfでFloat型を表示したいときはDouble型にCastしてからにしましょう。
