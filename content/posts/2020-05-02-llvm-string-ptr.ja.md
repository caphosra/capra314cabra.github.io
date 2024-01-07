---
title: "[LLVM] CreateGlobalStringPtrがクラッシュするときの対処法"
date: 2020-05-02T06:12:01+09:00
description: "CreateGlobalStringPtrをif文のブロックの中で失敗したので、それを解決する方法をご紹介します。"
keyword: "CreateGlobalStringPtr,LLVM,失敗,クラッシュ,エラー"
author: "caphosra"
tags: ["LLVM", "CPlusPlus"]
draft: false
---

CreateGlobalStringPtrをif文のブロックの中で失敗したので、それを解決する方法をご紹介します。

## 発生したエラー

先ずは愚直にif文を実装していきましょう。

``` C++
auto ifblock = llvm::BasicBlock::Create(module->getContext(), "then");

auto mergeblock = llvm::BasicBlock::Create(module->getContext(), "merged");
```

ブランチの分かれた部分と合流部分ですね。

``` C++
builder->CreateCondBr(match, ifblock, mergeblock);

builder->SetInsertPoint(ifblock);

auto strptr = builder->CreateGlobalStringPtr("Hello World"); // ERROR !

builder->CreateBr(mergeblock);
```

その後でブランチを組込んで、if文の中に`SetInsertPoint`してから、"Hello World"という文字列をグローバル空間に確保してポインターを取得します。  
この際、期待通りの動作であればグローバル空間に"Hello World"と書き込んでから、そのポインターを取得するという操作になります。  
今、適当な関数の中のBasicBlockで、この操作を行ったものと仮定すれば、以下のようなコードとほぼ同等なはずです。

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

しかし、このコードは失敗してしまいます。なぜでしょうか。

## BasicBlockの親の関数に注意!

鋭い方はもうお気づきでしょうが、(私は全く鋭くないので気づくのに2時間かかりました)  
`ifblock`と`mergeblock`の親の関数が指定されていません。`BasicBlock::Create`は親の関数を指定しなくても使えるので、意外と気づかないではまってしまいました。

``` C++
BasicBlock::Create(LLVMContext &Context, const Twine &Name="", Function *Parent=nullptr, BasicBlock *InsertBefore=nullptr);
```

[llvm::BasicBlock Class Reference](https://llvm.org/doxygen/classllvm_1_1BasicBlock.html)

親の関数を指定していなくても様々な操作をできるのですが、`CreateGlobalStringPtr`を呼び出すには関数とBasicBlockが必要条件なので実行に失敗していたわけです。

ということで纏めると、親の関数を指定しないと`CreateGlobalStringPtr`は呼び出せないよ、ということです。

## [おまけ] 現在挿入中の関数を取得する

現在のBasicBlockを取得してからその親の関数を取得すれば実現可能です。
BasicBlockを一度介すのがミソです。

``` C++
auto parent = builder->GetInsertBlock()->getParent();
```

これを使用すれば、以下の様に書き換えて先程のコードを動かすことができます。

``` C++
auto ifblock = llvm::BasicBlock::Create(module->getContext(), "then", parent);

auto mergeblock = llvm::BasicBlock::Create(module->getContext(), "merged", parent);
```

## さいごに

これだけは言いたい。LLVMの日本語資料少なすぎー! ~~(英語読めよ)~~  
まあ、これがLLVMの記事をかく原動力になっているのですが。