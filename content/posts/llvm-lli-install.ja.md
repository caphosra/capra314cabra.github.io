---
title: "LLVMをWindowsで使いたくて入れたらlliなかった話"
date: 2020-03-07T12:54:53+09:00
description: "LLVMのツールたちをWindowsにインストールするまでの話です。生温かい目でご覧ください。"
draft: false
author: caphosra
tags: ["CPlusPlus", "LLVM"]
keyword: "LLVM,Windows,lli,llc,llvm-as"
---

<img src="https://llvm.org/img/LLVM-Logo-Derivative-1.png" alt="LLVM logo" class="center" width="256" height="256" />

オレオレ言語を作るためにAntlr4を習得(?)したcapra314cabraです。  
今回は自分のWindowsのパソコンにLLVMを使える環境を作ろうとして手こずったのでそれの事について書いていきたいと思います。

## まずLLVMって?

> The LLVM compiler infrastructure project is a set of compiler and toolchain technologies, which can be used to develop a front end for any programming language and a back end for any instruction set architecture.

[wikipedia LLVM](https://en.wikipedia.org/wiki/LLVM)

そういうことらしいです。LLVMのツール群の使い方は触れない予定なので、~~他のサイトをご覧下さい。~~

## 最初にやったこと(失敗談)

取り敢えず、思考停止で[LLVMのリリースページ](http://releases.llvm.org/download.html)へ  
現時点でLLVM9.0.1が最新ですが、Pre-Built Binariesの何もなかったので、LLVM9.0.0のところにある`Windows (64-bit)`をポチっとしてダウンロード。
インストラーだったので実行してインストール完了!

...と思いきや、Clang等はインストールされていたものの、`lli`や`llc`、`llvm-as`などが見当たりませんでした。

## 次にやったこと(失敗談)

Chocolatery(Windows用のパッケージマネージャ)を使ってLLVMを入れれば全部のせになるかな、という希望的観測でやってみると、ひとつ前と全く同じ...

## 他の人がビルドしているものを貰う(止めた)

古いのばかり出てきました(LLVM3が多い印象)  
LLVM9.0.0が使いたいのでうーん、といった感じ

## 最終手段

ということで、結局ソースコードを全部ビルドすることにしました。  
私がやった手順としては

1. [LLVM Project(Github)](https://github.com/llvm/llvm-project/releases)から`llvm-9.0.1.src.tar.xz`をダウンロード
2. ダウンロードしたら、展開する(因みに私は7zip使いです)
3. CMakeを使ってVisual StudioのSolutionを生成(オプションは変更なしで行けました)
4. Visual Studioを開いてConfigurationをReleaseにしてビルド
5. Releaseフォルダの中にbinとlibフォルダが出来るので、その中にツール群が広がっているはずです!

後は適当にパスを通してインストール完了です!  
ソースコードと生成物を合わせて全部で2.8GBでした。想像より少なかった。

## さいごに

LLVMを学ぶことがとても大変なのにもかかわらず、"あれ、ツールがない!"で数時間無駄にしたくないですよね。  
Windows環境でLLVMをインストールしたい人はぜひ参考にしてみてください。
