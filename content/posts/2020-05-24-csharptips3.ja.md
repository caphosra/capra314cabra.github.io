---
title: "[C# tips] #3 C#を対話形式で実行しよう"
date: 2020-05-24T06:36:13+09:00
description: "簡単な計算をする時にPythonを使っていませんか?対話形式で実行するのはとても便利ですよね。しかし、これと同じことはC#でも出来るのです。"
keyword: "C#,tips,today,対話形式,動的実行"
author: "caphosra"
tags: ["CSharp"]
series: ["CSharp tips"]
draft: false
---

簡単な計算をする時にPythonを使っていませんか?  
対話形式で実行するのはとても便利ですよね。しかし、これと同じことはC#でも出来るのです。

## そもそも対話形式とは?

ユーザーがプログラムを入力すると、それを評価してくれるのが対話形式です。  
Pythonを使ったことがあれば、以下のような感じです。

``` python
>>> a = 10
>>> a * a * 3.14
314.0
```

その場で計算してくれるので、書き捨てコードとしてとても有用です。(筆者は素数判定とかを無性にしたくなった時に使っています。)

## C#って静的言語だから無理なんじゃないですか?

Pythonは動的実行をしている(実行時に型変換等を行っている)のに対して、  
C#はC++などと同じで静的言語であるので実行にはコンパイルが不可欠なはずです。  
コンパイルが必要ということは、時間がかかりすぎるので対話形式で実行するのには致命的...

[Wikipedia 動的プログラミング言語](https://ja.wikipedia.org/wiki/%E5%8B%95%E7%9A%84%E3%83%97%E3%83%AD%E3%82%B0%E3%83%A9%E3%83%9F%E3%83%B3%E3%82%B0%E8%A8%80%E8%AA%9E)

しかし、C#を動的に実行したいと考える人はいるようで

## C#を対話形式で実行する拡張

世の中にはC#を対話形式で実行したいと思う人が少なからずいるのでしょう。C#を標準で対話形式で実行することは出来ませんが、
拡張を使用することでできるようになります。  
いくつか拡張が存在するのでご紹介します。

### C# REPL

有名な対話形式の拡張として、オープンソースのC#の先駆けとなったMonoプロジェクトが提供する
[C# REPL](https://www.mono-project.com/docs/tools+libraries/tools/repl/)があります。

使い方は簡単です。Monoをインストールして

``` bash
$ csharp
```

と実行するだけです。  
以下の様にC#を対話形式で実行することが可能です。

``` bash
$ csharp
csharp> using System;
csharp> var a = 10;
csharp> a * a * Math.PI;
314.159265358979
```

Mono C#を使用している方は今すぐ試すことができます。

### dotnet script

C# REPLはMonoプロジェクトのものでした。一方でこちらは .NET Coreで使うことができるものです。  
[dotnet script](https://github.com/filipw/dotnet-script)は .NET CoreにGlobal toolとして以下のコマンドを使用してインストール出来ます。  
.NET Core 2.1以上が必要なことに注意してください。

``` bash
$ dotnet tool install -g dotnet-script
```

インストールした後は、`dotnet script`コマンドで対話形式で実行できます。

```
$ dotnet script
> var a = 10;
> a * a * Math.PI
314.1592653589793
```

また、dotnet scriptでは拡張子`csx`として作ったC#ファイルを動的実行することが可能であり、  
しかもnugetを使用するための`#r`コマンド等が独自に定義されているのでとても便利です。

### dotnet interactive

これは公式が出した対話形式実行のための拡張です。  
[dotnet interactive](https://github.com/dotnet/interactive)

この拡張を使用すれば、PythonユーザーにはおなじみであろうJupyter notebookでC#を動かせるようになります。

以下のコマンドを使用してインストールすることができます。

``` bash
$ dotnet tool install -g Microsoft.dotnet-interactive
$ dotnet interactive jupyter install
```

Jupyter notebookを開くとつい体が勝手に動いてPythonのコードを打ち込もうとすると思いますが、
一旦抑制してC#を書いてみてください。ちゃんと動きます。

## まとめ

いちいちC#のproject fileを作ってから書き捨てコードを書いている人は、今すぐinteractiveなC#に乗り換えましょう!  
~~普通はPythonですが~~
