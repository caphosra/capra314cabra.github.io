---
title: "C#でのusingの使い方を4つ紹介"
date: 2019-11-16T16:40:39+09:00
description: "C#で欠かせない存在の\"using\"の使い方を四つに分けて紹介したいと思います。"
draft: false
author: caphosra
tags: ["CSharp"]
keyword: "C#,using,C#8.0,IDisposable"
---

今回はC#で欠かせない存在の`using`の使い方を四つに分けて紹介したいと思います。  
早速、始めていきましょう!

## ディレクティブとしてのusing

C#でusingと言えば最初に思い浮かべるであろう使い方は、やはりディレクティブとしての`using`でしょう。
usingディレクティブと聞いてピンと来なかった方も以下のコードを見ればわかるはずです。

``` c#
// これがディレクティブとしてのusing
using System;
```

この`using`は、異なる名前空間の中にあるモジュールを短い名前で呼び出す為に使用されます。
例えば、ファイルの読み書きをストリームで行いたいときに

``` c#
System.Text.Encoding enc = System.Text.Encoding.GetEncoding("UTF8");
System.IO.StreamWriter writer = new System.IO.StreamWriter("./some_file.txt", false, enc);
```

と書くことはできますが、これでは余りにも冗長で可読性が低くなってしまいます。  
こんな時こそ`using`です。  
`using`を使えば名前空間を省略できます。先ほどの例であれば

``` c#
// ファイルの先頭にこれらを書く
using System.Text;
using System.IO;

// Before
System.Text.Encoding enc = System.Text.Encoding.GetEncoding("UTF8");
System.IO.StreamWriter writer = new System.IO.StreamWriter("./some_file.txt", false, enc);

// After
Encoding enc = Encoding.GetEncoding("UTF8");
StreamWriter writer = new StreamWriter("./some_file.txt", false, enc);

```

なんということでしょう。あんなに読みにくかったコードがこんなに簡潔に!
(今回の内容とは関係ないですがvarを使うともっと読みやすくなります。)

## 忘れられがちなusing static

先程の`using`の派生として`using static`というものがあります。これは クラス名を省略できるようにする為に使われます。例をあげます。

``` c#
// ファイルの先頭にこれを書く
using static System.Math;

// 半径10の円と同じ面積の正方形の一辺の長さを求めたい

// Before
double radius = 10d;
double ans = Math.Sqrt(radius * radius * Math.PI);

// After
double radius = 10d;
double ans = Sqrt(radius * radius * PI);
```

本来、`Math.Sqrt` `Math.PI`と書かなければならない所をこんなにも簡潔に書く事ができます。
`using static`はその名前の通りstaticなメンバについてのみクラス名を省略できるようになります。
(そうでなかったら色々やばそうですが...)  
因みにこの機能はあまり使わない印象です。使うのであれば`System.Math`か`System.Console`位でしょうか。

## 名前を変えるusing

ある日、caphosra君は以下のようなを実装しました。

``` c#
namespace CapraLib
{
    public class Random
    {
        // 乱数を出すよ(噓)
        public int Next(int maxv)
        {
            return 0;
        }
    }
}
```

そして、以下のようなコードを書きました。

``` c#
// ファイルの先頭にこれらを書く
using System;
using CapraLib;

// 51未満の乱数を出したい...がエラー
int rndVal = new Random().Next(51);
```

もうお分かりでしょう。これは上手く動きません。
ここで参照している`Random`クラスは`System.Random`でしょうか?それとも`CapraLib.Random`?
わかりませんね。

そこで登場するのが名前を変える`using`です。

``` c#
// これが名前を変えるusing
using CapRandom = CapraLib.Random;
using SystemRandom = System.Random;

// 51未満の乱数を出したい

// CapraLib.Randomの気分の時
int rndVal1 = new CapRandom().Next(51);

// System.Randomの気分の時
int rndVal2 = new SystemRandom().Next(51);
```

これで使い分けができます!

これはクラスに対して使っていますが、名前空間も同じように名前を変えられます。

``` c#
// 短い名前に変えられますよ!
using GenericCol = System.Collections.Generic;
```

これでとても長い名前空間とおさらばです。

## 解放してくれるusing

これは知っているのと知らないのでは大きく違います。
この`using`はリソース解放を忘れる事を防止する為に使われます。例を見ていきましょう。

``` c#
using System.Text;
using System.IO;

Encoding enc = Encoding.GetEncoding("UTF8");
StreamWriter writer = new StreamWriter("./some_file.txt", false, enc);
writer.WriteLine("I wanna be one of the GREATEST programmers!");

// writer.Close(); 忘れてる
```

このコード、やばいですね。気付きにくいですが、`writer`が解放されていません。  
即ち、ファイルを開きっぱなしでコードが終わっています。開けたら閉めるが基本ですよね。  
`writer`は`Close()`という関数を持っているのでこれを最後に呼んであげればいいです、が...

この方法だと、とても忘れやすい!

そこでこの方法。

``` c#
using System.Text;
using System.IO;

Encoding enc = Encoding.GetEncoding("UTF8");
using (StreamWriter writer = new StreamWriter("./some_file.txt", false, enc))
{
    writer.WriteLine("I wanna be one of the GREATEST programmers!");
} // ここでwriter.Dispose()が呼ばれる
```

この`using`を使えば、中カッコ(スコープ)を抜けたときに`Dispose()`を呼んでくれます。  
`StreamWriter`は`Close()`でも`Dispose()`でも解放できますので、このコードは正常に動作します。黙っててすみません。

この記法のメリットは何と言っても、`Dispose()`の呼び忘れが起こらない事じゃないでしょうか。  
ついうっかり、でメモリリークすることがないのでこの記法を絶対に使用すべきです。使える時は。

この`using`が使えるのはクラスが`IDisposable`を実装している時のみです。  
`IDisposable`を実装しているのは`StreamWriter`以外にも沢山あるので調べてみてください!  
あと、自分のライブラリとかを作るときに`IDisposable`を積極的に実装すれば、`using`好きが沢山使ってくれるかも...?

## [おまけ] C#8.0での解放する為のusing

C#8.0で解放する為のusingに新たな記法が加わりました。
これを利用すると、以下のように書く事ができます。

``` c#
using System.Text;
using System.IO;

Encoding enc = Encoding.GetEncoding("UTF8");
using StreamWriter writer = new StreamWriter("./some_file.txt", false, enc);
writer.WriteLine("I wanna be one of the GREATEST programmers!");

// スコープを抜けるとwriter.Dispose()が呼ばれる
```

変数の型の前に置いてある`using`によって、`writer`が寿命を迎えたときに`Dispose()`が呼ばれるようになります。  
これはとてもcoolな記法ですね。ミスも防げます。

## まとめ

いかがだったでしょうか。この記事を読んで、C#のusingにもっと優しくしてあげようかな、と思っていただければ幸いです。  
~~でも正直using static使わないだろうなぁ~~
