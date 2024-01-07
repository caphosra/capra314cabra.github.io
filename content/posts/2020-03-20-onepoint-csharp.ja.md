---
title: "[C# tips] #1 C#でSQLみたいな構文?"
date: 2020-03-30T16:26:36+09:00
description: "記念すべき初回は、C#で配列をSQLのような構文で書くことができるという、案外知られていないことを紹介したいと思います。"
keyword: "C#,tips,today,linq,sql"
author: "caphosra"
tags: ["CSharp"]
series: ["CSharp tips"]
draft: false
---

> 30億のデバイスで動くJavaの方がC#より強そう

> C#ってWin APIを呼ぶやつ...?

このような事をいわれたことがあったので、対抗策として、C#の豆知識や小話(というほどでもない)を紹介するシリーズを始めようと思った次第です。  
これが、記念すべき第一回です。

## 本編

じつはC#にはSQL likeな構文が用意されています、というのが今回の話です。(あ、これ知ってるよという方、~~黙ってこのページを閉じてください~~)

SQLと聞くと...

- データベースの操作をするやつ
- クエリを投げるやつ
- ~~実はSQLは言語そのもののことではない~~

など色々思い浮かべると思います。

SQLはデータを処理するのに特化した言語です。SQLでゲームを作るなどという話は聞いたことがありません。

## SQLでデータを取り出してみる

例えば、SQLのデータベースに以下のようなテーブルがあったとします。

Table名 : TestResults

|math|english|name|
|:-----|:-----|:-----|
|50|100|A|
|60|70|B|
|80|80|C|
|40|90|D|

この時、`math`が50以上なものを取り出し、`english`の値の降順でソートしたいと思います。

``` SQL
SELECT math, english
FROM TestResults
WHERE math >= 50
ORDER BY english DESC;
```

これを行うSQLの文はこのようになります。ここでの解説は本題ではないので飛ばします。詳しくはググって下さい。

## C#でこれができたなら...

できます。`System.Linq`を使用しましょう。

まず、Listを用意しましょう。Tupleを使用しました。古いバージョンのC#をお使いの方と匿名型大好きな方、すみません。

``` C#
// using System;
// using System.Collections.Generic;

var testResults = new List<(int math, int english, string name)>() {
    (50, 100, "A"),
    (60, 70, "B"),
    (80, 80, "C"),
    (40, 90, "D")
};
```

そして、C#でSQL likeに同じ処理を行ってみましょう。

``` C#
// using System.Linq;

var selected = from result in testResults
    where result.math >= 50
    orderby result.english descending
    select result;
```

``` SQL
SELECT math, english
FROM TestResults
WHERE math >= 50
ORDER BY english DESC;
```

見比べてみてください。`Select`の文法が違う、`in`であたかも`foreach`感を醸し出しているなどといった点を除けば、ほぼ同じじゃないでしょうか。

クエリと同じ感覚でも書けるC#、意外とやるな、という感じでしょうか。

## ただ、実際によく使われるのは...

悲しいかな、これと同じ事を関数を使用して記述出来ます。こちらの方がよく使われる印象です。

``` C#
var selected = testResults
    .Where(result => result >= 50)
    .OrderByDescending(result => result.english);
```

個人的に、こちらの方が汎用性が高いと思うので~~関数を使用した記法をお勧めします~~。

## おわりに

いかがだったでしょうか?  
C#であまり使われない印象のSQL likeな構文を紹介しました。こんな感じの豆知識を3日に1日くらいのペースで更新できたら、と思います。  
C#って本当に楽しい!

コメントや、ネタの応募はいつでも大歓迎です!
