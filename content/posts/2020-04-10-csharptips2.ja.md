---
title: "[C# tips] #2 privateなメンバーにアクセスしよう"
date: 2020-04-10T18:08:04+09:00
description: "System.Reflectionを使用してprivateなメンバーにアクセスする方法をお伝えします。"
keyword: "C#,tips,today,reflection,system"
author: "caphosra"
tags: ["CSharp"]
series: ["CSharp tips"]
draft: false
---

これで二回目です。前回はC#のLinqに関する軽い紹介を書きました。  
今日のテーマは"privateなメンバーにアクセスしよう"です。

## 注意

この記事では`System.Reflection`を使用してprivateなメンバーにアクセスする方法をお伝えします。ただ、自己責任でお願いします。(危ない操作ではありませんが、人のコードに対して行えば著作権侵害とかになりえるので。)

## 突然ですが問題です

あなたは以下のようなクラスのインスタンスを与えられました。  
このクラスにはどうやらfloat型の変数があってそれは秘密の値で初期化されているようです。  
秘密にされると暴きたくなるのが人間の性、Capra君はどうしても秘密の値を知りたいです。  
果たしてどうすれば秘密の値を手に入れられるでしょうか?

``` C#
public class HasSecret
{
    private float ????? = ?????;
    public float dummy1 = 3.14f;
    private int dummy2 = 314;
}
```

## ならディスアセンブルすれば...?

確かに、dnSpyというC#で凄まじい威力を発揮するディスアセンブラを使えば瞬殺できます。ただ、やはりC#のコードで解決したいですよね。(というより、dnSpy使うのなら記事の意味がなくなってしまいそう...)

[GitHub - 0xd4d/dnSpy](https://github.com/0xd4d/dnSpy)

ということでC#のコードから`HasSecret`内の変数にアクセスしてみましょう。

## まずは愚直にアクセス

試しに、dummy2に何も考えずにアクセスしてみましょう。

``` C#
var secret = new HasSecret();
Console.WriteLine(secert.dummy2);
```

```
error CS0122: 'HasSecret.dummy2' is inaccessible due to its protection level
```

当然ながらエラーが発生しました。これでアクセス出来たらライブラリ開発者はたまったものじゃないですよね。せっかくの実装の隠蔽が意味をなさなくなりますから。

また、この方法だと、privateな変数にアクセスするどころか変数名さえわかりません。  
今回は変数名さえわからない状態なので、どうすればいいのでしょうか...

## ここでSystem.Reflection

ここから、`System.Reflection`を使っていきます。  
`System.Reflection`は型の情報を使用して動的に物事を処理する方法を提供するクラスを揃えたバリューパックのような名前空間です。

それではそれらを使用して、privateな変数にアクセスしていきましょう。  
まず、`GetType`関数を使って動的に型を取得します。静的に型を取得したい方は`typeof`キーワードを利用するといいと思います。  
受け取った型の型は`System.Type`となります。

``` C#
// using System.Reflection;

var secret = new HasSecret();

var type = secret.GetType();
```

型を変数として受け取ったら、型が持っている`GetFields`を呼び出します。名前から想像がつくように、型から、条件を満たす全てのFieldの情報を取得してくる関数です。因みに戻り値は`System.Reflection.FieldInfo[]`です。

情報が取得出来たら、`foreach`で全てConsoleに表示してみましょう。

``` C#
var members = type.GetFields(
    BindingFlags.Instance |
    BindingFlags.Public |
    BindingFlags.NonPublic
);

foreach(var member in members)
{
    Console.WriteLine(member.Name);
}
```

```
$ dotnet run
password
dummy1
dummy2
```

`HasSecret`に含まれる全てのFieldの名前を表示できました。  
その出力の中には、`password`という怪しげな変数があります。次はこの変数の値を読んでみましょう。

## 値を手に入れる

秘密の値を保持している変数の名前が`password`だとわかりました。  
ただ、変数の名前がわかってもその値は分かりません。

とりあえず、先ほど`GetFields`を使用して手に入れた情報から、`Where`と`FirstOrDefault`を使って、名前が`password`であるFieldの`FieldInfo`を入手します。

続けて、`GetValue`を呼び出します。これは、`FieldInfo`の情報を基に、インスタンスから変数の値を取得する関数です。戻り値はObject型であることに注意してください。

最後に、floatへCastしてConsoleに表示してみます。

``` C#
// using System.Linq;

var passwordVal = members // FieldInfo[]
    .Where(info => info.Name == "password") // IEnumerable<FieldInfo>
    .FirstOrDefault() // FieldInfo
    .GetValue(secret); // Object

Console.WriteLine((float)passwordVal);
```

(筆者注 : `GetValue`の戻り値は厳密には`object?`で、Null許容型です。いずれ紹介します。)

```
$ dotnet run
2.71828
```

ネイピア数らしき値が出ました。これが`password`の値です。これで、`HasSecret`の全容が明らかになって目標を達成することができました!

``` C#
public class HasSecret
{
    private float password = 2.71828f;
    public float dummy1 = 3.14f;
    private int dummy2 = 314;
}
```

## ついでにprivateの変数の値を変更する

ただ、答えがネイピア数であることが気に入らなかったCapra君は`password`を円周率に変えたいと考えました。

これも、先程と似ている操作で行うことができます。  
値を取得した時と同じ方法で名前が`password`の変数の`FieldInfo`を手に入れて、`SetValue`という関数を呼ぶだけです。詳しい説明は不要でしょう。

``` C#
members
    .Where(info => info.Name == "password")
    .FirstOrDefault()
    .SetValue(secret, 3.1415f);
```

## さいごに

`System.Reflection`を多用するのは一部の場面を除いて、邪道でパフォーマンスはやはり直接アクセスに劣ります。(Delegateを使用した高速化や、GetValueDirectの利用とかである程度早くはなりますが。)  
どうしてもprivateなメンバーにアクセスしたいときや、ソースコードを紛失したライブラリの解析などにぜひ役立ててみてください。(~~その場合、dnSpyの方が圧倒的に便利~~)