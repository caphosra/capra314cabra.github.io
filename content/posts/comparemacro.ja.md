---
title: "[競プロ]役に立つCompareマクロ"
date: 2019-12-08T22:24:27+09:00
description: "競プロでPriorityQueueの型として必要なCompare型を作るのを簡略化した話です。"
draft: false
author: caphosra
tags: ["CPlusPlus", "Competitive programming"]
keyword: "競技プログラミング,Compare,C++,Priorityqueue,マクロ"
---

## TL;DR

任意の方法で変数を比較する型を一行で作るためのマクロ

``` c++
#define C(t, f) struct C##t { constexpr bool operator()(t const & a, t const & b) const noexcept { return f(a, b); } }
```

structの型名とマクロ名はお好みの名前に付け直してください。

## マクロの説明

競技プログラミングで見かける`greater<T>`と`less<T>`という型。  
この`greater<T>`は大なり記号、`less<T>`は小なり記号と同じ意味を持っています。  
これらは、たとえば逆順のPriorityQueueを使うときに用いられます。

``` c++
// このPriorityQueueは小さい順に出てくる
priority_queue<int, vector<int>, greater<int>> pq;

// この二つは同じ動作をする
priority_queue<int, vector<int>, less<int>> pq;
priority_queue<int> pq;
```

しかし、これだけしかないと問題が生じます。  
たとえば、`pair<int, int>`型で`second`の要素が小さい順に出すPriorityQueueが必要だとします。  
この時に`greater<pair<int, int>>`だと`first`の大小関係が優先され期待通りとなりません。

ではどうすればよいか。

``` c++
struct ComparePair {
    constexpr bool operator()(pair<int, int> const & a, pair<int, int> const & b) const noexcept {
        if(a.second == b.second){
            return a.first > b.first;
        }
        return a.second > b.second;
    }
};
```

上のように自前で比較をする型を作ればいいのです。
こうすれば、

``` c++
// 名前を簡略化
#define P pair<int, int>

// このように書けばsecondで順番が決定する
priority_queue<P, vector<P>, ComparePair> pq;
```

secondが小さい順に値が出てきます。

ただ、こんなに長いstructを変則的な比較の度にいちいち書きたくないですよね。  
コピペするにも、毎回変数名変えて関数いじって...とやっていると時間がかかります。  
そこでこのマクロ(2度目)

``` c++
#define C(t, f) struct C##t { constexpr bool operator()(t const & a, t const & b) const noexcept { return f(a, b); } }
```

先ほどのstructをそのままマクロにしました。  
使い方の例を挙げると、

``` c++
#define P pair<int, int>

// このマクロをライブラリゾーンなどに追加し
#define C(t, f) struct C##t { constexpr bool operator()(t const & a, t const & b) const noexcept { return f(a, b); } }

// 2変数を比較する関数を実装し
inline bool Compare(P a, P b){
    if(a.second == b.second){
        return a.first > b.first;
    }
    return a.second > b.second;
}

// マクロ呼び出せば...
C(P, Compare);

// CPという名前で比較する型が使えようになる!
priority_queue<P, vector<P>, CP> pq;
```

という感じです。  
いちいちstructを手動で実装せずに、比較する関数だけ用意できればすぐ使えるようになります。便利!  
関数は高速化のため`inline`にしておくことをお勧めします。`constexpr`でもいいです。

## さいごに

実用性があると踏んで書いたのですが、どうだったでしょうか?  
コードの文字数制限に引っ掛からないのであれば、是非、ライブラリゾーンにこのマクロを加えてあげてください。  
筆者が泣いて喜びます。

このマクロはノリで作った部分もあるので改善点のご指摘もお待ちしています。
