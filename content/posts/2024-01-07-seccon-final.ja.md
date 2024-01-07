---
title: "[CTF] SECCON CTF 2023 Finals Domestic writeup"
date: 2024-01-07T20:14:04+09:00
description: "SECCON CTF 2023 Finals DomesticにTSGとして参加したのでwriteupを公開します."
keyword: "ctf,seccon,seccon 2023,writeup"
author: "caphosra"
tags: ["CTF"]
draft: false
---

<script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>

SECCON CTF 2023の国内決勝にTSGとして参加しました. 1.5問くらい解いたのでwriteupを書きたいと思います.

## Reversing: ReMOV

Reversingの問題. 大量の意味のないmov, movaps命令が並んでいるバイナリが与えられ, そのバイナリが受理するFlagを考えるというもの.

GhidraでさっとDisassembleして読もうとしたが, 当然まともに読めそうになかったのでgdbで実行しながら怪しい部分を探した. まず, 最初の方は文字列の長さを見て32文字であるかを確認する部分がある. その次に, 文字列の先頭が`SECCON{`であるかどうかを判定する部分と最後が`}`で終了しているか確認する部分がある.

ここまでは, 適当に`SECCON{AAA....A}`のような長さ32の文字列を与えておけば特に問題はない. さて, ここから引数を8bytesごとにチェックするパートに入る. 具体的には8bytesを切り出して, ある固定値とxorを取ってから別の固定値と比較する操作が4回行われる. 一見, もう一度xorを取ることで容易にFlagを復号できそうだが, このままでは先頭8bytesの値が`L\xbd~\xb3HN{y`でなければならなくなり, これは先頭8bytesが`SECCON{`であることと矛盾する.

もう一度用心深く探ってみると, 途中で不審にptraceを呼んでいる部分がある. これでgdbのようなデバッガーをattachしているかどうか判定し, その返り値によってxorをとる固定値を変更しているようである. そこで, ptraceが呼ばれた後に`rax`を変えてしまえば問題ないだろうと推測し, 実際うまく行った. 以下のように書けばこれを実現できる.

``` python
gdb.execute('b *0x555555555096')
gdb.execute('c')
gdb.execute('set $rax = 0')
```

実際にその場で書いたソースコードはこんな感じ. 8bytesごとに答えが出てくる.
``` python
#!/bin/python3

import gdb
import re

flag = b"SECCON{y3t_4n0th3r_m0vfuAAAAAAA}"
gdb.execute('file ./remov')
o = gdb.execute(f'starti {flag.decode()}', to_string=True)
print(o)

gdb.execute('b *0x555555555096')
gdb.execute('b *0x555555555605')
gdb.execute('b *0x555555555637')
gdb.execute('b *0x55555555567d')

gdb.execute('c')
gdb.execute('set $rax = 0')

current = int.from_bytes(flag[0:8], "little")
a = []
for i in range(4):
    gdb.execute('c')
    output1 = gdb.execute('reg', to_string=True)
    print(output1)
    m = re.search(r'(0x.+)', output1)
    a.append(int(m.group(0), 16))
    print(f"rax: {hex(a[i])}")
    current = current ^ (a[i] << (0x8 * i))
    print(f"check: {hex(current)}")

assert len(a) == 4

e1 = 0xbde671e813ba0ec4
e2 = 0xfe313878bfd3832a
e3 = 0xefe4966fa7747a84
e4 = 0xac6a45cfcc93f053

from pwn import *

ans1 = e1 ^ a[0]
ans2 = e2 ^ a[1]
ans3 = e3 ^ a[2]
ans4 = e4 ^ a[3]
test = int.from_bytes(flag[0:8], "little") ^ a[0]

print(f"possible: {ans1}")
print(f"assume: {hex(test)}")

ans1 = ans1.to_bytes(8, "little")
print(f"ans1: {ans1}")
ans2 = ans2.to_bytes(8, "little")
print(f"ans2: {ans2}")
ans3 = ans3.to_bytes(8, "little")
print(f"ans3: {ans3}")
ans4 = ans4.to_bytes(8, "little")
print(f"ans4: {ans4}")
```

FLAG: `SECCON{y3t_4n0th3r_m0vfu5c4t0r?}`

## Crypto: DLP 4.0

この問題は考察パートのみ. 実装は同じチームの慈英さんが引き受けて下さった. 本当にありがとうございました.

333bit長の任意の素数 \\(p\\) をこちらから与えることができ, その上で, ランダムにとられた \\(p^2-1\\) 以下の十分大きい数 \\(x\\) と環 \\(\mathbb{Z}_p\\) での四元数 \\(g\\) について, \\(g\\) と \\(g^x\\) が与えられる. そこから \\(g^x = g^{x'}\\) となる \\(x'\\) を1つ与えると正答となる.

法を \\(p\\) としてノルムを考えると,
$$\\|g\\|_p^{x'} \equiv \\|g\\|_p^x \mod p$$

今, \\(\\|g\\|_p\\) と \\(\\|g\\|_p^x\\)は, \\(g\\) と \\(g^x\\)からすぐ計算できるので, 離散対数問題に帰着できる. こちらで\\(p\\)を指定できるので, あとはPohlig–Hellmanアルゴリズムを使えば良い.

FLAG: 知らない

## まとめ

運営の方, チームの方, 2日間ありがとうございました. もっと知識と技術をつけて出直してきます.

## (おまけ) 時間の使い方

1日目はReMOVをとりあえず解いてから, babyheap1970(Pascalでのheap pwn)に手をつけて沼らせ, 2日目はほとんどの時間をbabyheap1970とbombermanを行ったり来たりして時間を溶かしていた. 他の多くのチームがDLP 4.0を解いていたので, 2日目の昼頃に"自分にも解けるやろ"くらいの軽い気持ちでDLP 4.0を考察し実装を慈英さんに丸投げした.
