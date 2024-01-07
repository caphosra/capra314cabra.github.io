---
title: "Hugoで_index.mdの仕様を変更した話"
date: 2020-03-12T10:35:31+09:00
description: "Hugoで_index.mdは標準では限られたコンテンツしか許されていないので、それを改造してみる、という話です。"
keyword: "hugo,index.md,_index.md,not list,override"
author: "caphosra"
tags: ["Hugo"]
draft: false
---

<img src="https://gohugo.io/images/gohugoio-card.png" alt="Hugo Logo" class="center" width="600" height="300" />

今回は、Hugoについてです。  
`_index.md`は標準では限られたコンテンツしか含めないので、それを改造していきたいと思います。  
そもそも`_index.md`とは?というところにも触れるので、`_index.md`と`index.md`の仕様に疑問がある方は必見です。

## Hugoでの_index.md

以下のようなフォルダがサーバー上にあったとします。

```
- contents
    - old
        * index.html
        * old_content.html
    * index.html
    * content1.html
    * content2.html
```

この時に、`contents/`と`contents/index.html`はアクセスしたときに同じ様に表示されます。  
同様に`contents/old/`と`contents/old/index.html`も同じ表示となります。  
これは、フォルダにアクセスしたときに、`index.html`が存在するか探索されるからです。

一方で、Hugoでは、`index.md`と`_index.md`というこれとほぼ同様の役割を果たすものをが用意されています。  
ただ、これらは厳密には異なり、仕様が異なります。

ひとつづつ見ていきましょう。

### index.mdの仕様

`index.md`はほとんど`index.html`のようなものであると思ってもらってもいいです。  

```
- contents
    - blog
        * index.md
```

のようにファイルを配置すれば、ビルド後は、`[servername]/blog/`とアクセスすることもできるし、
`[servername]/blog/index.html`とアクセスすることも出来ます。

ただ、`index.md`には__落とし穴__が...

```
- contents
    - blog
        - item
            * index.md <- NG (index.md被りは禁止)
        * index.md <- OK
        * server.md <- NG (server/indexかのように扱われる)
    - about
        * index.md
```

このような配置をして、ビルドすると、`server.md`と`item/index.md`がビルドされません!  
なぜかと言うと、`index.md`は __下層ノードでの重複が禁止__ されているからです。  
即ち、`blog/`はもう既に`index.md`を持っているので、子ディレクトリの`index.md`はビルドされません。
Hugoは`server.md`の様なファイルを`server/index.html`にビルドしようとするので`server.md`もビルドされません。

ややこしいですね。即ち、`index.md`をフォルダに置いたら、その子フォルダのMarkdownファイルはすべてビルドされないということです。  
これは前述のHTMLのサーバーとは全く異なる仕様です。

### _index.mdの仕様

一方、_index.mdは

```
- contents
    - blog
        - item
            * _index.md <- OK
        * _index.md <- OK
```

この様に配置しても問題ありません!  
なぜかというと、`_index.md`は`index.md`と用途が異なるからです。  
Hugoにおいて、`_index.md`は、他のページへの __道しるべの役割__ を果たすものなのです。  
`_index.md`はその子フォルダにどの様な記事が存在するかを、リスト形式で示すために存在します。  
ただ、その用途に特化するためなのか、`_index.md`に記事を書いても、 __無視されます__。

ここまでをまとめると

||index.md|_index.md|
|:-----|:-----:|:-----:|
|下層ノードでの重複|x|o|
|記事を含めるか|o|x|

[Hugo Page-Bundles](https://gohugo.io/content-management/page-bundles/)

## 本編 (~~前置き長すぎ~~)

ここで、当然、疑問として、 __"下層ノードでの重複を許しながら、記事を含んだものを作れるの?"__ というのが浮かびます。  
答えは __YES__ です。  
私もこの疑問を持ったのですが、~~ごり押しで~~解決できたので、その方法を紹介したいと思います。

1. まず、Hugoで作業しているディレクトリに行きます。
2. 以下のようなディレクトリとファイルを作成します。パスでかけば、`layouts/_default/list.html`です。

<img src="https://caphosra.github.io/images/hugo-index-override-exp.jpg" alt="Example directory" class="center" width="240" height="60" />

3. `layouts/_default/list.html`を以下のように書き換えます。

``` html
{{ define "title" }}
  {{- .Title }} · {{ .Site.Title -}}
{{ end }}
{{ define "content" }}
  {{ if .Params.ispage }}
    {{ partial "page.html" . }}
  {{ else }}
    {{ partial "list.html" . }}
  {{ end }}
{{ end }}
```

何をしたかというと、`_index.md`をオーバーライドして、任意のコンテンツを含めるようにしました。  
これを行えば、`_index.md`に普通に記事を書いて、パラメーターとしてMarkdownの先頭に

``` json
ispage: true
```

と追加してあげるだけで、重複可能な記事を含んだコンテンツを作れるようになります!

## おわりに

いかがだったのでしょうか?  
いわゆる、`index.html`と同じ仕様のものを探していたのですが、なかったのでオーバーライドすることになりました。  
`index.md`を重複可能にする方法も探したのですが、どうやらHugo本体のほうで定義されているようなので、仕様変更は不可能でした。
