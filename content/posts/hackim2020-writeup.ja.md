---
title: "[CTF] Nullcon HackIM 2020 writeup"
date: 2020-02-09T17:54:45+09:00
draft: false
description: "HackIM 2020のwriteupです。解けている問題があまりにも少ないのは、気にしないで下さい..."
tags: ["CTF"]
keyword: "CTF,Nullcon,HackIM,2020,Zelda"
---

Nullcon HackIM 2020に出たのでそのwriteupでも書こうかなーと思った次第です。

結論から申し上げますと、解けた問題は**1**問です...(しかも、その問題はコピペするだけ)

ただ、そんなのではwriteupとして意味をなさないので、競技終了後も作業していました。  
結局ZeldaAdventureの最初の1問を解くことができたのでそれをここに載せます。

### 問題の見た目

<img src="/images/hackim2020-game.jpg" alt="Game scene" class="center" width="500" height="300" />

Unity製のGameで、このNPC(白い敵)を1体以上倒すとFlagを手に入れられる、とあります。  
Playerは剣と体当たり(接触)することでNPCにダメージを与えられますが、敵のHPがとても高く、現実的な時間に倒せないようになっています。

### やったこと

UnityのWindowsでビルドした時のファイル構成は決まっています。  
特に、プログラマーが書いたコードは`AssemblyCSharp.dll`というファイルにコンパイルされて存在しています。

ここで、dnSpyを使用して`AssemblyCSharp.dll`の中のコードを読んでみます。  
コードの森を探索していると...

``` C#
// Token: 0x06000006 RID: 6
private void TakeDamage(float damage)
{
    this.health -= damage;
    if (this.health <= 0f)
    {
        base.StartCoroutine(this.ShowSome());
        base.gameObject.SetActive(false);
    }
}
```

ダメージを処理している部分を見つけました。  
HPが0になると`ShowSome`というコールチンを回し始めるようです。

``` C#
// Token: 0x0600000A RID: 10
private IEnumerator ShowSome()
{
    this.textbox.SetActive(true);
    yield return new WaitForSeconds(3f);
    this.textbox.SetActive(false);
    yield return null;
    yield break;
}
```

`ShowSome`をみると`this.textbox`を見せるようにしているみたいです。  
これはこのTextBoxがFlagを持っているのでしょう。  
dnSpyは実はDLLを編集する事が出来るので、この`this.textbox`を最初から表示させるようにコードを書き換えれば、Flagゲットです。

``` yaml
Flag: REVOLUTIONSTARTSWITHME
```

フォントがおしゃれすぎて読みにくかったです(褒めてます)

## おわりに

HackIM 2020の前に無力さを感じたので、もっと勉強してから出直します...

## 参考

[Unity-Game-Hacking](https://github.com/xcsh/Unity-game-hacking)
