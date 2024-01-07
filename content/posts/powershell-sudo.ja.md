---
title: "Powershellでsudoしてみたい話"
date: 2019-12-11T22:28:26+09:00
description: "PowershellでBashでいうsudoのような管理者権限で実行できるようにする方法を紹介します"
draft: false
author: caphosra
tags: ["Powershell"]
keyword: "sudo,powershell"
---

今回紹介することはタイトルそのままです。  
PowershellではBashの`sudo`のように簡単に管理者権限で実行出来るようにするコマンドがありません。  
そこで、それとほぼ同等なものを作りたい、というのが今回の話題です。  
早速、始めて行きましょう。

## 手元の環境

Powershell 6.2.3

私が使っているPowershellはWindowsに標準でインストールされている.NET Framework依存のものではなく、
.NET Core依存のものです。これはWindowsだけでなくmacOSやLinuxでも動くのでWindows以外を使っている方もインストール出来ます。

以降、Powershellの実行ファイル名をpwsh.exeとしていますが、.NET Framework依存のものをお使いの方は適宜powershell.exeで読み替えてください。

## コマンドの実装方針

`sudo`と同等な機能をもった関数を実装し、`sudo`という名前のAliasとして登録する。

## 方法

まず、Powershellを起動し、`$profile`の値を読みます。

``` powershell
pwsh
# PowerShell 6.2.3
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# https://aka.ms/pscore6-docs
# Type 'help' to get help.

$profile
# C:\.....\Microsoft.PowerShell_profile.ps1
```

続いて読んだパスのファイルを開きます。  
お好みのソフトで開きましょう。因みに私はVisual Studio Codeで開きました。

``` powershell
code $profile
```

開けたら以下のようなコードを書きます。

``` powershell
# 管理者権限で実行する関数
function SudoRun
{
    # $programにコマンドを詰める
    foreach($arg in $args)
    {
        $program = "$program $arg"
    }

    # Powershellにより管理者権限で実行
    pwsh -command "Start-Process -Verb runas $program"
}

# 関数をAliasとして登録する
Set-Alias -Name sudo -Value SudoRun
```

これを書いたら、そっとそのファイルとPowershellを閉じましょう。  
その後、Powershellを起動すると、もうあなたは`sudo`をPowershellで使うことができます!

## 問題点

これはBashから見れば、なんちゃって`sudo`です。  
あくまで管理者権限でコマンドを別インスタンスで実行しているだけなので、出力は表示されません...  
例えば、

``` powershell
sudo pwd
```

とやっても、一瞬pwdの黒い画面が現れるだけです。  
ここは改善の余地がありそうなので出来たら報告します。

## まとめ

WindowsのパッケージマネージャーのChocolateryは実行に管理者権限が必要で、
その度にGUIで"管理者として実行"を押すのが億劫でした。  
`sudo`がPowershellで使えるようになると本当に便利です!

## 参考

[Windows で sudo なことをする。](https://mimumimu.net/blog/2014/12/11/windows-%E3%81%A7-sudo-%E3%81%AA%E3%81%93%E3%81%A8%E3%82%92%E3%81%99%E3%82%8B%E3%80%82/)
