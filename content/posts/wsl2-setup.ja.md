---
title: "WSL2を使えるようにする"
date: 2020-03-14T20:04:43+09:00
description: "WSL2をインストールすることが一筋縄ではいかなかったので、その教訓を書き残します。"
keyword: "wsl2,インストール,wsl,windows"
author: "caphosra"
tags: ["WSL2"]
draft: false
---

Windows上でLinuxをエミュレートしてくれるWSLが進化を遂げ...  
遂にWSL2が使用出来るようになりました!やったね!  

このニュースを聞いたら、当然プログラマー的には使ってみたくなりますよね。  
ということで、気楽にインストールしようとしたら..."あれ?コマンドがないよ"みたいにWindowsに怒られてしまいました。

WSL2を使用出来るようにするのは一筋縄ではいかなかったので使用できるまでの道筋を紹介していきたいと思います。

WSL2はまだ安定していない様なので __あくまで自己責任で__ お願いします。

## まず、Windowsをアップデート

実は、私はこれを忘れて数分溶かしました。

> WSL 2 is only available in Windows 10 builds 18917 or higher  
[Microsoft - WSL2 Install](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)

なるほど、Windows 10のビルド番号18917番以降を持っている必要があるのですね。  
しかしながら、ただ、愚直にWindowsをアップデートしても、現段階では18917番以前のものになってしまいます。(バージョン確認にはwinverコマンドを)

それを解決するために、[Windows Insider](https://insider.windows.com/en-us/)に加入しましょう。  
これは、Windowsの新しいバージョンをMicrosoftが配布し、問題を見つけたら報告するというシステムです。  
試験的な内容をいち早く使うことが出来ます。

Microsoftアカウントを持っていると登録は一瞬で終わります。なんと、__無料__　です。

続いて設定を開きます。そして"更新とセキュリティ"をクリック。

<img src="/images/wsl2-setup/settings.jpg" alt="Windows settings" class="center" width="900" height="300" />

<img src="/images/wsl2-setup/windows-insider-program.jpg" alt="Windows Insider Program" class="center" width="300" height="600" />

"Windows Insider Program"をクリックして、ログインしてください。  
Insiderの設定は"スロー"で問題ないと思います。  

続いて、"Windows Update"に移って、"更新プログラムのチェック"をクリック。
先程までなかった、より新しいWindows 10のバージョンへの更新ができるようになります!
これで、先程のWindowsバージョン問題は解決です。あとは、ひたすらWindows Updateを見る会です。

## WSLをインストールしていく

WSLのインストール方法は通常の方法と同じなので割愛します。  
以下のサイトがわかりやすかったです。(~~丸投げ~~)

[Qitta - Windows Subsystem for Linuxをインストールしてみよう！ @Aruneko](https://qiita.com/Aruneko/items/c79810b0b015bebf30bb)

本当にWSLのインストールと同じです。  
WSLを既にインストールしているよ、という方はここをスルーしても大丈夫です。

## WSL2へ変更しましょう

[Microsoft - Updating WSL2 Linux kernel](https://docs.microsoft.com/en-us/windows/wsl/wsl2-kernel)

このサイトに飛んで、WSL2のカーネルを入手します。  
ダウンロードしてきたインストーラーを実行しましょう!

<img src="/images/wsl2-setup/update-setup.jpg" alt="WSL2 Kernel Installer" class="center" width="450" height="360" />

インストールが終わったら長かったWSL2セットアップももうすぐおしまいです。  
好きなターミナルを開いて以下のコマンドを打ち込んで実行してください!

```
wsl --set-default-version 2
```
<img src="/images/wsl2-setup/command-prompt.jpg" alt="Running command" class="center" width="860" height="210" />

おめでとうございます!これであなたもWSL2デビュー!

## おわりに

いかがだったでしょうか?意外と簡単でしたね。(~~どの口が言う!~~)待ち時間が長めでしたが。  
WSL2で更にWindowsでの開発をブーストしていきましょう!

質問等あればコメント欄にお願いします。
