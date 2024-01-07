---
title: "Avalonia UIで画像を使ったボタンを作成する方法"
date: 2020-03-29T10:17:52+09:00
description: "Avalonia UIというC#のCross PlatformなGUIライブラリで、画像を使ったボタンを作るのは知らないと厳しいものなので、作り方を教えます。"
keyword: "Avalonia,画像,ボタン,C#"
author: "caphosra"
tags: ["CSharp", "Avalonia", "WPF"]
draft: false
---

今回は、知らないと難しい、Avalonia UIで画像を使ったボタンを作成していきます。  
前置きはさっさと飛ばして、本題に入りましょう。

## 前提条件

- もう既にAvaloniaのプロジェクトを作っていること。
- ボタンにする画像を選んでいること。

## 画像の準備

私は3枚の画像を選びました。通常の見た目と、Hover時の見た目と、Click時の見た目です。1枚で全ての場合をやってもいいんですが、Userが見た目からボタンとして認識してくれない危険性があるので推奨はしません。

画像は`Assets`フォルダに入れます。  
もし、`Assets`フォルダがない!という場合は、`Assets`フォルダを作ってから、プロジェクトファイルに
``` xml
<ItemGroup>
  <AvaloniaResource Include="Assets\*"/>
</ItemGroup>
```
と追記してください。

## UserControlを作る

先ずは、UserControlを作成しましょう。名前は適宜読み替えてください。  

> [Visual Studio]
>
> 1. Right click your project's Views folder in Solution Explorer
> 2. Select the Add -> New Item menu item
> 3. In the dialog that appears, navigate to the "Avalonia" section in the category tree
> 4. Select "User Control (Avalonia)"
> 5. Enter TodoListView as the "Name"
> 6. Click the "Add" button
>
> [.NET Core]
>
> ```dotnet new avalonia.usercontrol -o Views -n TodoListView  --namespace Todo.Views```

[Avalonia Tutorialから引用](https://avaloniaui.net/docs/tutorial/creating-a-view)

作成するとこんな感じになると思います。

``` xml
<UserControl xmlns="https://github.com/avaloniaui"
    	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    	xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    	xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    	mc:Ignorable="d" d:DesignWidth="800" d:DesignHeight="450"
    	x:Class="Hoge.Views.ImageButton">
    <StackPanel>
        Hello World
    </StackPanel>
</UserControl>
```

Hello Worldの部分にコードを書いていく形になります。

## ボタンを作り、Styleを追加

HTML+CSSでデザインをしたことのある人ならわかりやすいと思いますが、
Avaloniaの魅力として、エレメントと別にデザインを記述することが出来る事があります。  
ボタンを作成して、ボタンのStyleを作成します。以下のような感じです。

``` xml
<UserControl xmlns="https://github.com/avaloniaui"
    	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    	xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    	xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    	mc:Ignorable="d" d:DesignWidth="800" d:DesignHeight="450"
    	x:Class="AvaloniaTest.Views.MainContents">
    <StackPanel>
        <StackPanel.Styles>
            <Style Selector="Button.ImageButton">
                <!-- ここにStyleを記述 -->
            </Style>
        </StackPanel.Styles>
        <Button Classes="ImageButton">Click me</Button>
    </StackPanel>
</UserControl>
```

## ボタンに画像を適用する

ボタンの背景として画像を適用します。画像を描く事が出来る`ImageBrush`を使用して実現しています。

``` xml
<UserControl xmlns="https://github.com/avaloniaui"
    	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    	xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    	xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    	mc:Ignorable="d" d:DesignWidth="800" d:DesignHeight="450"
    	x:Class="AvaloniaTest.Views.MainContents">
    <StackPanel>
        <StackPanel.Styles>
            <Style Selector="Button.ImageButton">
                <!-- 見やすいようにデザイン(お好みで変更してください) -->
                <Setter Property="FontSize" Value="30" />
                <Setter Property="Width" Value="400" />
                <Setter Property="Height" Value="100" />

                <!-- ボタンの背景として適用 -->
                <Setter Property="Background">
					<Setter.Value>
                        <!-- avares://[プロジェクトの名前]/Assets/ファイル名 -->
						<ImageBrush Source="avares://AvaloniaTest/Assets/ButtonBar.png" />
					</Setter.Value>
				</Setter>
            </Style>
        </StackPanel.Styles>
        <Button Classes="ImageButton">Click me</Button>
    </StackPanel>
</UserControl>
```

このようにすると以下のようになります。

<img src="/images/2020-03-29/ButtonClick1.gif" alt="On button clicked (failed)" class="center" width="462" height="162" />

枠部分が消えていないので、Styleで変更していきましょう。BorderThicknessの値がDefaultで0ではないので0にして、枠線を消します。

``` xml
<Setter Property="BorderThickness" Value="0" />
```

## Hover時の見た目を変更

また、Hover時の見た目が変わらないと、Userにボタンだと気づいてもらえないと思うので、Hover時の見た目を記述しましょう。

``` xml
<!-- Hoverした時の見た目 -->
<Style Selector="Button.ImageButton:pointerover">
	<!-- ボタンの背景として適用 -->
    <Setter Property="Background">
		<Setter.Value>
            <!-- avares://[プロジェクトの名前]/Assets/ファイル名 -->
			<ImageBrush Source="avares://AvaloniaTest/Assets/ButtonBar_Hover.png" />
		</Setter.Value>
	</Setter>
</Style>
```

CSSを使ったことのある人は`[Classの名前]:[動作]`で記述することに慣れていると思うので親しみやすいかと。  
ただ、`hover`ではなく`pointerover`であることに注意です!  
ここまでやるとこんな感じです。

<img src="/images/2020-03-29/ButtonHover.gif" alt="On button clicked (failed)" class="center" width="462" height="162" />

## Click時の見た目を変更

ここからが、一番詰まりやすいポイントです。  
単に`Button.ImageButton:pressed`とするだけで、画像が変わると思ったのですが、なんと

``` xml
<!-- Click時の見た目 -->
<Style Selector="Button.ImageButton:pressed /template/ ContentPresenter">
    <!-- ボタンの背景として適用 -->
    <Setter Property="Background">
        <Setter.Value>
            <!-- avares://[プロジェクトの名前]/Assets/ファイル名 -->
            <ImageBrush Source="avares://AvaloniaTest/Assets/ButtonBar_Click.png" />
        </Setter.Value>
    </Setter>
</Style>
```

このように`Button.ImageButton:pressed /template/ ContentPresenter`と記述しないと __動きません__ 。  
Avalonia UIのGitterの履歴を漁ってこの方法にたどり着いたので、Avalonia UIのコミュニティの方に感謝です。

これで、画像を用いたボタンの作り方は完結です!

<img src="/images/2020-03-29/ButtonClick2.gif" alt="On button clicked (Successed)" class="center" width="438" height="211" />

## コード全文

``` xml
<UserControl xmlns="https://github.com/avaloniaui"
    	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    	xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    	xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    	mc:Ignorable="d" d:DesignWidth="800" d:DesignHeight="450"
    	x:Class="AvaloniaTest.Views.MainContents">
    <StackPanel>
        <StackPanel.Styles>
            <Style Selector="Button.ImageButton">
                <!-- 見やすいようにデザイン(お好みで変更してください) -->
                <Setter Property="FontSize" Value="30" />
                <Setter Property="Width" Value="400" />
                <Setter Property="Height" Value="100" />
                <Setter Property="BorderThickness" Value="0" />

                <!-- ボタンの背景として適用 -->
                <Setter Property="Background">
					<Setter.Value>
                        <!-- avares://[プロジェクトの名前]/Assets/ファイル名 -->
						<ImageBrush Source="avares://AvaloniaTest/Assets/ButtonBar.png" />
					</Setter.Value>
				</Setter>
            </Style>
            <!-- Hoverした時の見た目 -->
            <Style Selector="Button.ImageButton:pointerover">
                <!-- ボタンの背景として適用 -->
                <Setter Property="Background">
                    <Setter.Value>
                        <!-- avares://[プロジェクトの名前]/Assets/ファイル名 -->
                        <ImageBrush Source="avares://AvaloniaTest/Assets/ButtonBar_Hover.png" />
                    </Setter.Value>
                </Setter>
            </Style>
            <!-- Click時の見た目 -->
            <Style Selector="Button.ImageButton:pressed /template/ ContentPresenter">
                <!-- ボタンの背景として適用 -->
                <Setter Property="Background">
                    <Setter.Value>
                        <!-- avares://[プロジェクトの名前]/Assets/ファイル名 -->
                        <ImageBrush Source="avares://AvaloniaTest/Assets/ButtonBar_Click.png" />
                    </Setter.Value>
                </Setter>
            </Style>
        </StackPanel.Styles>
        <Button Classes="ImageButton">Click me</Button>
    </StackPanel>
</UserControl>
```

## おわりに

いかがだったでしょうか。Avalonia UIに関する資料は、日本語のものどころか英語のものも、とても少ないので
こういう知りたい情報が手に入りにくいです...  
互いに情報共有してAvalonia UIに詳しくなっていきたいです。

もっと、エレガントな方法を知っているよ、という方は是非コメントで教えて下さい!
