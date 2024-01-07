---
title: "C++で全てのstd::minやstd::maxにエラーが出た時の対処法"
date: 2020-07-14T21:53:29+09:00
description: "C++のWindows環境で`std::min`と`std::max`というポピュラーな関数がエラーになる時の解決策です"
keyword: "c++,max,min,windows,windef,std"
author: "caphosra"
tags: ["CPlusPlus"]
draft: false
---

今日、先程あった出来事なのですが、手元のLinux環境で動いているコードをWindows上でビルドしようとしたら突如大量のエラーが発生。

```
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(286,1): error C2059: syntax error: ')' [D:\a\kaprino\kaprino\build\kprc.vcxproj]
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(346,19): error C2589: '(': illegal token on right side of '::' [D:\a\kaprino\kaprino\build\kprc.vcxproj]
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(346,1): error C2062: type 'unknown-type' unexpected [D:\a\kaprino\kaprino\build\kprc.vcxproj]
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(346,1): error C2059: syntax error: ')' [D:\a\kaprino\kaprino\build\kprc.vcxproj]
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(579,20): error C2589: '(': illegal token on right side of '::' [D:\a\kaprino\kaprino\build\kprc.vcxproj]
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(579,1): error C2062: type 'unknown-type' unexpected [D:\a\kaprino\kaprino\build\kprc.vcxproj]
C:\Program Files (x86)\LLVM\include\llvm/ADT/StringRef.h(579,1): error C2059: syntax error: ')' [D:\a\kaprino\kaprino\build\kprc.vcxproj]
....
```

エラーが出ている部分を確認すると全て`std::min`と`std::max`でした。

なぜWindows環境で`std::min`と`std::max`というポピュラーな関数がエラーを吐いたんでしょう...?

## 結論

`#include<windows.h>`をしていたのが原因でした。(Linux環境では#ifdefではじいていたので気付かなかった)

`windows.h`が内部でincludeしている`windef.h`で

``` C++
#ifndef NOMINMAX
#ifndef max
#define max(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif
#endif
```

上記のように`max`マクロと`min`マクロが定義されています。  
それが`std::max`と`std::min`とconflictしてエラーが発生していました。~~そりゃ気づきませんわ~~

上記のコードから分かるように`#define NOMINMAX`することで`windows.h`の使用を諦めることなくエラーを回避することが出来ます。

## 参考

[windef.h](https://www.rpi.edu/dept/cis/software/g77-mingw32/include/windef.h)  
[Why is std::min failing when windows.h is included? (Stackover flow)](https://stackoverflow.com/questions/5004858/why-is-stdmin-failing-when-windows-h-is-included)
