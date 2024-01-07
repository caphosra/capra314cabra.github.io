---
title: "[C# tips] #1 Operate arrays like SQL"
date: 2020-03-30T14:15:06+09:00
description: "This is a first page of the new series, Today's C# tips. I will talk about how to manipulate arrays like SQL."
keyword: "C#,tips,today,linq,sql"
author: "caphosra"
tags: ["CSharp"]
series: ["CSharp tips"]
draft: false
---

> C# is not useful than Java. Why don't we use Java, which runs on 3 billion devices!

> Well... C#? Is it used to call Win API...?

These are what I have really been told about C#.  
When I listened them, I realized that many people haven't ever touched C# yet. Indeed, there are situations where you should not use C#. I think, however, there should be much more people who use C# even considering it.  
I have thought deeply and dicided: "I'm going to show C# tips everyday on my blog!"

That's why I started "Today's C# tips". This is the first article.  
(After a munite, I noticed it is hard to write everyday. I changed it every three days...)

## Main story

Today's main dish is the C# syntax which looks like SQL.  
(If you know that, ~~you should close this page and save your time~~.)

## Working with SQL

What do you associate SQL with?  
It may be:

- A kind of the tool for operating databases
- an initialism of Structured Query Language
- My SQL, Azure, Postgres, Oracle...

SQL is a language which specialize to manipulate databases. (And also I haven't heard somebody makes a game using it!) We will see the situation which SQL play an active part.

Table name : TestResults

|math|physics|name|
|:-----|:-----|:-----|
|50|100|A|
|60|70|B|
|80|80|C|
|40|90|D|

We have a table and want to extract those whose `math` is 50 or more and sort them in descending order of the value of `physics`. On this time, the following one is a SQL code which works as expected.

``` SQL
SELECT math, physics
FROM TestResults
WHERE math >= 50
ORDER BY physics DESC;
```

I don't describe more about SQL so if you want to know more, you should google.

## Can it be done by C#?

Yes! Use `System.Linq` to do that.

I used `List<>` and Tuple to express data. Sorry for the people who loves anonymous types.

``` C#
// using System;
// using System.Collections.Generic;

var testResults = new List<(int math, int physics, string name)>() {
    (50, 100, "A"),
    (60, 70, "B"),
    (80, 80, "C"),
    (40, 90, "D")
};
```

And here is the code which is equivalent to the previous SQL code.

``` C#
// using System.Linq;

var selected = from result in testResults
    where result.math >= 50
    orderby result.physics descending
    select result;
```

``` SQL
SELECT math, physics
FROM TestResults
WHERE math >= 50
ORDER BY physics DESC;
```

Compare them. Of course, there are small differences such as the usage of `Select` or `in`. However, They look alike each other, aren't they?

It is certain that you can write C# code like SQL.

## But many people use...

I told you about a SQL-like syntax for long time, but it's not a popular way to do so. Many people use some functions instead of it:

``` C#
var selected = testResults
    .Where(result => result >= 50)
    .OrderByDescending(result => result.physics);
```

~~I often use this and recommend this.~~ There are nothing which cannot do but with SQL-like syntax.

That's it.  
Have a nice C# day!