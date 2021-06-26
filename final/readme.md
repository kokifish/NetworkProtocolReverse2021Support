# 期末大作业

> 1. 基于客户端或者服务器端软件执行轨迹的加密网络应用的协议逆向分析
>
> 2. 采用“基于执行轨迹的协议逆向分析方法”对选定的加密应用进行协议逆向分析：
>    a)协议关键词、分界符？
>    b)报文格式？
>    c)字段的语义？例如长度、type、地址等；
>    协议的交互过程（或协议状态机）？
> 3. 写出分析报告：依据的原理、参考的文献、编写的代码、分析的过程、分析过程的截屏、展示结果的图表、关于结果的分析、关于你的逆向分析方法的讨论（特色和不足、与相关工作的对比等）。

参考链接：

-  Intel Pin官网:  https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html  里面找到User's Manual，很有用，写的很好，就是很长，没必要全部看完。（曾听说有大佬花了两天看完了）
- **Taint analysis and pattern matching with Pin**:   http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/  Intel Pin User's Manual看完必要看的一部分后(约1/3)，可以优先看这个巨佬写的
- 期末考试文档中的最后一个参考链接: https://github.com/zhilongwang/TaintAnalysisWithPin  新repo 没看过

# 关于分数

完成度越高分数越高，按已知信息，往届不乏按要求做完了的。

但是没法完全按要求做完也不用慌，能完成多少就完成多少，期末考试形式的大作业，拿出与之相配的努力就能拿高分。没有完全按要求做完的还是占多数。



# 高分指北

鉴于期末大作业难度较高(本课程近些年都如此)，完全按照要求完成有一定难度，这里给出一份高分指北，分实打实拿满分和拼一拼拿高分两个思路。

## 实打实拿满分

期末考试试卷(即大作业)上分三个小标题，实际上只需仔细阅读第一第二题即可，第三题是常见的大作业报告的要求，如果想要拿高分，第三题的要求是必须的。第二题的要求实际上是第一题的具体目标。

第一题题目：基于客户端或者服务器端软件**执行轨迹**的**加密**网络应用的**协议逆向分析**。结合推荐文献、链接可以猜测要求分为如下几点：

1. 使用的工具是Intel Pin
2. 分析的软件用的协议是加密的，至少是部分加密的。也就是用wireshark抓包时，传输的包会有部分是加密的。
3. 分析的主要行为是**软件执行轨迹**(但没要求是指令级还是函数/调用级)

猜测理想的大作业做的工作是：用Pin对某个应用使用污点扩散，分析数据报加密的数据在应用运行过程中是如何传播的，找到解密过程以及最后的明文，通过解密过程与明密文对照，分析协议的关键词、分节符、报文格式等。

## 拼一拼拿高分

首先明确一点，我不知道是否有要求一定要用Pin完成分析。如果没有明确说要用Pin完成分析，可以对任务做分拆：

1. 期望使用Pin，那就用Pin，但不用Pin真正完成作业目标。把Pin运行起来，找些指令级、函数/调用级的参考代码，在某个（较大的）应用上运行起来，保存分析过程的输出，对照着应用的行为（文件读写、wireshark抓包）分析一下，描述一些发现。
2. 要求协议是加密的，但是没有要求协议是未知的。所以分析的协议可以是已知的，有文档可查加密协议。拿着答案分析。很多应用都会用到TLS、HTTPS。
3. 用别的分析软件，静态分析如IDA Pro，动态的如gdb，ollydbg，分析一个非常小型的带有加密通信过程的应用。满足使用执行轨迹分析的要求。动态分析的工具入门较快，16h内搞懂基础操作，再用16h仔细分析和报文相关的操作（汇编指令+函数），注意截图。实际上很多动态分析是无法脱离静态分析的，只是纯静态分析难度往往更高。
4. 善用wireshark。用wireshark截获的包，与明文对比，完成题目2的分析。但是在写报告的时候应该侧重于描述：“我通过第3点的方法得出了....”
> 这里的小型应用指小于1k行的。可以从网上找现成的，但是建议找冷门一些的，或者对代码做一些改动，不然出现多份使用了相同应用的报告我也难办。

报告不用担心长，文字和图多多益善，但是注意排版，分段分标题，图片描述。

没事挂挂柯南吧。

# 该目录下的一些参考源码

- `github_syscalltest.cpp` 来源不详，应该来自github上某个仓库的。github上使用pin的源码挺多的，但是搜不搜得到适合自己用的，就....
- `Demo_ChapX.cpp ` 总共4个文件，根据源码中的信息，来自博客 http://shell-storm.org/blog/Taint-analysis-with-Pin/ 但实际应来自 http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/  （也就是期末考试文档的倒数第二个参考链接，不确定网站中的源码是否有更新）另外这个巨佬的repo  https://github.com/JonathanSalwan/PinTools 下的TaintAnalysis目录也可以参考。
  - 源码如`Demo_Chap4.cpp`包含一部分注释，也许对程序理解有一定帮助
- `Demo_Chap5.cpp` `Demo_Chap4.cpp`中包含一些污点分析中的核心操作（寄存器级、内存级标记/去标记过程），可以直接拿去用。问题的核心在于，对于不同应用，要选择一个合适的地方开始做标记。

污点标记起始位置选择：

1. 静态分析：IDA看源码，函数调用，标志性字符串等
2. 动态分析：依据平台选择调试器(ollydbg, gdb)，或者用Pin初步分析

对于小型程序，一般都是两者结合。

# Vmess Share

1. 复制下面vmess开头的内容
2. v2rayN (windows用) 菜单栏：服务器 -> 从剪贴板导入批量URL   或者 ctrl+V：导入 vmess节点。用于查找学习资料。

```
vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogImh0dHBzOi8vZ2l0LmlvL3Y5OTk5IOe+juWbvTU1IiwNCiAgImFkZCI6ICJmcmVlLXJ1c3NpYW4wMS1jZG4ueGlhb2hvdXppLmNsdWIiLA0KICAicG9ydCI6ICI4MCIsDQogICJpZCI6ICIzZDMxNzI4ZS0wNjRkLTQyYjgtYjk0NS1mNzljMDA4ZjczZmMiLA0KICAiYWlkIjogIjIzMyIsDQogICJuZXQiOiAid3MiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiZnJlZS1ydXNzaWFuMDEtY2RuLnhpYW9ob3V6aS5jbHViIiwNCiAgInBhdGgiOiAiLyIsDQogICJ0bHMiOiAiIg0KfQ==
```

