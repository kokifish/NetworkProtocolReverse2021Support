# 网络协议逆向分析课程第二次作业

> pre: protocol reverse engineering
>
> 本次作业所需附件：`TLVpackets.txt`， 大小：约17.9 M

作业要求描述（easyhpc.net）：附件数据是从网络上采集的UDP数据报，其中的每个整数代表一个字节的取值。例如，255代表该字节为0xFF。请编一个程序（语言不限，matlab也可以），解析其TLV结构。



# 思路

煮饺建议解题思路（妥协版）：

1. 将所给数据`TLVpackets.txt`读入，去除空行、注释行，保存为时候后续分析的数据类型
2. 数据包**去重**，可以同时统计不同数据包的重复个数
3. 根据TLV结构的相关知识，**猜测**其TLV结构（例如T和L的先后顺序，长度），在程序中按照所猜想的TLV结构，对每个包进行TLV解析，看解析结果是否与猜想的TLV结构有出入
4. 猜对了就**详细描述**该应用层协议的TLV结构，并**详细说明**你的**分析过程**

煮饺猜测原始的解题思路（可能是老师期待的版本）：

1. 前置步骤（1与2）与上相同
2. T先L后 / L先T后，L包含T / L不包含T，是否跳过前导字节，是否存在结尾字节，根据不同情况，设计一个**TLV解析函数**(可能需要递归调用)，对每个包（已去重）进行解析，看是否能刚好解析完整个包，或者都剩下相同的字节码（终止标志）

# 基础知识：TLV结构

> 参考链接（知乎）： https://zhuanlan.zhihu.com/p/62317518

- TLV编码结构：BER编码的一种，ASN1标准，全称Tag（标签），Length（长度），Value（值）
- IS-IS数据通信领域中，tlv三元组： tag-length-value（TLV）。T、L字段的长度往往固定（通常为1～4bytes），V字段长度可变。
  - T字段表示报文类型
  - L字段表示报文长度
  - V字段往往用来存放报文的内容



# 解决方案-部分（python）

- 暂时只放数据读取，数据转换部分，TLV解析部分自行完成

```python
# writer: github.com/hex-16   data: 2021.3.25   contact: hexhex16@outlook.com

def readData(fname="TLVpackets.txt"):
    # 读取数据集，将有用的数据存储在list中，外层list的元素也为list，内层list的元素为字节取值（0~255），int型
    # 示意图： list(list(0, 2, 128, 255), list(...), list() .... )
    f = open(fname)
    lines = f.readlines()
    all_pkts = list()
    for line in lines:
        if(len(line) <= 1 or line[0] == '#'):
            continue
        line = line.split(' ')
        if(line[-1] == '\n'):
            line = line[:-1]
        l = [int(a) for a in line]  # type(l[0]): int
        all_pkts.append(l)
    f.close()
    return all_pkts


def TLVparser(pkt: str): # TBD
    # 对传入的包做TLV解析，如果刚好能解析完整个包，则返回True，否则False
    return False


if __name__ == "__main__":
    all_pkts = readData()
    print(len(all_pkts))
    for i in range(len(all_pkts)):
        pkt = all_pkts[i]
        pkt = ''.join(map(chr, pkt))
        all_pkts[i] = pkt
        # print(type(pkt), len(pkt), pkt)
    all_pkts = list(set(all_pkts))
    print(len(all_pkts))  # 14911
    all_pkts.sort()
    for i in range(len(all_pkts)):
        print()
        l = [ord(c) for c in all_pkts[i]]
        print("l: ", l)
        b_pkt = bytes(all_pkts[i], 'utf-8')
        # print(b_pkt.hex())
        print(len(all_pkts[i]), all_pkts[i])
        flag = TLVparser(all_pkts[i])
```

