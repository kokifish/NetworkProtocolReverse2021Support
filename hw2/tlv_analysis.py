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


def TLVparser(pkt: str):
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
