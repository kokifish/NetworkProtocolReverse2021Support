//
//  Jonathan Salwan - Copyright (C) 2013-08
//
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 2 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Spread the taint in memory and registers.
//

#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>
#include "pin.H"

// taint a specific unique address, 标记内存地址
std::list<UINT64> addressTainted;
// contains all registers controlled by the user input
// 标记由用户输入控制的寄存器
std::list<REG> regsTainted;

INT32 Usage() {
    cerr << "Ex 2, Unexpected Error\n";
    return -1;
}

// 判断该寄存器是否被标记：true: 该寄存器被标记
bool checkAlreadyRegTainted(REG reg) {
    for (list<REG>::iterator itr = regsTainted.begin();
         itr != regsTainted.end(); itr++) {
        if (*itr == reg) {
            return true;
        }
    }
    return false;
}

VOID removeMemTainted(UINT64 addr) {
    addressTainted.remove(addr);  // Remove elements with specific value
    std::cout << std::hex << "\t\t\t" << addr << " is now freed\n";
}

VOID addMemTainted(UINT64 addr) {
    addressTainted.push_back(addr);
    std::cout << std::hex << "\t\t\t" << addr << " is now tainted\n";
}

// 从寄存器标记列表中增加某个寄存器的标记
bool taintReg(REG reg) {
    if (checkAlreadyRegTainted(reg) == true) {  //寄存器已被标记
        std::cout << "\t\t\t" << REG_StringShort(reg)
                  << " is already tainted\n";
        return false;
    }

    switch (reg) {
        case REG_RAX:
            regsTainted.push_front(REG_RAX);
        case REG_EAX:
            regsTainted.push_front(REG_EAX);
        case REG_AX:
            regsTainted.push_front(REG_AX);
        case REG_AH:
            regsTainted.push_front(REG_AH);
        case REG_AL:
            regsTainted.push_front(REG_AL);
            break;

        case REG_RBX:
            regsTainted.push_front(REG_RBX);
        case REG_EBX:
            regsTainted.push_front(REG_EBX);
        case REG_BX:
            regsTainted.push_front(REG_BX);
        case REG_BH:
            regsTainted.push_front(REG_BH);
        case REG_BL:
            regsTainted.push_front(REG_BL);
            break;

        case REG_RCX:
            regsTainted.push_front(REG_RCX);
        case REG_ECX:
            regsTainted.push_front(REG_ECX);
        case REG_CX:
            regsTainted.push_front(REG_CX);
        case REG_CH:
            regsTainted.push_front(REG_CH);
        case REG_CL:
            regsTainted.push_front(REG_CL);
            break;

        case REG_RDX:
            regsTainted.push_front(REG_RDX);
        case REG_EDX:
            regsTainted.push_front(REG_EDX);
        case REG_DX:
            regsTainted.push_front(REG_DX);
        case REG_DH:
            regsTainted.push_front(REG_DH);
        case REG_DL:
            regsTainted.push_front(REG_DL);
            break;

        case REG_RDI:
            regsTainted.push_front(REG_RDI);
        case REG_EDI:
            regsTainted.push_front(REG_EDI);
        case REG_DI:
            regsTainted.push_front(REG_DI);
        case REG_DIL:
            regsTainted.push_front(REG_DIL);
            break;

        case REG_RSI:
            regsTainted.push_front(REG_RSI);
        case REG_ESI:
            regsTainted.push_front(REG_ESI);
        case REG_SI:
            regsTainted.push_front(REG_SI);
        case REG_SIL:
            regsTainted.push_front(REG_SIL);
            break;

        default:
            std::cout << "\t\t\t" << REG_StringShort(reg)
                      << " can't be tainted\n";
            return false;
    }
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted\n";
    return true;
}

// 从寄存器标记列表中去除某个寄存器的标记
bool removeRegTainted(REG reg) {
    switch (reg) {
        case REG_RAX:
            regsTainted.remove(REG_RAX);
        case REG_EAX:
            regsTainted.remove(REG_EAX);
        case REG_AX:
            regsTainted.remove(REG_AX);
        case REG_AH:
            regsTainted.remove(REG_AH);
        case REG_AL:
            regsTainted.remove(REG_AL);
            break;

        case REG_RBX:
            regsTainted.remove(REG_RBX);
        case REG_EBX:
            regsTainted.remove(REG_EBX);
        case REG_BX:
            regsTainted.remove(REG_BX);
        case REG_BH:
            regsTainted.remove(REG_BH);
        case REG_BL:
            regsTainted.remove(REG_BL);
            break;

        case REG_RCX:
            regsTainted.remove(REG_RCX);
        case REG_ECX:
            regsTainted.remove(REG_ECX);
        case REG_CX:
            regsTainted.remove(REG_CX);
        case REG_CH:
            regsTainted.remove(REG_CH);
        case REG_CL:
            regsTainted.remove(REG_CL);
            break;

        case REG_RDX:
            regsTainted.remove(REG_RDX);
        case REG_EDX:
            regsTainted.remove(REG_EDX);
        case REG_DX:
            regsTainted.remove(REG_DX);
        case REG_DH:
            regsTainted.remove(REG_DH);
        case REG_DL:
            regsTainted.remove(REG_DL);
            break;

        case REG_RDI:
            regsTainted.remove(REG_RDI);
        case REG_EDI:
            regsTainted.remove(REG_EDI);
        case REG_DI:
            regsTainted.remove(REG_DI);
        case REG_DIL:
            regsTainted.remove(REG_DIL);
            break;

        case REG_RSI:
            regsTainted.remove(REG_RSI);
        case REG_ESI:
            regsTainted.remove(REG_ESI);
        case REG_SI:
            regsTainted.remove(REG_SI);
        case REG_SIL:
            regsTainted.remove(REG_SIL);
            break;

        default:  //没有匹配到哪个寄存器
            return false;
    }
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed\n";
    return true;  //寄存器标记被成功移除
}

// Memory spread: 读内存时的回调函数
// when the program loads a value from the tainted area, we check if this memory
// location is tainted. If it is true, we taint the destination register.
// Otherwise, the memory is not tainted, so we check if the destination register
// is tainted. If not, we remove the register because we can't control the
// memory location.
VOID ReadMem(INS ins, UINT64 memOp) {
    UINT64 addr = memOp;  // 内存操作的地址
    REG reg_r;

    if (INS_OperandCount(ins) != 2)
        return;
    // register name for this operand, may return REG_INVALID()
    reg_r = INS_OperandReg(ins, 0);
    for (list<UINT64>::iterator itr = addressTainted.begin();
         itr != addressTainted.end(); itr++) {
        // check if this memory location is tainted
        if (addr == *itr) {  // memory location is tainted
            std::cout << std::hex << "[READ in " << addr << "]\t"
                      << INS_Address(ins) << ": " << INS_Disassemble(ins)
                      << std::endl;
            taintReg(reg_r);  // taint the destination register
            return;
        }
    }
    // if mem != tained and reg == taint => free the reg
    // 内存地址没有被标记，而寄存器被标记了，则释放对寄存器的标记
    if (checkAlreadyRegTainted(reg_r)) {
        std::cout << std::hex << "[READ in " << addr << "]\t"
                  << INS_Address(ins) << ": " << INS_Disassemble(ins)
                  << std::endl;
        // remove the register because we can't control the memory location
        removeRegTainted(reg_r);  //移除寄存器标记
    }
}

// Memory spread: Store操作，写内存操作 e.g. mov [rbx], rax
// If the destination location is tainted, we check if the register is tainted.
// If it is false, we need to free the location memory. Otherwise if the
// register is tainted, we taint the memory destination.
VOID WriteMem(INS ins, UINT64 memOp) {
    UINT64 addr = memOp;  // 内存操作的地址
    REG reg_r;

    if (INS_OperandCount(ins) != 2)
        return;  //指令操作数不等于2

    reg_r = INS_OperandReg(ins, 1);  // 寄存器是后面一个
    for (list<UINT64>::iterator itr = addressTainted.begin();
         itr != addressTainted.end(); itr++) {
        // If the destination location is tainted, we check if the register is
        // tainted
        if (addr == *itr) {
            std::cout << std::hex << "[WRITE in " << addr << "]\t"
                      << INS_Address(ins) << ": " << INS_Disassemble(ins)
                      << std::endl;
            // 如果寄存器非法 或 该寄存器没有被标记
            if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
                removeMemTainted(addr);  // 移除对该处内存的标记
            return;
        }
    }
    // if the register is tainted, we taint the memory destination
    if (checkAlreadyRegTainted(reg_r)) {  //寄存器被标记
        std::cout << std::hex << "[WRITE in " << addr << "]\t"
                  << INS_Address(ins) << ": " << INS_Disassemble(ins)
                  << std::endl;
        addMemTainted(addr);  //标记内存地址
    }
}

// 寄存器标记扩展函数
// If the current instruction has two oprands and if the first operand is a
// register, we call the spreadRegTaint function.
VOID spreadRegTaint(INS ins) {  //指令有两个操作数，第一个操作数是寄存器
    REG reg_r, reg_w;

    if (INS_OperandCount(ins) != 2)  //操作数不为2，非法
        return;
    // kth read register of instruction x, including implicit reads (e.g. stack
    // pointer is read by push on IA-32 architectures)
    reg_r = INS_RegR(ins, 0);  // 指令中第0个 读的寄存器
    // kth write register of instruction x, including implicit writes (e.g.
    // stack pointer is written by push on IA-32 architectures)
    reg_w = INS_RegW(ins, 0);  // 指令中第0个 写的寄存器

    if (REG_valid(reg_w)) {  // Check if register is valid.
        // reg_w已经标记 且 （reg_r不是寄存器(可能为常数) 或者 reg_r没有被标记）
        // 意义：曾被标记的污点数据不再是污点数据 //去污
        if (checkAlreadyRegTainted(reg_w) &&
            (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
            std::cout << "[SPREAD]\t\t" << INS_Address(ins) << ": "
                      << INS_Disassemble(ins) << std::endl;
            std::cout << "\t\t\toutput: " << REG_StringShort(reg_w)
                      << " | input: "
                      << (REG_valid(reg_r) ? REG_StringShort(reg_r)
                                           : "constant")
                      << std::endl;
            removeRegTainted(reg_w);  // 移除对 reg_w 的标记 //e.g. Output:
            // [SPREAD]                  7fcccf0cf7db: mov edx, 0x1
            //                           output: edx | input: constant
            //                           edx is now freed
        }  // reg_w没有被标记 且 reg_r被标记：说明污点数据传播了
        else if (!checkAlreadyRegTainted(reg_w) &&
                 checkAlreadyRegTainted(reg_r)) {
            std::cout << "[SPREAD]\t\t" << INS_Address(ins) << ": "
                      << INS_Disassemble(ins) << std::endl;
            std::cout << "\t\t\toutput: " << REG_StringShort(reg_w)
                      << " | input: " << REG_StringShort(reg_r) << std::endl;
            taintReg(reg_w);  // 增加对 reg_w 的污点标记
        }
    }
}

VOID Instruction(INS ins, VOID* v) {
    // 操作数==2（two oprands ） 且 内存操作时读取 且 第一个操作数是寄存器
    if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) &&
        INS_OperandIsReg(ins, 0)) {
        // 调用内存读操作标记函数
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, IARG_PTR, ins,
                       IARG_MEMORYOP_EA, 0, IARG_END);
    }
    // 操作数==2 且 指令第一个操作数是寄存器
    else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)) {
        // 调用内存写操作标记函数
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, IARG_PTR, ins,
                       IARG_MEMORYOP_EA, 0, IARG_END);
    }
    // 操作数==2 且 指令第一个操作数是寄存器
    else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)) {
        // 调用寄存器标记扩展函数
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint, IARG_PTR,
                       ins, IARG_END);
    }
}

static unsigned int tryksOpen;

VOID Syscall_entry(THREADID thread_id,
                   CONTEXT* ctx,
                   SYSCALL_STANDARD std,
                   void* v) {
    UINT64 start, size;

    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        if (tryksOpen++ == 0) {
            return;  // tricks to ignore the first open
        }

        start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
        size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

        for (unsigned int idx = 0; idx < size; ++idx)
            addressTainted.push_back(start + idx);

        std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x"
                  << start << " to 0x" << start + size << " (via read)\n";
    }
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    PIN_SetSyntaxIntel();
    // 系统调用入口函数
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    // Instrument 插桩
    INS_AddInstrumentFunction(Instruction, 0);
    // 程序开始（被检测应用，宿主程序）
    PIN_StartProgram();

    return 0;
}

/*
$ ../../../pin -t ./obj-intel64/Taint.so -- ./test
[TAINT]                   bytes tainted from 0xb5b010 to 0xb5b030 (via read)
[READ in b5b010]          400649: movzx eax, byte ptr [rax]
                          eax is now tainted
[WRITE in 7fffa185d9ff]   40064c: mov byte ptr [rbp-0x1], al
                          7fffa185d9ff is now tainted
[READ in 7fffa185d9ff]    40064f: movzx eax, byte ptr [rbp-0x1]
                          eax is already tainted
[WRITE in 7fffa185d9fe]   400653: mov byte ptr [rbp-0x2], al
                          7fffa185d9fe is now tainted
[READ in b5b018]          40065a: movzx eax, byte ptr [rax+0x8]
                          eax is already tainted
[WRITE in 7fffa185d9fd]   40065e: mov byte ptr [rbp-0x3], al
                          7fffa185d9fd is now tainted
[READ in 7fffa185d9ff]    400661: movsx edx, byte ptr [rbp-0x1]
                          edx is now tainted
[READ in 7fffa185d9fe]    400665: movsx ecx, byte ptr [rbp-0x2]
                          ecx is now tainted
[READ in 7fffa185d9fd]    400669: movsx eax, byte ptr [rbp-0x3]
                          eax is already tainted
[SPREAD]                  40066d: mov esi, ecx
                          output: esi | input: ecx
                          esi is now tainted
[SPREAD]                  40066f: mov edi, eax
                          output: edi | input: eax
                          edi is now tainted
[WRITE in 7fffa185d9c4]   40061c: mov byte ptr [rbp-0x14], dil
                          7fffa185d9c4 is now tainted
[WRITE in 7fffa185d9c0]   400620: mov byte ptr [rbp-0x18], cl
                          7fffa185d9c0 is now tainted
[WRITE in 7fffa185d9bc]   400623: mov byte ptr [rbp-0x1c], al
                          7fffa185d9bc is now tainted
[SPREAD]                  400632: mov eax, 0x0
                          output: eax | input: constant
                          eax is now freed
[SPREAD]                  7fcccf0b960d: mov edi, eax
                          output: edi | input: eax
                          edi is now freed
[SPREAD]                  7fcccf0cf7db: mov edx, 0x1
                          output: edx | input: constant
                          edx is now freed
[SPREAD]                  7fcccf0cf750: mov esi, ebx
                          output: esi | input: ebx
                          esi is now freed
[READ in 7fcccf438140]    7fcccf11027e: mov ecx, dword ptr [rbp+0xc0]
                          ecx is now freed
                           */

/*
int foo2(char a, char b, char c) {
    a = 1;
    b = 2;
    c = 3;
    return 0;
}

int foo(char* buf) {
    char c, b, a;

    c = buf[0];
    b = c;
    a = buf[8];
    foo2(a, b, c);
    return true;
}

int main(int ac, char** av) {
    int fd;
    char* buf;

    if (!(buf = malloc(32)))
        return -1;

    fd = open("./file.txt", O_RDONLY);
    read(fd, buf, 32), close(fd);
    foo(buf);
}
 */