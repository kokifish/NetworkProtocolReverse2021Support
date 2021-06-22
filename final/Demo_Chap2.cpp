//
//  Jonathan Salwan - Copyright (C) 2013-08
//
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 1 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Simple taint memory area from read syscall.
//

#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>
#include "pin.H"

/* bytes range tainted */
struct range {
    UINT64 start;
    UINT64 end;
};

std::list<struct range> bytesTainted;  //跟踪的内存字节地址

INT32 Usage() {
    cerr << "Ex 1" << endl;
    return -1;
}

// callback: 读内存操作
VOID ReadMem(UINT64 insAddr,      // 指令的地址
             std::string insDis,  // 具体的指令 instruction description
             UINT64 memOp) {
    UINT64 addr = memOp;  // 内存操作的地址
    for (list<struct range>::iterator itr = bytesTainted.begin();
         itr != bytesTainted.end(); ++itr) {
        if (addr >= itr->start && addr < itr->end) {
            std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr
                      << ": " << insDis << std::endl;
            // e.g. [READ in 66501a]    400640: movzx eax, byte ptr [rax+0xa]
        }
    }
}

// callback: 写内存操作
VOID WriteMem(UINT64 insAddr, std::string insDis, UINT64 memOp) {
    UINT64 addr = memOp;
    for (list<struct range>::iterator itr = bytesTainted.begin();
         itr != bytesTainted.end(); ++itr) {
        if (addr >= itr->start && addr < itr->end) {
            std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr
                      << ": " << insDis << std::endl;
            // e.g. [WRITE in 665015]   40064f: mov byte ptr [rax], 0x74
        }
    }
}
// find the LOAD / STORE instruction
VOID Instruction(INS ins, VOID* v) {
    // 如果内存操作是读取操作 // e.g. mov rax, [rbx]
    // If the instruction's second operand read in the memory and if the first
    // operand is a register.  looks like 'mov reg, [r/imm]'
    if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)) {
        // if the instruction looks like 'mov reg, [r/imm]', it calls the
        // ReadMem function. When calling this function, it passes several
        // information like: the instruction address, the disassembly, and the
        // address of the memory read.
        // 指令增加回调函数：内存读的回调函数 memory read callback: ReadMem
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, IARG_ADDRINT,
                       INS_Address(ins), IARG_PTR,
                       new string(INS_Disassemble(ins)), IARG_MEMORYOP_EA, 0,
                       IARG_END);
    }
    // 如果内存操作是写入操作 // e.g. mov [rbx], rax
    else if (INS_MemoryOperandIsWritten(ins, 0)) {
        // 指令增加回调函数：内存写的回调函数：WriteMem
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, IARG_ADDRINT,
                       INS_Address(ins), IARG_PTR,
                       new string(INS_Disassemble(ins)), IARG_MEMORYOP_EA, 0,
                       IARG_END);
    }
}

static unsigned int lock;

#define TRICKS()         \
    {                    \
        if (lock++ == 0) \
            return;      \
    }

// Taint from Syscalls // 系统调用入口处的函数
// 供PIN_AddSyscallEntryFunction调用的回调函数
VOID Syscall_entry(THREADID thread_id,
                   CONTEXT* ctx,
                   SYSCALL_STANDARD std,
                   void* v) {
    struct range taint;

    // Taint from read
    // https://software.intel.com/sites/landingpage/pintool/docs/97971/Pin/html/group__PIN__SYSCALL__API.html
    // Get the number (ID) of the system call to be executed in the specified
    // context.
    // It is a user's responsibility to make sure that the specified context
    // represents the state of a system call before execution. For example, this
    // function can be safely used in the scope of SYSCALL_ENTRY_CALLBACK, but
    // not in a SYSCALL_EXIT_CALLBACK. Applying this function to an
    // inappropriate context results in undefined behavior.
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        TRICKS();
        // 第二个参数(idx=1)：内存起始位置
        taint.start =
            static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
        // 第三个参数(idx=2)：内存长度
        taint.end = taint.start +
                    static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
        // 将污点数据地址保存
        bytesTainted.push_back(taint);

        std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x"
                  << taint.start << " to 0x" << taint.end << " (via read)\n";
        // e.g. [TAINT] bytes tainted from 0x665010 to 0x665110 (via read)
    }
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    PIN_SetSyntaxIntel();
    // 系统调用前调用的函数
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    // 
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}

/*
$ ../../../pin -t ./obj-intel64/Taint_ex1.so -- ./test_ex1
[TAINT]             bytes tainted from 0x665010 to 0x665110 (via read)
[READ in 665010]    400620: movzx eax, byte ptr [rax]
[READ in 665014]    40062a: movzx eax, byte ptr [rax+0x4]
[READ in 665018]    400635: movzx eax, byte ptr [rax+0x8]
[READ in 66501a]    400640: movzx eax, byte ptr [rax+0xa]
[WRITE in 665015]   40064f: mov byte ptr [rax], 0x74
[WRITE in 66501a]   40065a: mov byte ptr [rax], 0x65
[WRITE in 665024]   400665: mov byte ptr [rax], 0x73
[WRITE in 66502e]   400670: mov byte ptr [rax], 0x74
 */

/* test_ex1.cpp
void foo(char *buf)
{
  char a;

  a = buf[0];
  a = buf[4];
  a = buf[8];
  a = buf[10];
  buf[5]  = 't';
  buf[10] = 'e';
  buf[20] = 's';
  buf[30] = 't';
}

int main(int ac, char **av)
{
  int fd;
  char *buf;

  if (!(buf = malloc(256)))
    return -1;

  fd = open("./file.txt", O_RDONLY);
  read(fd, buf, 256), close(fd);
  foo(buf);
}
 */