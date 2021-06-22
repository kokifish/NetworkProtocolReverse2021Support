#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>
#include "pin.H"

using std::list;
using std::ofstream;
using std::string;
// taint a specific unique address, 标记内存地址
std::list<UINT64> addressTainted;
// contains all registers controlled by the user input
// 标记由用户输入控制的寄存器
std::list<REG> regsTainted;

ofstream OutFile;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,
                            "pintool",
                            "o",
                            "MyPinTool.out",
                            "specify output file name");

INT32 Usage() {
    OutFile << "Taint demo, Unexpected Error\n";
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
    OutFile << std::hex << "\t\t\t" << addr << " is now freed\n";
}

VOID addMemTainted(UINT64 addr) {
    addressTainted.push_back(addr);
    OutFile << std::hex << "\t\t\t" << addr << " is now tainted\n";
}

// 从寄存器标记列表中增加某个寄存器的标记
bool taintReg(REG reg) {
    if (checkAlreadyRegTainted(reg) == true) {  //寄存器已被标记
        OutFile << "\t\t\t" << REG_StringShort(reg) << " is already tainted\n";
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
            OutFile << "\t\t\t" << REG_StringShort(reg)
                    << " can't be tainted\n";
            return false;
    }
    OutFile << "\t\t\t" << REG_StringShort(reg) << " is now tainted\n";
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

        default:
            return false;
    }
    OutFile << "\t\t\t" << REG_StringShort(reg) << " is now freed\n";
    return true;  //寄存器标记被成功移除
}

// Memory spread: 读内存时的回调函数
// when the program loads a value from the tainted area, we check if this memory
// location is tainted. If it is true, we taint the destination register.
// Otherwise, the memory is not tainted, so we check if the destination register
// is tainted. If not, we remove the register because we can't control the
// memory location.
VOID ReadMem(UINT64 insAddr,
             std::string insDis,
             UINT32 opCount,
             REG reg_r,
             UINT64 memOp  // 内存操作的地址
) {
    UINT64 addr = memOp;  // 内存操作的地址

    if (opCount != 2)
        return;

    for (list<UINT64>::iterator itr = addressTainted.begin();
         itr != addressTainted.end(); itr++) {
        // check if this memory location is tainted
        if (addr == *itr) {  // memory location is tainted
            OutFile << std::hex << "[READ in " << addr << "]\t" << insAddr
                    << ": " << insDis << std::endl;
            taintReg(reg_r);  // taint the destination register
            return;
        }
    }
    // if mem != tained and reg == taint => free the reg
    // 内存地址没有被标记，而寄存器被标记了，则释放对寄存器的标记
    if (checkAlreadyRegTainted(reg_r)) {
        OutFile << std::hex << "[READ in " << addr << "]\t" << insAddr << ": "
                << insDis << std::endl;
        // remove the register because we can't control the memory location
        removeRegTainted(reg_r);  //移除寄存器标记
    }
}

// Memory spread: Store操作，写内存操作 e.g. mov [rbx], rax
// If the destination location is tainted, we check if the register is tainted.
// If it is false, we need to free the location memory. Otherwise if the
// register is tainted, we taint the memory destination.
VOID WriteMem(UINT64 insAddr,
              std::string insDis,
              UINT32 opCount,
              REG reg_r,
              UINT64 memOp) {
    UINT64 addr = memOp;  // 内存操作的地址

    if (opCount != 2)
        return;  //指令操作数不等于2

    for (list<UINT64>::iterator itr = addressTainted.begin();
         itr != addressTainted.end(); itr++) {
        // If the destination location is tainted, we check if the register is
        // tainted
        if (addr == *itr) {
            OutFile << std::hex << "[WRITE in " << addr << "]\t" << insAddr
                    << ": " << insDis << std::endl;
            // 如果寄存器非法(常数) 或 该寄存器没有被标记
            if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
                removeMemTainted(addr);  // 移除对该处内存的标记
            return;
        }
    }
    // if the register is tainted, we taint the memory destination
    if (checkAlreadyRegTainted(reg_r)) {  //寄存器被标记
        OutFile << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": "
                << insDis << std::endl;
        addMemTainted(addr);  //标记内存地址
    }
}

// 寄存器标记扩展函数
// If the current instruction has two oprands and if the first operand is a
// register, we call the spreadRegTaint function.
// 指令有两个操作数，都是寄存器
VOID spreadRegTaint(UINT64 insAddr,
                    std::string insDis,
                    UINT32 opCount,
                    REG reg_r,  // 指令中第0个 读的寄存器
                    REG reg_w   // 指令中第0个 写的寄存器
) {
    if (opCount != 2)
        return;  //操作数不为2，非法
    // kth read register of instruction x, including implicit reads (e.g. stack
    // pointer is read by push on IA-32 architectures)
    if (REG_valid(reg_w)) {  // Check if register is valid.
        // reg_w已经标记 且 （reg_r不是寄存器(可能为常数) 或者 reg_r没有被标记）
        // 意义：曾被标记的污点数据不再是污点数据 //去污
        if (checkAlreadyRegTainted(reg_w) &&
            (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
            OutFile << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
            OutFile << "\t\t\toutput: " << REG_StringShort(reg_w)
                    << " | input: "
                    << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant")
                    << std::endl;
            removeRegTainted(reg_w);  // 移除对 reg_w 的标记 //e.g. Output:
            // [SPREAD]                  7fcccf0cf7db: mov edx, 0x1
            //                           output: edx | input: constant
            //                           edx is now freed
        }  // reg_w没有被标记 且 reg_r被标记：说明污点数据传播了
        else if (!checkAlreadyRegTainted(reg_w) &&
                 checkAlreadyRegTainted(reg_r)) {
            OutFile << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
            OutFile << "\t\t\toutput: " << REG_StringShort(reg_w)
                    << " | input: " << REG_StringShort(reg_r) << std::endl;
            taintReg(reg_w);  // 增加对 reg_w 的污点标记
        }
    }
}

VOID followData(UINT64 insAddr, std::string insDis, REG reg) {
    if (!REG_valid(reg))  // 不是合法寄存器 为常数
        return;

    if (checkAlreadyRegTainted(reg)) {  // 寄存器已经被标记
        OutFile << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
    }
}

VOID Instruction(INS ins, VOID* v) {
    // 操作数==2（two oprands ） 且 内存操作时读取 且 第一个操作数是寄存器
    if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) &&
        INS_OperandIsReg(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, IARG_ADDRINT,
                       INS_Address(ins), IARG_PTR,
                       new string(INS_Disassemble(ins)), IARG_UINT32,
                       INS_OperandCount(ins), IARG_UINT32,
                       INS_OperandReg(ins, 0), IARG_MEMORYOP_EA, 0, IARG_END);
    }
    // 操作数==2 且 指令第一个操作数是内存且为写入
    else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, IARG_ADDRINT,
                       INS_Address(ins), IARG_PTR,
                       new string(INS_Disassemble(ins)), IARG_UINT32,
                       INS_OperandCount(ins), IARG_UINT32,
                       INS_OperandReg(ins, 1), IARG_MEMORYOP_EA, 0, IARG_END);
    }
    // 操作数==2 且 指令第一个操作数是寄存器
    else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                       IARG_ADDRINT, INS_Address(ins), IARG_PTR,
                       new string(INS_Disassemble(ins)), IARG_UINT32,
                       INS_OperandCount(ins), IARG_UINT32, INS_RegR(ins, 0),
                       IARG_UINT32, INS_RegW(ins, 0), IARG_END);
    }

    // 操作数==2 且 指令第一个操作数是寄存器
    if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)followData, IARG_ADDRINT,
                       INS_Address(ins), IARG_PTR,
                       new string(INS_Disassemble(ins)), IARG_UINT32,
                       INS_RegR(ins, 0), IARG_END);
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

        OutFile << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x"
                << start << " to 0x" << start + size << " (via read)\n";
    }
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    OutFile.open(KnobOutputFile.Value().c_str());

    PIN_SetSyntaxIntel();
    // 系统调用入口函数
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    // Instrument 插桩
    INS_AddInstrumentFunction(Instruction, 0);
    // 程序开始（被检测应用，宿主程序）
    PIN_StartProgram();

    return 0;
}
