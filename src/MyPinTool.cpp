
#include "pin.H"
#include <iostream>
#include <iomanip>
#include <fstream>

// Global variables
UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 bblCount = 0;        //number of dynamically executed basic blocks

std::ostream *out = &cerr;

LOCALVAR VOID *WriteEa[PIN_MAX_THREADS];


// Command line switches
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "res.out", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobFlush(KNOB_MODE_WRITEONCE,                "pintool",
    "flush", "0", "Flush output after every instruction");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<BOOL>   KnobTraceMemory(KNOB_MODE_WRITEONCE,       "pintool",
    "memory", "0", "Trace memory");

KNOB<BOOL>   KnobTraceInstructions(KNOB_MODE_WRITEONCE,       "pintool",
    "instruction", "1", "Trace instructions");

KNOB<BOOL>   KnobSymbols(KNOB_MODE_WRITEONCE,       "pintool",
    "symbols", "0", "Include symbol information");
KNOB<BOOL>   KnobLines(KNOB_MODE_WRITEONCE,       "pintool",
    "lines", "0", "Include line number information");


// Utilities
/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

LOCALFUN BOOL Emit(THREADID threadid)
{
    return true;
}

LOCALFUN VOID Flush()
{
    if (KnobFlush)
        *out << flush;
}

VOID EmitNoValues(THREADID threadid, string * str)
{
    if (!Emit(threadid))
        return;

    *out
        << *str
        << endl;

    Flush();
}

VOID Emit1Values(THREADID threadid, string * str, string * reg1str, ADDRINT reg1val)
{
    if (!Emit(threadid))
        return;

    *out
        << *str << " | "
        << *reg1str << " = " << reg1val
        << endl;

    Flush();
}

VOID Emit2Values(THREADID threadid, string * str, string * reg1str, ADDRINT reg1val, string * reg2str, ADDRINT reg2val)
{
    if (!Emit(threadid))
        return;

    *out
        << *str << " | "
        << *reg1str << " = " << reg1val
        << ", " << *reg2str << " = " << reg2val
        << endl;

    Flush();
}

VOID Emit3Values(THREADID threadid, string * str, string * reg1str, ADDRINT reg1val, string * reg2str, ADDRINT reg2val, string * reg3str, ADDRINT reg3val)
{
    if (!Emit(threadid))
        return;

    *out
        << *str << " | "
        << *reg1str << " = " << reg1val
        << ", " << *reg2str << " = " << reg2val
        << ", " << *reg3str << " = " << reg3val
        << endl;

    Flush();
}


VOID Emit4Values(THREADID threadid, string * str, string * reg1str, ADDRINT reg1val, string * reg2str, ADDRINT reg2val, string * reg3str, ADDRINT reg3val, string * reg4str, ADDRINT reg4val)
{
    if (!Emit(threadid))
        return;

    *out
        << *str << " | "
        << *reg1str << " = " << reg1val
        << ", " << *reg2str << " = " << reg2val
        << ", " << *reg3str << " = " << reg3val
        << ", " << *reg4str << " = " << reg4val
        << endl;

    Flush();
}

const UINT32 MaxEmitArgs = 4;

AFUNPTR emitFuns[] =
{
    AFUNPTR(EmitNoValues), AFUNPTR(Emit1Values), AFUNPTR(Emit2Values), AFUNPTR(Emit3Values), AFUNPTR(Emit4Values)
};


VOID ShowN(UINT32 n, VOID *ea)
{
    out->unsetf(ios::showbase);
    // Print out the bytes in "big endian even though they are in memory little endian.
    // This is most natural for 8B and 16B quantities that show up most frequently.
    // The address pointed to
    *out << std::setfill('0');
    UINT8 b[512];
    UINT8* x;
    if (n > 512)
        x = new UINT8[n];
    else
        x = b;
    PIN_SafeCopy(x,static_cast<UINT8*>(ea),n);
    for (UINT32 i = 0; i < n; i++)
    {
        *out << std::setw(2) <<  static_cast<UINT32>(x[n-i-1]);
        if (((reinterpret_cast<ADDRINT>(ea)+n-i-1)&0x3)==0 && i<n-1)
            *out << "_";
    }
    *out << std::setfill(' ');
    out->setf(ios::showbase);
    if (n>512)
        delete [] x;
}

VOID EmitWrite(THREADID threadid, UINT32 size)
{
    if (!Emit(threadid))
        return;

    *out << "Write ";

    VOID * ea = WriteEa[threadid];

    switch(size)
    {
      case 0:
        *out << "0 repeat count" << endl;
        break;

      case 1:
        {
            UINT8 x;
            PIN_SafeCopy(&x, static_cast<UINT8*>(ea), 1);
            *out << "*(UINT8*)" << ea << " = " << static_cast<UINT32>(x) << endl;
        }
        break;

      case 2:
        {
            UINT16 x;
            PIN_SafeCopy(&x, static_cast<UINT16*>(ea), 2);
            *out << "*(UINT16*)" << ea << " = " << x << endl;
        }
        break;

      case 4:
        {
            UINT32 x;
            PIN_SafeCopy(&x, static_cast<UINT32*>(ea), 4);
            *out << "*(UINT32*)" << ea << " = " << x << endl;
        }
        break;

      case 8:
        {
            UINT64 x;
            PIN_SafeCopy(&x, static_cast<UINT64*>(ea), 8);
            *out << "*(UINT64*)" << ea << " = " << x << endl;
        }
        break;

      default:
        *out << "*(UINT" << dec << size * 8 << hex << ")" << ea << " = ";
        ShowN(size,ea);
        *out << endl;
        break;
    }

    Flush();
}

VOID EmitRead(THREADID threadid, VOID * ea, UINT32 size)
{
    if (!Emit(threadid))
        return;

    *out << "Read ";

    switch(size)
    {
      case 0:
        *out << "0 repeat count" << endl;
        break;

      case 1:
        {
            UINT8 x;
            PIN_SafeCopy(&x,static_cast<UINT8*>(ea),1);
            *out << static_cast<UINT32>(x) << " = *(UINT8*)" << ea << endl;
        }
        break;

      case 2:
        {
            UINT16 x;
            PIN_SafeCopy(&x,static_cast<UINT16*>(ea),2);
            *out << x << " = *(UINT16*)" << ea << endl;
        }
        break;

      case 4:
        {
            UINT32 x;
            PIN_SafeCopy(&x,static_cast<UINT32*>(ea),4);
            *out << x << " = *(UINT32*)" << ea << endl;
        }
        break;

      case 8:
        {
            UINT64 x;
            PIN_SafeCopy(&x,static_cast<UINT64*>(ea),8);
            *out << x << " = *(UINT64*)" << ea << endl;
        }
        break;

      default:
        ShowN(size,ea);
        *out << " = *(UINT" << dec << size * 8 << hex << ")" << ea << endl;
        break;
    }

    Flush();
}

VOID AddEmit(INS ins, IPOINT point, string & traceString, UINT32 regCount, REG regs[])
{
    if (regCount > MaxEmitArgs)
        regCount = MaxEmitArgs;

    IARGLIST args = IARGLIST_Alloc();
    for (UINT32 i = 0; i < regCount; i++)
    {
        IARGLIST_AddArguments(args, IARG_PTR, new string(REG_StringShort(regs[i])), IARG_REG_VALUE, regs[i], IARG_END);
    }

    INS_InsertCall(ins, point, emitFuns[regCount], IARG_THREAD_ID,
                   IARG_PTR, new string(traceString),
                   IARG_IARGLIST, args,
                   IARG_END);
    IARGLIST_Free(args);
}

string FormatAddress(ADDRINT address, RTN rtn)
{
    string s = StringFromAddrint(address);

    if (KnobSymbols && RTN_Valid(rtn))
    {
        s += " " + IMG_Name(SEC_Img(RTN_Sec(rtn))) + ":";
        s += RTN_Name(rtn);

        ADDRINT delta = address - RTN_Address(rtn);
        if (delta != 0)
        {
            s += "+" + hexstr(delta, 4);
        }
    }

    if (KnobLines)
    {
        INT32 line;
        string file;

        PIN_GetSourceLocation(address, NULL, &line, &file);

        if (file != "")
        {
            s += " (" + file + ":" + decstr(line) + ")";
        }
    }
    return s;
}

// Analysis routines
/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

VOID CaptureWriteEa(THREADID threadid, VOID * addr)
{
    WriteEa[threadid] = addr;
}

VOID InstructionTrace(TRACE trace, INS ins)
{
    //if (!KnobTraceInstructions)
        //return;

    ADDRINT addr = INS_Address(ins);
    ASSERTX(addr);

    // Format the string at instrumentation time
    string traceString = "";
    string astring = FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
    for (INT32 length = astring.length(); length < 30; length++)
    {
        traceString += " ";
    }
    traceString = astring + traceString;

    traceString += " " + INS_Disassemble(ins);

    for (INT32 length = traceString.length(); length < 80; length++)
    {
        traceString += " ";
    }

    INT32 regCount = 0;
    REG regs[20];

    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++)
    {
        REG x = REG_FullRegName(INS_RegW(ins, i));

        if (REG_is_gr(x)
#if defined(TARGET_IA32)
            || x == REG_EFLAGS
#elif defined(TARGET_IA32E)
            || x == REG_RFLAGS
#endif
        )
        {
            regs[regCount] = x;
            regCount++;
        }
    }

    if (INS_HasFallThrough(ins))
    {
        AddEmit(ins, IPOINT_AFTER, traceString, regCount, regs);
    }
    if (INS_IsBranchOrCall(ins))
    {
        AddEmit(ins, IPOINT_TAKEN_BRANCH, traceString, regCount, regs);
    }
}

VOID MemoryTrace(INS ins)
{
    if (!KnobTraceMemory)
        return;

    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CaptureWriteEa), IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_END);

        if (INS_HasFallThrough(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(EmitWrite), IARG_THREAD_ID, IARG_MEMORYWRITE_SIZE, IARG_END);
        }

        if (INS_IsBranchOrCall(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(EmitWrite),
                                     IARG_THREAD_ID, IARG_MEMORYWRITE_SIZE, IARG_END);
        }
    }

    if (INS_HasMemoryRead2(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitRead),
                                 IARG_THREAD_ID, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }

    if (INS_IsMemoryRead(ins) && !INS_IsPrefetch(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitRead),
                                 IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
}

// Instrumentation callbacks
/*!
 * Insert call to the CountBbl() analysis routine before every basic block
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

            InstructionTrace(trace, ins);
            //MemoryTrace(ins);
        }
    }
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out <<  "MyPinTool analysis results: " << endl;
    *out <<  "Number of instructions: " << insCount  << endl;
    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "===============================================" << endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    if (KnobCount)
    {
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }

    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }

    PIN_StartProgram();

    return 0;
}

