#include "pin.H"
#include "instlib.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

std::ostream *out = &cerr;

// Command line switches
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "res.out", "specify file name for MyPinTool output");

// Utilities
/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "Trace, on." << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/**
* Given a fully qualified path to a file, this function extracts the raw
* filename and gets rid of the path.
**/
std::string extractFilename(const std::string& filename)
{
    int lastBackslash = filename.rfind("\\");

    if (lastBackslash == -1)
    {
        return filename;
    }
    else
    {
        return filename.substr(lastBackslash + 1);
    }
}


/**
* Given an address, this function determines the name of the loaded module the
* address belongs to. If the address does not belong to any module, the empty
* string is returned.
**/
std::string getModule(ADDRINT address)
{
    // To find the module name of an address, iterate over all sections of all
    // modules until a section is found that contains the address.

    for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
            {
                return extractFilename(IMG_Name(img));
            }
        }
    }

    return "";
}

std::string dumpInstruction(INS ins)
{
    std::stringstream ss;

    ADDRINT address = INS_Address(ins);

    // Generate address and module information
    ss << getModule(address) << "  " << setfill('0') << setw(8) << uppercase << hex << address;
    ss << "   ";

    // Generate diassembled string
    string input = INS_Disassemble(ins);
    transform(input.begin(), input.end(), input.begin(), ::toupper);
    ss << input;

    for (unsigned int i=INS_Size(ins);i<8;i++)
    {
        ss << "   ";
    }

    return ss.str();
}

std::string dumpContext(CONTEXT* ctxt)
{
    std::stringstream ss;

    ss << "EAX=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_EAX) << ", "
       << "ECX=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_ECX) << ", "
       << "EDX=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_EDX) << ", "
       << "EBX=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_EBX) << ", "
       << "ESP=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_ESP) << ", "
       << "EBP=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_EBP) << ", "
       << "ESI=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_ESI) << ", "
       << "EDI=" << uppercase << setfill('0') << setw(8) << hex << PIN_GetContextReg(ctxt, REG_EDI);

    return ss.str();
}

void dump_shellcode(std::string* instructionString, CONTEXT* ctxt)
{
    std::stringstream ss;

    //ss << setw(8) << hex << PIN_GetContextReg(ctxt, REG_EIP);
    //return ss.str();
    *out << ss.str() << *instructionString << dumpContext(ctxt) << std::endl;
}

void traceInst(INS ins, VOID*)
{
    ADDRINT address = INS_Address(ins);

    std::string mod_name = getModule( address );

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dump_shellcode),
            IARG_PTR, new std::string(dumpInstruction(ins)),
            IARG_CONTEXT, IARG_END
            );
}

// Instrumentation callbacks
/*!
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            traceInst(ins, trace);
        }
    }
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

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }

    PIN_StartProgram();

    return 0;
}

