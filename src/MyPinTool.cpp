#include "pin.H"
#include "instlib.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <map>

std::ostream *out = &cerr;

ADDRINT main_begin;
ADDRINT main_end;
bool main_reached=false;
INT64 logfilter=1;
ADDRINT filter_begin=0;
ADDRINT filter_end=0;

struct moduledata_t
{
    BOOL excluded;
    ADDRINT begin;
    ADDRINT end;
};

typedef std::map<string, moduledata_t> modmap_t;
modmap_t mod_data;

// Command line switches
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "res.out", "specify file name for UBW output");

KNOB<string> KnobLogFilter(KNOB_MODE_WRITEONCE, "pintool",
    "f", "1", "(0) no filter\
                (1) filter system libraries\
                (2) filter all but main exec (0x400000-0x410000) trace only specified address range");

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

BOOL ExcludedAddress(ADDRINT ip)
{
    switch (logfilter)
    {
    case 1:
        if (! main_reached)
        {
	        // Filter loader before main
	        if ((ip < main_begin) || (ip > main_end))
	            return TRUE;
            else
                main_reached=true;
		}
        if ((ip >= main_begin) && (ip <= main_end))
            return FALSE;
        for(modmap_t::iterator it = mod_data.begin(); it != mod_data.end(); ++it)
        {
            if(it->second.excluded == FALSE) continue;
            /* Is the EIP value within the range of any excluded module? */
            if(ip >= it->second.begin && ip <= it->second.end) return TRUE;
        }
        break;
    case 2:
    {
        PIN_LockClient();
        IMG im = IMG_FindByAddress(ip);
        PIN_UnlockClient();
        if (! IMG_Valid(im) || ! IMG_IsMainExecutable(im))
            return TRUE;
        break;
    }
    case 3:
        return ((ip < filter_begin) || (ip > filter_end));
        break;
    default:
        break;
    }
    return FALSE;
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

    ADDRINT ceip = INS_Address(ins);

    // Generate address and module information
    ss << getModule(ceip) << "  " << setfill('0') << setw(8) << uppercase << hex << ceip;
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
    ADDRINT ceip = INS_Address(ins);

    if(ExcludedAddress(ceip))
        return;

    std::string mod_name = getModule(ceip);

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
        INS head = BBL_InsHead(bbl);
        if(ExcludedAddress(INS_Address(head)))
            return;

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

    char *endptr;
    const char *tmpfilter = KnobLogFilter.Value().c_str();
    logfilter=strtoull(tmpfilter, &endptr, 16);
    if (endptr == tmpfilter) {
        cerr << "ERR: Failed parsing option -f" <<endl;
        return 1;
    }
    if ((endptr[0] == '\0') && (logfilter > 2)) {
        cerr << "ERR: Failed parsing option -f" <<endl;
        return 1;
    }
    if (logfilter > 2) {
        filter_begin=logfilter;
        logfilter = 3;
        char *endptr2;
        if (endptr[0] != '-') {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
        filter_end=strtoull(endptr+1, &endptr2, 16);
        if (endptr2 == endptr+1) {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
        if (endptr2[0] != '\0') {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
        if (filter_end <= filter_begin) {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
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

