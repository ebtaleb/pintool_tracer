#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <map>

#include <unistd.h>
#include <fcntl.h>

#include "pin.H"
#include "instlib.H"

#include <sstream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <locale>

#include <stdint.h>

using namespace std;

// Returns false if the string contains any non-whitespace characters
// // Returns false if the string contains any non-ASCII characters
bool is_only_ascii_whitespace( const std::string& str )
{
    std::locale loc;
    std::string::const_iterator it = str.begin();
    do {
        if (it == str.end()) return true;
    } while (*it >= 0 && *it <= 0x7f && std::isspace(*(it++), loc));
    // one of these conditions will be optimized away by the compiler,
    // which one depends on whether char is signed or not
    return false;
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!is_only_ascii_whitespace(item))
            elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

struct d {
    int64_t start_ofs;
    int64_t end_ofs;
    int size;
    std::string perm;

    d & operator=(const d & first)
    {
        start_ofs = first.start_ofs;
        end_ofs = first.end_ofs;
        size = first.size;
        perm = first.perm;
        return *this;
    }
};

typedef map<string, d> procmap;

procmap exec(const char* cmd) {
    FILE *pipe=popen(cmd, "r");
    d first;
    procmap res;
    if (!pipe) {
        cout << "ERROR" << endl;
        return res;
    }
    char buffer[128];
    vector<string> v;
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL) {
            v = split(buffer, ' ');

            vector<string> range = split(v[0], '-');
            int64_t start = strtoul(range[0].c_str(), NULL, 16);
            int64_t end = strtoul(range[1].c_str(), NULL, 16);

            string perm = v[1];

            //d *first = new d;
            first.start_ofs = start;
            first.end_ofs = end;
            first.size = (int)end - start;
            first.perm= perm;

            res[v[0]] = first;
        }
    }

    pclose(pipe);

    typedef map<string, d>::iterator it_type;

    for(it_type iterator = res.begin(); iterator != res.end(); iterator++) {
        d n = iterator->second;
        cout << hex << n.start_ofs << "-" << n.end_ofs << " " << n.size << " " << n.perm<< endl;
    }

    return res;
}

std::ostream *out = &cerr;

ADDRINT main_begin;
ADDRINT main_end;
bool main_reached=false;
INT64 logfilter=1;
ADDRINT filter_begin=0;
ADDRINT filter_end=0;
ADDRINT entryPoint=0;

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
    *out << ss.str() << *instructionString << dumpContext(ctxt) << endl;
}

//static void DoBreakpoint(CONTEXT *ctxt, THREADID tid)
//{
    //if (IsFirstBreakpoint)
    //{
        //std::cout << "Tool stopping at breakpoint" << std::endl;
        //IsFirstBreakpoint = FALSE;
        //PIN_ApplicationBreakpoint(ctxt, tid, KnobWaitForDebugger.Value(), "The tool wants to stop");
        //PIN_ApplicationBreakpoint(ctxt, tid, true, "The tool wants to stop");
    //}
//}

void traceInst(INS ins, VOID*)
{
    ADDRINT ceip = INS_Address(ins);

    if(ExcludedAddress(ceip))
        return;

    if (ceip == entryPoint) {

        char mem_file_name[30];
        char buf[4096];
        int p1 = getpid();
        int mem_fd = -1;
        //int p2 = PIN_GetPid();
        //cout << dec << p1 << std::endl;
        //cout << dec << p2 << std::endl;

        sprintf(mem_file_name, "/proc/%d/mem", p1);
        if ((mem_fd = open(mem_file_name, O_RDONLY)) < 0) {
            cout << "error opening proc" << endl;
        } else {

            //ptrace(PTRACE_ATTACH, pid, NULL, NULL);
            //waitpid(pid, NULL, 0);
            //
            //0x8048000  0x8049000     0x1000
            if (lseek(mem_fd, 0x8048000, SEEK_SET) < 0) {
            //if (< 0) {
                cout << "error lseeking" << endl;
            }

            int res = 0;

            if ((res=read(mem_fd, buf, 0x1000)) < 0) {
                cout << "error reading" << endl;
            }

            //read(mem_fd, buf, _SC_PAGE_SIZE);
            //ptrace(PTRACE_DETACH, pid, NULL, NULL);
            //getpagesize()
            //
            close(mem_fd);
        }

        //INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoBreakpoint),
                       //IARG_CONTEXT, // IARG_CONST_CONTEXT has much lower overhead
                                     //// than IARG_CONTEX for passing the CONTEXT*
                                     //// to the analysis routine. Note that IARG_CONST_CONTEXT
                                     //// passes a read-only CONTEXT* to the analysis routine
                       //IARG_THREAD_ID, IARG_END);
    }

    //std::string mod_name = getModule(ceip);

    //INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dump_shellcode),
            //IARG_PTR, new std::string(dumpInstruction(ins)),
            //IARG_CONTEXT, IARG_END
            //);
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

#define START "_start"
#define MAIN "main"

VOID Image(IMG img, VOID *v)
{
    //  Find the malloc() function.
    RTN mallocRtn = RTN_FindByName(img, START);
    if (RTN_Valid(mallocRtn))
    {

        cout << "found _start at 0x" << hex << RTN_Address(mallocRtn) << endl;
        //RTN_Open(mallocRtn);

        //// Instrument malloc() to print the input argument value and the return value.
        //RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       //IARG_ADDRINT, MALLOC,
                       //IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       //IARG_END);
        //RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       //IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        //RTN_Close(mallocRtn);
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, MAIN);
    if (RTN_Valid(freeRtn))
    {
        cout << "found main at 0x" << hex << RTN_Address(freeRtn) << endl;
        //RTN_Open(freeRtn);
        //// Instrument free() to print the input argument value.
        //RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       //IARG_ADDRINT, FREE,
                       //IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       //IARG_END);
        //RTN_Close(freeRtn);
    }

    if (IMG_IsMainExecutable(img)) {
        entryPoint = IMG_Entry(img);
        cout << hex << entryPoint << endl;
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
    PIN_InitSymbols();
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

    IMG_AddInstrumentFunction(Image, 0);

    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }

    PIN_StartProgram();

    return 0;
}

