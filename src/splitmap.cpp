#include <sstream>
#include <vector>
#include <iostream>
#include <cstdio>
#include <map>
#include <cstdlib>

#include <stdint.h>
#include <unistd.h>

using namespace std;

// Returns false if the string contains any non-whitespace characters
// // Returns false if the string contains any non-ASCII characters
bool is_only_ascii_whitespace( const std::string& str )
{
    std::string::const_iterator it = str.begin();
    do {
        if (it == str.end()) return true;
    } while (*it >= 0 && *it <= 0x7f && std::isspace(*(it++)));
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

            first.start_ofs = start;
            first.end_ofs = end;
            first.size = (int)end - start;
            first.perm = perm;

            res[v[0]] = first;
        }
    }

    pclose(pipe);

    typedef map<string, d>::iterator it_type;

    for(it_type iterator = res.begin(); iterator != res.end(); iterator++) {
        d n = iterator->second;
        cout << hex << n.start_ofs << "-" << n.end_ofs << " " << n.size << " " << n.perm << endl;
    }

    return res;
}

int main(int argc, const char *argv[])
{
    char cmd[30];
    procmap p;
    sprintf(cmd, "cat /proc/%d/maps", getpid());
    p = exec(cmd);
    return 0;
}
