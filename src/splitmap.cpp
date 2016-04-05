#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <cstdio>
#include <memory>
#include <locale>
#include <cctype>
#include <tuple>
#include <map>

#include <unistd.h>

using namespace std;

// Returns false if the string contains any non-whitespace characters
// // Returns false if the string contains any non-ASCII characters
bool is_only_ascii_whitespace( const std::string& str )
{
    auto it = str.begin();
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

typedef tuple<int64_t, int64_t, int, string> d;
typedef map<string, d> procmap;

procmap exec(const char* cmd) {
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    procmap res;
    if (!pipe) {
        cout << "ERROR" << endl;
        return res;
    }
    char buffer[128];
    vector<string> v;
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL) {
            v = split(buffer, ' ');

            vector<string> range = split(v[0], '-');
            int64_t start = stoul(range[0], nullptr, 16);
            int64_t end = stoul(range[1], nullptr, 16);

            string perm = v[1];

            auto first = std::make_tuple (start, end, (int)end - start, perm);
            res[v[0]] = first;
        }
    }

    typedef map<string, d>::iterator it_type;

    for(it_type iterator = res.begin(); iterator != res.end(); iterator++) {
        auto n = iterator->second;
        cout << hex << get<0>(n) << "-" << get<1>(n) << " " << get<2>(n) << " " << get<3>(n) << endl;
    }

    return res;
}

//int main(int argc, const char *argv[])
//{
    //char cmd[30];
    //procmap p;
    //sprintf(cmd, "cat /proc/%d/maps", getpid());
    //p = exec(cmd);
    //return 0;
//}
