#include "util/StringUtils.h"

#include <algorithm>
#include <cmath>
#include <codecvt>
#include <map>
#include <string>
#include <vector>

double GetShannonEntropy(const bstring& str) {
    // Code from https://rosettacode.org/wiki/Entropy#C.2B.2B
    std::map<char, int> frequencies;
    for(char c : str)
        frequencies[c]++;
    int numlen = str.length();
    double infocontent = 0;
    for(std::pair<char, int> p : frequencies) {
        double freq = static_cast<double>(p.second) / numlen;
        infocontent -= freq * (log(freq) / log(2));
    }

    return infocontent;
}

bstring StringToWidestring(const std::string& str) {
    bstring s = { str.begin(), str.end() };
    return s;
}

std::string WidestringToString(const bstring& wstr) {
    std::string s = { wstr.begin(), wstr.end() };
    return s;
}

bstring ExpandEnvStringsW(const bstring& in) {
    WCHAR* expanded = new WCHAR[MAX_PATH];
    auto result = ExpandEnvironmentStringsW(in.c_str(), expanded, MAX_PATH);
    if(result > MAX_PATH) {
        delete[] expanded;
        expanded = new WCHAR[result];
        result = ExpandEnvironmentStringsW(in.c_str(), expanded, result);
    }

    bstring str{ expanded };

    delete[] expanded;

    return str;
}

std::string ExpandEnvStringsA(const std::string& in){
	CHAR* expanded = new CHAR[MAX_PATH];
	auto result = ExpandEnvironmentStringsA(in.c_str(), expanded, MAX_PATH);
	if(result > MAX_PATH){
		delete[] expanded;
		expanded = new CHAR[result];
		result = ExpandEnvironmentStringsA(in.c_str(), expanded, result);
	}

    std::string str{ expanded };

    delete[] expanded;

    return str;
}

bstring ToWstringPad(DWORD value, size_t length) {
    wchar_t* buf = new wchar_t[length + 1];
    swprintf(buf, (L"%0" + std::to_wstring(length) + L"d").c_str(), value);
    bstring str = buf;
    delete[] buf;
    return str;
}

template<class T>
T ToUpperCase(const T& in) {
    T copy = in;
    transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    return copy;
}

template bstring ToUpperCase(const bstring& in);
template std::string ToUpperCase(const std::string& in);

template<class T>
T ToLowerCase(const T& in) {
    T copy = in;
    transform(copy.begin(), copy.end(), copy.begin(), ::tolower);
    return copy;
}

template bstring ToLowerCase(const bstring& in);
template std::string ToLowerCase(const std::string& in);

template<class T>
bool CompareIgnoreCase(const T& in1, const T& in2) {
    return ToLowerCase(in1) == ToLowerCase(in2);
}

template bool CompareIgnoreCase(const bstring& in1, const bstring& in2);
template bool CompareIgnoreCase(const std::string& in, const std::string& in2);

template<class T>
T StringReplace(const T& string, const T& search, const T& replacement) {
    auto copy{ string };
    for(auto find{ copy.find(search) }; find != std::string::npos;
        find = copy.find(search, find + replacement.size())) {
        copy.replace(copy.begin() + find, copy.begin() + find + search.length(), replacement);
    }
    return copy;
}

template bstring
StringReplace(const bstring& string, const bstring& search, const bstring& replacement);
template std::string
StringReplace(const std::string& string, const std::string& search, const std::string& replacement);
template bool CompareIgnoreCase(const std::string& in, const std::string& in2);

template<class T>
std::vector<std::basic_string<T>> SplitString(const std::basic_string<T>& in, const std::basic_string<T>& delimiter) {
    std::vector<std::basic_string<T>> substrs{};
    for(size_t i = 0; i < in.length();) {
        auto next{ in.find(delimiter, i) };
        substrs.emplace_back(in.substr(i, next - i));
        if(next == std::basic_string<T>::npos) {
            return std::move(substrs);
        }
        i = next + delimiter.length();
    }
    return substrs;
}

template std::vector<bstring> SplitString(const bstring& in, const bstring& delimiter);
template std::vector<std::string> SplitString(const std::string& in, const std::string& delimiter);
