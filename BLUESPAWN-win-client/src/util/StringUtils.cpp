#include "util/StringUtils.h"

#include <algorithm>
#include <cmath>
#include <codecvt>
#include <map>
#include <string>
#include <vector>

double GetShannonEntropy(const std::wstring& str) {
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

std::wstring StringToWidestring(const std::string& str) {
    std::wstring s = { str.begin(), str.end() };
    return s;
}

std::string WidestringToString(const std::wstring& wstr) {
    std::string s = { wstr.begin(), wstr.end() };
    return s;
}

std::wstring ExpandEnvStringsW(const std::wstring& in) {
    WCHAR* expanded = new WCHAR[MAX_PATH];
    auto result = ExpandEnvironmentStringsW(in.c_str(), expanded, MAX_PATH);
    if(result > MAX_PATH) {
        delete[] expanded;
        expanded = new WCHAR[result];
        result = ExpandEnvironmentStringsW(in.c_str(), expanded, result);
    }

    std::wstring str{ expanded };

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

std::wstring ToWstringPad(DWORD value, size_t length) {
    wchar_t* buf = new wchar_t[length + 1];
    swprintf(buf, (L"%0" + std::to_wstring(length) + L"d").c_str(), value);
    std::wstring str = buf;
    delete[] buf;
    return str;
}

template<class T>
T ToUpperCase(const T& in) {
    T copy = in;
    transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    return copy;
}

template std::wstring ToUpperCase(const std::wstring& in);
template std::string ToUpperCase(const std::string& in);

template<class T>
T ToLowerCase(const T& in) {
    T copy = in;
    transform(copy.begin(), copy.end(), copy.begin(), ::tolower);
    return copy;
}

template std::wstring ToLowerCase(const std::wstring& in);
template std::string ToLowerCase(const std::string& in);

template<class T>
bool CompareIgnoreCase(const T& in1, const T& in2) {
    return ToLowerCase(in1) == ToLowerCase(in2);
}

template bool CompareIgnoreCase(const std::wstring& in1, const std::wstring& in2);
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

template std::wstring
StringReplace(const std::wstring& string, const std::wstring& search, const std::wstring& replacement);
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

template std::vector<std::wstring> SplitString(const std::wstring& in, const std::wstring& delimiter);
template std::vector<std::string> SplitString(const std::string& in, const std::string& delimiter);
