#include "common/StringUtils.h"

#include <Windows.h>

#include <string>
#include <codecvt>
#include <algorithm>

std::wstring StringToWidestring(const std::string& str){
	std::wstring s = { str.begin(), str.end() };
	return s;
}

std::string WidestringToString(const std::wstring& wstr){
	std::string s = { wstr.begin(), wstr.end() };
	return s;
}

template<class T>
T ToUpperCase(const T& in){
	T copy = in;
	transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
	return copy;
}

template std::wstring ToUpperCase(const std::wstring& in);
template std::string ToUpperCase(const std::string& in);

template<class T>
T ToLowerCase(const T& in){
	T copy = in;
	transform(copy.begin(), copy.end(), copy.begin(), ::tolower);
	return copy;
}

template std::wstring ToLowerCase(const std::wstring& in);
template std::string ToLowerCase(const std::string& in);

template<class T>
bool CompareIgnoreCase(const T& in1, const T& in2){
	return ToLowerCase(in1) == ToLowerCase(in2);
}

template bool CompareIgnoreCase(const std::wstring& in1, const std::wstring& in2);
template bool CompareIgnoreCase(const std::string& in, const std::string& in2);