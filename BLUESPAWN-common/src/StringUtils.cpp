#include "common/StringUtils.h"

#include <Windows.h>

#include <string>
#include <codecvt>
#include <algorithm>

std::wstring StringToWidestring(const std::string& str){
	WCHAR* wstr = new WCHAR[str.length() + 1];
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), wstr, static_cast<int>(str.length() + 1));
	std::wstring s = { str.begin(), str.end() };
	delete[] wstr;
	return s;
}

std::string WidestringToString(const std::wstring& wstr){
	int size = 0;
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0, nullptr, &size);
	CHAR* str = new CHAR[size];
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), static_cast<int>(wstr.length()), str, size, nullptr, nullptr);
	std::string s = { wstr.begin(), wstr.end() };
	delete[] str;
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