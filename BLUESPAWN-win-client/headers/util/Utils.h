#pragma once

#include <Windows.h>

#include <vector>
#include <string>

#define ADD_ALL_VECTOR(v1, v2)  \
    {                           \
        auto& tmp = v2;         \
		for(auto& v : tmp){     \
			v1.emplace_back(v); \
		}                       \
    }

int64_t SystemTimeToInteger(const SYSTEMTIME& st);
std::wstring FormatWindowsTime(const SYSTEMTIME& systemtime);
std::wstring FormatWindowsTime(const FILETIME& systemtime);
std::wstring FormatWindowsTime(const std::wstring& windowsTime);
