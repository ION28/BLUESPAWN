#include "common/Utils.h"
#include <windows.h>
#include <iostream>
#include <sstream>
	
std::wstring FormatWindowsTime(const std::wstring& windowsTime) {
	SYSTEMTIME st;
	FILETIME ft;

	ULONGLONG time = (ULONGLONG)stoull(windowsTime);
	ULONGLONG nano = 0;

	ft.dwHighDateTime = (DWORD)((time >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(time & 0xFFFFFFFF);

	FileTimeToSystemTime(&ft, &st);
	nano = (time % 10000000) * 100; // Display nanoseconds instead of milliseconds for higher resolution

	std::wostringstream w;
	w << st.wYear << "-" << st.wMonth << "-" << st.wDay << "-" << st.wHour << "-" << st.wMinute << "-" << st.wSecond << "-" << nano;
	return w.str();
}