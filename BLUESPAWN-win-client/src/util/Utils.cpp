#include "util/Utils.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>

int64_t SystemTimeToInteger(const SYSTEMTIME& st){
	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);

	ULARGE_INTEGER lv_Large;

	lv_Large.LowPart = ft.dwLowDateTime;
	lv_Large.HighPart = ft.dwHighDateTime;

	return lv_Large.QuadPart;
}

std::wstring FormatWindowsTime(const SYSTEMTIME& st){
	std::wostringstream w;
	w << std::setfill(L'0') << st.wYear << "-" << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " " <<
		std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2) << st.wSecond << "." <<
		((st.wMilliseconds % 10000000) * 100) << "Z";
	return w.str();
}


std::wstring FormatWindowsTime(const FILETIME& ft){
	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);

	std::wostringstream w;
	w << std::setfill(L'0') << st.wYear << "-" << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " " <<
		std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2) << st.wSecond << "." <<
		st.wMilliseconds << "Z";
	return w.str();
}


std::wstring FormatWindowsTime(const std::wstring& windowsTime){
	SYSTEMTIME st;
	FILETIME ft;

	ULONGLONG time = (ULONGLONG) stoull(windowsTime);
	ULONGLONG nano = 0;

	ft.dwHighDateTime = (DWORD) ((time >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD) (time & 0xFFFFFFFF);

	FileTimeToSystemTime(&ft, &st);
	nano = (time % 10000000) * 100; // Display nanoseconds instead of milliseconds for higher resolution

	std::wostringstream w;
	w << std::setfill(L'0') << st.wYear << "-" << std::setw(2) << st.wMonth << "-" << std::setw(2) << st.wDay << " " <<
		std::setw(2) << st.wHour << ":" << std::setw(2) << st.wMinute << ":" << std::setw(2) << st.wSecond << "." <<
		nano << "Z";
	return w.str();
}
