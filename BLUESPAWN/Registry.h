#ifndef REGISTRY_H   
#define REGISTRY_H

#include "windows.h"
#include <string>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <tchar.h>
#include "Output.h"

using namespace std;

#pragma comment(lib, "advapi32.lib")

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

struct key {
	HKEY hive;
	LPCWSTR path;
	LPCWSTR key;
	wstring value;
	ULONG type;
};

void ExamineRegistryPersistence();
void ExamineRegistryOtherBad();
void PrintRegistryKeyResult(bool, key&, wstring);
void GetRegistryKey(HKEY, ULONG, wstring&, wstring);
LONG GetDWORDRegKey(HKEY, const std::wstring&, DWORD&);
LONG GetBoolRegKey(HKEY, const std::wstring&, bool&, bool);
LONG GetStringRegKey(HKEY, const std::wstring&, std::wstring&);
bool CheckKeyIsDefaultValue(key&, wstring&);
void QueryKey(HKEY, wstring&, key&);

#endif