#ifndef REGISTRY_H   
#define REGISTRY_H

#include "windows.h"
#include "string"
#include <iostream>
#include "Output.h"

using namespace std;

#pragma comment(lib, "advapi32.lib")

struct key {
	HKEY hive;
	LPCWSTR path;
	LPCWSTR key;
	wstring value;
};

void ExamineRegistry();
LONG GetDWORDRegKey(HKEY, const std::wstring&, DWORD&, DWORD);
LONG GetBoolRegKey(HKEY, const std::wstring&, bool&, bool);
LONG GetStringRegKey(HKEY, const std::wstring&, std::wstring&);
bool CheckKeyIsDefaultValue(key& k);

#endif