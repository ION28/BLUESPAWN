#ifndef REGISTRY_H   
#define REGISTRY_H

#include "windows.h"
#include <string>
#include <iostream>
#include <sstream>
#include "Output.h"

using namespace std;

#pragma comment(lib, "advapi32.lib")

struct key {
	HKEY hive;
	LPCWSTR path;
	LPCWSTR key;
	wstring value;
	int type;
};

void ExamineRegistryPersistence();
void ExamineRegistryOtherBad();
LONG GetDWORDRegKey(HKEY, const std::wstring&, DWORD&);
LONG GetBoolRegKey(HKEY, const std::wstring&, bool&, bool);
LONG GetStringRegKey(HKEY, const std::wstring&, std::wstring&);
bool CheckKeyIsDefaultValue(key&, wstring&);

#endif