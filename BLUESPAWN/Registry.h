#ifndef REGISTRY_H   
#define REGISTRY_H

#include "windows.h"
#include "string"
#include <iostream>
#include <locale>
#include <codecvt>

using namespace std;

#pragma comment(lib, "advapi32.lib")

void TestQuery();
LONG GetDWORDRegKey(HKEY, const std::wstring&, DWORD&, DWORD);
LONG GetBoolRegKey(HKEY, const std::wstring&, bool&, bool);
LONG GetStringRegKey(HKEY, const std::wstring&, std::wstring&, const std::wstring&);


#endif