#ifndef OUTPUT_H   
#define OUTPUT_H

#include <iostream>
#include <string>
#include <stdio.h>
#include <fstream>
#include "windows.h"
#include <locale>
#include <codecvt>

using namespace std;

#pragma comment(lib, "advapi32.lib")

void SetConsoleColor(string);
void PrintInfoHeader(string);
void PrintInfoStatus(string);
void PrintBadStatus(string);
void PrintGoodStatus(string);
void PrintSectionDivider();
wstring s2ws(const string&);
string ws2s(const wstring&);
string hive2s(HKEY);

#endif