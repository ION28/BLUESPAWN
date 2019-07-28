#pragma once

#include <iostream>
#include <windows.h>
using namespace std;
#include <Lmcons.h>
#include <time.h>
#include <string>
#include <fstream>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <ctime>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <VersionHelpers.h>
#include "logging/Output.h"
#include <logging\Log.h>

#define SECURITY_WIN32
#include <Security.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "Secur32.lib")

void OutputComputerInformation();
string GetOsVersion();
string GetComputerDNSName();
string GetDomain();
string GetFQDN();
string GetCurrentUser();