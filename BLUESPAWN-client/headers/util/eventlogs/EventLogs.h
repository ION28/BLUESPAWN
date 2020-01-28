#pragma once   

#include "windows.h"
#include <string>
#include <iostream>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include "hunt/reaction/Reaction.h"

using namespace std;

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

DWORD PrintResults(EVT_HANDLE hResults);
DWORD PrintEvent(EVT_HANDLE hEvent); // Shown in the Rendering Events topic
DWORD PrintEventValues(EVT_HANDLE hEvent);

int QueryEvents(const wchar_t* channel, unsigned int id, Reaction reaction);