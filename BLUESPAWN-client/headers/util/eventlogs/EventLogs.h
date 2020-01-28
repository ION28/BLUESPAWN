#pragma once   

#include "windows.h"
#include <string>
#include <iostream>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include "hunt/reaction/Reaction.h"
#include <set>

using namespace std;

#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

/**
@ param channel the channel to look for the event log (exe, 'Microsoft-Windows-Sysmon/Operational')
@param id the event ID to filter for
@param reaction the reaction to use when an event is detected
@return the number of events detected, or -1 if something went wrong.
*/
int QueryEvents(const wchar_t* channel, unsigned int id, Reaction& reaction);

/**
@ param channel the channel to look for the event log (exe, 'Microsoft-Windows-Sysmon/Operational')
@param id the event ID to filter for
@param reaction the reaction to use when an event is detected
@param params extra parameters to print in the output
@return the number of events detected, or -1 if something went wrong.
*/
int QueryEvents(const wchar_t* channel, unsigned int id, std::set<std::wstring>& params, Reaction& reaction);