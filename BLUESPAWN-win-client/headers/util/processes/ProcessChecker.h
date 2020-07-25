#pragma once

#include <Windows.h>

bool ProcessIsDoppelganger(DWORD pid);
bool ProcessContainsShellcode(DWORD pid);
bool ProcessContainsHollows(DWORD pid);
bool ProcessContainsPEImplants(DWORD pid);
bool ProcessContainsHooks(DWORD pid);