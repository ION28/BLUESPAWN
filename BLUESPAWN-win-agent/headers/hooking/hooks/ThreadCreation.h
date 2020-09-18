#pragma once

#include "hooking/Call.h"
#include "utils/ProcessUtils.h"

/**
 * \brief Hook calls to CreateRemoteThread, allowing threads only to be injected to child processes, but recording
 *        all calls
 */
HANDLE CreateRemoteThreadHook(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
){
	DWORD dwPID{ GetProcessId(hProcess) };
	if(RequestParentPID(dwPID) != GetCurrentProcessId()){

	}
}