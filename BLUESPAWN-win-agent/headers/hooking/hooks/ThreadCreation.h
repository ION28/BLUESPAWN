#pragma once

#include "hooking/Call.h"
#include "hooking/HookRegister.h"
#include "utils/ProcessUtils.h"
#include "utils/Debug.h"
#include "utils/StackWalker.h"

namespace BLUESPAWN::Agent::ThreadCreation {

	typedef HANDLE(WINAPI* CreateRemoteThread_t)(
			HANDLE                 hProcess,
			LPSECURITY_ATTRIBUTES  lpThreadAttributes,
			SIZE_T                 dwStackSize,
			LPTHREAD_START_ROUTINE lpStartAddress,
			LPVOID                 lpParameter,
			DWORD                  dwCreationFlags,
			LPDWORD                lpThreadId
		);

	/// Store a pointer to the original CreateRemoteThread
	extern CreateRemoteThread_t _CreateRemoteThread;

	enum class CreateRemoteThreadParams {
		hProcess = 0,
		lpThreadAttributes = 1,
		dwStackSize = 2,
		lpStartAddress = 3,
		lpParameter = 4,
		dwCreationFlags = 5,
		lpThreadId = 6
	};

	/**
	 * \brief Hook calls to CreateRemoteThread, allowing threads only to be injected to child processes, but recording
	 *        all calls
	 *
	 * \details See the Windows API documentation for information about the arguments
	 */
	HANDLE WINAPI CreateRemoteThreadHook(
		HANDLE                 hProcess,
		LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		SIZE_T                 dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID                 lpParameter,
		DWORD                  dwCreationFlags,
		LPDWORD                lpThreadId
	);
}