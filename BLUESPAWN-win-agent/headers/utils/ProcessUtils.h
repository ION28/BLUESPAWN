#pragma once

#include <Windows.h>

#include <string>

// TODO: Move to client interface
inline DWORD RequestParentPID(DWORD dwPID){ return 0; }

namespace BLUESPAWN::Agent::Util{
	std::wstring GetProcessName(_In_ HANDLE hProcess);
}