#pragma once

#include "hooking/hooks/CloseHandle.h"

namespace BLUESPAWN::Agent::Hooks{
	const HandleCloseHook HandleCloseHook::instance{};

	HandleCloseHook::HandleCloseHook() :
		Hook{ L"Kernel32.dll", "CloseHandle", this }{}

	const HandleCloseHook& HandleCloseHook::GetInstance(){
		return instance;
	}

	BOOL HandleCloseHook::HookFunc(
		HANDLE                 hObject
	) const{
		
		Util::FlushHandleCache(hObject);

		if(lpOriginalFunction){
			return lpOriginalFunction(hObject);
		}

		return FALSE;
	}
}