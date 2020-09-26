#include "hooking/Hook.h"
#include "hooking/HookRegister.h"

#include <string>

namespace BLUESPAWN::Agent::Hooks{
	template<class Func, class... Args>
	template<class HookType>
	Hook<Func, Args...>::Hook(_In_ const std::wstring& szLibraryName, _In_ const std::string& szFunctionName, HookType* type) :
		szLibraryName{ szLibraryName }, szFunctionName{ szFunctionName }{

		if(HMODULE hLibrary = LoadLibraryW(szLibraryName.c_str())){
			lpOriginalFunction = GetProcAddress(hLibary, szFunctionName.c_str());
		}

		if(lpOriginalFunction){
			HookRegister::GetInstance().RegisterHook(szLibraryName, szFunctionName,
													 HookDelegate<std::remove_pointer_t<type>, Args...>, 
													 reinterpret_cast<LPVOID*>(&lpOriginalFunction));
		}
	}
};