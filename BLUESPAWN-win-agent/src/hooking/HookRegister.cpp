#include "hooking/HookRegister.h"
#include "utils/Debug.h"

#include "detours/detours.h"

namespace BLUESPAWN::Agent{
	HookRegister HookRegister::instance{};

	_Success_(return == true)
	bool HookRegister::RegisterHook(_In_ LPVOID hook, _Inout_ LPVOID * func){
		if(func && *func && hook){
			if(initialized){
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(func, hook);
				auto error{ DetourTransactionCommit() };
				if(error != NO_ERROR){
					LOG_DEBUG_MESSAGE(LOG_ERROR, L"Error: Unable to hook function at " << *func << L" with hook at " << hook);
				}
			}

			hooks.emplace_back(std::make_pair(hook, func));
		} else{
			LOG_DEBUG_MESSAGE(LOG_ERROR, L"Invalid argument passed to RegisterHook");
		}
	}

	void HookRegister::Initialize(){
		if(initialized == true){
			LOG_DEBUG_MESSAGE(LOG_WARN, L"HookRegister::Initialized called while already initialized!");
		} else{
			for(const auto& hook : hooks){
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(hook.second, hook.first);
				auto error{ DetourTransactionCommit() };
				if(error != NO_ERROR){
					LOG_DEBUG_MESSAGE(LOG_ERROR, L"Error: Unable to hook function at " << *hook.second << L" with hook at "
									  << hook.first);
				}
			}
			initialized = true;
		}
	}

	void HookRegister::Deinitialize(){
		if(initialized == false){
			LOG_DEBUG_MESSAGE(LOG_WARN, L"HookRegister::Deinitialized called while not initialized!");
		} else{
			for(const auto& hook : hooks){
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourDetach(hook.second, hook.first);
				auto error{ DetourTransactionCommit() };
				if(error != NO_ERROR){
					LOG_DEBUG_MESSAGE(LOG_ERROR, L"Error: Unable to remove hook from function at " << *hook.second 
									             << L" with hook at " << hook.first);
				}
			}
			initialized = false;
		}
	}
};