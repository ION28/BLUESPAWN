#include "hooking/HookRegister.h"
#include "utils/Debug.h"

#include "detours/detours.h"

namespace BLUESPAWN::Agent{
	HookRegister HookRegister::instance{};

	_Success_(return == true)
	bool HookRegister::RegisterHook(_In_ LPVOID hook, _Inout_ LPVOID* func){
		if(func && *func && hook){
			if(initialized){
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach(func, hook);
				auto error{ DetourTransactionCommit() };
				if(error != NO_ERROR){
					LOG_DEBUG_MESSAGE(LOG_ERROR, L"Error: Unable to hook function at " << *func << L" with hook at " << hook);
					hooks.emplace_back(std::make_pair(hook, func));
					return false;
				}
			}

			hooks.emplace_back(std::make_pair(hook, func));
			return true;
		} else{
			LOG_DEBUG_MESSAGE(LOG_ERROR, L"Invalid argument passed to RegisterHook");
			return false;
		}
	}

	void HookRegister::Initialize(){
		if(initialized == true){
			LOG_DEBUG_MESSAGE(LOG_WARN, L"HookRegister::Initialized called while already initialized!");
		} else{
			for(const auto& hook : hooks){
				LOG_DEBUG_MESSAGE(LOG_INFO, "Hooking a function");
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

	CallAction HookRegister::GetAction(_In_ const Call& call){
		// TODO: Communicate with BLUESPAWN-client via RPC
		return CallAction::Allowed;
	}

	void HookRegister::RecordCall(_In_ const Call& call, _In_ CallAction action){
		// TODO: Communicate with BLUESPAWN-client via RPC

		std::wstringstream info{};
		if(call.GetFunctionExtensions()){
			info << L"Detected call to " << call.GetFunctionExtensions()->szFunctionName.c_str() << std::endl;
		} else{
			info << L"Detected call to " << call.GetPointer() << std::endl;
		}

		info << "Call stack:" << std::endl;
		for(auto entry : call.GetCallStack()){
			if(entry.GetFunctionExtensions()){
				info << L"\t" << entry.GetFunctionExtensions()->szFunctionName.c_str() << std::endl;
			} else{
				info << L"\t" << entry.GetPointer() << std::endl;
			}
		}

		info << L"Action Taken: " << (action == CallAction::Allowed ? L"Allowed" : (action == CallAction::Blocked ? 
																					L"Blocked" : L"Modified"));

		LOG_DEBUG_MESSAGE(LOG_INFO, info.str());
	}

	HookRegister& HookRegister::GetInstance(){ return instance; }
};