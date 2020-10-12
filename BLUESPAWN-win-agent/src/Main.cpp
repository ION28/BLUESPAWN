#include <Windows.h>
#include <winternl.h>
#include "hooking/hooks/ThreadCreation.h"

#include "Setup.h"
#include "hooking/Call.h"
#include "utils/Debug.h"

std::wstring BLUESPAWN::Agent::Log::name;

/**
 * \brief Entrypoint to the DLL run when DLL is loaded or unloaded by the process or any thread.
 * 
 * \details This function dispatches necessary setup actions for the DLL when it is first loaded into the process as
 *          well as cleanup procedures.
 * 
 * \param[in] hModule    An HMODULE referencing this DLL, equal to the DLL's base address
 * \param[in] dwReason   Refers to the reason this function is called. The possible values are below.
 *					     DLL_PROCESS_ATTACH - Indicates this DLL was just loaded
 *                       DLL_PROCESS_DETACH - Indicates this DLL is about to be unloaded
 *                       DLL_THREAD_ATTACH  - Indicates a new thread has been created in the process
 *                       DLL_THREAD_DETACH  - Indicates a thread in the process is being killed
 * \param[in] lpReserved This parameter is unused.
 */
_Success_(return != FALSE)
extern "C" BOOL APIENTRY DllMain(_In_ HMODULE hModule, _In_ DWORD dwReason, LPVOID lpReserved){
	UNREFERENCED_PARAMETER(lpReserved);

	if(dwReason == DLL_PROCESS_ATTACH){
		if(!BLUESPAWN::Agent::Log::name.length()){
			WCHAR path[MAX_PATH];
			if(GetModuleFileNameW(nullptr, path, MAX_PATH)){
				std::wstring filepath{ path };
				BLUESPAWN::Agent::Log::name = filepath.substr(filepath.find_last_of(L"\\/") + 1);
			} else{
				BLUESPAWN::Agent::Log::name = L"Unknown";
				LOG_DEBUG_MESSAGE(LOG_ERROR, L"Unable to obtain current process name");
			}
		}

		return BLUESPAWN::Agent::PerformAttachActions();
	} else if(dwReason == DLL_PROCESS_DETACH){
		return BLUESPAWN::Agent::PerformDetachActions();
	}
}

#ifdef _DEBUG

#include "test/HandleInferenceTests.h"

// A function intended to be used with rundll32 to cause rundll32 to load the DLL and hang
extern "C" __declspec(dllexport) void APIENTRY Wait(){
	LOG_DEBUG_MESSAGE(LOG_INFO, L"Entering infinite wait!");


	Sleep(INFINITE);
}

extern "C" __declspec(dllexport) void APIENTRY HandleInference(){
	LOG_DEBUG_MESSAGE(LOG_INFO, L"Beginning Handle Inference Tests!");

	BLUESPAWN::Agent::Test::TestFileInference();
	BLUESPAWN::Agent::Test::TestSectionInference();
	BLUESPAWN::Agent::Test::TestProcessThreadInference();
	BLUESPAWN::Agent::Test::TestRegistryKeyInference();
	BLUESPAWN::Agent::Test::TestTokenInference();
	BLUESPAWN::Agent::Test::TestSynchronizationInference();
}
#endif