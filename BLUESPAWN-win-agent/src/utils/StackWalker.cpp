#include "utils/StackWalker.h"
#include "utils/Common.h"
#include "utils/MemoryMap.h"

#include <DbgHelp.h>

#pragma comment(lib, "dbghelp")

namespace BLUESPAWN::Agent::Util {

	CriticalSection dbghelpGuard;

	_Success_(return == true)
	bool WalkStack(_Out_ std::vector<Address>& addresses){
		CONTEXT context{};
		context.ContextFlags = CONTEXT_CONTROL;
		RtlCaptureContext(&context);

		STACKFRAME64 stack{};
		stack.AddrPC.Mode = AddrModeFlat;
		stack.AddrStack.Mode = AddrModeFlat;
		stack.AddrFrame.Mode = AddrModeFlat;

#ifdef _WIN64
		stack.AddrPC.Offset = context.Rip;
		stack.AddrStack.Offset = context.Rsp;
		stack.AddrFrame.Offset = context.Rbp;

		DWORD dwMachineType = IMAGE_FILE_MACHINE_AMD64;
#else
		stack.AddrPC.Offset = context.Eip;
		stack.AddrStack.Offset = context.Esp;
		stack.AddrFrame.Offset = context.Ebp;

		DWORD dwMachineType = IMAGE_FILE_MACHINE_I386;
#endif

		addresses = {};
		std::vector<LPVOID> pointers{};

		BeginCriticalSection _(dbghelpGuard);
		SymInitialize(GetCurrentProcess(), nullptr, true);
		while(StackWalk64(dwMachineType, GetCurrentProcess(), GetCurrentThread(), &stack, &context, nullptr, 
						  SymFunctionTableAccess64, SymGetModuleBase64, nullptr)){
			pointers.emplace_back(reinterpret_cast<LPVOID>(stack.AddrPC.Offset));
		}
		SymCleanup(GetCurrentProcess());
		_.Release();

		for(auto ptr : pointers){
			addresses.emplace_back(GetAddressInformation(ptr));
		}

		return addresses.size();
	}
}