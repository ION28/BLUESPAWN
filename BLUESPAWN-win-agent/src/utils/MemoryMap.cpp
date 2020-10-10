#include "utils/MemoryMap.h"
#include "utils/StackWalker.h"

#include <DbgHelp.h>

#include <vector>

namespace BLUESPAWN::Agent::Util{

	Address GetAddressInformation(_In_ LPVOID lpAddress, _In_opt_ HANDLE hProcess){
		BeginCriticalSection _(dbghelpGuard);
		SymInitialize(hProcess, nullptr, true);
		auto moduleBase = SymGetModuleBase(hProcess, reinterpret_cast<ULONG_PTR>(lpAddress));
		if(moduleBase){
			std::wstring mod{};
			std::string fun{};

			std::vector<WCHAR> buffer(MAX_PATH);
			if(GetModuleFileNameW(reinterpret_cast<HMODULE>(moduleBase), buffer.data(), buffer.size())){
				mod = buffer.data();
			}

			std::vector<char> symBuffer(sizeof(IMAGEHLP_SYMBOL) + 255);
			auto symbol = reinterpret_cast<PIMAGEHLP_SYMBOL>(symBuffer.data());
			symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL) + 255;
			symbol->MaxNameLength = 254;

			if(SymGetSymFromAddr(hProcess, reinterpret_cast<ULONG_PTR>(lpAddress), nullptr, symbol)){
				fun = symbol->Name;
			}

			SymCleanup(hProcess);
			if(fun.length() && mod.length()){
				return Address{ mod, fun };
			} else return Address{ lpAddress };
		} 

		SymCleanup(hProcess);
		return Address{ lpAddress };
	}
}