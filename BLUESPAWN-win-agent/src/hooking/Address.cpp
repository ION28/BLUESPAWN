#include "hooking/Address.h"

#include "utils/Debug.h"

#include <string>

namespace BLUESPAWN::Agent{

	void Address::PrepareFields(){
		if(lpPointer){
			MEMORY_BASIC_INFORMATION info{};
			if(VirtualQuery(lpPointer, &info, sizeof(info))){
				if(info.AllocationProtect == PAGE_EXECUTE_WRITECOPY){
					if(!hImage){
						hImage = reinterpret_cast<HMODULE>(info.AllocationBase);
					}
				}

				dwAllocationProtections = info.AllocationProtect;
				dwPageProtections = info.Protect;
			} else{
				LOG_DEBUG_MESSAGE(LOG_ERROR, L"Unable to query address " << lpPointer << "; Error " << GetLastError());
			}
		}
	}

	Address::Address(LPVOID lpPointer) : lpPointer{ lpPointer }{
		PrepareFields();
	}

	Address::Address(_In_ const std::wstring& szLibrary, _In_ const std::string& szFunction) : lpPointer{ lpPointer }{
		functionExtensions = FunctionExtensions{ szFunction, szLibrary };
		hImage = GetModuleHandleW(szLibrary.c_str());
		lpPointer = hImage ? GetProcAddress(hImage, szFunction.c_str()) : nullptr;
		PrepareFields();
	}

	const std::optional<Address::FunctionExtensions>& Address::GetFunctionExtensions() const { 
		return functionExtensions; 
	}
}