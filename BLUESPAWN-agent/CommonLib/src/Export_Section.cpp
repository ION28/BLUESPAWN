#include "pe/Export_Section.h"
#include "pe/PE_Image.h"

#include "common/DynamicLinker.h"
#include "common/StringUtils.h"
#include "logging/Log.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <string>

PE_Export::PE_Export(DWORD rva, WORD ordinal, std::string name) : 
	rva{ rva }, ordinal{ ordinal }, name{ name }, redirect{} {}
PE_Export::PE_Export(WORD ordinal, std::string name, std::wstring redirect) : 
	rva{ 0 }, ordinal{ ordinal }, name{ name }, redirect{ redirect } {}

Export_Section::Export_Section(const PE_Section& section) : 
	exports{}, ExportDirectory{}, PE_Section{ section }{
	ExportDirectory = *section.SectionContent.Convert<IMAGE_EXPORT_DIRECTORY>();
	
	int dwExportCount = ExportDirectory.NumberOfFunctions;
	MemoryWrapper<DWORD> lpFunctionAddresses = AssociatedImage.base.GetOffset(
		AssociatedImage.expanded ? AssociatedImage.RVAToOffset(ExportDirectory.AddressOfFunctions) : ExportDirectory.AddressOfFunctions
	).Convert<DWORD>();
	MemoryWrapper<DWORD> lpNameAddresses = AssociatedImage.base.GetOffset(
		AssociatedImage.expanded ? AssociatedImage.RVAToOffset(ExportDirectory.AddressOfNames) : ExportDirectory.AddressOfNames
	).Convert<DWORD>();
	MemoryWrapper<WORD> lpOrdinalAddresses = AssociatedImage.base.GetOffset(
		AssociatedImage.expanded ? AssociatedImage.RVAToOffset(ExportDirectory.AddressOfNameOrdinals) : ExportDirectory.AddressOfNameOrdinals
	).Convert<WORD>();

	for(int i = 0; i < dwExportCount; i++){
		auto name = AssociatedImage.base.GetOffset(*lpNameAddresses.GetOffset(i * sizeof(DWORD))).ReadString();
		auto address = *lpFunctionAddresses.GetOffset(i * sizeof(DWORD));

		if(name.find(".") == std::string::npos){
			exports.emplace_back(PE_Export{ address, *lpOrdinalAddresses.GetOffset(i * sizeof(WORD)), name });
		} else {
			std::string redirection{};

			size_t idx = redirection.find(".");
			std::wstring dllName = StringToWidestring(redirection.substr(0, idx));
			std::string importName = redirection.substr(idx + 1);

			std::wstring wsProcessedDllName{};
			wsProcessedDllName.resize(MAX_PATH);

			UNICODE_STRING usPreprocessed = { dllName.length() * 2, MAX_PATH * 2, &dllName[0] };
			UNICODE_STRING usProcessed = { wsProcessedDllName.length() * 2, MAX_PATH * 2, &wsProcessedDllName[0] };
			ULONG_PTR zero = 0;

			NTSTATUS status = Linker::LdrpPreprocessDllName(&usPreprocessed, &usProcessed, &zero, &zero);
			if(!NT_SUCCESS(status)){
				LOG_ERROR("An error occured while attempting to parse " << importName << ", located in " << dllName);
			} else {
				exports.emplace_back(PE_Export{ *lpOrdinalAddresses.GetOffset(i * sizeof(WORD)), name, wsProcessedDllName });
			}
		}
	}
}

LPVOID Export_Section::GetExportAddress(std::string name){
	for(auto dllExport : exports){
		if(dllExport.name == name){
			if(dllExport.rva){
				return AssociatedImage.base.GetOffset(AssociatedImage.RVAToOffset(dllExport.rva));
			} else {
				LOG_WARNING("Exporting function from separate DLL! Functionality is not yet implemented!");

				return nullptr;
			}
		}
	}
}

LPVOID Export_Section::GetExportAddress(WORD ordinal){
	for(auto dllExport : exports){
		if(dllExport.ordinal == ordinal){
			if(dllExport.rva){
				return AssociatedImage.base.GetOffset(AssociatedImage.RVAToOffset(dllExport.rva));
			} else {
				LOG_WARNING("Exporting function from separate DLL! Functionality is not yet implemented!");

				return nullptr;
			}
		}
	}
}