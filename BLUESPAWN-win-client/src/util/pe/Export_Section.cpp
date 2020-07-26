#include "util/pe/Export_Section.h"
#include "util/pe/PE_Image.h"
#include "util/pe/Image_Loader.h"

#include "util/DynamicLinker.h"
#include "util/StringUtils.h"
#include "util/log/Log.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <string>
#include <functional>

LINK_FUNCTION(LdrpPreprocessDllName, NTDLL.dll);

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

		if(!AssociatedImage.sections.at(".text").ContainsRVA(address)){
			exports.emplace_back(PE_Export{ address, *lpOrdinalAddresses.GetOffset(i * sizeof(WORD)), name });
		} else {
			std::string redirection = lpNameAddresses.GetOffset(address - ExportDirectory.AddressOfNames).ReadString();

			size_t idx = redirection.find(".");
			std::wstring dllName = StringToWidestring(redirection.substr(0, idx));
			std::string importName = redirection.substr(idx + 1);

			std::wstring wsProcessedDllName{};
			wsProcessedDllName.resize(MAX_PATH);

			UNICODE_STRING usPreprocessed = { static_cast<USHORT>(dllName.length() * 2), static_cast<USHORT>(MAX_PATH * 2), &dllName[0] };
			UNICODE_STRING usProcessed = { static_cast<USHORT>(wsProcessedDllName.length() * 2), static_cast<USHORT>(MAX_PATH * 2), &wsProcessedDllName[0] };
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

DWORD64 Export_Section::GetExportAddress(std::string name) const {
	for(auto dllExport : exports){
		if(dllExport.name == name){
			return GetExportAddress(dllExport.ordinal);
		}
	}
	return 0;
}

DWORD64 Export_Section::GetExportAddress(WORD ordinal) const {
	for(auto dllExport : exports){
		if(dllExport.ordinal == ordinal){
			if(dllExport.rva){
				return AssociatedImage.base.GetOffset(AssociatedImage.RVAToOffset(dllExport.rva));
			} else {
				auto hProcess = AssociatedImage.base.process;
				auto Loader = Image_Loader(hProcess);
				if(!Loader.ContainsImage(StringToWidestring(dllExport.name))){
					PE_Image image = PE_Image(StringToWidestring(dllExport.name));
					if(!image.ValidatePE()){
						return 0;
					}
					if(!image.LoadTo({ VirtualAllocEx(hProcess, nullptr, image.dwExpandSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE),
						image.dwExpandSize, hProcess }, true)){
						return 0;
					}
					Loader.AddImage(Loaded_Image{ image, true, image.swzImagePath.has_value() ? *image.swzImagePath : L"" });
				}

				auto ImageInfo = Loader.GetImageInfo(StringToWidestring(dllExport.name));
				if(!ImageInfo.has_value()){
					return 0;
				}
				auto Image = ImageInfo->GetImage();
				return Image.exports->GetExportAddress(ordinal);
			}
		}
	}
	return 0;
}