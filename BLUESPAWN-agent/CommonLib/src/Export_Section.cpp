#include "pe/Export_Section.h"
#include "pe/PE_Image.h"

#include "common/DynamicLinker.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <string>

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

		auto NameAddress = AssociatedImage.base.GetOffset(*lpNameAddresses.GetOffset(i * sizeof(DWORD)));

		//exports.emplace_back(PE_Export{ *lpFunctionAddresses.GetOffset(i * sizeof(DWORD)), *lpOrdinalAddresses.GetOffset(i * sizeof(WORD)), name });
	}
}