#include "util/pe/Import_Section.h"
#include "util/pe/PE_Image.h"
#include "util/pe/Image_Loader.h"
#include "util/StringUtils.h"

#include <queue>

bool LoadLibraries(const HandleWrapper& process, const std::set<std::wstring>& libs){
	Image_Loader loader = { process };
	std::queue<std::tuple<PE_Image*, MemoryWrapper<>, std::wstring>> images = {};
	std::set<std::wstring> ToImport = libs;
	
	// Perform a BFS on library dependency tree to import them all
	while(!ToImport.empty()){
		std::set<std::wstring> MoreLibs = {};
		for(auto lib : libs){
			if(!loader.ContainsImage(lib)){
				auto image = new PE_Image(lib);
				if(!image->ValidatePE()){
					return false;
				}

				images.emplace(std::tuple<PE_Image*, MemoryWrapper<>, std::wstring>{ image,
					VirtualAllocEx(process, nullptr, image->dwExpandSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), lib });
				if(!loader.AddImage(Loaded_Image{ image, false, lib })){
					return false;
				}

				for(auto ImportLibrary : image->imports->GetRequiredLibraries()){
					if(!loader.ContainsImage(ImportLibrary) && libs.find(ImportLibrary) == libs.end()){
						MoreLibs.emplace(ImportLibrary);
					}
				}
			}
		}
		ToImport = MoreLibs;
	}

	// Process imports on all imported libraries.
	while(!images.empty()){
		auto info = images.front();
		images.pop();

		PE_Image* image = info._Myfirst._Val;
		MemoryWrapper<> address = info._Get_rest()._Myfirst._Val;
		std::wstring name = info._Get_rest()._Get_rest()._Myfirst._Val;

		if(image->LoadTo(address)){
			return false;
		}
		loader.MarkLoaded(name);
		delete image;
	}
	return true;
}

Import_Library::Import_Library(const PE_Image& image, const IMPORT_DIRECTORY_TABLE& ImportDirectoryTable) : image{ image }{
	DWORD dwNameOffset = image.expanded ? ImportDirectoryTable.dwNameRVA : image.RVAToOffset(ImportDirectoryTable.dwNameRVA);
	DWORD dwLookupTableOffset = image.expanded ? ImportDirectoryTable.dwImportLookupTableRVA : image.RVAToOffset(ImportDirectoryTable.dwImportLookupTableRVA);
	DWORD dwIATOffset = image.expanded ? ImportDirectoryTable.dwImportAddressTableRVA : image.RVAToOffset(ImportDirectoryTable.dwImportAddressTableRVA);;
	this->sLibraryName = StringToWidestring(image.base.GetOffset(dwNameOffset).ReadString());
	if(image.arch == x64){
		MemoryWrapper<IMPORT_LOOKUP_TABLE64> entry = image.base.GetOffset(dwLookupTableOffset).Convert<IMPORT_LOOKUP_TABLE64>();
		while(entry->value){
			Import i = {};
			if(entry->type){
				i = { true, static_cast<WORD>(entry->value), 0 };
			} else {
				DWORD dwHintOffset = image.expanded ? entry->value : image.RVAToOffset(entry->value);
				WORD hint = *image.base.GetOffset(dwHintOffset).Convert<WORD>();
				std::string name = image.base.GetOffset(dwHintOffset + 2).ReadString();
				i = { false, 0, {hint, name} };
			}
			vImportToIAT.emplace_back(std::pair<Import, DWORD>{ i, dwIATOffset });
			dwLookupTableOffset += 8;
			dwIATOffset += 8;
		}
	} else {
		MemoryWrapper<IMPORT_LOOKUP_TABLE32> entry = image.base.GetOffset(dwLookupTableOffset).Convert<IMPORT_LOOKUP_TABLE32>();
		while(entry->value){
			Import i = {};
			if(entry->type){
				i = { true, static_cast<WORD>(entry->value), 0 };
			} else {
				DWORD dwHintOffset = image.expanded ? entry->value : image.RVAToOffset(entry->value);
				WORD hint = *image.base.GetOffset(dwHintOffset).Convert<WORD>();
				std::string name = image.base.GetOffset(dwHintOffset + 2).ReadString();
				i = { false, 0, {hint, name} };
			}
			vImportToIAT.emplace_back(std::pair<Import, DWORD>{ i, dwIATOffset });
			dwLookupTableOffset += 4;
			dwIATOffset += 4;
		}
	}
}

bool Import_Library::LoadImportLibrary(const HandleWrapper& context){
	auto info = Image_Loader(context).GetImageInfo(sLibraryName);
	if(!info.has_value()){
		return false;
	}

	auto& TargetImage = info->GetImage();
	for(auto pair : vImportToIAT){
		auto im = pair.first;
		auto offset = pair.second;
		if(im.IsOrdinal){
			if(image.arch == x64){
				DWORD64 address = TargetImage.exports->GetExportAddress(im.ordinal);
				if(!address){
					return false;
				}

				image.base.Write(reinterpret_cast<CHAR*>(&address), sizeof(address), offset);
			}
		}
	}
	return true;
}

Import_Section::Import_Section(const PE_Section& section) : PE_Section{ section } {
	MemoryWrapper<IMPORT_DIRECTORY_TABLE> table = SectionContent.Convert<IMPORT_DIRECTORY_TABLE>();
	while((*table).dwImportLookupTableRVA){
		imports.emplace_back(Import_Library{ section.AssociatedImage, *table });
	}
}

bool Import_Section::LoadAllImports(const HandleWrapper& context){
	std::set<std::wstring> images = {};

	if(!LoadLibraries(context, GetRequiredLibraries())) return false;

	for(auto lib : imports){
		if(!lib.LoadImportLibrary(context)) return false;
	}
	return true;
}

std::set<std::wstring> Import_Section::GetRequiredLibraries() const {
	std::set<std::wstring> names = {};
	for(auto lib : imports){
		names.emplace(lib.sLibraryName);
	}
	return names;
}