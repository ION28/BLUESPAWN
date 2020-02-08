#include "util/configurations/RegistryValue.h"

namespace Registry {

	RegistryValue::RegistryValue(std::wstring wValueName, RegistryType type, std::wstring wData) :
		wValueName{ wValueName },
		type{ type },
		wData{ wData }{}

	RegistryValue::RegistryValue(std::wstring wValueName, RegistryType type, DWORD dwData) :
		wValueName{ wValueName },
		type{ type },
		dwData{ dwData }{}

	RegistryValue::RegistryValue(std::wstring wValueName, RegistryType type, AllocationWrapper lpData) :
		wValueName{ wValueName },
		type{ type },
		lpData{ lpData }{}

	RegistryValue::RegistryValue(std::wstring wValueName, RegistryType type, std::vector<std::wstring> vData) :
		wValueName{ wValueName },
		type{ type },
		vData{ vData }{}

	RegistryType RegistryValue::GetType() const {
		return type;
	}

	std::wstring RegistryValue::ToString() const {
		if(type == RegistryType::REG_SZ_T || type == RegistryType::REG_EXPAND_SZ_T)
			return wData;
		else if(type == RegistryType::REG_DWORD_T)
			return std::to_wstring(dwData);
		else if(type == RegistryType::REG_MULTI_SZ_T){
			std::wstring string = L"[\"";
			for(auto str : vData){
				string += str + L"\", \"";
			}
			return string.substr(0, string.length() - 3) + L"\"]";
		} else {
			if(!lpData){
				return L"(null)";
			}

			std::wstring string = L"";
			for(auto i = 0; i < lpData.GetSize(); i++){
				wchar_t buf[3];
				wsprintf(buf, L"%02x", lpData[i]);
				string += buf;
				string += L" ";
			}
			return string;
		}
	}
}