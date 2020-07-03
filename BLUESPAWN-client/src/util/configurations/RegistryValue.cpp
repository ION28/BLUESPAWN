#include "util/configurations/RegistryValue.h"
#include "util/configurations/Registry.h"

#include <memory>
#include <sstream>
#include <iomanip>

namespace Registry {

	RegistryValue::RegistryValue(const RegistryKey& key, const std::wstring& wValueName, std::wstring&& wData) :
		key{ key },
		wValueName{ wValueName },
		type{ RegistryType::REG_SZ_T },
		data{ std::forward<std::wstring>(wData) }{}

	RegistryValue::RegistryValue(const RegistryKey& key, const std::wstring& wValueName, DWORD&& dData) :
		key{ key },
		wValueName{ wValueName },
		type{ RegistryType::REG_DWORD_T },
		data{ std::forward<DWORD>(dData) }{}

	RegistryValue::RegistryValue(const RegistryKey& key, const std::wstring& wValueName, AllocationWrapper&& lpData) :
		key{ key },
		wValueName{ wValueName },
		type{ RegistryType::REG_BINARY_T },
		data{ std::forward<AllocationWrapper>(lpData) }{}

	RegistryValue::RegistryValue(const RegistryKey& key, const std::wstring& wValueName, std::vector<std::wstring>&& vData) :
		key{ key },
		wValueName{ wValueName },
		type{ RegistryType::REG_MULTI_SZ_T },
		data{ std::forward<std::vector<std::wstring>>(vData) }{}


	std::optional<RegistryValue> RegistryValue::Create(IN CONST RegistryKey& key, 
													   IN CONST std::wstring& wsValueName){
		if(key.ValueExists(wsValueName)){
			auto type{ key.GetValueType(wsValueName) };
			if(type == RegistryType::REG_DWORD_T){
				return RegistryValue{ key, wsValueName, *key.GetValue<DWORD>(wsValueName) };
			} else if(type == RegistryType::REG_MULTI_SZ_T){
				return RegistryValue{ key, wsValueName, *key.GetValue<std::vector<std::wstring>>(wsValueName) };
			} else if(type == RegistryType::REG_EXPAND_SZ_T || type == RegistryType::REG_SZ_T){
				return RegistryValue{ key, wsValueName, *key.GetValue<std::wstring>(wsValueName) };
			} else return RegistryValue{ key, wsValueName, key.GetRawValue(wsValueName) };
		}

		return std::nullopt;
	}

	RegistryType RegistryValue::GetType() const {
		return type;
	}

	std::wstring RegistryValue::GetPrintableName() const {
		std::wstringstream oss;
		for (int i = 0; i < wValueName.length(); i++) {
			if (wValueName[i] < 0x20 || wValueName[i] > 0x7F) {
				oss << L"\\x" << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(wValueName[i]);
			}
			else {
				oss << wValueName[i];
			}
		}
		return oss.str();
	}

	std::wstring RegistryValue::ToString() const {
		if(type == RegistryType::REG_SZ_T || type == RegistryType::REG_EXPAND_SZ_T)
			return std::get<std::wstring>(data);
		else if(type == RegistryType::REG_DWORD_T)
			return std::to_wstring(std::get<DWORD>(data));
		else if(type == RegistryType::REG_MULTI_SZ_T){
			std::wstring string = L"[\"";
			for(auto& str : std::get<std::vector<std::wstring>>(data)){
				string += str + L"\", \"";
			}
			return string.substr(0, string.length() - 3) + L"\"]";
		} else {
			auto& lpData = std::get<AllocationWrapper>(data);
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

	bool RegistryValue::operator==(const RegistryValue& value) const{
		return value.key == key && value.wValueName == wValueName && value.data == data;
	}

	bool RegistryValue::operator<(const RegistryValue& value) const{
		return value.key < key ||
			(value.key == key && value.wValueName < wValueName);
	}
}