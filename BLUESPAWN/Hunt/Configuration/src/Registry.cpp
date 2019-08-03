#include <Windows.h>

#include <algorithm>
#include <set>

#include "configuration/Registry.h"
#include "logging/Log.h"


namespace Registry {
	std::map<std::wstring, HKEY> vHiveNames{
		{L"HKLM", HKEY_LOCAL_MACHINE},
		{L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE},

		{L"HKCR", HKEY_CLASSES_ROOT},
		{L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT},

		{L"HKCU", HKEY_CURRENT_USER},
		{L"HKEY_CURRENT_USER", HKEY_CURRENT_USER},

		{L"HKU", HKEY_USERS},
		{L"HKEY_USERS", HKEY_USERS},

		{L"HKCC", HKEY_CURRENT_CONFIG},
		{L"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG},
	};

	std::map<HKEY, std::wstring> vHives{
		{HKEY_LOCAL_MACHINE, L"HKEY_LOCAL_MACHINE"},
		{HKEY_CLASSES_ROOT, L"HKEY_CLASSES_ROOT"},
		{HKEY_CURRENT_USER, L"HKEY_CURRENT_USER"},
		{HKEY_USERS, L"HKEY_USERS"},
		{HKEY_CURRENT_CONFIG, L"HKEY_CURRENT_CONFIG"},
	};

	HKEY RemoveHive(std::wstring& path){
		SIZE_T fslashIdx = path.find(L"/");
		SIZE_T bslashIdx = path.find(L"\\");
		if(fslashIdx == (SIZE_T) -1 && bslashIdx == (SIZE_T) -1){
			LOG_ERROR("Registry hive not found!");
			return nullptr;
		}

		std::wstring sHiveName = path.substr(0, fslashIdx > bslashIdx ? bslashIdx : fslashIdx);
		transform(sHiveName.begin(), sHiveName.end(), sHiveName.begin(), ::toupper);
		if(vHiveNames.find(sHiveName) == vHiveNames.end()){
			LOG_ERROR("Unknown registry hive " << sHiveName);
			return nullptr;
		}

		HKEY hive = vHiveNames[sHiveName];
		path = path.substr((fslashIdx > bslashIdx ? bslashIdx : fslashIdx) + 1);

		return hive;
	}

	RegistryKey::RegistryKey(HKEY hive, std::wstring path, std::wstring name, bool Create) : hive{ hive }, name{ name }, path{ path } {
		LSTATUS status = Create ? RegOpenKeyEx(hive, path.c_str(), 0, KEY_ALL_ACCESS, &key)
			: RegCreateKeyEx(hive, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, nullptr);

		if(status != ERROR_SUCCESS){
			LOG_ERROR("Error " << status << " << occured when attempting to read registry key " << GetName());
			SetLastError(status);
		}
		
		LOG_VERBOSE(1, "Searching for value " << GetName());
		status = RegQueryValueEx(key, name.c_str(), 0, &dwDataType, nullptr, &dwDataSize);
		if(status != ERROR_SUCCESS && status != ERROR_MORE_DATA){
			LOG_ERROR("Unable to query value " << GetName());
			SetLastError(status);
		}

		LOG_VERBOSE(3, "Value is of type " << dwDataType << " and size " << dwDataSize);
		status = RegQueryValueEx(key, name.c_str(), 0, &dwDataType, lpbValue, &dwDataSize);
		if(status != ERROR_SUCCESS){
			LOG_ERROR("Unable to read value " << GetName());
			SetLastError(status);
		}

		valid = true;
	}

	RegistryKey::RegistryKey(std::wstring path, std::wstring name) : RegistryKey(RemoveHive(path), path, name){};

	RegistryKey::~RegistryKey() { RegCloseKey(key); }

	bool RegistryKey::Exists() { return valid; }

	std::wstring RegistryKey::GetName(){
		return vHives[hive] + L"\\" + path + L":" + name;
	}

	bool RegistryKey::Set(LPVOID value, DWORD dwSize, DWORD dwType) {
		if(dwType == -1) dwType = dwDataType;

		LOG_VERBOSE(3, "Setting registry key " << GetName());
		if(!Exists()){
			LOG_VERBOSE(2, "Registry key " << GetName() << " did not exist; creating key now");
			LSTATUS status = RegCreateKeyEx(hive, name.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, nullptr);
			
			if(status != ERROR_SUCCESS){
				LOG_ERROR("Error " << status << " occurred when attempting to create key " << GetName());
				SetLastError(status);
				
				return false;
			}
		}

		LSTATUS status = RegSetValueEx(key, name.c_str(), 0, dwType, reinterpret_cast<BYTE*>(value), dwSize);
		if(status != ERROR_SUCCESS){
			LOG_ERROR("Error " << status << " occurred when attempting to set key " << GetName());
			SetLastError(status);

			return false;
		}

		lpbValue = reinterpret_cast<BYTE*>(value);

		return true;
	};

	template<>
	inline bool RegistryKey::Set<REG_DWORD_T>(REG_DWORD_T value) {
		LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

		return Set(&value, sizeof(DWORD), REG_DWORD);
	}

	template<>
	inline bool RegistryKey::Set<REG_SZ_T>(REG_SZ_T value) {
		LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

		return Set(const_cast<wchar_t*>(value.c_str()), sizeof(WCHAR) * static_cast<DWORD>(value.length() + 1), REG_SZ); 
	}

	template<>
	inline bool RegistryKey::Set<REG_MULTI_SZ_T>(REG_MULTI_SZ_T value) {
		SIZE_T size = 1;
		for(auto string : value){
			size += (string.length() + 1);
		}

		WCHAR* data = new WCHAR[size];
		int ptr = 0;

		std::wstring wsLogStatement{};
		for(auto string : value){
			wsLogStatement += string + L"; ";
			LPCWSTR lpRawString = string.c_str();
			for(int i = 0; i < string.length() + 1; i++){
				if(ptr < size){
					data[ptr++] = lpRawString[i];
				}
			}
		}
		
		if(ptr < size){
			data[ptr] = { static_cast<WCHAR>(0) };
		}

		LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << wsLogStatement);

		return Set(data, static_cast<DWORD>(size * sizeof(WCHAR)), REG_MULTI_SZ);
	}

	LPVOID RegistryKey::GetRaw(){
		return lpbValue;
	}

	template<>
	inline REG_DWORD_T RegistryKey::Get<REG_DWORD_T>(){ 
		DWORD value = *reinterpret_cast<DWORD*>(GetRaw());
		LOG_VERBOSE(2, "Read value " << value << " from key " << GetName());

		return value;
	}

	template<>
	inline REG_SZ_T RegistryKey::Get<REG_SZ_T>() {
		std::wstring value = reinterpret_cast<LPWSTR>(GetRaw());
		LOG_VERBOSE(2, "Read value " << value << " from key " << GetName());

		return value;
	}

	template<>
	inline REG_MULTI_SZ_T RegistryKey::Get<REG_MULTI_SZ_T>(){
		std::vector<std::wstring> strings{};
		std::wstring wsLogString{};

		LPCWSTR data = reinterpret_cast<LPCWSTR>(GetRaw());
		while(*data){
			std::wstring str = data;
			strings.emplace_back(data);
			wsLogString += str;

			data += str.length() + 1;
		}

		LOG_VERBOSE(2, "Read value " << wsLogString << " from key " << GetName());

		return strings;
	}

	template<>
	inline bool RegistryKey::operator==<const wchar_t*>(const wchar_t* wcsKnownGood){
		return operator==<std::wstring>(std::wstring(wcsKnownGood));
	}

	template<>
	inline bool RegistryKey::operator==<REG_MULTI_SZ_T>(REG_MULTI_SZ_T vKnownGood){
		auto data = Get<std::vector<std::wstring>>();

		std::set<std::wstring> GoodContents{};
		for(auto string : vKnownGood){
			GoodContents.insert(string);
		}

		std::set<std::wstring> ActualContents{};
		for(auto string : data){
			ActualContents.insert(string);
		}

		for(auto string : GoodContents){
			if(ActualContents.find(string) == ActualContents.end()){
				return false;
			}
		}

		for(auto string : ActualContents){
			if(GoodContents.find(string) == GoodContents.end()){
				return false;
			}
		}

		return true;
	}

	std::wstring RegistryKey::ToString(){
		return GetName();
	}
}