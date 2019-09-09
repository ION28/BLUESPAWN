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

	std::map<HKEY, DWORD> _globalOpenKeys{};

	HKEY RemoveHive(std::wstring* path){
		SIZE_T fslashIdx = path->find(L"/");
		SIZE_T bslashIdx = path->find(L"\\");
		if(fslashIdx == (SIZE_T) -1 && bslashIdx == (SIZE_T) -1){
			LOG_ERROR("Registry hive not found!");
			return nullptr;
		}

		std::wstring sHiveName = path->substr(0, fslashIdx > bslashIdx ? bslashIdx : fslashIdx);
		transform(sHiveName.begin(), sHiveName.end(), sHiveName.begin(), ::toupper);
		if(vHiveNames.find(sHiveName) == vHiveNames.end()){
			LOG_ERROR("Unknown registry hive " << sHiveName);
			return nullptr;
		}

		HKEY hive = vHiveNames[sHiveName];
		*path = path->substr((fslashIdx > bslashIdx ? bslashIdx : fslashIdx) + 1);

		return hive;
	}

	RegistryKey::RegistryKey(HKEY hive, std::wstring path, std::wstring name, bool Create) : hive{ hive }, name{ name }, path{ path } {
		LSTATUS status{};
		if(Create){
			if(status = RegCreateKeyEx(hive, path.c_str(), 0, nullptr, 0, KEY_READ, nullptr, &key, nullptr)){
				SetLastError(status);
				LOG_ERROR("Error " << status << " occured when attempting to create registry key " << GetName());

				// Don't do any more initialization if the key couldn't be created.
				return;
			}
		}
		
		else {
			status = RegOpenKeyEx(hive, path.c_str(), 0, KEY_READ, &key);
			if(status != ERROR_SUCCESS){
				LOG_VERBOSE(1, "Error " << status << " occured when attempting to read registry key " << GetName() << ". Probably means key was not found");
				SetLastError(status);
				return;
			}
		}

		if(_globalOpenKeys.find(key) != _globalOpenKeys.end()){
			_globalOpenKeys[key] = 1;
		} else {
			_globalOpenKeys[key]++;
		}
		bKeyExists = true;
		
		LOG_VERBOSE(2, "Searching for value " << name << " under " << vHives[hive] << "\\" << path);

		status = RegQueryValueEx(key, name.length() == 0 ? nullptr : name.c_str(), 0, &dwDataType, nullptr, &dwDataSize);
		if(status != ERROR_SUCCESS && status != ERROR_MORE_DATA){
			LOG_VERBOSE(1, "Unable to query value " << GetName() << ". Probably means value was not found");
			SetLastError(status);

			return;
		}

		bValueExists = true;

		LOG_VERBOSE(3, "Value is of type " << dwDataType << " and size " << dwDataSize);
		lpbValue = new BYTE[dwDataSize];
		status = RegQueryValueEx(key, name.length() == 0 ? nullptr : name.c_str(), 0, &dwDataType, lpbValue, &dwDataSize);
		if(status != ERROR_SUCCESS){
			LOG_ERROR("Unable to read value " << GetName());
			SetLastError(status);
		}

		bKeyExists = true;

		LOG_VERBOSE(1, "Created new registry key object - " << GetName());
	}

	RegistryKey::RegistryKey(std::wstring path, std::wstring name) : RegistryKey(RemoveHive(&path), path, name){};

	RegistryKey::~RegistryKey() { 
		if(!--_globalOpenKeys[key]){
			RegCloseKey(key);
		}
	}

	std::wstring RegistryKey::GetName(){
		return vHives[hive] + L"\\" + path + (name.length() ? L":" + name : L"");
	}

	std::wstring RegistryKey::GetPath(){
		return vHives[hive] + L"\\" + path;
	}

	bool RegistryKey::Set(LPVOID value, DWORD dwSize, DWORD dwType) {
		if(dwType == -1) dwType = dwDataType;

		if(!KeyExists()){
			SetLastError(SPAPI_E_KEY_DOES_NOT_EXIST);

			LOG_ERROR("Attempted to set a registry value belonging to a key that does not exist - " << GetName());
		}
		HKEY temp_key{};
		LOG_VERBOSE(3, "Opening a duplicate key for with write access to set " << GetName());
		LSTATUS status = RegOpenKeyEx(key, nullptr, 0, KEY_WRITE, &temp_key);
		if(status != ERROR_SUCCESS){
			LOG_ERROR("Error " << status << " occurred when reopen key to set " << GetName());
			SetLastError(status);

			return false;
		}

		LOG_VERBOSE(2, "Setting registry key " << GetName());
		status = RegSetValueEx(temp_key, name.length() == 0 ? nullptr : name.c_str(), 0, dwType, reinterpret_cast<BYTE*>(value), dwSize);
		RegCloseKey(temp_key);
		if(status != ERROR_SUCCESS){
			LOG_ERROR("Error " << status << " occurred when attempting to set key " << GetName());
			SetLastError(status);

			return false;
		}

		lpbValue = reinterpret_cast<BYTE*>(value);

		return true;
	};

	bool RegistryKey::Create(LPVOID value, DWORD dwSize, DWORD dwType){
		if(!KeyExists()){
			LSTATUS status = RegCreateKeyEx(hive, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, nullptr);

			if(status != ERROR_SUCCESS){
				LOG_ERROR("Error " << status << " occurred when attempting to create key " << GetName());
				SetLastError(status);

				return false;
			}

			if(_globalOpenKeys.find(key) != _globalOpenKeys.end()){
				_globalOpenKeys[key] = 1;
			} else {
				_globalOpenKeys[key]++;
			}
			bKeyExists = true;

			LOG_VERBOSE(2, "Successfully created registry key " << vHives[hive] << "\\" << path);
		}

		return Set(value, dwSize, dwType);
	}

	LPVOID RegistryKey::GetRaw(){
		if(!ValueExists()){
			lpbValue = new BYTE[2]{};
		}
		return lpbValue;
	}

	std::wstring RegistryKey::ToString(){
		return GetName();
	}

	inline bool RegistryKey::KeyExists() { return bKeyExists; }
	bool RegistryKey::ValueExists() { return bValueExists; }

	std::vector<RegistryKey> RegistryKey::KeyValues(){
		if(!KeyExists()){
			LOG_VERBOSE(1, "Attempting to enumerate values of nonexistent key " << GetName());
			return {};
		}

		DWORD dwValueCount{};
		DWORD dwLongestValue{};
		LSTATUS status = RegQueryInfoKey(key, nullptr, nullptr, 0, nullptr, nullptr, nullptr, &dwValueCount, &dwLongestValue, nullptr, nullptr, nullptr);

		LOG_VERBOSE(1, dwValueCount << " subkeys detected under " << vHives[hive] << "\\" << path);

		std::vector<RegistryKey> vSubKeys{};

		if(status == ERROR_SUCCESS && dwValueCount) {
			for(unsigned i = 0; i < dwValueCount; i++) {
				LPWSTR lpwName = new WCHAR[dwLongestValue];
				DWORD length = dwLongestValue * 2;
				status = RegEnumValueW(key, i, lpwName, &length, nullptr, nullptr, nullptr, nullptr);

				if(status == ERROR_SUCCESS) {
					vSubKeys.push_back({ hive, path, lpwName });
				} else {
					LOG_WARNING("Error " << status << " when enumerating the next value!");
				}
			}
		}
		return vSubKeys;
	}

	std::vector<RegistryKey> RegistryKey::Subkeys(){
		if(!KeyExists()){
			LOG_VERBOSE(1, "Attempting to enumerate values of nonexistent key " << GetName());
			return {};
		}

		DWORD dwSubkeyCount{};
		DWORD dwLongestSubkey{};
		LSTATUS status = RegQueryInfoKey(key, nullptr, nullptr, 0, &dwSubkeyCount, &dwLongestSubkey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

		LOG_VERBOSE(1, dwSubkeyCount << " subkeys detected under " << vHives[hive] << "\\" << path);

		std::vector<RegistryKey> vSubKeys{};

		if(status == ERROR_SUCCESS && dwSubkeyCount) {
			for(unsigned i = 0; i < dwSubkeyCount; i++) {
				LPWSTR lpwName = new WCHAR[dwLongestSubkey];
				DWORD length = dwLongestSubkey * 2;
				status = RegEnumKey(key, i, lpwName, length);

				if(status == ERROR_SUCCESS) {
					vSubKeys.push_back({ hive, path + L"\\" + lpwName, L"" });
				} else {
					LOG_WARNING("Error " << status << " when enumerating the next value!");
				}
			}
		}
		return vSubKeys;
	}
}