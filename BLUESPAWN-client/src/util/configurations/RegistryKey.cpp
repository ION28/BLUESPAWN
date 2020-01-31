#include <Windows.h>

#include <iostream>
#include <optional>

#include "util/configurations/Registry.h"
#include "common/StringUtils.h"

LINK_FUNCTION(NtQueryKey, ntdll.dll);

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

	std::map<HKEY, int> RegistryKey::_ReferenceCounts = {};
	
	RegistryKey::RegistryKey(const RegistryKey& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->hkBackingKey = key.hkBackingKey;

		if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
			_ReferenceCounts[hkBackingKey] = 1;
		} else {
			_ReferenceCounts[hkBackingKey]++;
		}
	}

	RegistryKey& RegistryKey::operator=(const RegistryKey& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->hkBackingKey = key.hkBackingKey;

		if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
			_ReferenceCounts[hkBackingKey] = 1;
		} else {
			_ReferenceCounts[hkBackingKey]++;
		}

		return *this;
	}

	RegistryKey::RegistryKey(RegistryKey&& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->hkBackingKey = key.hkBackingKey;

		key.bKeyExists = false;
		key.path = {};
		key.hkHive = nullptr;
		key.hkBackingKey = nullptr;
	}

	RegistryKey& RegistryKey::operator=(RegistryKey&& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->hkBackingKey = key.hkBackingKey;

		key.bKeyExists = false;
		key.path = {};
		key.hkHive = nullptr;
		key.hkBackingKey = nullptr;

		return *this;
	}

	RegistryKey::RegistryKey(HKEY key){
		this->hkBackingKey = key;

		this->bKeyExists = true;

		if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
			_ReferenceCounts[hkBackingKey] = 1;
		} else {
			_ReferenceCounts[hkBackingKey]++;
		}
	}

	RegistryKey::RegistryKey(HKEY hive, std::wstring path){
		LSTATUS status = RegOpenKeyEx(hive, path.c_str(), 0, KEY_ALL_ACCESS, &hkBackingKey);
		if(status == ERROR_ACCESS_DENIED){
			status = RegOpenKeyEx(hive, path.c_str(), 0, KEY_READ, &hkBackingKey);
		}

		if(status != ERROR_SUCCESS){
			bKeyExists = false;

			this->hkHive = hive;
			this->path = path;
		} else {
			bKeyExists = true;

			if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
				_ReferenceCounts[hkBackingKey] = 1;
			} else {
				_ReferenceCounts[hkBackingKey]++;
			}
		}
	}
	
	RegistryKey::RegistryKey(std::wstring name){
		name = ToLowerCase(name);

		SIZE_T fSlash = name.find(L"/");
		SIZE_T bSlash = name.find(L"\\");

		SIZE_T slash = fSlash == -1 ? (bSlash == -1 ? name.length() : bSlash) : (fSlash > bSlash ? fSlash : bSlash);

		std::wstring HiveName = name.substr(0, slash);

		if(vHiveNames.find(HiveName) == vHiveNames.end()){
			this->bKeyExists = false;
			this->hkBackingKey = nullptr;
		}

		else {
			hkHive = vHiveNames[HiveName];

			if(slash == name.length()){
				this->bKeyExists = true;
				this->hkBackingKey = hkHive;
			}

			else {
				path = name.substr(slash + 1, name.length());

				LSTATUS status = RegOpenKeyEx(hkHive, path.c_str(), 0, KEY_ALL_ACCESS, &hkBackingKey);
				if(status == ERROR_ACCESS_DENIED){
					status = RegOpenKeyEx(hkHive, path.c_str(), 0, KEY_READ, &hkBackingKey);
				}

				if(status == ERROR_SUCCESS){
					if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
						_ReferenceCounts[hkBackingKey] = 1;
					} else {
						_ReferenceCounts[hkBackingKey]++;
					}

					bKeyExists = true;
				} else {
					bKeyExists = false;
				}
			}
		}
	}

	RegistryKey::~RegistryKey(){
		if(_ReferenceCounts.find(hkBackingKey) != _ReferenceCounts.end()){
			if(!--_ReferenceCounts[hkBackingKey]){
				_ReferenceCounts.erase(hkBackingKey);
				CloseHandle(hkBackingKey);
			}
		}
	}

	bool RegistryKey::Exists() const {
		return bKeyExists;
	}

	bool RegistryKey::ValueExists(std::wstring wsValueName) const {
		return ERROR_SUCCESS == RegQueryValueExW(hkBackingKey, wsValueName.c_str(), nullptr, nullptr, nullptr, nullptr);
	}

	bool RegistryKey::Create(){
		if(Exists()){
			return true;
		}

		if(!hkHive){
			SetLastError(ERROR_NOT_FOUND);
			return false;
		}

		LSTATUS status = RegCreateKeyEx(hkHive, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &hkBackingKey, nullptr);
		if(status == ERROR_SUCCESS){
			bKeyExists = true;

			if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
				_ReferenceCounts[hkBackingKey] = 1;
			} else {
				_ReferenceCounts[hkBackingKey]++;
			}

			return true;
		}

		SetLastError(status);

		return false;
	}

	AllocationWrapper RegistryKey::GetRawValue(std::wstring ValueName) const {
		if(!Exists()){
			SetLastError(FILE_DOES_NOT_EXIST);
			return { nullptr, 0 };
		}

		DWORD dwDataSize{};

		LSTATUS status = RegQueryValueExW(hkBackingKey, ValueName.c_str(), 0, nullptr, nullptr, &dwDataSize);
		if(status != ERROR_SUCCESS && status != ERROR_MORE_DATA){
			SetLastError(status);
			return { nullptr, 0 };
		}

		auto lpbValue = new BYTE[dwDataSize];
		status = RegQueryValueExW(hkBackingKey, ValueName.c_str(), 0, nullptr, lpbValue, &dwDataSize);
		if(status != ERROR_SUCCESS){
			SetLastError(status);
			return { nullptr, 0 };
		}

		return { lpbValue, dwDataSize };
	}

	std::optional<RegistryType> RegistryKey::GetValueType(std::wstring ValueName) const {
		if(!Exists()){
			SetLastError(FILE_DOES_NOT_EXIST);
			return std::nullopt;
		}

		DWORD dwType{};

		LSTATUS status = RegQueryValueExW(hkBackingKey, ValueName.c_str(), 0, &dwType, nullptr, nullptr);
		if(status != ERROR_SUCCESS && status != ERROR_MORE_DATA){
			SetLastError(status);
			return std::nullopt;
		}

		if(dwType == REG_SZ){
			return RegistryType::REG_SZ_T;
		} else if(dwType == REG_EXPAND_SZ){
			return RegistryType::REG_EXPAND_SZ_T;
		} else if(dwType == REG_MULTI_SZ){
			return RegistryType::REG_MULTI_SZ_T;
		} else if(dwType == REG_DWORD){
			return RegistryType::REG_DWORD_T;
		}

		return RegistryType::REG_BINARY_T;
	}

	template<class T>
	std::optional<T> RegistryKey::GetValue(std::wstring wsValueName) const {
		if(ValueExists(wsValueName)){
			return GetRawValue(wsValueName).Dereference<T>();
		}
		return std::nullopt;
	}

	template std::optional<DWORD> RegistryKey::GetValue(std::wstring wsValueName) const;

	template<>
	std::optional<std::wstring> RegistryKey::GetValue(std::wstring wsValueName) const {
		if(ValueExists(wsValueName)){
			return GetRawValue(wsValueName).ReadWString();
		}
		return std::nullopt;
	}

	template<>
	std::optional<std::vector<std::wstring>> RegistryKey::GetValue(std::wstring wsValueName) const {
		if(ValueExists(wsValueName)){
			std::vector<std::wstring> strings{};
			std::wstring wsLogString{};

			LPCWSTR data = reinterpret_cast<LPCWSTR>(GetRawValue(wsValueName).Copy());
			auto tmp = data;

			while(*data){
				std::wstring str = data;
				strings.emplace_back(data);
				wsLogString += str;

				data += str.length() + 1;
			}

			delete tmp;

			return strings;
		}

		return std::nullopt;
	}

	bool RegistryKey::SetRawValue(std::wstring name, AllocationWrapper bytes, DWORD dwType) const {
		if(!Exists()){
			return false;
		}

		auto copy = bytes.Copy();
		if(!copy){
			SetLastError(ERROR_INVALID_PARAMETER);
			return false;
		}

		LSTATUS status = RegSetValueEx(hkBackingKey, name.c_str(), 0, dwType, reinterpret_cast<BYTE*>(copy), bytes.GetSize());
		delete[] copy;
		if(status != ERROR_SUCCESS){
			SetLastError(status);
			return false;
		}

		return true;
	}

	template<class T>
	bool RegistryKey::SetValue(std::wstring name, T value, DWORD size, DWORD type) const {
		return SetRawValue(name, { reinterpret_cast<BYTE*>(value), size, AllocationWrapper::STACK_ALLOC }, type);
	}

	template<>
	bool RegistryKey::SetValue(std::wstring name, LPCWSTR value, DWORD size, DWORD type) const {
		return RegistryKey::SetRawValue(name, { PBYTE(value), wcslen(value), AllocationWrapper::STACK_ALLOC }, type);
	}
	template bool RegistryKey::SetValue<LPCWSTR>(std::wstring name, LPCWSTR value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(std::wstring name, LPCSTR value, DWORD size, DWORD type) const {
		return RegistryKey::SetRawValue(name, { PBYTE(value), strlen(value), AllocationWrapper::STACK_ALLOC }, type);
	}
	template bool RegistryKey::SetValue<LPCSTR>(std::wstring name, LPCSTR value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(std::wstring name, DWORD value, DWORD size, DWORD type) const {
		return SetRawValue(name, { reinterpret_cast<BYTE*>(&value), 4, AllocationWrapper::STACK_ALLOC }, REG_DWORD);
	}
	template bool RegistryKey::SetValue<DWORD>(std::wstring name, DWORD value, DWORD size, DWORD type) const;

	template<> 
	bool RegistryKey::SetValue(std::wstring name, std::wstring value, DWORD size, DWORD type) const {
		return SetValue<LPCWSTR>(name, value.c_str(), static_cast<DWORD>((value.size() + 1) * 2), REG_SZ);
	}
	template bool RegistryKey::SetValue<std::wstring>(std::wstring name, std::wstring value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(std::wstring name, std::string value, DWORD size, DWORD type) const {
		return SetValue<std::wstring>(name, StringToWidestring(value));
	}
	template bool RegistryKey::SetValue<std::string>(std::wstring name, std::string value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(std::wstring name, std::vector<std::wstring> value, DWORD _size, DWORD type) const {
		SIZE_T size = 1;
		for(auto string : value){
			size += (string.length() + 1);
		}

		WCHAR* data = new WCHAR[size];
		unsigned ptr = 0;

		std::wstring wsLogStatement{};
		for(auto string : value){
			wsLogStatement += string + L"; ";
			LPCWSTR lpRawString = string.c_str();
			for(unsigned i = 0; i < string.length() + 1; i++){
				if(ptr < size){
					data[ptr++] = lpRawString[i];
				}
			}
		}

		if(ptr < size){
			data[ptr] = { static_cast<WCHAR>(0) };
		}

		bool succeeded = SetRawValue(name, AllocationWrapper{ data, static_cast<DWORD>(size * sizeof(WCHAR)), AllocationWrapper::CPP_ARRAY_ALLOC }, REG_MULTI_SZ);

		delete[] data;

		return succeeded;
	}

	template bool RegistryKey::SetValue<std::vector<std::wstring>>(std::wstring name, std::vector<std::wstring> value, 
		DWORD _size, DWORD type) const;

	std::vector<RegistryKey> RegistryKey::EnumerateSubkeys() const {
		if(!Exists()){
			SetLastError(ERROR_NOT_FOUND);
			return {};
		}

		DWORD dwSubkeyCount{};
		DWORD dwLongestSubkey{};
		LSTATUS status = RegQueryInfoKey(hkBackingKey, nullptr, nullptr, 0, &dwSubkeyCount, &dwLongestSubkey, 
			                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

		std::vector<RegistryKey> vSubKeys{};

		if(status == ERROR_SUCCESS && dwSubkeyCount) {
			for(unsigned i = 0; i < dwSubkeyCount; i++) {
				DWORD length = dwLongestSubkey * 2;
				LPWSTR lpwName = new WCHAR[length];
				status = RegEnumKey(hkBackingKey, i, lpwName, length);

				if(status == ERROR_SUCCESS) {
					vSubKeys.push_back({ hkBackingKey, lpwName });
				}

				delete[] lpwName;
			}
		}
		return vSubKeys;
	}

	std::vector<std::wstring> RegistryKey::EnumerateValues() const {
		if(!Exists()){
			SetLastError(ERROR_NOT_FOUND);
			return {};
		}

		DWORD dwValueCount{};
		DWORD dwLongestValue{};
		LSTATUS status = RegQueryInfoKey(hkBackingKey, nullptr, nullptr, 0, nullptr, nullptr, nullptr, &dwValueCount, 
			                             &dwLongestValue, nullptr, nullptr, nullptr);

		std::vector<std::wstring> vSubKeys{};

		if(status == ERROR_SUCCESS && dwValueCount) {
			for(unsigned i = 0; i < dwValueCount; i++) {
				DWORD length = dwLongestValue * 2;
				LPWSTR lpwName = new WCHAR[length];
				status = RegEnumValueW(hkBackingKey, i, lpwName, &length, nullptr, nullptr, nullptr, nullptr);

				if(status == ERROR_SUCCESS) {
					vSubKeys.push_back({ lpwName });
				}

				delete[] lpwName;
			}
		}
		return vSubKeys;
	}

	std::wstring RegistryKey::GetName() const {
		// Taken largely from https://stackoverflow.com/questions/937044/determine-path-to-registry-key-from-hkey-handle-in-c
		std::wstring keyPath = {};
		if(hkBackingKey && Linker::NtQueryKey){
			DWORD size = 0;
			DWORD result = 0;
			result = Linker::NtQueryKey(hkBackingKey, 3, 0, 0, &size);
			if(result == ((NTSTATUS) 0xC0000023L)){
				size = size + sizeof(wchar_t);
				wchar_t* buffer = new wchar_t[size / sizeof(wchar_t)];
				if(buffer != NULL){
					result = Linker::NtQueryKey(hkBackingKey, 3, buffer, size, &size);
					if(result == 0){
						buffer[size / sizeof(wchar_t)] = L'\0';
						keyPath = std::wstring(buffer + 2);
					}
					delete[] buffer;
				}
			}
		}
		return keyPath;
	}

	std::wstring RegistryKey::ToString() const {
		return GetName();
	}


	bool RegistryKey::operator<(RegistryKey key) const {
		return hkBackingKey < key.hkBackingKey;
	}
}