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

	bool RegistryKey::CheckKeyExists(HKEY hive, const std::wstring& name, bool WoW64){
		auto wLowerPath = ToLowerCase(name);

		HKEY key{};
		WoW64 = WoW64 || wLowerPath.find(L"wow6432node") != std::wstring::npos;
		LSTATUS status = RegOpenKeyExW(hive, name.c_str(), 0, KEY_READ | KEY_NOTIFY | (WoW64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key);
		if(status == ERROR_ACCESS_DENIED){
			status = RegOpenKeyExW(hive, name.c_str(), 0, KEY_READ | KEY_NOTIFY | (WoW64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key);
		}

		if(status == ERROR_SUCCESS){
			if(_ReferenceCounts.find(key) == _ReferenceCounts.end()){
				RegCloseKey(key);
			}
		}
	}
	
	RegistryKey::RegistryKey(const RegistryKey& key) noexcept :
		bKeyExists{ key.bKeyExists },
		bWow64{ key.bWow64 },
		hkBackingKey{ key.hkBackingKey }{

		if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
			_ReferenceCounts[hkBackingKey] = 1;
		} else {
			_ReferenceCounts[hkBackingKey]++;
		}
	}

	RegistryKey& RegistryKey::operator=(const RegistryKey& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->bWow64 = key.bWow64;
		this->hkBackingKey = key.hkBackingKey;

		if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
			_ReferenceCounts[hkBackingKey] = 1;
		} else {
			_ReferenceCounts[hkBackingKey]++;
		}

		return *this;
	}

	RegistryKey::RegistryKey(RegistryKey&& key) noexcept :
		bKeyExists{ key.bKeyExists },
		bWow64{ key.bWow64 },
		hkBackingKey{ key.hkBackingKey }{

		key.bKeyExists = false;
		key.bWow64 = false;
		key.path = {};
		key.hkHive = nullptr;
		key.hkBackingKey = nullptr;
	}

	RegistryKey& RegistryKey::operator=(RegistryKey&& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->bWow64 = key.bWow64;
		this->hkBackingKey = key.hkBackingKey;

		key.bKeyExists = false;
		key.bWow64 = false;
		key.path = {};
		key.hkHive = nullptr;
		key.hkBackingKey = nullptr;

		return *this;
	}

	/// TODO - Add smart WoW64 checking
	RegistryKey::RegistryKey(HKEY key) :
		bKeyExists{ true },
		bWow64{ false },
		hkBackingKey{ key }{


		if(_ReferenceCounts.find(hkBackingKey) == _ReferenceCounts.end()){
			_ReferenceCounts[hkBackingKey] = 1;
		} else {
			_ReferenceCounts[hkBackingKey]++;
		}
	}

	RegistryKey::RegistryKey(HKEY hive, std::wstring path, bool WoW64){
		auto wLowerPath = ToLowerCase(path);

		bWow64 = WoW64 || wLowerPath.find(L"wow6432node") != std::wstring::npos;
		LSTATUS status = RegOpenKeyEx(hive, path.c_str(), 0, KEY_ALL_ACCESS | (bWow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hkBackingKey);
		if(status == ERROR_ACCESS_DENIED){
			status = RegOpenKeyEx(hive, path.c_str(), 0, KEY_READ | KEY_NOTIFY | (bWow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hkBackingKey);
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
	
	RegistryKey::RegistryKey(std::wstring name, bool WoW64){
		name = ToUpperCase(name);

		SIZE_T slash = name.find_first_of(L"/\\");

		std::wstring HiveName = slash == std::wstring::npos ? name : name.substr(0, slash);

		if(vHiveNames.find(HiveName) == vHiveNames.end()){
			this->bKeyExists = false;
			this->bWow64 = false;
			this->hkBackingKey = nullptr;
		}

		else {
			hkHive = vHiveNames[HiveName];

			if(slash == name.length()){
				this->bKeyExists = true;
				this->bWow64 = false;
				this->hkBackingKey = hkHive;
			}

			else {
				path = name.substr(slash + 1, name.length());
				auto wLowerPath = ToLowerCase(path);

				bWow64 = WoW64 || wLowerPath.find(L"wow6432node") != std::wstring::npos;
				LSTATUS status = RegOpenKeyEx(hkHive, path.c_str(), 0, KEY_ALL_ACCESS | (WoW64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hkBackingKey);
				if(status == ERROR_ACCESS_DENIED){
					status = RegOpenKeyEx(hkHive, path.c_str(), 0, KEY_READ | KEY_NOTIFY | (WoW64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hkBackingKey);
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
			if(!--_ReferenceCounts[hkBackingKey] && !(ULONG_PTR(hkBackingKey) & 0xFFFFFFFF80000000)){
				RegCloseKey(hkBackingKey);
			}
		}
	}

	bool RegistryKey::Exists() const {
		return bKeyExists;
	}

	bool RegistryKey::ValueExists(const std::wstring& wsValueName) const {
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

	AllocationWrapper RegistryKey::GetRawValue(const std::wstring& ValueName) const {
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

	std::optional<RegistryType> RegistryKey::GetValueType(const std::wstring& ValueName) const {
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
	std::optional<T> RegistryKey::GetValue(const std::wstring& wsValueName) const {
		if(ValueExists(wsValueName)){
			return GetRawValue(wsValueName).Dereference<T>();
		}
		return std::nullopt;
	}

	template std::optional<DWORD> RegistryKey::GetValue(const std::wstring& wsValueName) const;

	template<>
	std::optional<std::wstring> RegistryKey::GetValue(const std::wstring& wsValueName) const {
		if(ValueExists(wsValueName)){
			if(GetValueType(wsValueName) == RegistryType::REG_EXPAND_SZ_T){
				return ExpandEnvStringsW(*GetRawValue(wsValueName).ReadWString());
			}
			return GetRawValue(wsValueName).ReadWString();
		}
		return std::nullopt;
	}

	template<>
	std::optional<std::vector<std::wstring>> RegistryKey::GetValue(const std::wstring& wsValueName) const {
		if(ValueExists(wsValueName)){
			std::vector<std::wstring> strings{};

			LPCWSTR data = reinterpret_cast<LPCWSTR>((LPVOID) GetRawValue(wsValueName));

			while(*data){
				std::wstring str = data;
				strings.emplace_back(data);

				data += str.length() + 1;
			}

			return strings;
		}

		return std::nullopt;
	}

	bool RegistryKey::SetRawValue(const std::wstring& name, AllocationWrapper bytes, DWORD dwType) const {
		if(!Exists()){
			return false;
		}

		LSTATUS status = RegSetValueEx(hkBackingKey, name.c_str(), 0, dwType, reinterpret_cast<BYTE*>((LPVOID) bytes), bytes.GetSize());
		if(status != ERROR_SUCCESS){
			SetLastError(status);
			return false;
		}

		return true;
	}

	template<class T>
	bool RegistryKey::SetValue(const std::wstring& name, T value, DWORD size, DWORD type) const {
		return SetRawValue(name, { reinterpret_cast<BYTE*>(value), size, AllocationWrapper::STACK_ALLOC }, type);
	}

	template<>
	bool RegistryKey::SetValue(const std::wstring& name, LPCWSTR value, DWORD size, DWORD type) const {
		return RegistryKey::SetRawValue(name, { PBYTE(value), wcslen(value) * 2 + 2, AllocationWrapper::STACK_ALLOC }, type);
	}
	template bool RegistryKey::SetValue<LPCWSTR>(const std::wstring& name, LPCWSTR value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(const std::wstring& name, LPCSTR value, DWORD size, DWORD type) const {
		return RegistryKey::SetRawValue(name, { PBYTE(value), strlen(value), AllocationWrapper::STACK_ALLOC }, type);
	}
	template bool RegistryKey::SetValue<LPCSTR>(const std::wstring& name, LPCSTR value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(const std::wstring& name, DWORD value, DWORD size, DWORD type) const {
		return SetRawValue(name, { reinterpret_cast<BYTE*>(&value), 4, AllocationWrapper::STACK_ALLOC }, REG_DWORD);
	}
	template bool RegistryKey::SetValue<DWORD>(const std::wstring& name, DWORD value, DWORD size, DWORD type) const;

	template<> 
	bool RegistryKey::SetValue(const std::wstring& name, std::wstring value, DWORD size, DWORD type) const {
		return SetValue<LPCWSTR>(name, value.c_str(), static_cast<DWORD>((value.size() + 1) * 2), REG_SZ);
	}
	template bool RegistryKey::SetValue<std::wstring>(const std::wstring& name, std::wstring value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(const std::wstring& name, std::string value, DWORD size, DWORD type) const {
		return SetValue<std::wstring>(name, StringToWidestring(value));
	}
	template bool RegistryKey::SetValue<std::string>(const std::wstring& name, std::string value, DWORD size, DWORD type) const;

	template<>
	bool RegistryKey::SetValue(const std::wstring& name, std::vector<std::wstring> value, DWORD _size, DWORD type) const {
		SIZE_T size = 1;
		for(auto string : value){
			size += (string.length() + 1);
		}

		auto data = new WCHAR[size];
		auto allocation = AllocationWrapper{ data, static_cast<DWORD>(size * sizeof(WCHAR)), AllocationWrapper::CPP_ARRAY_ALLOC };
		unsigned ptr = 0;

		for(auto string : value){
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

		bool succeeded = SetRawValue(name, allocation, REG_MULTI_SZ);

		return succeeded;
	}

	template bool RegistryKey::SetValue<std::vector<std::wstring>>(const std::wstring& name, std::vector<std::wstring> value,
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
		} else {
			SetLastError(status);
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
		} else {
			SetLastError(status);
		}

		return vSubKeys;
	}

	std::wstring RegistryKey::GetName() const {
		if(!Exists()){
			SetLastError(ERROR_NOT_FOUND);
			return {};
		}

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
					auto location = keyPath.find(L"\\REGISTRY\\MACHINE");
					if(location != std::string::npos){
						keyPath.replace(location, 17, L"HKEY_LOCAL_MACHINE");
					}
					location = keyPath.find(L"\\REGISTRY\\USER");
					if(location != std::string::npos){
						keyPath.replace(location, 14, L"HKEY_USERS");
					}
				}
			}
		}
		return keyPath;
	}

	std::wstring RegistryKey::ToString() const {
		return GetName();
	}

	bool RegistryKey::operator==(const RegistryKey& key) const {
		return hkBackingKey == key.hkBackingKey;
	}

	bool RegistryKey::operator<(const RegistryKey& key) const {
		return hkBackingKey < key.hkBackingKey;
	}

	bool RegistryKey::RemoveValue(const std::wstring& wsValueName) const {
		auto status = RegDeleteValueW(hkBackingKey, wsValueName.c_str());
		SetLastError(status);
		return status == ERROR_SUCCESS;
	}

	RegistryKey::operator HKEY() const {
		return hkBackingKey;
	}
}