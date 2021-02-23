#include <Windows.h>

#include <iostream>
#include <optional>

#include "util/StringUtils.h"
#include "util/Internals.h"

#include "util/configurations/Registry.h"

LINK_FUNCTION(NtQueryKey, ntdll.dll);
LINK_FUNCTION(NtQueryValueKey, ntdll.dll);
LINK_FUNCTION(NtDeleteValueKey, ntdll.dll);

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

	RegistryKey::Tracker::Tracker(){}

	void RegistryKey::Tracker::Increment(IN HKEY hKey){
		BeginCriticalSection _{ hGuard };
		if(hKey){
			if(counts.find(hKey) == counts.end()){
				counts[hKey] = 1;
			} else{
				counts[hKey]++;
			}
		}
	}

	void RegistryKey::Tracker::Decrement(IN HKEY hKey){
		BeginCriticalSection _{ hGuard };
		if(hKey){
			if(counts.find(hKey) != counts.end()){
				if(!--counts[hKey] && !(reinterpret_cast<ULONG_PTR>(hKey) & 0xFFFFFFFF80000000)){
					CloseHandle(hKey);
				}
			}
		}
	}

	int RegistryKey::Tracker::Get(IN HKEY hKey){
		BeginCriticalSection _{ hGuard };
		if(counts.find(hKey) != counts.end()){
			return counts[hKey];
		} else{
			return 0;
		}
	}

	std::shared_ptr<RegistryKey::Tracker> RegistryKey::__tracker{ std::make_shared<RegistryKey::Tracker>() };

	RegistryKey::RegistryKey(const RegistryKey& key) noexcept :
		bKeyExists{ key.bKeyExists },
		bWow64{ key.bWow64 },
		hkBackingKey{ key.hkBackingKey },
		path{ key.path },
		hkHive{ key.hkHive },
		tracker{ __tracker }{

		tracker->Increment(hkBackingKey);
	}

	RegistryKey& RegistryKey::operator=(const RegistryKey& key) noexcept {
		this->bKeyExists = key.bKeyExists;
		this->bWow64 = key.bWow64;
		this->hkBackingKey = key.hkBackingKey;
		this->path = key.path;
		this->hkHive = key.hkHive;

		tracker->Increment(hkBackingKey);

		return *this;
	}

	RegistryKey::RegistryKey(RegistryKey&& key) noexcept :
		bKeyExists{ key.bKeyExists },
		bWow64{ key.bWow64 },
		hkBackingKey{ key.hkBackingKey },
		path{ std::move(key.path) },
		hkHive{ key.hkHive },
		tracker{ __tracker }{

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
		this->path = std::move(key.path);
		this->hkHive = key.hkHive;

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
		hkBackingKey{ key },
		tracker{ __tracker }{

		tracker->Increment(hkBackingKey);
	}

	RegistryKey::RegistryKey(HKEY hive, std::wstring path, bool WoW64) :
		tracker{ __tracker }, hkHive{ hive }, path{ path }{
		auto wLowerPath = ToLowerCase(path);

		bWow64 = WoW64 || wLowerPath.find(L"wow6432node") != std::wstring::npos;
		LSTATUS status = RegOpenKeyExW(hive, path.c_str(), 0, KEY_ALL_ACCESS | (bWow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hkBackingKey);
		if(status == ERROR_ACCESS_DENIED){
			status = RegOpenKeyExW(hive, path.c_str(), 0, KEY_READ | KEY_NOTIFY | (bWow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hkBackingKey);
		}

		if(status != ERROR_SUCCESS){
			bKeyExists = false;
		} else {
			bKeyExists = true;

			tracker->Increment(hkBackingKey);
		}
	}

	RegistryKey::RegistryKey(const RegistryKey& hive, const std::wstring& path, bool wow64) :
		RegistryKey{ hive.Exists() ? hive.hkBackingKey : hive.hkHive, hive.Exists() ? path : hive.path + L"\\" + path, 
		             wow64 }{}
	
	RegistryKey::RegistryKey(std::wstring name, bool WoW64) :
		tracker{ __tracker }{
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

			if(slash == name.length() || slash == std::wstring::npos){
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
					tracker->Increment(hkBackingKey);

					bKeyExists = true;
				} else {
					bKeyExists = false;
				}
			}
		}
	}

	RegistryKey::~RegistryKey(){
		if(Exists()){
			tracker->Decrement(hkBackingKey);
		}
	}

	bool RegistryKey::CheckKeyExists(HKEY hive, const std::wstring& name, bool WoW64){
		auto wLowerPath = ToLowerCase(name);

		HKEY key{};
		WoW64 = WoW64 || wLowerPath.find(L"wow6432node") != std::wstring::npos;
		LSTATUS status = RegOpenKeyExW(hive, name.c_str(), 0,
									   KEY_READ | KEY_NOTIFY | (WoW64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key);
		if(status == ERROR_ACCESS_DENIED){ return true; }

		if(status == ERROR_SUCCESS){
			if(!__tracker->Get(key)){ RegCloseKey(key); }
			return true;
		}

		return false;
	}

	bool RegistryKey::Exists() const {
		return bKeyExists;
	}

	bool RegistryKey::ValueExists(const std::wstring& wsValueName) const {
		if(!Exists()){
			return false;
		}

		UNICODE_STRING RegistryKeyName{ 
			static_cast<USHORT>(wsValueName.length() * 2), 
			static_cast<USHORT>(wsValueName.length() * 2 + 2),
			const_cast<PWSTR>(wsValueName.c_str())
		};

		ULONG size{};
		NTSTATUS status{ Linker::NtQueryValueKey(hkBackingKey, &RegistryKeyName, 0, nullptr, 0, &size) }; //First 0 is KeyValueBasicInformation

		return status != 0xC0000034; //0xC0000034 = STATUS_OBJECT_NAME_NOT_FOUND
	}

	bool RegistryKey::Create(){
		if(Exists()){
			return true;
		}

		if(!hkHive){
			SetLastError(ERROR_NOT_FOUND);
			return false;
		}

		LSTATUS status = RegCreateKeyExW(hkHive, path.c_str(), 0, nullptr, 0, 
										KEY_ALL_ACCESS | (this->bWow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), nullptr,
										&hkBackingKey, nullptr);
		if(status == ERROR_SUCCESS){
			bKeyExists = true;

			tracker->Increment(hkBackingKey);

			return true;
		}

		SetLastError(status);

		return false;
	}

	AllocationWrapper RegistryKey::GetRawValue(const std::wstring& wsValueName) const {
		if(!Exists()){
			SetLastError(FILE_DOES_NOT_EXIST);
			return { nullptr, 0 };
		}

		UNICODE_STRING RegistryKeyName{
			static_cast<USHORT>(wsValueName.length() * 2),
			static_cast<USHORT>(wsValueName.length() * 2 + 2),
			const_cast<PWSTR>(wsValueName.c_str())
		};

		ULONG size{};
		NTSTATUS status{ Linker::NtQueryValueKey(hkBackingKey, &RegistryKeyName, 1, nullptr, 0, &size) }; //First 1 is KeyValueFullInformation

		auto data = AllocationWrapper{ new CHAR[size], size, AllocationWrapper::CPP_ARRAY_ALLOC };
		status = Linker::NtQueryValueKey(hkBackingKey, &RegistryKeyName, 1, data, size, &size);

		if (!NT_SUCCESS(status)) {
			SetLastError(status);
			return { nullptr, 0 };
		}

		KEY_VALUE_FULL_INFORMATION* KeyValueInfo{ data.GetAsPointer<KEY_VALUE_FULL_INFORMATION>() };

		DWORD dwDataSize = KeyValueInfo->DataLength;
		DWORD dwDataOffset = KeyValueInfo->DataOffset;

		auto lpbValue = new BYTE[dwDataSize];
		MoveMemory(lpbValue, reinterpret_cast<PCHAR>(KeyValueInfo) + dwDataOffset, dwDataSize);

		return { lpbValue, dwDataSize, AllocationWrapper::CPP_ARRAY_ALLOC };
	}

	std::optional<RegistryType> RegistryKey::GetValueType(const std::wstring& wsValueName) const {
		if(!Exists()){
			SetLastError(FILE_DOES_NOT_EXIST);
			return std::nullopt;
		}

		UNICODE_STRING RegistryKeyName{
			static_cast<USHORT>(wsValueName.length() * 2),
			static_cast<USHORT>(wsValueName.length() * 2 + 2),
			const_cast<PWSTR>(wsValueName.c_str())
		};

		ULONG size{};
		NTSTATUS status{ Linker::NtQueryValueKey(hkBackingKey, &RegistryKeyName, 0, nullptr, 0, &size) }; //First 0 is KeyValueBasicInformation

		std::vector<CHAR> data(size);
		status = Linker::NtQueryValueKey(hkBackingKey, &RegistryKeyName, 0, data.data(), size, &size);

		if(!NT_SUCCESS(status)){
			SetLastError(status);
			return std::nullopt;
		}

		auto KeyValueInfo{ reinterpret_cast<KEY_VALUE_BASIC_INFORMATION*>(data.data()) };

		DWORD dwType = KeyValueInfo->Type;

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

		LSTATUS status = RegSetValueEx(hkBackingKey, name.c_str(), 0, dwType, reinterpret_cast<BYTE*>((LPVOID) bytes),
									   bytes.GetSize());
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
		return RegistryKey::SetRawValue(name, { PBYTE(value), wcslen(value) * 2 + 2, AllocationWrapper::STACK_ALLOC },
										type);
	}
	template bool RegistryKey::SetValue<LPCWSTR>(const std::wstring& name, LPCWSTR value, DWORD size, 
												 DWORD type) const;

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
	template bool RegistryKey::SetValue<std::wstring>(const std::wstring& name, std::wstring value, DWORD size, 
													  DWORD type) const;

	template<>
	bool RegistryKey::SetValue(const std::wstring& name, std::string value, DWORD size, DWORD type) const{
		return SetValue<std::wstring>(name, StringToWidestring(value));
	}
	template bool RegistryKey::SetValue<std::string>(const std::wstring& name, std::string value, DWORD size, 
													 DWORD type) const;

	bool RegistryKey::SetDataValue(const std::wstring& name, RegistryData value) const{
		auto idx = value.index();
		if(idx == 0){
			return SetValue<std::wstring>(name, std::get<0>(value));
		}
		if(idx == 1){
			return SetValue<DWORD>(name, std::get<1>(value));
		}
		if(idx == 2){
			return SetRawValue(name, std::get<2>(value), REG_BINARY);
		}
		if(idx == 3){
			return SetValue<std::vector<std::wstring>>(name, std::get<3>(value));
		} else{
			throw std::exception("Unknown registry data type");
		}
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

	std::vector<std::wstring> RegistryKey::EnumerateSubkeyNames() const{
		if(!Exists()){
			SetLastError(ERROR_NOT_FOUND);
			return {};
		}

		DWORD dwSubkeyCount{};
		DWORD dwLongestSubkey{};
		LSTATUS status = RegQueryInfoKeyW(hkBackingKey, nullptr, nullptr, 0, &dwSubkeyCount, &dwLongestSubkey,
										 nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

		std::vector<std::wstring> vSubKeys{};

		if(status == ERROR_SUCCESS && dwSubkeyCount){
			for(unsigned i = 0; i < dwSubkeyCount; i++){
				std::vector<WCHAR> name(dwLongestSubkey + 1);
				status = RegEnumKeyW(hkBackingKey, i, name.data(), dwLongestSubkey + 1);

				if(status == ERROR_SUCCESS){
					vSubKeys.push_back(std::wstring{ name.data() });
				}
			}
		} else{
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
					vSubKeys.push_back({ lpwName, length });
				}

				delete[] lpwName;
			}
		} else {
			SetLastError(status);
		}

		return vSubKeys;
	}

	std::wstring RegistryKey::GetNameWithoutHive() const {
		std::wstring ret = GetName();
		auto location = ret.find(L"HKEY_LOCAL_MACHINE");
		if (location != std::string::npos) {
			ret.replace(location, 19, L"");
		}
		location = ret.find(L"HKEY_USERS");
		if (location != std::string::npos) {
			ret.replace(location, 11, L"");
		}
		return ret;
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

		UNICODE_STRING RegistryKeyName{
			static_cast<USHORT>(wsValueName.length() * 2),
			static_cast<USHORT>(wsValueName.length() * 2 + 2),
			const_cast<PWSTR>(wsValueName.c_str())
		};

		NTSTATUS status{ Linker::NtDeleteValueKey(hkBackingKey, &RegistryKeyName)};
		SetLastError(status);
		return NT_SUCCESS(status);
	}

	RegistryKey::operator HKEY() const {
		return hkBackingKey;
	}

	bool RegistryKey::DeleteSubkey(const std::wstring& name) const {
		if(!Exists()){
			return true;
		}

		if(!RegistryKey::CheckKeyExists(hkBackingKey, name, bWow64)){
			return true;
		}

		LSTATUS status = RegDeleteKeyExW(hkBackingKey, name.c_str(), bWow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY, 0);
		if(status == ERROR_SUCCESS){
			return true;
		}

		SetLastError(status);

		return false;
	}
}

size_t std::hash<Registry::RegistryKey>::operator()(IN CONST Registry::RegistryKey& key) const{
	return reinterpret_cast<size_t>(static_cast<HKEY>(key));
}
