#pragma once

#include <windows.h>

#include <string>
#include <map>

#include "logging/Log.h"

namespace Registry {
	extern std::map<std::wstring, HKEY> vHiveNames;
	extern std::map<std::wstring, HKEY> vHives;
	
	HKEY RemoveHive(std::wstring& path){}

	class RegistryKey {
		HKEY hive;
		std::wstring path;
		std::wstring name;

		HKEY key = nullptr;
		BYTE* lpbValue = nullptr;
		DWORD dwDataSize{};
		DWORD dwDataType{};

		bool valid = false;

	public:
		RegistryKey(HKEY hive, std::wstring& path, std::wstring& name, bool Create = false);

		RegistryKey(std::wstring path, std::wstring name);

		~RegistryKey();

		bool Exists();

		std::wstring GetName();

		bool Set(LPVOID value, DWORD dwSize, DWORD dwType = REG_BINARY);

		template<class T>
		bool Set(T value) {
			LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

			Set(&value, sizeof(value)); 
		}

		LPVOID GetRaw();

		template<class T>
		T Get(){ *reinterpret_cast<T*>(Get()); }

		template<class T>
		bool CompareValue(T value){
			return Get() == value;
		}
	};
}