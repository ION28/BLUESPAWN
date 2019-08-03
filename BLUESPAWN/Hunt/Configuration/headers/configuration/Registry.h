#pragma once

#include <windows.h>

#include <string>
#include <map>

#include "logging/Log.h"

namespace Registry {
	typedef std::wstring REG_SZ_T;
	typedef std::vector<std::wstring> REG_MULTI_SZ_T;
	typedef DWORD REG_DWORD_T;

	extern std::map<std::wstring, HKEY> vHiveNames;
	extern std::map<HKEY, std::wstring> vHives;
	
	HKEY RemoveHive(std::wstring& path);

	class RegistryKey : Loggable {
		HKEY hive;
		std::wstring path;
		std::wstring name;

		BYTE* lpbValue = nullptr;
		DWORD dwDataSize{};
		DWORD dwDataType{};

		bool valid = false;

	public:
		HKEY key = nullptr;

		RegistryKey(HKEY hive, std::wstring path, std::wstring name, bool Create = false);

		RegistryKey(std::wstring path, std::wstring name);

		~RegistryKey();

		bool Exists();

		std::wstring GetName();

		bool Set(LPVOID value, DWORD dwSize, DWORD dwType = REG_BINARY);

		template<class T>
		inline bool Set(T value) {
			LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

			Set(&value, sizeof(value)); 
		}

		LPVOID GetRaw();

		template<class T>
		inline T Get(){ return *reinterpret_cast<T*>(GetRaw()); }

		template<class T>
		inline bool operator==(T value){
			return Get<T>() == value;
		}

		virtual std::wstring ToString();
	};
}