#pragma once

#include <windows.h>

#include <string>
#include <map>
#include <vector>
#include <set>
#include <iostream>

#include "logging/Log.h"

namespace Registry {
	typedef std::wstring REG_SZ_T;
	typedef std::vector<std::wstring> REG_MULTI_SZ_T;
	typedef DWORD REG_DWORD_T;

	extern std::map<std::wstring, HKEY> vHiveNames;
	extern std::map<HKEY, std::wstring> vHives;
	extern std::map<HKEY, DWORD> _globalOpenKeys;
	
	HKEY RemoveHive(std::wstring& path);

	class RegistryKey : public Loggable {
		HKEY hive;
		std::wstring path;
		std::wstring name;

		BYTE* lpbValue = nullptr;
		DWORD dwDataSize{};
		DWORD dwDataType{};

		bool bKeyExists = false;
		bool bValueExists = false;

	public:
		HKEY key = nullptr;

		RegistryKey(HKEY hive, std::wstring path, std::wstring name = L"", bool Create = false);

		RegistryKey(std::wstring path, std::wstring name = L"");

		~RegistryKey();

		bool KeyExists();
		bool ValueExists();

		std::wstring GetName();

		bool Set(LPVOID value, DWORD dwSize, DWORD dwType = REG_BINARY);
		bool Create(LPVOID value, DWORD dwSize, DWORD dwType = REG_BINARY);

		template<class T>
		inline bool Set(T value) {
			LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

			Set(&value, sizeof(value));
		}

		template<>
		inline bool Set<REG_DWORD_T>(REG_DWORD_T value) {
			LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

			return Set(&value, sizeof(DWORD), REG_DWORD);
		}

		template<>
		inline bool Set<REG_SZ_T>(REG_SZ_T value) {
			LOG_VERBOSE(1, "Setting registry key " << GetName() << " to " << value);

			return Set(const_cast<wchar_t*>(value.c_str()), sizeof(WCHAR) * static_cast<DWORD>(value.length() + 1), REG_SZ);
		}

		template<>
		inline bool Set<REG_MULTI_SZ_T>(REG_MULTI_SZ_T value) {
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

		LPVOID GetRaw();

		template<class T>
		inline T Get(){ return reinterpret_cast<T>(GetRaw()); }

		template<>
		inline REG_DWORD_T Get<REG_DWORD_T>(){
			DWORD value = *reinterpret_cast<DWORD*>(GetRaw());
			LOG_VERBOSE(2, "Read value " << value << " from key " << GetName());

			return value;
		}

		template<>
		inline REG_SZ_T Get<REG_SZ_T>() {
			if(ValueExists()){
				LOG_VERBOSE(2, "Read value " << reinterpret_cast<LPCWSTR>(GetRaw()) << " from key " << GetName());
				return reinterpret_cast<LPCWSTR>(GetRaw());
			}

			LOG_VERBOSE(1, "Tried to read key " << GetName() << ", but the value did not exist!");
			return L"";
		}

		template<>
		inline REG_MULTI_SZ_T Get<REG_MULTI_SZ_T>(){
			if(ValueExists()){
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

			LOG_VERBOSE(1, "Tried to read key " << GetName() << ", but the value did not exist!");
			return {};
		}

		template<class T>
		inline bool operator==(T value){
			return Get<T>() == value;
		}

		template<>
		inline bool operator==<LPCWSTR>(LPCWSTR wcsKnownGood){
			return operator==<std::wstring>(std::wstring(wcsKnownGood));
		}

		template<>
		inline bool operator==<REG_MULTI_SZ_T>(REG_MULTI_SZ_T vKnownGood){
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

		std::vector<RegistryKey> KeyValues();
		std::vector<RegistryKey> Subkeys();

		std::wstring GetPath();

		virtual std::wstring ToString();
	};
}