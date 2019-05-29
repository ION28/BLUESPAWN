#include "Registry.h"

//base registry info: https://stackoverflow.com/a/35717/3302799

const int number_of_keys = 2;
key keys[number_of_keys] =
{
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", s2ws("explorer.exe")},
	{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup", s2ws("%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")},
};

void ExamineRegistry() {
	PrintInfoHeader("Analyzing Reigstry");
	for (int i = 0; i < number_of_keys; i++) {
		if (!CheckKeyIsDefaultValue(keys[i])) {
			PrintBadStatus("Found non-default key: " + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
		}
		else {
			PrintGoodStatus("Key is okay: " + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
		}
	}
}

bool CheckKeyIsDefaultValue(key&  k) {
	HKEY hKey;
	LONG lRes = RegOpenKeyEx(k.hive, k.path, 0, KEY_READ, &hKey);
	bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

	if (bExistsAndSuccess) {
		wstring key_value;
		GetStringRegKey(hKey, k.key, key_value);
		RegCloseKey(hKey);
		if (key_value.compare(k.value) == 0) {
			return true;
		}
		else {
			return false;
		}
	}
	else {
		return false;
	} 
}


LONG GetDWORDRegKey(HKEY hKey, const std::wstring& strValueName, DWORD& nValue, DWORD nDefaultValue)
{
	nValue = nDefaultValue;
	DWORD dwBufferSize(sizeof(DWORD));
	DWORD nResult(0);
	LONG nError = ::RegQueryValueExW(hKey,
		strValueName.c_str(),
		0,
		NULL,
		reinterpret_cast<LPBYTE>(&nResult),
		&dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		nValue = nResult;
	}
	return nError;
}


LONG GetBoolRegKey(HKEY hKey, const std::wstring& strValueName, bool& bValue, bool bDefaultValue)
{
	DWORD nDefValue((bDefaultValue) ? 1 : 0);
	DWORD nResult(nDefValue);
	LONG nError = GetDWORDRegKey(hKey, strValueName.c_str(), nResult, nDefValue);
	if (ERROR_SUCCESS == nError)
	{
		bValue = (nResult != 0) ? true : false;
	}
	return nError;
}


LONG GetStringRegKey(HKEY hKey, const wstring& strValueName, wstring& strValue)
{
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		strValue = szBuffer;
	}
	return nError;
}