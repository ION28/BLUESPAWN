#include "Registry.h"

const int number_of_persist_keys = 2;
key persist_keys[number_of_persist_keys] =
{
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", s2ws("explorer.exe"), REG_SZ},
	{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup", s2ws("%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
};

const int number_of_other_keys = 1;
key other_keys[number_of_other_keys] =
{
	{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"UserAuthentication", s2ws("1"), REG_DWORD},
};

void ExamineRegistryPersistence() {
	PrintInfoHeader("Analyzing Reigstry - Persistence");
	for (int i = 0; i < number_of_persist_keys; i++) {
		key& k = persist_keys[i];
		wstring current_key_val;
		if (!CheckKeyIsDefaultValue(k, current_key_val)) {
			PrintBadStatus("Key is non-default: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
			PrintBadStatus("Value was: " + ws2s(current_key_val));
			PrintBadStatus("Value should be: " + ws2s(k.value));
		}
		else {
			PrintGoodStatus("Key is okay: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
		}
	}
}

void ExamineRegistryOtherBad() {
	PrintInfoHeader("Analyzing Reigstry - Other Security Settings");
	for (int i = 0; i < number_of_other_keys; i++) {
		key& k = other_keys[i];
		wstring current_key_val;
		if (!CheckKeyIsDefaultValue(k, current_key_val)) {
			PrintBadStatus("Key is non-default: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
			PrintBadStatus("Value was: " + ws2s(current_key_val));
			PrintBadStatus("Value should be: " + ws2s(k.value));
		}
		else {
			PrintGoodStatus("Key is okay: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
		}
	}
}

bool CheckKeyIsDefaultValue(key& k, wstring& key_value) {
	HKEY hKey;
	LONG lRes = RegOpenKeyEx(k.hive, k.path, 0, KEY_READ, &hKey);
	bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

	if (bExistsAndSuccess) {
		//required for DWORD/BINARY
		ostringstream stream;
		DWORD x = 0;
		DWORD& n_val = x;

		switch (k.type) {
		case REG_SZ:
			GetStringRegKey(hKey, k.key, key_value);
			break;
		case REG_DWORD:
			GetDWORDRegKey(hKey, k.key, n_val);
			stream << n_val;
			key_value = s2ws(stream.str());
			break;
		case REG_BINARY:
			break;
		};
		
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


LONG GetDWORDRegKey(HKEY hKey, const std::wstring& strValueName, DWORD& nValue)
{
	DWORD dwBufferSize(sizeof(DWORD));
	DWORD nResult(0);
	LONG nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, reinterpret_cast<LPBYTE>(&nResult), &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		nValue = nResult;
	}
	return nError;
}


LONG GetBoolRegKey(HKEY hKey, const std::wstring& strValueName, bool& bValue, bool bDefaultValue)
{
	DWORD nResult(0);
	LONG nError = GetDWORDRegKey(hKey, strValueName.c_str(), nResult);
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