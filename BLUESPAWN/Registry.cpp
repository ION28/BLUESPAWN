#include "Registry.h"

/*	FORMAT: {HIVE, PATH, KEY, EXPECTED/DEFAULT VALUE, TYPE} 
	USE ay "*" to check and report any subkey for a given path
*/

const int number_of_persist_keys = 24;
key persist_keys[number_of_persist_keys] =
{
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", s2ws("explorer.exe"), REG_SZ},

	//T1037
	{HKEY_CURRENT_USER,L"Environment",L"UserInitMprLogonScript", s2ws(""), REG_SZ},

	//T1103
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", s2ws(""), REG_SZ}, 
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", s2ws("0"), REG_DWORD},
	{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", s2ws(""), REG_SZ}, 
	{HKEY_LOCAL_MACHINE,L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", s2ws("0"), REG_DWORD},

	//T1060
	{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
	{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
	{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"*", s2ws("*"), REG_SZ},
	{HKEY_CURRENT_USER,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", L"*", s2ws("*"), REG_SZ},
	{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"*", s2ws("*"), REG_SZ},
	{HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Startup", s2ws("%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", L"Common Startup", s2ws("%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"Common Startup", s2ws("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), REG_SZ},

	//T1182
	//https://b3n7s.github.io/2018/10/27/AppCert-Dlls.html
	{HKEY_LOCAL_MACHINE,L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", L"*", s2ws("*"), REG_SZ},

	//T1138
	{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"InstalledSDB", s2ws(""), REG_SZ},
	{HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags", L"Custom", s2ws(""), REG_SZ},

};

const int number_of_other_keys = 2;
key other_keys[number_of_other_keys] =
{
	{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"UserAuthentication", s2ws("1"), REG_DWORD},
	{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", s2ws("1"), REG_DWORD},
};

void ExamineRegistryPersistence() {
	PrintInfoHeader("Analyzing Reigstry - Persistence");
	for (int i = 0; i < number_of_persist_keys; i++) {
		key& k = persist_keys[i];
		wstring current_key_val;
		bool b = CheckKeyIsDefaultValue(k, current_key_val);
		PrintRegistryKeyResult(b, k, current_key_val);
	}
}

void ExamineRegistryOtherBad() {
	PrintInfoHeader("Analyzing Reigstry - Other Security Settings");
	for (int i = 0; i < number_of_other_keys; i++) {
		key& k = other_keys[i];
		wstring current_key_val;
		bool b = CheckKeyIsDefaultValue(k, current_key_val);
		PrintRegistryKeyResult(b, k, current_key_val);
	}
}

void PrintRegistryKeyResult(bool b, key& k, wstring current_key_val) {
	if (!b) {
		if (ws2s(k.key).compare("*") != 0) {
			PrintBadStatus("Key is non-default: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
			PrintInfoStatus("Value was: " + ws2s(current_key_val));
			PrintInfoStatus("Value should be: " + ws2s(k.value));
		}
	}
	else {
		PrintGoodStatus("Key is okay: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
	}
}

bool CheckKeyIsDefaultValue(key& k, wstring& key_value) {
	HKEY hKey;
	LONG lRes = RegOpenKeyEx(k.hive, k.path, 0, KEY_READ, &hKey);
	bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

	if (bExistsAndSuccess) {
		if (ws2s(k.key).compare("*") == 0) {
			QueryKey(hKey, key_value, k);
			RegCloseKey(hKey);
		}
		else {
			wstring key_name = k.key;
			GetRegistryKeyWrapper(hKey, k.type, key_value, key_name);
			RegCloseKey(hKey);
			if (key_value.compare(k.value) == 0) {
				return true;
			}
			else {
				return false;
			}
		}
	}
	else {
		return true;
	} 
}

void GetRegistryKeyWrapper(HKEY hKey, ULONG type, wstring& key_value, wstring key_name) {
	vector<wstring> s;
	GetRegistryKey(hKey, type, key_value, key_name, s);
}

void GetRegistryKey(HKEY hKey, ULONG type, wstring& key_value, wstring key_name, vector<wstring>& target) {
	//required for DWORD/BINARY
	//reg types: https://docs.microsoft.com/en-us/windows/desktop/SysInfo/registry-value-types
	ostringstream stream;
	DWORD x = 0;
	DWORD& n_val = x;

	switch (type) {
	case REG_SZ:
		GetStringRegKey(hKey, key_name, key_value);
		break;
	case REG_EXPAND_SZ:
		GetStringRegKey(hKey, key_name, key_value);
		break;
	case REG_MULTI_SZ:
		GetMultiStringRegKey(hKey, key_name, key_value, target);
		break;
	case REG_DWORD:
		GetDWORDRegKey(hKey, key_name, n_val);
		stream << n_val;
		key_value = s2ws(stream.str());
		break;
	case REG_BINARY:
		break;
	};
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

LONG GetMultiStringRegKey(HKEY hKey, const wstring& strValueName, wstring& strValue, vector<wstring>& target)
{
	DWORD dwBufferSize;
	ULONG nError, nError2;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), NULL, 0, NULL, &dwBufferSize);
	if (ERROR_SUCCESS == nError) {
		vector<wchar_t> temp(dwBufferSize / sizeof(wchar_t));
		nError2 = RegQueryValueExW(hKey, strValueName.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&temp[0]), &dwBufferSize);
		if (ERROR_SUCCESS == nError2) {
			size_t index = 0;
			size_t len = wcslen(&temp[0]);
			while (len > 0)
			{
				target.push_back(&temp[index]);
				index += len + 1;
				len = wcslen(&temp[index]);
			}
		}
		else {
			return nError2;
		}
	}
	return nError;
}

//enumerate all subkeys: https://docs.microsoft.com/en-us/windows/desktop/sysinfo/enumerating-registry-subkeys
void QueryKey(HKEY hKey, wstring& key_value, key& k) {
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the key values. 

	if (cValues) {
		PrintBadStatus("Key is non-default and contains following entries: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++) {
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			DWORD type = REG_DWORD;
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				&type,
				NULL,
				NULL);

			if (retCode == ERROR_SUCCESS) {
				wstring key_name(achValue);
				GetRegistryKeyWrapper(hKey, (ULONG)type, key_value, key_name);
				PrintInfoStatus("SubKey name: " + ws2s(key_name));
				PrintInfoStatus("Subkey value: " + ws2s(key_value));
			}
		}
	}
	else {
		PrintGoodStatus("Key is okay: " + hive2s(k.hive) + (string)"\\" + ws2s(k.path) + (string)"\\" + ws2s(k.key));
	}
}

void HuntT1101SecuritySupportProvider() {
	PrintInfoHeader("Hunting for T1101 - Security Support Provider");

	key keys[2] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", s2ws("*"), REG_MULTI_SZ},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages", s2ws("*"), REG_MULTI_SZ},
	};

	vector<wstring> okSecPackages = { L"\"\"", L"wsauth", L"kerberos", L"msv1_0", L"schannel", L"wdigest", L"tspkg", L"pku2u" };

	for (int i = 0; i < 2; i++) {
		HKEY hKey;
		LONG lRes = RegOpenKeyEx(keys[i].hive, keys[i].path, 0, KEY_READ, &hKey);
		bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

		if (bExistsAndSuccess) {
			wstring key_name = keys[i].key;
			wstring result;
			vector<wstring> target;
			GetRegistryKey(hKey, keys[i].type, result, key_name, target);
			RegCloseKey(hKey);

			bool foundBad = false;
			for (auto& val : target) {
				if (find(okSecPackages.begin(), okSecPackages.end(), val) == okSecPackages.end()) {
					PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
					PrintInfoStatus("Found potentially bad package: " + ws2s(val));
					foundBad = true;
				}
			}
			if (!foundBad) {
				PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
			}
		}
		else {
			PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
		}
	}
}

void HuntT1131AuthenticationPackage() {
	PrintInfoHeader("Hunting for T1131 - Authentication Package");

	key keys[2] = {
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", s2ws("*"), REG_MULTI_SZ},
		{HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", s2ws("*"), REG_MULTI_SZ},
	};

	vector<wstring> okAuthPackages = { L"msv1_0", L"SshdPinAuthLsa" };
	vector<wstring> okNotifPackages = { L"scecli" };

	for (int i = 0; i < 2; i++) {
		HKEY hKey;
		LONG lRes = RegOpenKeyEx(keys[i].hive, keys[i].path, 0, KEY_READ, &hKey);
		bool bExistsAndSuccess(lRes == ERROR_SUCCESS);

		if (bExistsAndSuccess) {
			wstring key_name = keys[i].key;
			wstring result;
			vector<wstring> target;
			GetRegistryKey(hKey, keys[i].type, result, key_name, target);
			RegCloseKey(hKey);

			bool foundBad = false;
			for (auto& val : target) {
				if (i == 0) {
					if (find(okAuthPackages.begin(), okAuthPackages.end(), val) == okAuthPackages.end()) {
						PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
						PrintInfoStatus("Found potentially bad package: " + ws2s(val));
						foundBad = true;
					}
				}
				else if (i == 1) {
					if (find(okNotifPackages.begin(), okNotifPackages.end(), val) == okNotifPackages.end()) {
						PrintBadStatus("Key is non-default: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
						PrintInfoStatus("Found potentially bad package: " + ws2s(val));
						foundBad = true;
					}
				}
			}
			if (!foundBad) {
				PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
			}
		}
		else {
			PrintGoodStatus("Key is okay: " + hive2s(keys[i].hive) + (string)"\\" + ws2s(keys[i].path) + (string)"\\" + ws2s(keys[i].key));
		}
	}
}