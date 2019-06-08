#include "Registry.h"

void ExamineRegistryKeySet(key keys[], int key_cnt) {
	for (int i = 0; i < key_cnt; i++) {
		key& k = keys[i];
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
