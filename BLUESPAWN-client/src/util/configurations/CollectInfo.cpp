#include <windows.h>

#define SECURITY_WIN32
#include <Security.h>

#include "util/configurations/CollectInfo.h"
#include "util/configurations/Registry.h"
#include "util/log/Log.h"

void OutputComputerInformation() {
	LOG_INFO(1, L"Computer Information\n");
	LOG_INFO(1, L"DNS FQDN: " << GetFQDN());
	LOG_INFO(1, L"Computer DNS Name: " << GetComputerDNSName());
	LOG_INFO(1, L"Active Directory Domain: " << GetDomain());
	LOG_INFO(1, L"Operating System: " << GetOSVersion());
	LOG_INFO(1, L"Current User: " << GetCurrentUser());
}

std::wstring GetOSVersion() {
	return *Registry::RegistryKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\WIndows NT\\CurrentVersion").GetValue<std::wstring>(L"ProductName");
}

std::wstring GetComputerDNSName() {
	LPWSTR buffer = new WCHAR[256];
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	bool status = GetComputerNameEx(ComputerNamePhysicalDnsHostname, buffer, &dwSize);

	return buffer;
}

std::wstring GetDomain() {
	LPWSTR buffer = new WCHAR[256];
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx(ComputerNamePhysicalDnsDomain, buffer, &dwSize);

	std::wstring name = *buffer ? buffer : L"WORKGROUP";
	return name;
}

std::wstring GetFQDN() {
	LPWSTR buffer = new WCHAR[256];
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, buffer, &dwSize);

	return std::wstring(L"\\\\") + buffer;
}

std::wstring GetCurrentUser() {
	LPWSTR buffer = new WCHAR[512];
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/secext/ne-secext-extended_name_format
	GetUserNameEx(NameSamCompatible, buffer, &dwSize);

	return buffer;
}