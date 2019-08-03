#include <windows.h>

#define SECURITY_WIN32
#include <Security.h>

#include "configuration/CollectInfo.h"
#include "configuration/Registry.h"

#include <logging/Log.h>

void OutputComputerInformation() {
	LOG_INFO("Computer Information\n");
	LOG_INFO("DNS FQDN: " << GetFQDN());
	LOG_INFO("Computer DNS Name: " << GetComputerDNSName());
	LOG_INFO("Active Directory Domain: " << GetDomain());
	LOG_INFO("Operating System: " << GetOSVersion());
	LOG_INFO("Current User: " << GetCurrentUser());
}

std::wstring GetOSVersion() {
	auto key = Registry::RegistryKey(L"HKLM\\SOFTWARE\\Microsoft\\WIndows NT\\CurrentVersion", L"ProductName");
	return key.Get<std::wstring>();
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