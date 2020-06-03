

#define SECURITY_WIN32
#include <Security.h>

#include "util/configurations/CollectInfo.h"
#include "util/configurations/Registry.h"
#include "util/log/Log.h"

void OutputComputerInformation() {
	LOG_INFO("Computer Information\n");
	LOG_INFO("DNS FQDN: " << GetFQDN());
	LOG_INFO("Computer DNS Name: " << GetComputerDNSName());
	LOG_INFO("Active Directory Domain: " << GetDomain());
	LOG_INFO("Operating System: " << GetOSVersion());
	LOG_INFO("Current User: " << GetCurrentUser());
}

std::string GetOSVersion() {
	return *Registry::RegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\WIndows NT\\CurrentVersion").GetValue<std::string>("ProductName");
}

std::string GetComputerDNSName() {
	LPWSTR buffer = new WCHAR[256];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	bool status = GetComputerNameEx(ComputerNamePhysicalDnsHostname, buffer, &dwSize);

	return buffer;
}

std::string GetDomain() {
	LPWSTR buffer = new WCHAR[256];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx(ComputerNamePhysicalDnsDomain, buffer, &dwSize);

	std::string name = *buffer ? buffer : "WORKGROUP";
	return name;
}

std::string GetFQDN() {
	LPWSTR buffer = new WCHAR[256];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, buffer, &dwSize);

	return std::string("\\\\") + buffer;
}

std::string GetCurrentUser() {
	LPWSTR buffer = new WCHAR[512];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/secext/ne-secext-extended_name_format
	GetUserNameEx(NameSamCompatible, buffer, &dwSize);

	return buffer;
}