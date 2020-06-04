

#include "util/configurations/CollectInfo.h"
#include "util/log/Log.h"
#include "util/permissions/permissions.h"
#include <sys/utsname.h>

void OutputComputerInformation() {
	LOG_INFO("Computer Information\n");
	LOG_INFO("DNS FQDN: " << GetFQDN());
	LOG_INFO("Computer DNS Name: " << GetComputerDNSName());
	LOG_INFO("Active Directory Domain: " << GetDomain());
	LOG_INFO("Operating System: " << GetOSVersion());
	LOG_INFO("Current User: " << GetCurrentUser());
}

std::string GetOSVersion() {
	struct utsname name;
	uname(&name); //only way this doesnt work is if its not valid
	return std::string(name.sysname) + " " + std::string(name.release) + " " + std::string(name.machine);
}

std::string GetComputerDNSName() {
	/*LPWSTR buffer = new WCHAR[256];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	bool status = GetComputerNameEx(ComputerNamePhysicalDnsHostname, buffer, &dwSize);

	return buffer;*/
	//TODO
	return std::string();
}

std::string GetDomain() {
	/*LPWSTR buffer = new WCHAR[256];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx(ComputerNamePhysicalDnsDomain, buffer, &dwSize);

	std::string name = *buffer ? buffer : "WORKGROUP";
	return name;*/
	return std::string();
}

std::string GetFQDN() {
	/*LPWSTR buffer = new WCHAR[256];
	unsigned int dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, buffer, &dwSize);

	return std::string("\\\\") + buffer;*/
	//TODO
	return std::string();
}

std::string GetCurrentUser() {
	return Permissions::GetProcessOwner().value().GetName();
}