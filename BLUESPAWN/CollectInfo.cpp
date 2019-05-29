#include "CollectInfo.h"

void OutputComputerInformation() {
	PrintInfoHeader("Computer Information");
	PrintInfoStatus("DNS FQDN: " + GetFQDN());
	PrintInfoStatus("Computer DNS Name: " + GetComputerDNSName());
	PrintInfoStatus("Active Directory Domain: " + GetDomain());
	PrintInfoStatus("Operating System: " + GetOsVersion());
	PrintInfoStatus("Current User: " + GetCurrentUser());
}

string GetOsVersion() {
	//future proofed get OS version: https://stackoverflow.com/questions/25986331/how-to-determine-windows-version-in-future-proof-way
	static const wchar_t kernel32[] = L"\\kernel32.dll";
	wchar_t* path = NULL;
	void* ver = NULL, * block;
	UINT n;
	UINT uLen;
	BOOL r;
	DWORD versz;
	VS_FIXEDFILEINFO* vinfo;

	path = (wchar_t*)malloc(sizeof(*path) * MAX_PATH);

	n = GetSystemDirectory(path, MAX_PATH);
	if (n >= MAX_PATH || n == 0 ||
		n > MAX_PATH - sizeof(kernel32) / sizeof(*kernel32))
		abort();
	memcpy(path + n, kernel32, sizeof(kernel32));

	versz = GetFileVersionInfoSize(path, NULL);
	if (versz == 0)
		abort();
	ver = malloc(versz);
	if (!ver)
		abort();
	r = GetFileVersionInfo(path, 0, versz, ver);
	if (!r)
		abort();
	r = VerQueryValue(ver, L"\\", &block, &uLen);
	if (!r || uLen < sizeof(VS_FIXEDFILEINFO))
		abort();
	vinfo = (VS_FIXEDFILEINFO*)block;

	int major_version = (int)HIWORD(vinfo->dwProductVersionMS);
	int minor_version = (int)LOWORD(vinfo->dwProductVersionMS);
	int service_pkg = (int)HIWORD(vinfo->dwProductVersionLS);
	bool is_server = IsWindowsServer();
	free(path);
	free(ver);

	//Version chart: https://docs.microsoft.com/en-us/windows/desktop/sysinfo/operating-system-version
	if (major_version == 10) {
		if (minor_version == 0) {
			if (is_server) {
				return "Windows Server 2016/2019";
			}
			else {
				return "Windows 10";
			}
		}
	}
	else if (major_version == 6) {
		if (minor_version == 3) {
			if (is_server) {
				return "Windows Server 2012 R2";
			}
			else {
				return "Windows 8.1";
			}
		}
		else if (minor_version == 2) {
			if (is_server) {
				return "Windows Server 2012";
			}
			else {
				return "Windows 8";
			}
		}
		else if (minor_version == 1) {
			if (is_server) {
				return "Windows Server 2008 R2";
			}
			else {
				return "Windows 7";
			}
		}
		else if (minor_version == 0) {
			if (is_server) {
				return "Windows Server 2008";
			}
			else {
				return "Windows Vista";
			}
		}
	}
	else if (major_version == 5) {
		if (minor_version == 2) {
			if (is_server) {
				return "Windows Server 2003/R2";
			}
			else {
				return "Windows XP (64-bit)";
			}
		}
		else if (minor_version == 1) {
			return "Windows XP";
		}
		else if (minor_version == 0) {
			return "Windows 2000";
		}
	}
	else {
		return "Failed to get OS Version.";
	}
}

string GetComputerDNSName() {
	TCHAR buffer[256] = TEXT("");
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx((COMPUTER_NAME_FORMAT)ComputerNamePhysicalDnsHostname, buffer, &dwSize);
	wstring result(buffer);
	string dns_name(result.begin(), result.end());
	dwSize = _countof(buffer);
	ZeroMemory(buffer, dwSize);

	return dns_name;
}

string GetDomain() {
	TCHAR buffer[256] = TEXT("");
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx((COMPUTER_NAME_FORMAT)ComputerNamePhysicalDnsDomain, buffer, &dwSize);
	wstring result(buffer);
	string domain_name(result.begin(), result.end());
	dwSize = _countof(buffer);
	ZeroMemory(buffer, dwSize);

	if (domain_name == "") {
		domain_name = "WORKGROUP";
	}

	return domain_name;
}

string GetFQDN() {
	TCHAR buffer[256] = TEXT("");
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ne-sysinfoapi-_computer_name_format
	GetComputerNameEx((COMPUTER_NAME_FORMAT)ComputerNamePhysicalDnsFullyQualified, buffer, &dwSize);
	wstring result(buffer);
	string fqdn(result.begin(), result.end());
	dwSize = _countof(buffer);
	ZeroMemory(buffer, dwSize);


	return "\\\\" + fqdn;
}

string GetCurrentUser() {
	TCHAR buffer[512] = TEXT("");
	DWORD dwSize = sizeof(buffer);

	//enum info: https://docs.microsoft.com/en-us/windows/desktop/api/secext/ne-secext-extended_name_format
	GetUserNameEx((EXTENDED_NAME_FORMAT)NameSamCompatible, buffer, &dwSize);
	wstring result(buffer);
	string sam_name(result.begin(), result.end());
	dwSize = _countof(buffer);
	ZeroMemory(buffer, dwSize);

	return sam_name;
}

