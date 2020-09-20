#include "util/configurations/CollectInfo.h"

#include <Windows.h>

#include "util/log/Log.h"

std::wstring GetComputerDNSHostname() {
    DWORD dwSize;

    if(GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, NULL, &dwSize) == ERROR_MORE_DATA) {
        LPWSTR lpBuffer = new WCHAR[dwSize];
        if(GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, lpBuffer, &dwSize) == ERROR_SUCCESS) {
            return lpBuffer;
        }
    }
    LOG_VERBOSE(2, L"Unable to obtain computer hostname");
    return L"";
}
