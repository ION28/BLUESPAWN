#include "hunt/Scope.h"

bool Scope::FileIsInScope(LPCSTR sFileName) const {
	return true;
}
bool Scope::FileIsInScope(HANDLE hFile) const {
	return true;
}
std::vector<HANDLE> Scope::GetScopedFileHandles() const {
	return std::vector<HANDLE>();
}
std::vector<LPCSTR> Scope::GetScopedFileNames() const {
	return std::vector<LPCSTR>();
}

bool Scope::RegistryKeyIsInScope(LPCSTR pid) const {
	return true;
}
bool Scope::RegistryKeyIsInScope(HKEY key) const {
	return true;
}
std::vector<HKEY> Scope::GetScopedKHEYs() const {
	return std::vector<HKEY>();
}
std::vector<LPCSTR> Scope::GetScopedRegKeyNames() const {
	return std::vector<LPCSTR>();
}

bool Scope::ProcessIsInScope(DWORD sProcessName) const {
	return true;
}
bool Scope::ProcessIsInScope(HANDLE hProcess) const {
	return true;
}
std::vector<HANDLE> Scope::GetScopedProcessHandles() const {
	return std::vector<HANDLE>();
}
std::vector<DWORD> Scope::GetScopedProcessPIDs() const {
	return std::vector<DWORD>();
}

bool Scope::ServiceIsInScope(LPCSTR sServiceName) const {
	return true;
}
bool Scope::ServiceIsInScope(SC_HANDLE hService) const {
	return true;
}
std::vector<SC_HANDLE> Scope::GetScopedServiceHandles() const {
	return std::vector<SC_HANDLE>();
}
std::vector<LPCSTR> Scope::GetScopedServiceNames() const {
	return std::vector<LPCSTR>();
}