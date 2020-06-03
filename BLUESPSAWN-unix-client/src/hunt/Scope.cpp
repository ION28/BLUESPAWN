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

bool Scope::ProcessIsInScope(unsigned int sProcessName) const {
	return true;
}
bool Scope::ProcessIsInScope(HANDLE hProcess) const {
	return true;
}
std::vector<HANDLE> Scope::GetScopedProcessHandles() const {
	return std::vector<HANDLE>();
}
std::vector<unsigned int> Scope::GetScopedProcessPIDs() const {
	return std::vector<unsigned int>();
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