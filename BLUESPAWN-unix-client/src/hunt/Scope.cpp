#include "hunt/Scope.h"
#include <string>

bool Scope::FileIsInScope(std::string sFileName) const {
	return true;
}
bool Scope::FileIsInScope(int hFile) const {
	return true;
}
std::vector<int> Scope::GetScopedFileHandles() const {
	return std::vector<int>();
}
std::vector<std::string> Scope::GetScopedFileNames() const {
	return std::vector<std::string>();
}

bool Scope::ProcessIsInScope(std::string sProcessName) const {
	return true;
}
bool Scope::ProcessIsInScope(pid_t hProcess) const {
	return true;
}

std::vector<pid_t> Scope::GetScopedProcessPIDs() const {
	return std::vector<pid_t>();
}

bool Scope::ServiceIsInScope(std::string sServiceName) const {
	return true;
}

std::vector<std::string> Scope::GetScopedServiceNames() const {
	return std::vector<std::string>();
}