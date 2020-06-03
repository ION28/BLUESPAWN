#pragma once
#include <vector>

/**
 * Used to define the scope of a hunt. Currently, this operates by requiring the programmer to
 * define a new class for each new scope. This is less than ideal, as scopes should eventually 
 * be defined by the end user. Future implementation will allow the programmer to pass in lambdas
 * which will be handled by the functions built in to the class, removing the need for new scopes.
 */
class Scope {
public:
	virtual bool FileIsInScope(LPCSTR sFileName) const;
	virtual bool FileIsInScope(HANDLE hFile) const;
	virtual std::vector<HANDLE> GetScopedFileHandles() const;
	virtual std::vector<LPCSTR> GetScopedFileNames() const;

	virtual bool RegistryKeyIsInScope(LPCSTR sKeyPath) const;
	virtual bool RegistryKeyIsInScope(HKEY key) const;
	virtual std::vector<HKEY> GetScopedKHEYs() const;
	virtual std::vector<LPCSTR> GetScopedRegKeyNames() const;

	virtual bool ProcessIsInScope(DWORD pid) const;
	virtual bool ProcessIsInScope(HANDLE hProcess) const;
	virtual std::vector<HANDLE> GetScopedProcessHandles() const;
	virtual std::vector<DWORD> GetScopedProcessPIDs() const;

	virtual bool ServiceIsInScope(LPCSTR sServiceName) const;
	virtual bool ServiceIsInScope(SC_HANDLE hService) const;
	virtual std::vector<SC_HANDLE> GetScopedServiceHandles() const;
	virtual std::vector<LPCSTR> GetScopedServiceNames() const;
};

