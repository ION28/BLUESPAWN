#pragma once
#include <Windows.h>
#include <vector>

/**
 * Used to define the scope of a hunt. Currently, this operates by requiring the programmer to
 * define a new class for each new scope. This is less than ideal, as scopes should eventually 
 * be defined by the end user. Future implementation will allow the programmer to pass in lambdas
 * which will be handled by the functions built in to the class, removing the need for new scopes.
 */
class Scope {
public:
	virtual bool FileIsInScope(LPCSTR sFileName);
	virtual bool FileIsInScope(HANDLE hFile);
	virtual std::vector<HANDLE> GetScopedFileHandles();
	virtual std::vector<LPCSTR> GetScopedFileNames();

	virtual bool RegistryKeyIsInScope(LPCSTR sKeyPath);
	virtual bool RegistryKeyIsInScope(HKEY key);
	virtual std::vector<HKEY> GetScopedKHEYs();
	virtual std::vector<LPCSTR> GetScopedRegKeyNames();

	virtual bool ProcessIsInScope(LPCSTR sProcessName);
	virtual bool ProcessIsInScope(HANDLE hProcess);
	virtual std::vector<HANDLE> GetScopedProcessHandles();
	virtual std::vector<LPCSTR> GetScopedProcessNames();

	virtual bool ServiceIsInScope(LPCSTR sServiceName);
	virtual bool ServiceIsInScope(SC_HANDLE hService);
	virtual std::vector<SC_HANDLE> GetScopedServiceHandles();
	virtual std::vector<LPCSTR> GetScopedServiceNames();
};

