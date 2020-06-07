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
	virtual bool FileIsInScope(std::string sFileName) const;
	virtual bool FileIsInScope(int hFile) const;
	virtual std::vector<int> GetScopedFileHandles() const;
	virtual std::vector<std::string> GetScopedFileNames() const;

	virtual bool ProcessIsInScope(std::string sProcessName) const;
	virtual bool ProcessIsInScope(pid_t hProcess) const;
	virtual std::vector<pid_t> GetScopedProcessPIDs() const;

	virtual bool ServiceIsInScope(std::string sServiceName) const;
	virtual std::vector<std::string> GetScopedServiceNames() const;
};

