#include "hunts/Scope.h"

bool Scope::FileIsInScope(LPCSTR sFileName){
	return true;
}
bool Scope::FileIsInScope(HANDLE hFile){
	return true;
}
std::vector<HANDLE> Scope::GetScopedFileHandles(){
	return std::vector<HANDLE>();
}
std::vector<LPCSTR> Scope::GetScopedFileNames(){
	return std::vector<LPCSTR>();
}

bool Scope::RegistryKeyIsInScope(LPCSTR sKeyPath){
	return true;
}
bool Scope::RegistryKeyIsInScope(HKEY key){
	return true;
}
std::vector<HKEY> Scope::GetScopedKHEYs(){
	return std::vector<HKEY>();
}
std::vector<LPCSTR> Scope::GetScopedRegKeyNames(){
	return std::vector<LPCSTR>();
}

bool Scope::ProcessIsInScope(LPCSTR sProcessName){
	return true;
}
bool Scope::ProcessIsInScope(HANDLE hProcess){
	return true;
}
std::vector<HANDLE> Scope::GetScopedProcessHandles(){
	return std::vector<HANDLE>();
}
std::vector<LPCSTR> Scope::GetScopedProcessNames(){
	return std::vector<LPCSTR>();
}

bool Scope::ServiceIsInScope(LPCSTR sServiceName){
	return true;
}
bool Scope::ServiceIsInScope(SC_HANDLE hService){
	return true;
}
std::vector<SC_HANDLE> Scope::GetScopedServiceHandles(){
	return std::vector<SC_HANDLE>();
}
std::vector<LPCSTR> Scope::GetScopedServiceNames(){
	return std::vector<LPCSTR>();
}