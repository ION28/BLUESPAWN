#pragma once

#include <Windows.h>

#include <vector>
#include <string>

#include "common/wrappers.hpp"
#include "common/dynamiclinker.h"

#include "util/pe/Image_Loader.h"

struct Hook {
	LPVOID ModificationAddress;
	LPVOID RedirectionAddress;
};

bool HookIsOkay(const Hook& hook);

std::vector<LPVOID> GetExecutableNonImageSections(DWORD pid);
std::vector<LPVOID> GetUnregisteredImages(DWORD pid);
std::vector<LPVOID> GetModifiedImages(DWORD pid);
std::vector<LPVOID> GetHooks(DWORD pid);

std::wstring GetProcessImage(DWORD dwPID);
std::wstring GetProcessImage(const HandleWrapper& hProcess);
std::wstring GetProcessCommandline(DWORD dwPID);
std::wstring GetProcessCommandline(const HandleWrapper& hProcess);
std::vector<std::wstring> EnumModules(DWORD dwPID);
std::vector<std::wstring> EnumModules(const HandleWrapper& hProcess);
LPVOID GetModuleAddress(DWORD dwPID, const std::wstring& wsModuleName);
LPVOID GetModuleAddress(const HandleWrapper&, const std::wstring& wsModuleName);