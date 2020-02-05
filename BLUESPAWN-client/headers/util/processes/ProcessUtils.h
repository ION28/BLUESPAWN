#pragma once

#include <Windows.h>

#include <vector>

struct Hook {
	LPVOID ModificationAddress;
	LPVOID RedirectionAddress;
};

bool HookIsOkay(const Hook& hook);

std::vector<LPVOID> GetExecutableNonImageSections(DWORD pid);
std::vector<LPVOID> GetUnregisteredImages(DWORD pid);
std::vector<LPVOID> GetModifiedImages(DWORD pid);
std::vector<LPVOID> GetHooks(DWORD pid);