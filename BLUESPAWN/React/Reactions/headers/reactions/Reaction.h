#pragma once
#include <Windows.h>

#include "configuration/Registry.h"

class Reaction {
protected: 
	DWORD dwSupportedReactions = 0;

public: 
	virtual void FileIdentified(HANDLE hFile) = 0;
	virtual void RegistryKeyIdentified(Registry::RegistryKey hkRegistryKey) = 0;
	virtual void ProcessIdentified(HANDLE hProcess) = 0;
	virtual void ServiceIdentified(SC_HANDLE schService) = 0;

	bool SupportsReactions(DWORD dwDesired);
};

namespace Reactions {
	enum SupportedReactions {
		IdentifyFile        = 1 << 0,
		IdentifyRegistryKey = 1 << 1,
		IdentifyProcess     = 1 << 2,
		IdentifyService     = 1 << 3
	};
}