#pragma once
#include "Reaction.h"

namespace Reactions {
	class LogReaction : public Reaction {
	public:
		LogReaction();

		virtual void FileIdentified(HANDLE hFile);
		virtual void RegistryKeyIdentified(Registry::RegistryKey hkRegistryKey);
		virtual void ProcessIdentified(HANDLE hProcess);
		virtual void ServiceIdentified(SC_HANDLE schService);
	};
}

