#pragma once
#include "Reaction.h"

namespace Reactions {
	class Log : public Reaction {
	public:
		Log();

		virtual void FileIdentified(HANDLE hFile);
		virtual void RegistryKeyIdentified(HKEY hkRegistryKey);
		virtual void ProcessIdentified(HANDLE hProcess);
		virtual void ServiceIdentified(SC_HANDLE schService);
	};
}

