#pragma once
#include "Reaction.h"
#include "logging/NetworkSink.h"

namespace Reactions {
	class ServerReaction : public Reaction {
	public:
		ServerReaction();

		virtual void FileIdentified(HANDLE hFile);
		virtual void RegistryKeyIdentified(Registry::RegistryKey hkRegistryKey);
		virtual void ProcessIdentified(HANDLE hProcess);
		virtual void ServiceIdentified(SC_HANDLE schService);

	};
}