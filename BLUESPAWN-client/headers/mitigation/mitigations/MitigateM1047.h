#pragma once

#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations {

	/**
	 * MitigateM1047 checks the registry to ensure that key but optional 
	 * event log channels are enabled. These sources are used by many Hunts
	 * and monitoring services in BLUESPAWN.
	 */
	class MitigateM1047 : public Mitigation {
	public:
		MitigateM1047();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	private:
		std::vector<std::wstring> channelList;
	};
}
