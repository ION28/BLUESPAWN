#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations {
	/**
	* Mitigation M1035 Limits access to RDP over network by ensuring that NLA is enabled.
	*/
	class MitigateM1035RDP : public Mitigation {
	public:
		MitigateM1035RDP();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}