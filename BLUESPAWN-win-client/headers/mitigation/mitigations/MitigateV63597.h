#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV63597 looks for the setting to filter privileged tokens
	 * over the network. (V-63597). This helps protect against T1075 
	 * (PTH) and is M1052 (UAC).
	 */
	class MitigateV63597 : public Mitigation {
	public:
		MitigateV63597();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
