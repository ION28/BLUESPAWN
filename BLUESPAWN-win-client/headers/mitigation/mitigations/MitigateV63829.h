#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV63829 looks for UAC to be enabled.
	 * (V-63829).  M1052 (UAC).
	 */
	class MitigateV63829 : public Mitigation {
	public:
		MitigateV63829();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
