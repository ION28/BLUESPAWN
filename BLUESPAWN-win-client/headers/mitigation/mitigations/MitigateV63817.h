#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV63817 looks for the setting to include the built-in
	 * administrator account in UAC Admin Approval mode to be enabled. 
	 * (V-63817). M1052 (UAC).
	 */
	class MitigateV63817 : public Mitigation {
	public:
		MitigateV63817();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
