#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV71769 looks for remote calls to SAM to be restricted to Administrators
	 * (V-71769).
	 */
	class MitigateV71769 : public Mitigation {
	public:
		MitigateV71769();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
