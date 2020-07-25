#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV73511 looks for Process command line logging to be enabled.
	 * (V-73511).
	 */
	class MitigateV73511 : public Mitigation {
	public:
		MitigateV73511();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
