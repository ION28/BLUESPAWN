#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV3479 looks for DLL Safe Search Mode to be enabled
	 * (V-3479). M1044 (DLL).
	 */
	class MitigateV3479 : public Mitigation {
	public:
		MitigateV3479();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
