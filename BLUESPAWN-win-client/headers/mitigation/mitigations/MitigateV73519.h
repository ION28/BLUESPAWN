#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV73519 looks for SMBv1 to be disabled. (V-73519).
	 */
	class MitigateV73519 : public Mitigation {
	public:
		MitigateV73519();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
