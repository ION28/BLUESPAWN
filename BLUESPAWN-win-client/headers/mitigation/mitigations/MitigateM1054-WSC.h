#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateM1054-WSC looks for the Windows Security Center to provide appropriate
	 * warnings about issues M1054 (WSC).
	 */
	class MitigateM1054WSC : public Mitigation {
	public:
		MitigateM1054WSC();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
