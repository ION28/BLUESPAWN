#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>

namespace Mitigations {

	/**
	 * MitigateV1093 looks for anonymous shares that are not restricted
	 * (V-1093, CCI-001090).
	 */
	class MitigateV1093 : public Mitigation {
	public:
		MitigateV1093();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}