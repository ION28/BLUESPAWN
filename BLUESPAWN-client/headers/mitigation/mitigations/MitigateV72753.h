#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations {

	/**
	 * MitigateV72753 looks for Wdigest authentication to be disabled. (V-72753).
	 */
	class MitigateV72753 : public Mitigation {
	public:
		MitigateV72753();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}