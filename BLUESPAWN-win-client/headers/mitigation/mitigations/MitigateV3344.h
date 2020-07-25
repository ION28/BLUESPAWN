#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>

namespace Mitigations{

	/**
	 * MitigateV3344 prevents non-console logons from accounts with blank passwords.
	 */
	class MitigateV3344 : public Mitigation {
	public:
		MitigateV3344();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
