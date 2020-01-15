#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>

namespace Mitigations {

	/**
	 * MitigateV1152 looks for anonymous access to the registry to be restricted
	 */
	class MitigateV1152 : public Mitigation {
	public:
		MitigateV1152(MitigationRegister& record);

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}