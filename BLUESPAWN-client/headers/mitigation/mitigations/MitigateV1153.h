#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>

namespace Mitigations{

	/**
	 * MitigateV1153 ensures NTLMv2 is used (V-1153).
	 */
	class MitigateV1153 : public Mitigation {
	public:
		MitigateV1153();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
