#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV63825 looks for the setting to prompt application
	 * installations for elevation. (V-63825). M1052 (UAC).
	 */
	class MitigateV63825 : public Mitigation {
	public:
		MitigateV63825();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
