#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV63753 looks for caching of domain creds to be disabled
	 * (V-63753).
	 */
	class MitigateV63753 : public Mitigation {
	public:
		MitigateV63753();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
