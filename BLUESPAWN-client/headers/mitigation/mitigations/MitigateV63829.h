#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Mitigations{

	/**
	 * MitigateV63829 looks for UAC to be enabled.
	 * (V-63829).  M1052 (UAC).
	 */
	class MitigateV63829 : public Mitigation {
	public:
		MitigateV63829(MitigationRegister& record);

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
