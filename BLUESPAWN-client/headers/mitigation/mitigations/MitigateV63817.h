#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Mitigations{

	/**
	 * MitigateV63817 looks for the setting to include the built-in
	 * administrator account in UAC Admin Approval mode to be enabled. 
	 * (V-63817). M1052 (UAC).
	 */
	class MitigateV63817 : public Mitigation {
	public:
		MitigateV63817(MitigationRegister& record);

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
