#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Mitigations {

	/**
	 * MitigateV3338 looks for unauthorized named pipes that are accessible with anonymous
	 * credentials (V-3338, CCI-001090).
	 */
	class MitigateV3338 : public Mitigation {
	public:
		MitigateV3338(MitigationRegister& record);

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}