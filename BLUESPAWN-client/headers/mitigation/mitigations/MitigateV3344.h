#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Mitigations{

	/**
	 * MitigateV3338 looks for local accounts with blank passwords
	 */
	class MitigateV3344 : public Mitigation {
	public:
		MitigateV3344(MitigationRegister& record);

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}