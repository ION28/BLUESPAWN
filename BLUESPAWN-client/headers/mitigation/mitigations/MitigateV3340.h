#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Mitigations {

	/**
	 * MitigateV3340 looks for unauthorized shares that can be accessed anonymously
	 * (V-3340).
	 */
	class MitigateV3340 : public Mitigation {
	public:
		MitigateV3340();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
