#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Mitigations{

	/**
	 * MitigateV3379 ensures that the LAN Manager does not store LM hashes in the 
	 * SAM registry hive.
	 */
	class MitigateV3379 : public Mitigation {
	public:
		MitigateV3379();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}