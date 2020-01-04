#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>
#include "util/reaction/Reaction.h"
#include "util/reaction/Log.h"

namespace Mitigations {

	/**
	 * MitigateV3338 looks for unauthorized named pipes that are accessible with anonymous
	 * credentials (V-3338, CCI-001090).
	 */
	class MitigateV3338 : public Mitigation {
	public:
		MitigateV3338(MitigationRegister& record);

		virtual bool isEnforced(SecurityLevel level, Reaction reaction) override;
		virtual bool enforce(SecurityLevel level, Reaction reaction) override;
	};
}