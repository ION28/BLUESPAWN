#pragma once
#include "../Mitigation.h"
#include <mitigation\MitigationRegister.h>
#include "util/reaction/Reaction.h"
#include "util/reaction/Log.h"

namespace Mitigations {

	/**
	 * MitigateV72753 looks for Wdigest authentication to be disabled. (V-72753).
	 */
	class MitigateV72753 : public Mitigation {
	public:
		MitigateV72753(MitigationRegister& record);

		virtual bool isEnforced(SecurityLevel level, Reaction reaction) override;
		virtual bool enforce(SecurityLevel level, Reaction reaction) override;
	};
}