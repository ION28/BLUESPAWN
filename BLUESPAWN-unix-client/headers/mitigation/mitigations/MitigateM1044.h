#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Mitigations{

	/**
	 * MitigateM1044 prevents misconfigurations with ld.so
	 */
	class MitigateM1044: public Mitigation {
	public:
		MitigateM1044();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}