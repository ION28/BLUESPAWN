#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateM1042-NBT looks for Netbios (NBT) to be disabled. This helps
	 * to prevent against T1171 and is M1042 (NBT).
	 */
	class MitigateM1042NBT : public Mitigation {
	public:
		MitigateM1042NBT();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
