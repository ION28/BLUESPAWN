#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateM1025 looks for LSA to be run as a protected process light,
	 * which requires all loaded DLLs to be properly signed and prevents other processes
	 * from interfering with LSA.
	 */
	class MitigateM1025 : public Mitigation {
	public:
		MitigateM1025();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
