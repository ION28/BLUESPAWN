#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations {
	/**
	* Mitigation M1054-RDP Prevents Remote Users from force logging off Console Users.
	*/
	class MitigateM1054RDP : public Mitigation {
	public:
		MitigateM1054RDP();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}