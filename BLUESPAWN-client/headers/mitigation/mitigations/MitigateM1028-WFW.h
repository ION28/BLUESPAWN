#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateM1028-WFW looks for the Windows Firewall to be properly configured.
	 * M1028 (WFW). V-17418, V-17417, V-17407
	 */
	class MitigateM1028WFW : public Mitigation {
	public:
		MitigateM1028WFW();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
