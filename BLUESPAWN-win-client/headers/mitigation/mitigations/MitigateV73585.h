#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateV73585 looks for Windows Installer to be configured to always
	 * install elevated (V-73585).
	 */
	class MitigateV73585 : public Mitigation {
	public:
		MitigateV73585();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
