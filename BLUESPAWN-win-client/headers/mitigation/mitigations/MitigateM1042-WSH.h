#pragma once
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

namespace Mitigations{

	/**
	 * MitigateM1042-WSH looks for Windows Script Host, a typically
	 * unused and unneeded feature to be disabled. Sean Metcalf 
	 * recommends this is disabled at https://adsecurity.org/?p=3299
	 * M1042-WSH
	 */
	class MitigateM1042WSH : public Mitigation {
	public:
		MitigateM1042WSH();

		virtual bool MitigationIsEnforced(SecurityLevel level) override;
		virtual bool EnforceMitigation(SecurityLevel level) override;
		virtual bool MitigationApplies() override;
	};
}
