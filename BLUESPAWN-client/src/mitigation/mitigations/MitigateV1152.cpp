#include "mitigation/mitigations/MitigateV1152.h"

#include "util/configurations/Registry.h"
#include "util/log/Log.h"
#include <sddl.h>

using namespace Registry;

namespace Mitigations {

	MitigateV1152::MitigateV1152(MitigationRegister& record) :
		Mitigation(
			record,
			L"V-1152 - Anonymous access to the registry must be restricted.",
			L"This is a High finding because of the potential for gaining unauthorized system access. The registry "
				" is integral to the function, security, and stability of the Windows system. Some processes may require "
				"anonymous access to the registry. This must be limited to properly protect the system.",
			L"registry",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::High
		) {}

	bool MitigateV1152::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);
		
		auto key = RegistryKey{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers", L"winreg"};
		//auto key = RegistryKey{ HKEY_CURRENT_USER, L"Software\\9bis.com", L"KiTTY"};

		if(key.KeyExists()){

			Information::SecurityInformation sec_info = key.GetSecurityInformation();
			std::wcout << sec_info.ToString() << std::endl;
			std::wcout << sec_info.GetOwnerSid() << std::endl;
			std::wcout << sec_info.GetOwnerUsername() << std::endl;

			return true;
		}
		else {
			return false;
		}
		
		return true;
	}

	bool MitigateV1152::EnforceMitigation(SecurityLevel level) {
		return true;
	}

	bool MitigateV1152::MitigationApplies(){
		return true;
	}
}