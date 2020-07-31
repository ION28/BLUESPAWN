#include "mitigation/mitigations/MitigateM1044.h"
#include "util/filesystem/FileSystem.h"
#include "util/permissions/permissions.h"

#include "util/log/Log.h"

namespace Mitigations{

	MitigateM1044::MitigateM1044() :
		Mitigation(
			"M1044 - Restrict Library Loading",
			"Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by"
			"configuring appropriate library loading mechanisms and investigating potential vulnerable software.",
			"ld.so",
			SoftwareAffected::OperatingSystem,
			MitigationSeverity::High
		) {}

	bool MitigateM1044::MitigationIsEnforced(SecurityLevel level) {
		LOG_INFO("Checking for presence of " << name);
		FileSystem::File ldp("/etc/ld.so.preload");
		if(ldp.GetFileExists()){
			if(ldp.CanRead(Permissions::GetProcessOwner().value())){
				if(ldp.GetFileSize() > 0){
					LOG_VERBOSE(1, "/etc/ld.so.preload exists and is not empty!");
					return false;
				}
			}else{
				LOG_ERROR("LD_PRELOAD exists but BlueSpawn cant read the file.");
				return false;
			}
		}
		return true;
	}

	bool MitigateM1044::EnforceMitigation(SecurityLevel level) {
		LOG_INFO("Enforcing Mitigation for " << name);
		FileSystem::File ldp("/etc/ld.so.preload");
		if(ldp.GetFileExists()){
			LOG_VERBOSE(1, "Attempting to delete /etc/ld.so.preload");
			return ldp.Delete();
		}
		return false;
	}

	bool MitigateM1044::MitigationApplies(){
		return true;
	}
}