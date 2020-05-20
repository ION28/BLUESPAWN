#pragma once
#include "../Hunt.h"

#include "reaction/Reaction.h"
#include "reaction/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	/**
	 * HuntT1037 examines the registry and filesystem for logon scripts
	 * 
	 * @scans Cursory checks the value of the UserInitMprLogonScript key for scripts, scans with YARA
	 * @scans Normal Scans Registry + Filesystem with YARA and suspicious extensions
	 * @scans Intensive Scans Registry and FileSystem and alerts on everything
	 */
	class HuntT1037 : public Hunt {
	private:
		std::vector<std::wstring> sus_exts = { L".bat", L".cmd", L".dll", L".job", L".js", L".jse", 
					L".lnk", L".ps1", L".sct", L".vb", L".vbe", L".vbs", L".vbscript", L".hta" };

		int HuntT1037::EvaluateStartupFile(FileSystem::File file, Reaction& reaction, Aggressiveness level);
	public:
		HuntT1037();

		int AnalyzeRegistryStartupKey(Reaction reaction, Aggressiveness level);
		int AnalayzeStartupFolders(Reaction reaction, Aggressiveness level);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual int ScanNormal(const Scope& scope, Reaction reaction);
		virtual int ScanIntensive(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}