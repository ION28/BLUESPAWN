#pragma once
#include "../Hunt.h"

#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	/**
	 * HuntT1037 examines the registry for logon scripts
	 * 
	 * @scans Cursory checks the value of the UserInitMprLogonScript key for scripts
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1037 : public Hunt {
	private:
		std::vector<std::wstring> sus_exts = { L".bat", L".cmd", L".exe", L".dll", L".job", L".js", L".jse", 
					L".lnk", L".ps1", L".sct", L".vb", L".vbe", L".vbs", L".vbscript" };

		int HuntT1037::EvaluateStartupFile(FileSystem::File file, Reaction& reaction, Aggressiveness level);
	public:
		HuntT1037();

		int AnalyzeRegistryStartupKey(Reaction reaction, Aggressiveness level);
		int AnalayzeStartupFolders(Reaction reaction, Aggressiveness level);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual int ScanNormal(const Scope& scope, Reaction reaction);
		virtual int ScanIntensive(const Scope& scope, Reaction reaction);
	};
}