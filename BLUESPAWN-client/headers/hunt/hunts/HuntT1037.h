#pragma once
#include "../Hunt.h"

#include "reaction/Reaction.h"
#include "reaction/Log.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

namespace Hunts {

	/**
	 * HuntT1037 examines the registry and filesystem for logon scripts
	 */
	class HuntT1037 : public Hunt {
	private:
		std::vector<std::wstring> sus_exts = { L".bat", L".cmd", L".exe", L".dll", L".job", L".js", L".jse", 
					L".lnk", L".ps1", L".sct", L".vb", L".vbe", L".vbs", L".vbscript" };
	public:
		HuntT1037();

		virtual std::vector<std::shared_ptr<DETECTION>> RunHunt(const Scope& scope) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}