#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1484 examines the local file system for presence of ntuser.man files which
	 * can be used to override GPO settings
	 * 
	 * @scans Cursory checks for ntuser.man in all user folders
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1484 : public Hunt {
	public:
		HuntT1484();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}