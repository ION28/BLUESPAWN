#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1068 examines the registry and file system for evidence of CVE-2020-1048.
	 * 
	 * @scans Cursory checks for registry ports that write to files (CVE-2020-1048).
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1068 : public Hunt {
	private:
		int HuntCVE20201048(Reaction reaction);
	public:
		HuntT1068();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}