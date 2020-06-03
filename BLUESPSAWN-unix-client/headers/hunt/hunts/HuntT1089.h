#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1089 examines the registry for firewall settings that allow
	 * applications to override the existing firewall rules.
	 * 
	 * @scans Cursory checks for potentially malicious firewall configurations
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1089 : public Hunt {
	public:
		HuntT1089();

		virtual int ScanCursory(const Scope& scope, Reaction reaction) override;
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}