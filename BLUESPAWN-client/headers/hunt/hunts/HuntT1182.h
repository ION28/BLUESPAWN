#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"

namespace Hunts {

	/**
	 * HuntT1182 examines AppCert DLLs related registry keys that can be used for
	 * persistence and privilege escalation.
	 * 
	 * @scans Cursory checks the values of the associated AppCert DLLs keys that
	 * can be abused.
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1182 : public Hunt {
	public:
		HuntT1182();

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
		virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents() override;
	};
}