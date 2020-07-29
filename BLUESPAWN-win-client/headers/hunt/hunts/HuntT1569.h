#pragma once
#include <Windows.h>

#include <vector>

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1569 examines the system for malicious services
	 * 
	 * @scans Cursory scans the services that are installed and their binaries
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
    class HuntT1569 : public Hunt {
        private:
        std::wstring t1569_002 = L"002: Service Execution";

        public:
        HuntT1569();

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::unique_ptr<Event>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
