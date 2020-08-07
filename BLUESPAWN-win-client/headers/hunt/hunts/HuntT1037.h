#pragma once
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1037 examines the registry and filesystem for logon scripts
	 */
    class HuntT1037 : public Hunt {

        public:
        HuntT1037();

        void Subtechnique001(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
