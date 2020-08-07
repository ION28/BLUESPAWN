#pragma once

#include "../Hunt.h"

namespace Hunts {

    /**
	 * HuntT1036 examines the local file system for executables in user writable
	 * locations in %WINDIR%
	 * 
	 * @scans Cursory checks all such writable folders for executable files
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
    class HuntT1036 : public Hunt {
        private:
        // Credit: https://twitter.com/mattifestation/status/1172520995472756737/photo/1
        std::vector<std::wstring> writableFolders = { L"%WINDIR%\\System32\\Microsoft\\crypto\\rsa\\machinekeys",
                                                      L"%WINDIR%\\System32\\tasks_"
                                                      L"migrated\\microsoft\\windows\\pla\\system",
                                                      L"%WINDIR%\\Syswow64\\tasks\\microsoft\\windows\\pla\\system",
                                                      L"%WINDIR%\\debug\\WIA",
                                                      L"%WINDIR%\\System32\\Tasks",
                                                      L"%WINDIR%\\Syswow64\\Tasks",
                                                      L"%WINDIR%\\Tasks",
                                                      L"%WINDIR%\\Registration\\crmlog",
                                                      L"%WINDIR%\\System32\\com\\dmp",
                                                      L"%WINDIR%\\System32\\fxstmp",
                                                      L"%WINDIR%\\System32\\spool\\drivers\\color",
                                                      L"%WINDIR%\\System32\\spool\\printers",
                                                      L"%WINDIR%\\System32\\spool\\servers",
                                                      L"%WINDIR%\\Syswow64\\com\\dmp",
                                                      L"%WINDIR%\\Syswow64\\fxstmp",
                                                      L"%WINDIR%\\Temp",
                                                      L"%WINDIR%\\tracing" };

        public:
        HuntT1036();

        void Subtechnique005(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}   // namespace Hunts
