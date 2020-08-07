#include "hunt/hunts/HuntT1068.h"

#include <regex>

#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"

#include "user/bluespawn.h"

using namespace Registry;

#define PRINTERS 0
#define PORTS 1

namespace Hunts {

    HuntT1068::HuntT1068() : Hunt(L"T1068 - Exploitation for Privilege Escalation") {
        dwCategoriesAffected = (DWORD) Category::Configurations | (DWORD) Category::Files;
        dwSourcesInvolved = (DWORD) DataSource::Registry | (DWORD) DataSource::FileSystem;
        dwTacticsUsed = (DWORD) Tactic::PrivilegeEscalation;
    }

    std::vector<std::shared_ptr<Detection>> HuntT1068::RunHunt(const Scope& scope) {
        HUNT_INIT();

        SUBSECTION_INIT(PRINTERS, Cursory)
        RegistryKey printers{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers",
                              true };
        for(auto printer : printers.EnumerateSubkeys()) {
            if(printer.ValueExists(L"Port")) {
                auto value{ RegistryValue::Create(printer, L"Port") };
                FileSystem::File filepath{ value->ToString() };

                // Regex ensures the file is an actual drive and not, say, a COM port
                if(std::regex_match(filepath.GetFilePath(), std::wregex(L"([a-zA-z]{1}:\\\\)(.*)")) &&
                   filepath.GetFileExists() && filepath.HasReadAccess()) {
                    CREATE_DETECTION(Certainty::Strong,
                                     RegistryDetectionData{ *value, RegistryDetectionType::FileReference });
                }
            }
        }
        SUBSECTION_END();

        SUBSECTION_INIT(PORTS, Cursory);
        RegistryKey ports{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports", true };
        for(auto value : ports.EnumerateValues()) {
            FileSystem::File filepath{ value };

            // Regex ensures the file is an actual drive and not, say, a COM port
            if(std::regex_match(filepath.GetFilePath(), std::wregex(L"([a-zA-z]{1}:\\\\)(.*)")) &&
               filepath.GetFileExists() && filepath.HasReadAccess()) {
                CREATE_DETECTION(Certainty::Strong, RegistryDetectionData{ *RegistryValue::Create(ports, value),
                                                                           RegistryDetectionType::Unknown });
                CREATE_DETECTION(Certainty::Strong, FileDetectionData{ filepath });
            }
        }
        SUBSECTION_END();

        HUNT_END();
    }

    std::vector<std::pair<std::unique_ptr<Event>, Scope>> HuntT1068::GetMonitoringEvents() {
        std::vector<std::pair<std::unique_ptr<Event>, Scope>> events;

        // CVE-2020-1048
        Registry::GetRegistryEvents(events, SCOPE(PRINTERS), HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers", true, false, 
                                    true);
        Registry::GetRegistryEvents(events, SCOPE(PORTS), HKEY_LOCAL_MACHINE, 
                                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports", true, false, false);

        return events;
    }
}   // namespace Hunts
