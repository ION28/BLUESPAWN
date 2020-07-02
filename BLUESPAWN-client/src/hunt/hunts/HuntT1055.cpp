#include "hunt/hunts/HuntT1055.h"

#include <Psapi.h>
#include <Windows.h>

#include "common/StringUtils.h"
#include "common/wrappers.hpp"

#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "pe_sieve.h"
#include "pe_sieve_types.h"
#include "user/bluespawn.h"

extern "C" {
void __stdcall PESieve_help(void);
DWORD __stdcall PESieve_version(void);
pesieve::t_report __stdcall PESieve_scan(pesieve::t_params args);
};

namespace Hunts {

    HuntT1055::HuntT1055() : Hunt(L"T1055 - Process Injection") {
        dwCategoriesAffected = (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::Processes;
        dwTacticsUsed = (DWORD) Tactic::PrivilegeEscalation | (DWORD) Tactic::DefenseEvasion;
    }

    bool ScanProcess(DWORD pid, std::vector<std::shared_ptr<Detection>>& detections) { return false; }

    std::vector<std::shared_ptr<Detection>> HuntT1055::RunHunt(const Scope& scope) {
        HUNT_INIT();

        if(Bluespawn::aggressiveness == Aggressiveness::Cursory){
            HUNT_END();
        }

        DWORD processes[1024];
        DWORD ProcessCount = 0;
        ZeroMemory(processes, sizeof(processes));
        auto success{ EnumProcesses(processes, sizeof(processes), &ProcessCount) };
        if(success) {
            ProcessCount /= sizeof(DWORD);
            for(int i = 0; i < ProcessCount; i++) {
                if(scope.ProcessIsInScope(processes[i])) {
                    pesieve::t_params params{ processes[i],
                                              3,
                                              pesieve::PE_IMPREC_NONE,
                                              true,
                                              pesieve::OUT_NO_DIR,
                                              true,
                                              false,
                                              false,
                                              false,
                                              pesieve::PE_DUMP_AUTO,
                                              false,
                                              0 };

                    WRAP(pesieve::ReportEx*, report, scan_and_dump(params), delete data);

                    if(!report) {
                        LOG_WARNING("Unable to scan process " << processes[i] << " due to an error in PE-Sieve.dll");
                        continue;
                    }

                    auto summary{ report->scan_report->generateSummary() };
                    if(summary.skipped) {
                        LOG_WARNING("Skipped scanning " << summary.skipped << " modules in process " << processes[i]
                                                        << ". This is likely due to use of .NET");
                    }

                    if(summary.suspicious && !summary.errors) {
                        std::wstring path = StringToWidestring(report->scan_report->mainImagePath);

                        for(auto module : report->scan_report->module_reports) {
                            if(module->status & SCAN_SUSPICIOUS) {
                                CREATE_DETECTION(Certainty::Strong, ProcessDetectionData::CreateMemoryDetectionData(
                                                                        processes[i], path, module->module,
                                                                        static_cast<DWORD>(module->moduleSize),
                                                                        StringToWidestring(module->moduleFile), path));
                            }
                        }
                    }
                }
            }
        } else {
            LOG_ERROR("Unable to enumerate processes - Process related hunts will not run.");
        }

        HUNT_END();
    }

}   // namespace Hunts
