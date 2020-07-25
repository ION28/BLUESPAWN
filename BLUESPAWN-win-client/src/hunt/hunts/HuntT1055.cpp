#include "hunt/hunts/HuntT1055.h"

#include <Psapi.h>
#include <Windows.h>

#include "common/StringUtils.h"
#include "common/ThreadPool.h"
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

    void HuntT1055::HandleReport(OUT std::vector<std::shared_ptr<Detection>>& detections,
                                 IN CONST Promise<GenericWrapper<pesieve::ReportEx*>>& promise) {
        auto value{ promise.GetValue() };
        if(value) {
            auto report{ *value };
            auto summary{ report->scan_report->generateSummary() };
            if(summary.skipped) {
                LOG_WARNING("Skipped scanning " << summary.skipped << " modules in process "
                                                << report->scan_report->getPid()
                                                << ". This is likely due to use of .NET");
            }

            if(summary.suspicious && !summary.errors) {
                std::wstring path = StringToWidestring(report->scan_report->mainImagePath);

                for(auto module : report->scan_report->module_reports) {
                    if(module->status & SCAN_SUSPICIOUS) {
                        CREATE_DETECTION(Certainty::Strong, ProcessDetectionData::CreateMemoryDetectionData(
                                                                report->scan_report->getPid(), path, module->module,
                                                                static_cast<DWORD>(module->moduleSize),
                                                                StringToWidestring(module->moduleFile), path));
                    }
                }
            }
        }
    }

    std::vector<std::shared_ptr<Detection>> HuntT1055::RunHunt(const Scope& scope) {
        HUNT_INIT_LEVEL(Normal);

        DWORD processes[1024];
        DWORD ProcessCount = 0;
        ZeroMemory(processes, sizeof(processes));
        auto success{ EnumProcesses(processes, sizeof(processes), &ProcessCount) };
        if(success) {
            std::vector<Promise<GenericWrapper<pesieve::ReportEx*>>> results{};

            ProcessCount /= sizeof(DWORD);
            for(int i = 0; i < ProcessCount; i++) {
                if(scope.ProcessIsInScope(processes[i])) {
                    auto pid{ processes[i] };
                    results.emplace_back(
                        ThreadPool::GetInstance().RequestPromise<GenericWrapper<pesieve::ReportEx*>>([pid]() {
                            pesieve::t_params params{ pid,
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
                                LOG_WARNING("Unable to scan process " << pid << " due to an error in PE-Sieve.dll");
                                throw std::exception{ "Failed to scan process" };
                            }

                            return report;
                        }));
                }
            }

            for(auto& promise : results){
                HandleReport(detections, promise);
            }
        } else {
            LOG_ERROR("Unable to enumerate processes - Process related hunts will not run.");
        }

        HUNT_END();
    }

}   // namespace Hunts
