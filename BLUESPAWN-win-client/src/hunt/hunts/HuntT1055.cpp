#include "hunt/hunts/HuntT1055.h"

#include <Psapi.h>
#pragma pack(push, 8)
#include <TlHelp32.h>
#pragma pack(pop)
#include <Windows.h>

#include "util/StringUtils.h"
#include "util/ThreadPool.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"
#include "util/wrappers.hpp"

#include "pe_sieve.h"
#include "pe_sieve_types.h"
#include "user/bluespawn.h"
#include "utils/debug.h"

extern "C" {
void __stdcall PESieve_help(void);
DWORD __stdcall PESieve_version(void);
pesieve::t_report __stdcall PESieve_scan(pesieve::t_params args);
};

bool debug_output = false;

namespace Hunts {

    HuntT1055::HuntT1055() : Hunt(L"T1055 - Process Injection") {
        debug_output = false;
        dwCategoriesAffected = (DWORD) Category::Processes;
        dwSourcesInvolved = (DWORD) DataSource::Processes;
        dwTacticsUsed = (DWORD) Tactic::PrivilegeEscalation | (DWORD) Tactic::DefenseEvasion;
    }

    void HuntT1055::HandleReport(OUT std::vector<std::shared_ptr<Detection>>& detections,
                                 IN CONST Promise<GenericWrapper<pesieve::ReportEx*>>& promise) {
        auto __name{ L"T1055 - Process Injection" };
        auto value{ promise.GetValue() };
        if(value) {
            auto report{ *value };
            auto summary{ report->scan_report->generateSummary() };
            if(summary.skipped) {
                LOG_INFO(2, "Skipped scanning " << summary.skipped << " modules in process "
                                                << report->scan_report->getPid()
                                                << ". This is likely due to use of .NET");
            }

            if(summary.suspicious && !summary.errors) {
                std::wstring path = StringToWidestring(report->scan_report->mainImagePath);

                for(auto module : report->scan_report->moduleReports) {
                    if(module->status == pesieve::SCAN_SUSPICIOUS) {
                        CREATE_DETECTION_WITH_CONTEXT(Certainty::Strong,
                                                      ProcessDetectionData::CreateMemoryDetectionData(
                                                          report->scan_report->getPid(), path, module->module,
                                                          static_cast<DWORD>(module->moduleSize),
                                                          StringToWidestring(module->moduleFile), path),
                                                      DetectionContext{ __name });
                    }
                }
            }
        }
    }

    Promise<GenericWrapper<pesieve::ReportEx*>> HuntT1055::QueueProcessScan(DWORD pid){
        return ThreadPool::GetInstance().RequestPromise<GenericWrapper<pesieve::ReportEx*>>([pid](){
            pesieve::t_params params{
                pid,
                3,
                Bluespawn::aggressiveness == Aggressiveness::Intensive ? pesieve::PE_DNET_NONE :
                                                                         pesieve::PE_DNET_SKIP_HOOKS,
                pesieve::PE_IMPREC_NONE,
                true,
                pesieve::OUT_NO_DIR,
                Bluespawn::aggressiveness != Aggressiveness::Intensive,
                Bluespawn::aggressiveness == Aggressiveness::Intensive,
                Bluespawn::aggressiveness == Aggressiveness::Intensive ? pesieve::PE_IATS_FILTERED :
                                                                         pesieve::PE_IATS_NONE,
                Bluespawn::aggressiveness == Aggressiveness::Intensive ? pesieve::PE_DATA_SCAN_NO_DEP :
                                                                         pesieve::PE_DATA_NO_SCAN,
                false,
                pesieve::PE_DUMP_AUTO,
                false,
                0
            };

            WRAP(pesieve::ReportEx*, report, scan_and_dump(params), delete data);
            if(!report){
                LOG_INFO(2, "Unable to scan process " << pid << " due to an error in PE-Sieve.dll");
                throw std::exception{ "Failed to scan process" };
            }

            return report;
        });
    }

    std::vector<std::shared_ptr<Detection>> HuntT1055::RunHunt(const Scope& scope) {
        HUNT_INIT();

        SUBSECTION_INIT(0, Normal);
        HandleWrapper snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if(snapshot) {
            PROCESSENTRY32W info{};
            info.dwSize = sizeof(info);
            if(Process32FirstW(snapshot, &info)) {
                std::vector<Promise<GenericWrapper<pesieve::ReportEx*>>> results{};
                do {
                    auto pid{ info.th32ProcessID };
                    if(info.szExeFile == std::wstring{ L"vmmem" }) {
                        LOG_INFO(2, L"Skipping scans for process with PID " << pid << ".");
                        continue;
                    }

                    results.emplace_back(QueueProcessScan(pid));
                } while(Process32NextW(snapshot, &info));

                for(auto& promise : results) {
                    HandleReport(detections, promise);
                }
            } else {
                auto error{ GetLastError() };
                LOG_ERROR("Unable to enumerate processes - Process related hunts will not run." << GetLastError());
            }
        } else {
            LOG_ERROR("Unable to enumerate processes - Process related hunts will not run.");
        }
        SUBSECTION_END();

        HUNT_END();
    }

}   // namespace Hunts
