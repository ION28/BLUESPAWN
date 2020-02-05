#include <Windows.h>
#include <Psapi.h>

#include "hunt/hunts/HuntT1055.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"

#include "pe_sieve_types.h"

extern "C" {
	void __stdcall PESieve_help(void);
	DWORD __stdcall PESieve_version(void);
	pesieve::t_report __stdcall PESieve_scan(pesieve::t_params args);
};


namespace Hunts{

	HuntT1055::HuntT1055(HuntRegister& record) : Hunt(record, L"T1055 - Process Injection") {
		// TODO: update these categories
		dwSupportedScans = (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	bool ScanProcess(DWORD pid, Reaction& reaction){
		pesieve::t_params params = {
			pid,
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
			0
		};

		auto summary = PESieve_scan(params);
		if(summary.errors){
			LOG_WARNING("Unable to scan process " << pid << " due to an error in PE-Sieve.dll");
		}
		
		if(summary.skipped){
			LOG_WARNING("Skipped scanning " << summary.skipped << " modules in process " << pid << ". This is likely due to use of .NET");
		}

		if(summary.suspicious && !summary.errors){
			DWORD identifiers = 0;
			if(summary.replaced) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Replaced);
			if(summary.hdr_mod) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::HeaderModified);
			if(summary.detached) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Detached);
			if(summary.hooked) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Hooked);
			if(summary.implanted) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Implanted);
			if(summary.implanted + summary.hooked + summary.detached + summary.hdr_mod + summary.replaced != summary.suspicious)
				identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Other);

			HandleWrapper handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			std::wstring name = {};
			std::wstring path = {};
			if(handle){
				DWORD buffSize = 1024;
				wchar_t buffer[1024];
				if(QueryFullProcessImageNameW(handle, 0, buffer, &buffSize))
					name = buffer;

				buffSize = 1024;
				if(GetProcessImageFileNameW(handle, buffer, buffSize))
					path = buffer;
			}



			reaction.ProcessIdentified(std::make_shared<PROCESS_DETECTION>(name, path, std::wstring{}, pid, 0, identifiers));
			return true;
		}

		return false;
	}

	int HuntT1055::ScanNormal(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1055 - Process Injection at level Normal");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		DWORD processes[4096];
		DWORD ProcessCount = 0;
		ZeroMemory(processes, sizeof(processes));
		auto success = EnumProcesses(processes, sizeof(processes), &ProcessCount);
		if(success){
			ProcessCount /= sizeof(DWORD);
			for(int i = 0; i < ProcessCount; i++){
				if(scope.ProcessIsInScope(processes[i])){
					if(ScanProcess(processes[i], reaction)){
						identified++;
					}
				}
			}
		} else {
			LOG_ERROR("Unable to enumerate processes - Process related hunts will not run.");
		}

		reaction.EndHunt();
		return identified;
	}

}