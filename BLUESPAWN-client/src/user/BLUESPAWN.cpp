#include "user/bluespawn.h"
#include "user/CLI.h"
#include "util/log/HuntLogMessage.h"
#include "util/log/DebugSink.h"
#include "util/log/XMLSink.h"
#include "common/DynamicLinker.h"
#include "common/StringUtils.h"
#include "util/eventlogs/EventLogs.h"
#include "reaction/SuspendProcess.h"
#include "reaction/RemoveValue.h"
#include "reaction/CarveMemory.h"
#include "reaction/DeleteFile.h"
#include "reaction/QuarantineFile.h"
#include "util/permissions/permissions.h"

#include "hunt/hunts/HuntT1004.h"
#include "hunt/hunts/HuntT1013.h"
#include "hunt/hunts/HuntT1015.h"
#include "hunt/hunts/HuntT1031.h"
#include "hunt/hunts/HuntT1035.h"
#include "hunt/hunts/HuntT1036.h"
#include "hunt/hunts/HuntT1037.h"
#include "hunt/hunts/HuntT1050.h"
#include "hunt/hunts/HuntT1053.h"
#include "hunt/hunts/HuntT1055.h"
#include "hunt/hunts/HuntT1060.h"
#include "hunt/hunts/HuntT1068.h"
#include "hunt/hunts/HuntT1089.h"
#include "hunt/hunts/HuntT1099.h"
#include "hunt/hunts/HuntT1100.h"
#include "hunt/hunts/HuntT1101.h"
#include "hunt/hunts/HuntT1103.h"
#include "hunt/hunts/HuntT1122.h"
#include "hunt/hunts/HuntT1128.h"
#include "hunt/hunts/HuntT1131.h"
#include "hunt/hunts/HuntT1136.h"
#include "hunt/hunts/HuntT1138.h"
#include "hunt/hunts/HuntT1182.h"
#include "hunt/hunts/HuntT1183.h"
#include "hunt/hunts/HuntT1198.h"
#include "hunt/hunts/HuntT1484.h"

#include "monitor/ETW_Wrapper.h"

#include "mitigation/mitigations/MitigateM1025.h"
#include "mitigation/mitigations/MitigateM1028-WFW.h"
#include "mitigation/mitigations/MitigateM1035-RDP.h"
#include "mitigation/mitigations/MitigateM1042-LLMNR.h"
#include "mitigation/mitigations/MitigateM1042-NBT.h"
#include "mitigation/mitigations/MitigateM1042-WSH.h"
#include "mitigation/mitigations/MitigateM1047.h"
#include "mitigation/mitigations/MitigateM1054-RDP.h"
#include "mitigation/mitigations/MitigateM1054-WSC.h"
#include "mitigation/mitigations/MitigateV1093.h"
#include "mitigation/mitigations/MitigateV1153.h"
#include "mitigation/mitigations/MitigateV3338.h"
#include "mitigation/mitigations/MitigateV3340.h"
#include "mitigation/mitigations/MitigateV3344.h"
#include "mitigation/mitigations/MitigateV3379.h"
#include "mitigation/mitigations/MitigateV3479.h"
#include "mitigation/mitigations/MitigateV63597.h"
#include "mitigation/mitigations/MitigateV63687.h"
#include "mitigation/mitigations/MitigateV63753.h"
#include "mitigation/mitigations/MitigateV63817.h"
#include "mitigation/mitigations/MitigateV63825.h"
#include "mitigation/mitigations/MitigateV63829.h"
#include "mitigation/mitigations/MitigateV71769.h"
#include "mitigation/mitigations/MitigateV72753.h"
#include "mitigation/mitigations/MitigateV73511.h"
#include "mitigation/mitigations/MitigateV73519.h"
#include "mitigation/mitigations/MitigateV73585.h"

#pragma warning(push)

#pragma warning(disable : 26451)
#pragma warning(disable : 26444)

#include "cxxopts.hpp"

#pragma warning(pop)

#include <iostream>
#include <VersionHelpers.h>

DEFINE_FUNCTION(BOOL, IsWow64Process2, NTAPI, HANDLE hProcess, USHORT* pProcessMachine, USHORT* pNativeMachine);
LINK_FUNCTION(IsWow64Process2, KERNEL32.DLL);

const IOBase& Bluespawn::io = CLI::GetInstance();
HuntRegister Bluespawn::huntRecord{ io };
MitigationRegister Bluespawn::mitigationRecord{ io };

Bluespawn::Bluespawn(){

	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1004>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1013>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1015>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1031>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1035>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1036>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1037>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1050>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1053>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1055>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1060>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1068>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1089>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1099>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1100>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1101>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1103>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1122>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1128>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1131>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1136>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1138>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1182>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1183>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1198>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1484>());

	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1025>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1028WFW>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1035RDP>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042LLMNR>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042NBT>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042WSH>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1047>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1054RDP>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1054WSC>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV1093>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV1153>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3338>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3340>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3344>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3379>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3479>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63597>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63687>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63753>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63817>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63825>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63829>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV71769>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV72753>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV73511>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV73519>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV73585>());
}

void Bluespawn::dispatch_hunt(Aggressiveness aHuntLevel, vector<string> vExcludedHunts, vector<string> vIncludedHunts) {
	Bluespawn::io.InformUser(L"Starting a Hunt");
	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};

	huntRecord.RunHunts(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction, vExcludedHunts, vIncludedHunts);
}

void Bluespawn::dispatch_mitigations_analysis(MitigationMode mode, bool bForceEnforce) {
	if (mode == MitigationMode::Enforce) {
		Bluespawn::io.InformUser(L"Enforcing Mitigations");
		mitigationRecord.EnforceMitigations(SecurityLevel::High, bForceEnforce);
	}
	else {
		Bluespawn::io.InformUser(L"Auditing Mitigations");
		mitigationRecord.AuditMitigations(SecurityLevel::High);
	}
}

void Bluespawn::monitor_system(Aggressiveness aHuntLevel) {
	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};

	Bluespawn::io.InformUser(L"Monitoring the system");
	huntRecord.SetupMonitoring(aHuntLevel, reaction);

	HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
	while (true) {
		SetEvent(hRecordEvent);
		Sleep(5000);
	}
}

void Bluespawn::SetReaction(const Reaction& reaction){
	this->reaction = reaction;
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string help_category = result["help"].as < std::string >();

	std::transform(help_category.begin(), help_category.end(),
		help_category.begin(), [](unsigned char c) { return std::tolower(c); });

	if(help_category.compare("hunt") == 0) {
		std::cout << (options.help({ "hunt" })) << std::endl;
	} else if(help_category.compare("general") == 0) {
		std::cout << (options.help()) << std::endl;
	} else {
		std::cerr << ("Unknown help category") << std::endl;
	}
}

void Bluespawn::check_correct_arch() {
	BOOL bIsWow64 = FALSE;
	if (IsWindows10OrGreater()) {
		USHORT ProcessMachine;
		USHORT NativeMachine;

		Linker::IsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine);
		if (ProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
			bIsWow64 = TRUE;
		}
	}
	else {
		IsWow64Process(GetCurrentProcess(), &bIsWow64);
	}
	if (bIsWow64) {
		Bluespawn::io.AlertUser(L"Running the x86 version of BLUESPAWN on an x64 system! This configuration is not fully supported, so we recommend downloading the x64 version.", 5000, ImportanceLevel::MEDIUM);
		LOG_WARNING("Running the x86 version of BLUESPAWN on an x64 system! This configuration is not fully supported, so we recommend downloading the x64 version.");
	}
}

int main(int argc, char* argv[]){

	Bluespawn bluespawn{};

	print_banner();

	bluespawn.check_correct_arch();

	cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

	options.add_options()
		("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
		("n,monitor", "Monitor the System for Malicious Activity. Available options are Cursory, Normal, or Intensive.", cxxopts::value<std::string>()->implicit_value("Normal"))
		("m,mitigate", "Mitigates vulnerabilities by applying security settings. Available options are audit and enforce.", cxxopts::value<std::string>()->implicit_value("audit"))
		("help", "Help Information. You can also specify a category for help on a specific module such as hunt.", cxxopts::value<std::string>()->implicit_value("general"))
		("log", "Specify how Bluespawn should log events. Options are console (default), xml, and debug.", cxxopts::value<std::string>()->default_value("console"))
		("reaction", "Specifies how bluespawn should react to potential threats dicovered during hunts.", cxxopts::value<std::string>()->default_value("log"))
		("v,verbose", "Verbosity", cxxopts::value<int>()->default_value("0"))
		("debug", "Enable Debug Output", cxxopts::value<bool>())
		;

	options.add_options("hunt")
		("l,level", "Aggressiveness of Hunt. Either Cursory, Normal, or Intensive", cxxopts::value<std::string>())
		("hunts", "List of hunts to run by Mitre ATT&CK name. Will only run these hunts.", cxxopts::value<std::vector<std::string>>())
		("exclude-hunts", "List of hunts to avoid running by Mitre ATT&CK name. Will run all hunts but these.", cxxopts::value<std::vector<std::string>>())
		;

	options.add_options("mitigate")
		("force", "Use this option to forcibly apply mitigations with no prompt", cxxopts::value<bool>())
		;

	options.parse_positional({ "level" });
	try {
		auto result = options.parse(argc, argv);

		if (result.count("verbose")) {
			if(result["verbose"].as<int>() >= 1) {
				Log::LogLevel::LogVerbose1.Enable();
			}
			if(result["verbose"].as<int>() >= 2) {
				Log::LogLevel::LogVerbose2.Enable();
			}
			if(result["verbose"].as<int>() >= 3) {
				Log::LogLevel::LogVerbose3.Enable();
			}
		}

		auto sinks = result["log"].as<std::string>();
		std::set<std::string> sink_set;
		for(unsigned startIdx = 0; startIdx < sinks.size();){
			auto endIdx = min(sinks.find(',', startIdx), sinks.size());
			auto sink = sinks.substr(startIdx, endIdx - startIdx);
			sink_set.emplace(sink);
			startIdx = endIdx + 1;
		}
		for(auto sink : sink_set){
			if(sink == "console"){
				auto Console = std::make_shared<Log::CLISink>();
				Log::AddHuntSink(Console);
				if(result.count("debug")) Log::AddSink(Console);
			} else if(sink == "xml"){
				auto XMLSink = std::make_shared<Log::XMLSink>();
				Log::AddHuntSink(XMLSink);
				if(result.count("debug")) Log::AddSink(XMLSink);
			} else if(sink == "debug"){
				auto DbgSink = std::make_shared<Log::DebugSink>();
				Log::AddHuntSink(DbgSink);
				if(result.count("debug")) Log::AddSink(DbgSink);
			} else {
				bluespawn.io.AlertUser(L"Unknown log sink \"" + StringToWidestring(sink) + L"\"", INFINITY, ImportanceLevel::MEDIUM);
			}
		}

		if (result.count("help")) {
			print_help(result, options);
		}

		else if (result.count("hunt") || result.count("monitor")) {
			std::map<std::string, Reaction> reactions = {
				{"log", Reactions::LogReaction{}},
				{"remove-value", Reactions::RemoveValueReaction{ bluespawn.io }},
				{"suspend", Reactions::SuspendProcessReaction{ bluespawn.io }},
				{"carve-memory", Reactions::CarveProcessReaction{ bluespawn.io }},
				{"delete-file", Reactions::DeleteFileReaction{ bluespawn.io }},
				{"quarantine-file", Reactions::QuarantineFileReaction{ bluespawn.io}},
			};

			auto UserReactions = result["reaction"].as<std::string>();
			std::set<std::string> reaction_set;
			for(unsigned startIdx = 0; startIdx < UserReactions.size();){
				auto endIdx = min(UserReactions.find(',', startIdx), UserReactions.size());
				auto sink = UserReactions.substr(startIdx, endIdx - startIdx);
				reaction_set.emplace(sink);
				startIdx = endIdx + 1;
			}

			Reaction combined = {};
			for(auto reaction : reaction_set){
				if(reactions.find(reaction) != reactions.end()){
					combined.Combine(reactions[reaction]);
				} else {
					bluespawn.io.AlertUser(L"Unknown reaction \"" + StringToWidestring(reaction) + L"\"", INFINITY, ImportanceLevel::MEDIUM);
				}
			}

			bluespawn.SetReaction(combined);

			// Parse the hunt level
			std::string sHuntLevelFlag = "Normal";
			Aggressiveness aHuntLevel;
			try {
				sHuntLevelFlag = result["level"].as < std::string >();
			}
			catch (int e) {}

			if (CompareIgnoreCase<std::string>(sHuntLevelFlag, "Cursory")) {
				aHuntLevel = Aggressiveness::Cursory;
			}
			else if (CompareIgnoreCase<std::string>(sHuntLevelFlag, "Normal")) {
				aHuntLevel = Aggressiveness::Normal;
			}
			else if (CompareIgnoreCase<std::string>(sHuntLevelFlag, "Intensive")) {
				aHuntLevel = Aggressiveness::Intensive;
			}
			else {
				LOG_ERROR("Error " << sHuntLevelFlag << " - Unknown level. Please specify either Cursory, Normal, or Intensive");
				LOG_ERROR("Will default to Cursory for this run.");
				Bluespawn::io.InformUser(L"Error " + StringToWidestring(sHuntLevelFlag) + L" - Unknown level. Please specify either Cursory, Normal, or Intensive");
				Bluespawn::io.InformUser(L"Will default to Cursory.");
				aHuntLevel = Aggressiveness::Cursory;
			}

			//Parse included and excluded hunts
			std::vector<std::string> vIncludedHunts;
			std::vector<std::string> vExcludedHunts;

			if (result.count("hunts")) {
				vIncludedHunts = result["hunts"].as<std::vector<std::string>>();
			}
			else if (result.count("exclude-hunts")) {
				vExcludedHunts = result["exclude-hunts"].as<std::vector<std::string>>();
			}

			if (result.count("hunt"))
				bluespawn.dispatch_hunt(aHuntLevel, vExcludedHunts, vIncludedHunts);
			else if (result.count("monitor"))
				bluespawn.monitor_system(aHuntLevel);

		}
		else if (result.count("mitigate")) {
			bool bForceEnforce = false;
			if (result.count("force"))
				bForceEnforce = true;

			MitigationMode mode = MitigationMode::Audit;
			if (result["mitigate"].as<std::string>() == "e" || result["mitigate"].as<std::string>() == "enforce")
				mode = MitigationMode::Enforce;

			bluespawn.dispatch_mitigations_analysis(mode, bForceEnforce);
		}
		else {
			LOG_ERROR("Nothing to do. Use the -h or --hunt flags to launch a hunt");
		}
	}
	catch (cxxopts::OptionParseException e1) {
		LOG_ERROR(e1.what());
	}
}
