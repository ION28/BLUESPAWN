#include "user/bluespawn.h"
#include "user/CLI.h"
#include "util/log/HuntLogMessage.h"
#include "util/log/DebugSink.h"
#include "common/DynamicLinker.h"
#include "common/StringUtils.h"
#include "util/eventlogs/EventLogs.h"

#include "hunt/hunts/HuntT1004.h"
#include "hunt/hunts/HuntT1037.h"
#include "hunt/hunts/HuntT1050.h"
#include "hunt/hunts/HuntT1055.h"
#include "hunt/hunts/HuntT1060.h"
#include "hunt/hunts/HuntT1100.h"
#include "hunt/hunts/HuntT1101.h"
#include "hunt/hunts/HuntT1103.h"
#include "hunt/hunts/HuntT1131.h"
#include "hunt/hunts/HuntT1138.h"
#include "hunt/hunts/HuntT1182.h"
#include "hunt/hunts/HuntT1183.h"

#include "monitor/ETW_Wrapper.h"

#include "mitigation/mitigations/MitigateM1042-LLMNR.h"
#include "mitigation/mitigations/MitigateM1042-WSH.h"
#include "mitigation/mitigations/MitigateV1093.h"
#include "mitigation/mitigations/MitigateV1153.h"
#include "mitigation/mitigations/MitigateV3338.h"
#include "mitigation/mitigations/MitigateV63597.h"
#include "mitigation/mitigations/MitigateV63817.h"
#include "mitigation/mitigations/MitigateV63825.h"
#include "mitigation/mitigations/MitigateV63829.h"
#include "mitigation/mitigations/MitigateV72753.h"
#include "mitigation/mitigations/MitigateV73519.h"

#include <iostream>

IOBase& Bluespawn::io = CLI();
HuntRegister Bluespawn::huntRecord{ io };
MitigationRegister Bluespawn::mitigationRecord{ io };

Bluespawn::Bluespawn() {
	using namespace Hunts;

	HuntT1004* t1004 = new HuntT1004(huntRecord);
	HuntT1037* t1037 = new HuntT1037(huntRecord);
	HuntT1050* t1050 = new HuntT1050(huntRecord);
	HuntT1055* t1055 = new HuntT1055(huntRecord);
	HuntT1060* t1060 = new HuntT1060(huntRecord);
	HuntT1100* t1100 = new HuntT1100(huntRecord);
	HuntT1101* t1101 = new HuntT1101(huntRecord);
	HuntT1103* t1103 = new HuntT1103(huntRecord);
	HuntT1131* t1131 = new HuntT1131(huntRecord);
	HuntT1138* t1138 = new HuntT1138(huntRecord);
	HuntT1182* t1182 = new HuntT1182(huntRecord);
	HuntT1183* t1183 = new HuntT1183(huntRecord);

	using namespace Mitigations;
   
	MitigateM1042LLMNR* m1042llmnr = new MitigateM1042LLMNR(mitigationRecord);
	MitigateM1042WSH* m1042wsh = new MitigateM1042WSH(mitigationRecord);
	MitigateV1093* v1093 = new MitigateV1093(mitigationRecord);
	MitigateV1153* v1153 = new MitigateV1153(mitigationRecord);
	MitigateV3338* v3338 = new MitigateV3338(mitigationRecord);
	MitigateV63597* v63597 = new MitigateV63597(mitigationRecord);
	MitigateV63817* v63817 = new MitigateV63817(mitigationRecord);
	MitigateV63825* v63825 = new MitigateV63825(mitigationRecord);
	MitigateV63829* v63829 = new MitigateV63829(mitigationRecord);
	MitigateV72753* v72753 = new MitigateV72753(mitigationRecord);
	MitigateV73519* v73519 = new MitigateV73519(mitigationRecord);
}

void Bluespawn::dispatch_hunt(Aggressiveness aHuntLevel) {
	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};
	Reaction reaction = Reactions::LogReaction();

	Bluespawn::io.InformUser(L"Starting a Hunt");
	huntRecord.RunHunts(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction);
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
	Reaction reaction = Reactions::LogReaction();

	Bluespawn::io.InformUser(L"Monitoring the system");
	huntRecord.SetupMonitoring(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction);

	while (true) {}
}

int main(int argc, char* argv[]){
	Linker::LinkFunctions();

	Log::DebugSink DebugOutput{};
	Log::CLISink ConsoleOutput{};
	Log::AddSink(DebugOutput);
	Log::AddHuntSink(ConsoleOutput);

	Bluespawn bluespawn;

	print_banner();

	cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

	options.add_options()
		("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
		("n,monitor", "Monitor the System for Malicious Activity. Available options are Cursory, Normal, or Intensive.", cxxopts::value<std::string>()->implicit_value("Normal"))
		("m,mitigate", "Mitigates vulnerabilities by applying security settings. Available options are audit and enforce.", cxxopts::value<std::string>()->implicit_value("audit"))
		("help", "Help Information. You can also specify a category for help on a specific module such as hunt"
			, cxxopts::value<std::string>()->implicit_value("general"))
		("v,verbose", "Verbosity", cxxopts::value<int>()->default_value("0"))
		("debug", "Enable Debug Output", cxxopts::value<bool>())
		;

	options.add_options("hunt")
		("l,level", "Aggressiveness of Hunt. Either Cursory, Normal, or Intensive",
			cxxopts::value<std::string>())
		;

	options.add_options("mitigate")
		("force", "Use this option to forcibly apply mitigations with no prompt",
			cxxopts::value<bool>())
		;

	options.parse_positional({ "level" });
	try {
		auto result = options.parse(argc, argv);

		if (result.count("debug")) {
			Log::AddSink(ConsoleOutput);
		}

		if (result.count("verbose")) {
			if (result["verbose"].as<int>() >= 1) {
				Log::LogLevel::LogVerbose1.Enable();
			}
			if (result["verbose"].as<int>() >= 2) {
				Log::LogLevel::LogVerbose2.Enable();
			}
			if (result["verbose"].as<int>() >= 3) {
				Log::LogLevel::LogVerbose3.Enable();
			}
		}

		if (result.count("help")) {
			print_help(result, options);
		}
		else if (result.count("hunt") || result.count("monitor")) {
			std::string flag("level");
			if (result.count("monitor"))
				flag = "monitor";

			// Parse the hunt level
			std::string sHuntLevelFlag = "Normal";
			Aggressiveness aHuntLevel;
			try {
				sHuntLevelFlag = result[flag].as < std::string >();
			}
			catch (int e) {}

			if (sHuntLevelFlag == "Cursory") {
				aHuntLevel = Aggressiveness::Cursory;
			}
			else if (sHuntLevelFlag == "Normal") {
				aHuntLevel = Aggressiveness::Normal;
			}
			else if (sHuntLevelFlag == "Intensive") {
				aHuntLevel = Aggressiveness::Intensive;
			}
			else {
				LOG_ERROR("Error " << sHuntLevelFlag << " - Unknown level. Please specify either Cursory, Normal, or Intensive");
				LOG_ERROR("Will default to Cursory for this run.");
				Bluespawn::io.InformUser(L"Error " + StringToWidestring(sHuntLevelFlag) + L" - Unknown level. Please specify either Cursory, Normal, or Intensive");
				Bluespawn::io.InformUser(L"Will default to Cursory.");
				aHuntLevel = Aggressiveness::Cursory;
			}
			
			if (result.count("hunt"))
				bluespawn.dispatch_hunt(aHuntLevel);
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
		LOG_ERROR(StringToWidestring(e1.what()));
	}
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string help_category = result["help"].as < std::string >();

	std::transform(help_category.begin(), help_category.end(),
		help_category.begin(), [](unsigned char c) { return std::tolower(c); });

	if (help_category.compare("hunt") == 0) {
		std::cout << (options.help({ "hunt" })) << std::endl;
	}
	else if (help_category.compare("general") == 0) {
		std::cout << (options.help()) << std::endl;
	}
	else {
		std::cerr << ("Unknown help category") << std::endl;
	}
}
