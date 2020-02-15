#include "user/bluespawn.h"
#include "user/CLI.h"
#include "util/log/HuntLogMessage.h"
#include "util/log/DebugSink.h"
#include "common/DynamicLinker.h"
#include "common/StringUtils.h"
#include "util/eventlogs/EventLogs.h"
#include "hunt/reaction/SuspendProcess.h"
#include "hunt/reaction/RemoveValue.h"

#include "hunt/hunts/HuntT1004.h"
#include "hunt/hunts/HuntT1015.h"
#include "hunt/hunts/HuntT1037.h"
#include "hunt/hunts/HuntT1050.h"
#include "hunt/hunts/HuntT1055.h"
#include "hunt/hunts/HuntT1060.h"
#include "hunt/hunts/HuntT1100.h"
#include "hunt/hunts/HuntT1101.h"
#include "hunt/hunts/HuntT1103.h"
#include "hunt/hunts/HuntT1131.h"
#include "hunt/hunts/HuntT1136.h"
#include "hunt/hunts/HuntT1138.h"
#include "hunt/hunts/HuntT1182.h"
#include "hunt/hunts/HuntT1183.h"

#include "monitor/ETW_Wrapper.h"

#include "mitigation/mitigations/MitigateM1025.h"
#include "mitigation/mitigations/MitigateM1042-LLMNR.h"
#include "mitigation/mitigations/MitigateM1042-NBT.h"
#include "mitigation/mitigations/MitigateM1042-WSH.h"
#include "mitigation/mitigations/MitigateV1093.h"
#include "mitigation/mitigations/MitigateV1153.h"
#include "mitigation/mitigations/MitigateV3338.h"
#include "mitigation/mitigations/MitigateV3340.h"
#include "mitigation/mitigations/MitigateV3344.h"
#include "mitigation/mitigations/MitigateV3379.h"
#include "mitigation/mitigations/MitigateV63597.h"
#include "mitigation/mitigations/MitigateV63817.h"
#include "mitigation/mitigations/MitigateV63825.h"
#include "mitigation/mitigations/MitigateV63829.h"
#include "mitigation/mitigations/MitigateV72753.h"
#include "mitigation/mitigations/MitigateV73519.h"

#include <iostream>

const IOBase& Bluespawn::io = CLI::GetInstance();
HuntRegister Bluespawn::huntRecord{ io };
MitigationRegister Bluespawn::mitigationRecord{ io };

Bluespawn::Bluespawn() {

	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1004>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1015>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1037>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1050>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1055>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1060>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1100>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1101>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1103>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1131>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1136>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1138>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1182>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1183>());

	using namespace Mitigations;
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1025>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042LLMNR>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042NBT>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042WSH>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV1093>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV1153>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3338>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3340>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3344>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV3379>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63597>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63817>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63825>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV63829>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV72753>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV73519>());

	bLogOnly = false;
}

void Bluespawn::dispatch_hunt(Aggressiveness aHuntLevel) {
	Bluespawn::io.InformUser(L"Starting a Hunt");
	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};
	Reaction logreact = Reactions::LogReaction();

	if (!bLogOnly) {
		Reaction suspendreact = Reactions::SuspendProcessReaction(io);
		Reaction logsuspend = logreact.Combine(suspendreact);
		Reaction removereact = Reactions::RemoveValueReaction(io);
		auto reaction = logsuspend.Combine(removereact);

		huntRecord.RunHunts(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction);
	}
	else {
		huntRecord.RunHunts(tactics, dataSources, affectedThings, scope, aHuntLevel, logreact);
	}

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
	//huntRecord.SetupMonitoring(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction);
	huntRecord.SetupMonitoring(aHuntLevel, reaction);

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
		("log-only", "Log only and do not prompt for input", cxxopts::value<bool>())
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

		if (result.count("log-only")) {
			bluespawn.bLogOnly = true;
		}

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
	return 0;
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
