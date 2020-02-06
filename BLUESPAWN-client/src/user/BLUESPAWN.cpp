#include "user/bluespawn.h"
#include "user/CLI.h"
#include "util/log/HuntLogMessage.h"
#include "util/log/DebugSink.h"
#include "common/DynamicLinker.h"
#include "common/StringUtils.h"
#include "util/eventlogs/EventLogs.h"

#include <iostream>

int main(int argc, char* argv[]){
	Linker::LinkFunctions();

	Log::DebugSink DebugOutput{};
	Log::CLISink ConsoleOutput{};
	Log::AddSink(DebugOutput);
	Log::AddHuntSink(ConsoleOutput);

	IOBase& io = CLI();

	print_banner();

	/*
	// Create and initialize the ETW wrapper
	ETW_Wrapper wrapper;
	wrapper.init();
	*/

	cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

	options.add_options()
		("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
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
		else if (result.count("hunt")) {
			dispatch_hunt(result, options, io);
		}
		else if (result.count("mitigate")) {
			dispatch_mitigations_analysis(result, options, io);
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

void dispatch_hunt(cxxopts::ParseResult result, cxxopts::Options options, IOBase& io) {
	std::string sHuntLevelFlag = "Cursory";
	Aggressiveness aHuntLevel;
	if(result.count("level")) {
		try {
			sHuntLevelFlag = result["level"].as < std::string >();
		} catch(int e) {
			LOG_ERROR("Error " << e << " - Unknown hunt level. Please specify either Cursory, Normal, or Intensive");
			io.InformUser(L"Error " + std::to_wstring(e) + L" - Unknown hunt level. Please specify either Cursory, Normal, or Intensive");
		}
	}
	if(sHuntLevelFlag == "Cursory") {
		aHuntLevel = Aggressiveness::Cursory;
	} else if(sHuntLevelFlag == "Normal") {
		aHuntLevel = Aggressiveness::Normal;
	} else if (sHuntLevelFlag == "Intensive") {
		aHuntLevel = Aggressiveness::Intensive;
	} else {
		LOG_ERROR("Error " << sHuntLevelFlag << " - Unknown hunt level. Please specify either Cursory, Normal, or Intensive");
		LOG_ERROR("Will default to Cursory for this run.");
		io.InformUser(L"Error " + StringToWidestring(sHuntLevelFlag) + L" - Unknown hunt level. Please specify either Cursory, Normal, or Intensive");
		io.InformUser(L"Will default to Cursory for this run.");
		aHuntLevel = Aggressiveness::Cursory;
	}

	HuntRegister record{io};
	Hunts::HuntT1004 t1004(record);
	Hunts::HuntT1037 t1037(record);
	Hunts::HuntT1050 t1050(record);
	Hunts::HuntT1055 t1055(record);
	Hunts::HuntT1060 t1060(record);
	Hunts::HuntT1100 t1100(record);
	Hunts::HuntT1101 t1101(record);
	Hunts::HuntT1103 t1103(record);
	Hunts::HuntT1131 t1131(record);
	Hunts::HuntT1138 t1138(record);
	Hunts::HuntT1182 t1182(record);
	Hunts::HuntT1183 t1183(record);

	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};
	Reaction reaction = Reactions::LogReaction();
	record.RunHunts(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction);
}


void dispatch_mitigations_analysis(cxxopts::ParseResult result, cxxopts::Options options, IOBase& io) {
	bool bForceEnforce = false;
	if (result.count("force")) {
		bForceEnforce = true;
	}

	MitigationRegister record{io};

	Mitigations::MitigateV1093 v1093(record);
	Mitigations::MitigateV1153 v1153(record);
	Mitigations::MitigateV3338 v3338(record);
	Mitigations::MitigateV63597 v63597(record);
	Mitigations::MitigateV63817 v63817(record);
	Mitigations::MitigateV63825 v63825(record);
	Mitigations::MitigateV63829 v63829(record);
	Mitigations::MitigateV72753 v72753(record);
	Mitigations::MitigateV73519 v73519(record);

	if (result["mitigate"].as<std::string>() == "e" || result["mitigate"].as<std::string>() == "enforce") {
		io.InformUser(L"Enforcing Mitigations");
		record.EnforceMitigations(SecurityLevel::High, bForceEnforce);
	}
	else {
		io.InformUser(L"Auditing Mitigations");
		record.AuditMitigations(SecurityLevel::High);
	}
}
