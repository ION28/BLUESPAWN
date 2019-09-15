#include "bluespawn/bluespawn.h"
#include "common/wrappers.hpp"
#include "logging/HuntLogMessage.h"

#include <iostream>

int main(int argc, char* argv[])
{
	Log::CLISink output{};
	Log::AddSink(output);
	Log::AddHuntSink(output);

	auto info = HuntInfo{
		std::wstring{L"T0000 - Test"},
		Aggressiveness::Moderate,
		(DWORD) Tactic::Execution,
		(DWORD) DataSource::Processes,
		(DWORD) Category::Processes,
		0
	};

	Log::HuntLogMessage hunt_test = { info, Log::_LogHuntSinks };

	hunt_test.AddDetection(reinterpret_cast<DETECTION*>(new PROCESS_DETECTION{
		DetectionType::Process,
		L"test.exe",
		L"C:\\test.exe",
		L"test.exe",
		0,
		0,
		NotInLoader,
		NULL
	}));

	hunt_test << "THIS IS A TEST OF THE DETECTION LOGGING CAPABILITEIS OF BLUESPAWN" << Log::endlog;

	print_banner();

	cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

	options.add_options()
		("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
		("help", "Help Information. You can also specify a category for help on a specific module such as hunt"
			, cxxopts::value<std::string>()->implicit_value("general"))
			("example", "Perform the example hunt")
		;

	options.add_options("hunt")
		("l,level", "Aggressiveness of Hunt. Either Cursory, Moderate, Careful, or Aggressive",
			cxxopts::value<std::string>())
		;

	options.parse_positional({ "help", "level" });
	auto result = options.parse(argc, argv);

	if (result.count("help")) {
		print_help(result, options);
	}
	else if (result.count("hunt")) {
		dispatch_hunt(result, options);
	}
	else {
		LOG_ERROR("Nothing to do. Use the -h or --hunt flags to launch a hunt");
	}
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string help_category = result["help"].as < std::string >();

	std::transform(help_category.begin(), help_category.end(),
		help_category.begin(), [](unsigned char c) { return std::tolower(c); });

	if (help_category.compare("hunt") == 0) {
		LOG_INFO(options.help({ "hunt" }));
	}
	else if (help_category.compare("general") == 0) {
		LOG_INFO(options.help());
	}
	else {
		LOG_ERROR("Unknown help category");
	}
}

void dispatch_hunt(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string sHuntLevelFlag = "Moderate";
	Aggressiveness aHuntLevel;
	if (result.count("level")) {
		try {
			sHuntLevelFlag = result["level"].as < std::string >();
		}
		catch (int e) {
			LOG_ERROR("Error " << e << " - Unknown hunt level. Please specify either Cursory, Moderate, Careful, or Aggressive");
		}
	}
	if (sHuntLevelFlag == "Cursory") {
		aHuntLevel = Aggressiveness::Cursory;
	}
	else if (sHuntLevelFlag == "Moderate") {
		aHuntLevel = Aggressiveness::Moderate;
	}
	else if (sHuntLevelFlag == "Careful") {
		aHuntLevel = Aggressiveness::Careful;
	}
	else {
		aHuntLevel = Aggressiveness::Aggressive;
	}

	HuntRegister record{};
	Hunts::HuntT1004 t1004(record);
	Hunts::HuntT1037 t1037(record);
	Hunts::HuntT1060 t1060(record);
	Hunts::HuntT1100 t1100(record);
	Hunts::HuntT1101 t1101(record);
	Hunts::HuntT1103 t1103(record);
	Hunts::HuntT1131 t1131(record);
	Hunts::HuntT1138 t1138(record);
	Hunts::HuntT1182 t1182(record);

	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};
	Reaction* reaction = new Reactions::LogReaction();
	record.RunHunts(tactics, dataSources, affectedThings, scope, aHuntLevel, reaction);
}