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

#include "hunt/hunts/HuntT1004.h"
#include "hunt/hunts/HuntT1015.h"
#include "hunt/hunts/HuntT1037.h"
#include "hunt/hunts/HuntT1050.h"
#include "hunt/hunts/HuntT1053.h"
#include "hunt/hunts/HuntT1055.h"
#include "hunt/hunts/HuntT1060.h"
#include "hunt/hunts/HuntT1099.h"
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
#include "mitigation/mitigations/MitigateM1035-RDP.h"
#include "mitigation/mitigations/MitigateM1042-LLMNR.h"
#include "mitigation/mitigations/MitigateM1042-NBT.h"
#include "mitigation/mitigations/MitigateM1042-WSH.h"
#include "mitigation/mitigations/MitigateM1047.h"
#include "mitigation/mitigations/MitigateM1054-RDP.h"
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
#include "mitigation/mitigations/MitigateV72753.h"
#include "mitigation/mitigations/MitigateV73519.h"
#include "mitigation/mitigations/MitigateV73585.h"

#pragma warning(push)

#pragma warning(disable : 26451)
#pragma warning(disable : 26444)

#include "cxxopts.hpp"

#pragma warning(pop)

#include <iostream>
#include <memory>

const IOBase& Bluespawn::io = CLI::GetInstance();
HuntRegister Bluespawn::huntRecord{ io };
MitigationRegister Bluespawn::mitigationRecord{ io };

std::map<std::string, std::shared_ptr<Reaction>> reactions = {
	{"log", std::make_shared<Reactions::LogReaction>()},
	{"remove-value", std::make_shared<Reactions::RemoveValueReaction>( Bluespawn::io )},
	{"suspend", std::make_shared<Reactions::SuspendProcessReaction>( Bluespawn::io )},
	{"carve-memory", std::make_shared<Reactions::CarveProcessReaction>( Bluespawn::io )},
};

Bluespawn::Bluespawn(){

	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1004>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1015>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1037>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1050>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1053>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1055>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1060>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1099>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1100>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1101>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1103>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1131>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1136>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1138>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1182>());
	huntRecord.RegisterHunt(std::make_shared<Hunts::HuntT1183>());

	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1025>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1035RDP>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042LLMNR>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042NBT>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1042WSH>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1047>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateM1054RDP>());
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
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV72753>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV73519>());
	mitigationRecord.RegisterMitigation(std::make_shared<Mitigations::MitigateV73585>());
}

void Bluespawn::RunHunts() {
	Bluespawn::io.InformUser(L"Starting a Hunt");
	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};

	huntRecord.RunHunts(tactics, dataSources, affectedThings, scope);
}

void Bluespawn::RunMitigations(bool enforce, bool force) {
	if (enforce) {
		Bluespawn::io.InformUser(L"Enforcing Mitigations");
		mitigationRecord.EnforceMitigations(SecurityLevel::High, force);
	}
	else {
		Bluespawn::io.InformUser(L"Auditing Mitigations");
		mitigationRecord.AuditMitigations(SecurityLevel::High);
	}
}

void Bluespawn::RunMonitor() {
	DWORD tactics = UINT_MAX;
	DWORD dataSources = UINT_MAX;
	DWORD affectedThings = UINT_MAX;
	Scope scope{};

	Bluespawn::io.InformUser(L"Monitoring the system");
	huntRecord.SetupMonitoring();

	HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
	while (true) {
		SetEvent(hRecordEvent);
		Sleep(5000);
	}
}

void Bluespawn::AddReaction(const std::shared_ptr<Reaction>& reaction){
	this->reaction.Combine(*reaction);
}

void Bluespawn::EnableMode(BluespawnMode mode, int option){
	modes.emplace(mode, option);
}

void Bluespawn::Run(){
	if(modes.find(BluespawnMode::MITIGATE) != modes.end()){
		RunMitigations(modes[BluespawnMode::MITIGATE] & 0x01, modes[BluespawnMode::MITIGATE] & 0x02);
	}
	if(modes.find(BluespawnMode::HUNT) != modes.end()){
		RunHunts();
	}
	if(modes.find(BluespawnMode::MONITOR) != modes.end()){
		RunMonitor();
	}
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string help_category = result["help"].as < std::string >();

	if(CompareIgnoreCase(help_category, std::string{ "hunt" })) {
		Bluespawn::io.InformUser(StringToWidestring(options.help({ "hunt" })));
	} else if(CompareIgnoreCase(help_category, std::string{ "scan" })) {
		Bluespawn::io.InformUser(StringToWidestring(options.help({ "scan" })));
	} else if(CompareIgnoreCase(help_category, std::string{ "monitor" })) {
		Bluespawn::io.InformUser(StringToWidestring(options.help({ "monitor" })));
	} else if(CompareIgnoreCase(help_category, std::string{ "mitigate" })) {
		Bluespawn::io.InformUser(StringToWidestring(options.help({ "mitigate" })));
	} else {
		Bluespawn::io.InformUser(StringToWidestring(options.help()));
	}
}

void ParseLogSinks(const std::string& sinks, bool debug){
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
			if(debug) Log::AddSink(Console);
		} else if(sink == "xml"){
			auto XMLSink = std::make_shared<Log::XMLSink>();
			Log::AddHuntSink(XMLSink);
			if(debug) Log::AddSink(XMLSink);
		} else if(sink == "debug"){
			auto DbgSink = std::make_shared<Log::DebugSink>();
			Log::AddHuntSink(DbgSink);
			if(debug) Log::AddSink(DbgSink);
		} else {
			Bluespawn::io.AlertUser(L"Unknown log sink \"" + StringToWidestring(sink) + L"\"", INFINITY, ImportanceLevel::MEDIUM);
		}
	}
}

Aggressiveness GetAggressiveness(const cxxopts::OptionValue& value){
	Aggressiveness aHuntLevel{};
	auto level{ value.as<std::string>() };

	if(CompareIgnoreCase<std::string>(level, "Cursory")) {
		aHuntLevel = Aggressiveness::Cursory;
	} else if(CompareIgnoreCase<std::string>(level, "Normal")) {
		aHuntLevel = Aggressiveness::Normal;
	} else if(CompareIgnoreCase<std::string>(level, "Intensive")) {
		aHuntLevel = Aggressiveness::Intensive;
	} else {
		LOG_ERROR("Error " << level << " - Unknown level. Please specify either Cursory, Normal, or Intensive");
		LOG_ERROR("Will default to Normal for this run.");
		Bluespawn::io.InformUser(L"Error " + StringToWidestring(level) + L" - Unknown level. Please specify either Cursory, Normal, or Intensive");
		Bluespawn::io.InformUser(L"Will default to Normal.");
		aHuntLevel = Aggressiveness::Normal;
	}

	return aHuntLevel;
}

int main(int argc, char* argv[]){

	Bluespawn bluespawn{};

	print_banner();

	cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

	options.add_options()
		("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
		("n,monitor", "Monitor the System for Malicious Activity. Available options are Cursory, Normal, or Intensive.", cxxopts::value<std::string>()->implicit_value("Normal"))
		("m,mitigate", "Mitigates vulnerabilities by applying security settings. Available options are audit and enforce.", cxxopts::value<std::string>()->implicit_value("audit"))
		("s,scan", "Mitigates vulnerabilities by applying security settings. Available options are audit and enforce.", cxxopts::value<std::string>()->implicit_value("audit"))
		("help", "Help Information. You can also specify a category for help on a specific module such as hunt.", cxxopts::value<std::string>()->implicit_value("general"))
		("log", "Specify how Bluespawn should log events. Options are console (default), xml, and debug.", cxxopts::value<std::string>()->default_value("console"))
		("r,react", "Specifies how bluespawn should react to potential threats dicovered during hunts.", cxxopts::value<std::string>()->default_value("log"))
		("v,verbose", "Verbosity", cxxopts::value<int>()->default_value("0"))
		("debug", "Enable Debug Output", cxxopts::value<bool>());

	options.add_options("scan")("l,level", "Aggressiveness of scan. Either Cursory, Normal, or Intensive", cxxopts::value<std::string>()->default_value("Normal"));
	options.add_options("mitigate")("force", "Use this option to forcibly apply mitigations with no prompt", cxxopts::value<bool>());

	options.parse_positional({ "level" });
	try {
		auto result = options.parse(argc, argv);

		if(result.count("help")) {
			print_help(result, options);
			return 0;
		}

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

		ParseLogSinks(result["log"].as<std::string>(), result.count("debug"));

		auto UserReactions = result["react"].as<std::string>();
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
				bluespawn.AddReaction(reactions[reaction]);
			} else {
				bluespawn.io.AlertUser(L"Unknown reaction \"" + StringToWidestring(reaction) + L"\"", INFINITY, ImportanceLevel::MEDIUM);
			}
		}

		if (result.count("scan")) {
			bluespawn.EnableMode(BluespawnMode::SCAN, static_cast<DWORD>(GetAggressiveness(result["level"])));
		}
		if (result.count("mitigate")) {
			bool bForceEnforce = false;
			if (result.count("force"))
				bForceEnforce = true;

			MitigationMode mode = MitigationMode::Audit;
			if (result["mitigate"].as<std::string>() == "e" || result["mitigate"].as<std::string>() == "enforce")
				mode = MitigationMode::Enforce;

			bluespawn.EnableMode(BluespawnMode::MITIGATE, (static_cast<DWORD>(bForceEnforce) << 1) | (static_cast<DWORD>(mode) << 0));
		}
		if(result.count("hunt")){
			bluespawn.EnableMode(BluespawnMode::HUNT);
		}
		if(result.count("monitor")){
			bluespawn.EnableMode(BluespawnMode::MONITOR);
		}

		bluespawn.Run();
	}
	catch (cxxopts::OptionParseException e1) {
		Bluespawn::io.InformUser(StringToWidestring(options.help()));
		LOG_ERROR(e1.what());
	}
	return 0;
}
