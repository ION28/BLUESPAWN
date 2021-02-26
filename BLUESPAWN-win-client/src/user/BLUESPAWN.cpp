#include "user/bluespawn.h"

#include <iostream>
#include <memory>

#include "util/DynamicLinker.h"
#include "util/StringUtils.h"
#include "util/ThreadPool.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/CLISink.h"
#include "util/log/DebugSink.h"
#include "util/log/JSONSink.h"
#include "util/log/XMLSink.h"

#include "hunt/hunts/HuntT1036.h"
#include "hunt/hunts/HuntT1037.h"
#include "hunt/hunts/HuntT1053.h"
#include "hunt/hunts/HuntT1055.h"
#include "hunt/hunts/HuntT1068.h"
#include "hunt/hunts/HuntT1070.h"
#include "hunt/hunts/HuntT1136.h"
#include "hunt/hunts/HuntT1484.h"
#include "hunt/hunts/HuntT1505.h"
#include "hunt/hunts/HuntT1543.h"
#include "hunt/hunts/HuntT1546.h"
#include "hunt/hunts/HuntT1547.h"
#include "hunt/hunts/HuntT1548.h"
#include "hunt/hunts/HuntT1553.h"
#include "hunt/hunts/HuntT1562.h"
#include "hunt/hunts/HuntT1569.h"
#include "reaction/CarveMemory.h"
#include "reaction/DeleteFile.h"
#include "reaction/QuarantineFile.h"
#include "reaction/RemoveValue.h"
#include "reaction/SuspendProcess.h"
#include "scan/FileScanner.h"
#include "scan/ProcessScanner.h"
#include "user/CLI.h"

#pragma warning(push)

#pragma warning(disable : 26451)
#pragma warning(disable : 26444)

#include "cxxopts.hpp"

#pragma warning(pop)

#include <VersionHelpers.h>

#include <iostream>

DEFINE_FUNCTION(BOOL, IsWow64Process2, NTAPI, HANDLE hProcess, USHORT* pProcessMachine, USHORT* pNativeMachine);
LINK_FUNCTION(IsWow64Process2, KERNEL32.DLL);

const IOBase& Bluespawn::io = CLI::GetInstance();
HuntRegister Bluespawn::huntRecord{};
MitigationRegister Bluespawn::mitigationRecord{};
Aggressiveness Bluespawn::aggressiveness{ Aggressiveness::Normal };
DetectionRegister Bluespawn::detections{ Certainty::Moderate };
ReactionManager Bluespawn::reaction{};
std::vector<std::shared_ptr<DetectionSink>> Bluespawn::detectionSinks{};
bool Bluespawn::EnablePreScanDetections{ false };

std::map<std::string, std::unique_ptr<Reaction>> reactions{};

Bluespawn::Bluespawn() {
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1036>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1037>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1053>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1055>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1068>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1070>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1136>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1484>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1505>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1543>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1546>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1547>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1548>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1553>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1562>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1569>());

    mitigationRecord.Initialize();

    reactions.emplace("carve-memory", std::make_unique<Reactions::CarveMemoryReaction>());
    reactions.emplace("delete-file", std::make_unique<Reactions::DeleteFileReaction>());
    reactions.emplace("quarantine-file", std::make_unique<Reactions::QuarantineFileReaction>());
    reactions.emplace("remove-value", std::make_unique<Reactions::RemoveValueReaction>());
    reactions.emplace("suspend", std::make_unique<Reactions::SuspendProcessReaction>());
}

void Bluespawn::RunHunts() {
    Bluespawn::io.InformUser(L"Starting a Hunt");
    DWORD tactics = UINT_MAX;
    DWORD dataSources = UINT_MAX;
    DWORD affectedThings = UINT_MAX;
    Scope scope{};

    huntRecord.RunHunts(vIncludedHunts, vExcludedHunts, scope);
}

void Bluespawn::RunMitigations(bool enforce) {
    if(enforce) {
        Bluespawn::io.InformUser(L"Enforcing Mitigations");
        mitigationRecord.PrintMitigationReports(mitigationRecord.EnforceMitigations(*mitigationConfig));
    } else {
        Bluespawn::io.InformUser(L"Auditing Mitigations");
        mitigationRecord.PrintMitigationReports(mitigationRecord.AuditMitigations(*mitigationConfig));
    }
}

void Bluespawn::RunMonitor() {
    DWORD tactics = UINT_MAX;
    DWORD dataSources = UINT_MAX;
    DWORD affectedThings = UINT_MAX;
    Scope scope{};

    Bluespawn::io.InformUser(L"Monitoring the system");
    huntRecord.SetupMonitoring(vIncludedHunts, vExcludedHunts);

    HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
    while(true) {
        SetEvent(hRecordEvent);
        Sleep(5000);
    }
}

void Bluespawn::AddReaction(std::unique_ptr<Reaction>&& reaction) {
    Bluespawn::reaction.AddHandler(std::move(reaction));
}

void Bluespawn::EnableMode(BluespawnMode mode, int option) {
    modes.emplace(mode, option);
}

void Bluespawn::SetIncludedHunts(std::vector<std::string> includedHunts) {
    for(auto& id : includedHunts) {
        Bluespawn::vIncludedHunts.emplace_back(StringToWidestring(id));
    }
}

void Bluespawn::SetExcludedHunts(std::vector<std::string> excludedHunts) {
    for(auto& id : excludedHunts) {
        Bluespawn::vExcludedHunts.emplace_back(StringToWidestring(id));
    }
}

void Bluespawn::RunScan(){
    std::vector<std::shared_ptr<Detection>> detections;
    for(auto& file : scanFiles){
        if(FileScanner::PerformQuickScan(file.GetFilePath())){
            detections.emplace_back(Bluespawn::detections.AddDetection(Detection(FileDetectionData{ file })));
        }
    }
    for(auto pid : scanProcesses){
        Hunts::HuntT1055::HandleReport(detections, Hunts::HuntT1055::QueueProcessScan(pid));
    }
}

void Bluespawn::Run() {
    if(modes.find(BluespawnMode::MITIGATE) != modes.end()) {
        RunMitigations(modes[BluespawnMode::MITIGATE]);
    }
    if(modes.find(BluespawnMode::HUNT) != modes.end()) {
        RunHunts();
    }
    if(modes.find(BluespawnMode::MONITOR) != modes.end()){
        RunMonitor();
    }
    if(modes.find(BluespawnMode::SCAN) != modes.end()){
        RunScan();
    }

    ThreadPool::GetInstance().Wait();
    Bluespawn::detections.Wait();
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
    std::string help_category = result["help"].as<std::string>();

    std::string output = "";
    if(CompareIgnoreCase(help_category, std::string{ "hunt" })) {
        output = options.help({ "hunt" });
    } else if(CompareIgnoreCase(help_category, std::string{ "monitor" })) {
        output = std::regex_replace(options.help({ "hunt" }), std::regex("hunt options"), "monitor options");
    } else if(CompareIgnoreCase(help_category, std::string{ "mitigate" })) {
        output = options.help({ "mitigate" });
    } else {
        output = std::regex_replace(options.help(), std::regex("hunt options"), "hunt/monitor options");
    }
    Bluespawn::io.InformUser(StringToWidestring(output));
}

void Bluespawn::SetMitigationConfig(const MitigationsConfiguration& config){
    mitigationConfig = config;
}

void Bluespawn::check_correct_arch() {
    BOOL bIsWow64 = FALSE;
    if(IsWindows10OrGreater() && Linker::IsWow64Process2) {
        USHORT ProcessMachine;
        USHORT NativeMachine;
        Linker::IsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine);
        if(ProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
            bIsWow64 = TRUE;
        }
    } else {
        IsWow64Process(GetCurrentProcess(), &bIsWow64);
    }
    if(bIsWow64) {
        Bluespawn::io.AlertUser(L"Running the x86 version of BLUESPAWN on an x64 system! This configuration is not "
                                L"fully supported, so we recommend downloading the x64 version.",
                                5000, ImportanceLevel::MEDIUM);
        LOG_WARNING("Running the x86 version of BLUESPAWN on an x64 system! This configuration is not fully supported, "
                    "so we recommend downloading the x64 version.");
    }
}

void ParseLogSinks(const std::string& sinks, const std::string& logdir) {
    std::set<std::string> sink_set;
    for(unsigned startIdx = 0; startIdx < sinks.size();) {
        auto endIdx{ sinks.find(',', startIdx) };
        auto sink{ sinks.substr(startIdx, endIdx - startIdx) };
        sink_set.emplace(sink);
        startIdx = endIdx + 1;
        if(endIdx == std::string::npos) {
            break;
        }
    }

    std::wstring outputFolderPath = L".";

    auto outputDir = FileSystem::Folder(StringToWidestring(logdir));
    if(outputDir.GetFolderExists() && !outputDir.GetCurIsFile() && outputDir.GetFolderWrite()) {
        outputFolderPath = outputDir.GetFolderPath();
    } else {
        LOG_ERROR(L"Unable to access " << StringToWidestring(logdir)
                                       << L" to write logs. Defaulting to current directory.");
        Bluespawn::io.AlertUser(L"Unable to access " + StringToWidestring(logdir) +
                                    L" to write logs. Defaulting to current directory.",
                                5000, ImportanceLevel::MEDIUM);
    }

    std::vector<std::reference_wrapper<Log::LogLevel>> levels{
        Log::LogLevel::LogError, Log::LogLevel::LogWarn,     Log::LogLevel::LogInfo1,    Log::LogLevel::LogInfo2,
        Log::LogLevel::LogInfo3, Log::LogLevel::LogVerbose1, Log::LogLevel::LogVerbose2, Log::LogLevel::LogVerbose3,
    };

    for(auto sink : sink_set) {
        if(sink == "console") {
            auto console = std::make_shared<Log::CLISink>();
            Log::AddSink(console, levels);
            Bluespawn::detectionSinks.emplace_back(console);
        } else if(sink == "xml") {
            auto XML = std::make_shared<Log::XMLSink>(outputFolderPath);
            Log::AddSink(XML, levels);
            Bluespawn::detectionSinks.emplace_back(XML);
        } else if(sink == "json") {
            auto JSON = std::make_shared<Log::JSONSink>(outputFolderPath);
            Log::AddSink(JSON, levels);
            Bluespawn::detectionSinks.emplace_back(JSON);
        } else if(sink == "debug") {
            auto debug = std::make_shared<Log::DebugSink>();
            Log::AddSink(debug, levels);
            Bluespawn::detectionSinks.emplace_back(debug);
        } else {
            Bluespawn::io.AlertUser(L"Unknown log sink \"" + StringToWidestring(sink) + L"\"", INFINITY,
                                    ImportanceLevel::MEDIUM);
        }
    }
}

Aggressiveness GetAggressiveness(const cxxopts::OptionValue& value) {
    Aggressiveness aHuntLevel{};
    auto level{ value.as<std::string>() };

    if(CompareIgnoreCase<std::string>(level, "Cursory")) {
        aHuntLevel = Aggressiveness::Cursory;
    } else if(CompareIgnoreCase<std::string>(level, "Normal")) {
        aHuntLevel = Aggressiveness::Normal;
    } else if(CompareIgnoreCase<std::string>(level, "Intensive")) {
        aHuntLevel = Aggressiveness::Intensive;
    } else {
        LOG_ERROR("Error " << StringToWidestring(level)
                           << " - Unknown level. Please specify either Cursory, Normal, or Intensive");
        LOG_ERROR("Will default to Normal for this run.");
        Bluespawn::io.InformUser(L"Error " + StringToWidestring(level) +
                                 L" - Unknown level. Please specify either Cursory, Normal, or Intensive");
        Bluespawn::io.InformUser(L"Will default to Normal.");
        aHuntLevel = Aggressiveness::Normal;
    }

    return aHuntLevel;
}

int main(int argc, char* argv[]) {
    Log::LogLevel::LogError.Enable();
    Log::LogLevel::LogWarn.Enable();
    ThreadPool::GetInstance().AddExceptionHandler([](const auto& e) { LOG_ERROR(e.what()); });

    Bluespawn bluespawn{};

    print_banner();

    bluespawn.check_correct_arch();

    if(argc == 1) {
        Bluespawn::io.AlertUser(L"Please launch BLUESPAWN from a CLI and specify what you want it to do. You can use "
                                L"the --help flag to see what options are available.",
                                INFINITE, ImportanceLevel::MEDIUM);
    }

    cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: An Active Defense and EDR software to empower Blue Teams");

    // clang-format off
    options.add_options()
        ("h,hunt", "Hunt for malicious activity on the system", cxxopts::value<bool>())
        ("n,monitor", "Monitor the system for malicious activity, dispatching hunts as changes are detected.",
            cxxopts::value<bool>())
        ("m,mitigate", "Mitigate vulnerabilities by applying security settings.", 
            cxxopts::value<bool>())
        ("s,scan", "Scan a particular process, file, or folder", cxxopts::value<bool>())
        ("log", "Specify how BLUESPAWN should log events. Options are console, xml, json, and debug.",
            cxxopts::value<std::string>()->default_value("console")->implicit_value("console"))
        ("help", "Help Information. You can also specify a category for help on a specific module such as hunt.",
            cxxopts::value<std::string>()->implicit_value("general"))
        ("v,verbose", "Verbosity", cxxopts::value<int>()->default_value("1"))
        ("debug", "Enable Debug Output", cxxopts::value<int>()->default_value("0"))
        ("a,aggressiveness", "Sets the aggressiveness of BLUESPAWN. Options are cursory, normal, and intensive",
         cxxopts::value<std::string>()->default_value("Normal"))
        ("r,react", "Specifies how BLUESPAWN should react to potential threats dicovered during hunts. Available reactions are remove-value, carve-memory, suspend, delete-file, and quarantine-file",
         cxxopts::value<std::string>()->default_value(""))
        ;

    options.add_options("scan")
        ("scan-folder", "Specify a folder to scan", cxxopts::value<std::vector<std::string>>()->implicit_value({}))
        ("scan-file", "Specify a file to scan", cxxopts::value<std::vector<std::string>>()->implicit_value({}))
        ("scan-process", "Specify a process to scan by PID", cxxopts::value<std::vector<int>>()->implicit_value({}))
        ;

    options.add_options("hunt")
		("hunts", "Only run the hunts specified. Provide as a comma separated list of Mitre ATT&CK Technique IDs.", 
            cxxopts::value<std::vector<std::string>>())
		("exclude-hunts", "Run all hunts except those specified. Provide as a comma separated list of Mitre ATT&CK Technique IDs.", 
            cxxopts::value<std::vector<std::string>>())
		;

    options.add_options("log")
		("o,output", "Specify the output folder for any logs written to a file", 
            cxxopts::value<std::string>()->default_value("."))
        ;

    options.add_options("mitigate")
		("mode", "Selects whether to audit or enforce each mitigations. Options are audit and enforce. Ignored if "
                 "--gen-config is specified",
            cxxopts::value<std::string>()->default_value("audit")->implicit_value("audit"))
        ("config-json", "Specify a file containing a JSON configuration for which mitigations and policies should run", 
            cxxopts::value<std::string>())
        ("enforcement-level", "Specify the enforcement level for mitigations. This is used to select which policies "
                               "should be run. Available levels are none, low, moderate, high, and all",
            cxxopts::value<std::string>()->default_value("moderate")->implicit_value("moderate"))
        ("add-mitigations", "Specify additional JSON files containing mitigations.",
            cxxopts::value<std::vector<std::string>>())
        ("gen-config", "Generate a default JSON configuration file (./bluespawn-mitigation-config.json) with the "
                       "specified level of detail. Options are global, mitigations, and mitigation-policies. Will not "
                       "run any mitigations if this is specified",
            cxxopts::value<std::string>()->default_value("mitigations"))
        ;
    // clang-format on

    try {
        auto result = options.parse(argc, argv);

        if(result.count("help")) {
            print_help(result, options);
            return 0;
        }

        if(result["verbose"].as<int>() >= 1) {
            Log::LogLevel::LogInfo1.Enable();
        }
        if(result["verbose"].as<int>() >= 2) {
            Log::LogLevel::LogInfo2.Enable();
        }
        if(result["verbose"].as<int>() >= 3) {
            Log::LogLevel::LogInfo3.Enable();
        }

        if(result.count("debug")) {
            if(result["debug"].as<int>() >= 1) {
                Log::LogLevel::LogVerbose1.Enable();
            }
            if(result["debug"].as<int>() >= 2) {
                Log::LogLevel::LogVerbose2.Enable();
            }
            if(result["debug"].as<int>() >= 3) {
                Log::LogLevel::LogVerbose3.Enable();
            }
        }

        ParseLogSinks(result["log"].as<std::string>(), result["output"].as<std::string>());

        if(result.count("aggressiveness")){
            bluespawn.aggressiveness = GetAggressiveness(result["aggressiveness"]);
        }

        if(result.count("hunt") || result.count("monitor") || result.count("scan")) {
            if(result.count("hunt")) {
                bluespawn.EnableMode(BluespawnMode::HUNT);
            }
            if(result.count("monitor")) {
                bluespawn.EnableMode(BluespawnMode::MONITOR);
            }

            if(result.count("scan")){
                if(result.count("scan-file")){
                    for(auto& filePath : result["scan-file"].as<std::vector<std::string>>()){
                        FileSystem::File file{ StringToWidestring(filePath) };
                        if(!file.GetFileExists()){
                            Bluespawn::io.AlertUser(L"File " + file.GetFilePath() + L" not found");
                            continue;
                        }
                        bluespawn.scanFiles.emplace_back(file);
                    }
                }
                if(result.count("scan-folder")){
                    for(auto& folderPath : result["scan-folder"].as<std::vector<std::string>>()){
                        FileSystem::Folder folder{ StringToWidestring(folderPath) };
                        if(!folder.GetFolderExists()){
                            Bluespawn::io.AlertUser(L"Folder " + folder.GetFolderPath() + L" not found");
                            continue;
                        }
                        auto folderContents{ folder.GetFiles() };
                        for(auto& file : folderContents){
                            bluespawn.scanFiles.emplace_back(file);
                        }
                    }
                }
                if(result.count("scan-process")){
                    for(auto& process : result["scan-process"].as<std::vector<int>>()){
                        bluespawn.scanProcesses.emplace_back(process);
                    }
                }
                bluespawn.EnableMode(BluespawnMode::SCAN);
            }

            if(result.count("hunts")) {
                bluespawn.SetIncludedHunts(result["hunts"].as<std::vector<std::string>>());
            } else if(result.count("exclude-hunts")) {
                bluespawn.SetExcludedHunts(result["exclude-hunts"].as<std::vector<std::string>>());
            }

            auto UserReactions = result["react"].as<std::string>();
            std::set<std::string> reaction_set;
            for(unsigned startIdx = 0; startIdx < UserReactions.size();) {
                auto endIdx{ UserReactions.find(',', startIdx) };
                auto sink{ UserReactions.substr(startIdx, endIdx - startIdx) };
                reaction_set.emplace(sink);
                startIdx = endIdx + 1;
                if(endIdx == std::string::npos) {
                    break;
                }
            }

            for(auto reaction : reaction_set) {
                if(reactions.find(reaction) != reactions.end()) {
                    bluespawn.AddReaction(std::move(reactions[reaction]));
                } else {
                    bluespawn.io.AlertUser(L"Unknown reaction \"" + StringToWidestring(reaction) + L"\"", INFINITY,
                                           ImportanceLevel::MEDIUM);
                }
            }
        }

        if(result.count("mitigate")) {
            if(result.count("add-mitigations")){
                for(auto& path : result["add-mitigations"].as<std::vector<std::string>>()){
                    Bluespawn::mitigationRecord.ParseMitigationsJSON({ StringToWidestring(path) });
                }
            }
            if(result.count("gen-config")){
                auto opt{ ToLowerCaseA(result["gen-config"].as<std::string>()) };
                std::map<std::string, int> genConfigOptions{
                    {"global", 0},
                    {"mitigations", 1},
                    {"mitigation-policies", 2}
                };
                if(genConfigOptions.count(opt)){
                    if(Bluespawn::mitigationRecord.CreateConfig(
                        FileSystem::File{ L".\\bluespawn-mitigation-config.json" }, genConfigOptions[opt])){
                        Bluespawn::io.InformUser(L"Saved configuration to .\\bluespawn-mitigation-config.json");
                    }
                } else{
                    Bluespawn::io.AlertUser(StringToWidestring("Unknown gen-config mode \"" + opt + "\". Options are "
                                                               "global, mitigations, and mitigation-policies"));
                }
            } else{
                auto mode{ result["mode"].as<std::string>() };
                bool enforce{ mode == "e" || mode == "enforce" };
                std::map<std::string, EnforcementLevel> enforcementLevelOptions{
                    {"none", EnforcementLevel::None},
                    {"low", EnforcementLevel::Low},
                    {"moderate", EnforcementLevel::Moderate},
                    {"high", EnforcementLevel::High},
                    {"all", EnforcementLevel::All},
                };
                auto fileSpecified{ result.count("config-json") };
                if(!fileSpecified){
                    auto level{ EnforcementLevel::None };
                    auto levelSpecified{ result["enforcement-level"].as<std::string>() };
                    if(enforcementLevelOptions.count(levelSpecified)){
                        level = enforcementLevelOptions[levelSpecified];
                    } else{
                        Bluespawn::io.AlertUser(
                            StringToWidestring("Unknown enforcement level \"" + levelSpecified + "\". Options are none,"
                                               "low, moderate, high, and all. Defaulting to none"));
                    }
                    bluespawn.SetMitigationConfig(level);
                } else{
                    auto file{ FileSystem::File(StringToWidestring(result["config-json"].as<std::string>())) };
                    if(file.GetFileExists()){
                        try{
                            auto contents{ file.Read() };
                            bluespawn.SetMitigationConfig(json::parse(nlohmann::detail::span_input_adapter(
                                contents.GetAsPointer<char>(), contents.GetSize())));
                        } catch(std::exception& e){
                            Bluespawn::io.AlertUser(L"Error parsing JSON: " + StringToWidestring(e.what()));
                        }
                    } else{
                        Bluespawn::io.AlertUser(L"JSON configuration file " + file.GetFilePath() + L" not found!");
                        bluespawn.SetMitigationConfig(EnforcementLevel::None);
                    }
                }
                bluespawn.EnableMode(BluespawnMode::MITIGATE, enforce);
            }
        }

        bluespawn.Run();
    } catch(cxxopts::OptionParseException e1) {
        Bluespawn::io.InformUser(StringToWidestring(options.help()));
        LOG_ERROR(e1.what());
    }
    return 0;
}
