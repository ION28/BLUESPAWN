#include "user/bluespawn.h"

#include <iostream>
#include <memory>

#include "common/DynamicLinker.h"
#include "common/StringUtils.h"
#include "common/ThreadPool.h"

#include "util/eventlogs/EventLogs.h"
#include "util/log/CLISink.h"
#include "util/log/DebugSink.h"
#include "util/log/XMLSink.h"

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
#include "reaction/CarveMemory.h"
#include "reaction/DeleteFile.h"
#include "reaction/QuarantineFile.h"
#include "reaction/RemoveValue.h"
#include "reaction/SuspendProcess.h"
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
MitigationRegister Bluespawn::mitigationRecord{ io };
Aggressiveness Bluespawn::aggressiveness{ Aggressiveness::Normal };
DetectionRegister Bluespawn::detections{ Certainty::Moderate };
ReactionManager Bluespawn::reaction{};
std::vector<std::shared_ptr<DetectionSink>> Bluespawn::detectionSinks{};
bool Bluespawn::EnablePreScanDetections{ false };

std::map<std::string, std::unique_ptr<Reaction>> reactions{};

Bluespawn::Bluespawn() {
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1004>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1013>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1015>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1031>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1035>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1036>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1037>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1050>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1053>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1055>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1060>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1068>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1089>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1099>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1100>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1101>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1103>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1122>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1128>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1131>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1136>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1138>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1182>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1183>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1198>());
    huntRecord.RegisterHunt(std::make_unique<Hunts::HuntT1484>());

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

    huntRecord.RunHunts(scope);
}

void Bluespawn::RunMitigations(bool enforce, bool force) {
    if(enforce) {
        Bluespawn::io.InformUser(L"Enforcing Mitigations");
        mitigationRecord.EnforceMitigations(SecurityLevel::High, force);
    } else {
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

void Bluespawn::Run() {
    if(modes.find(BluespawnMode::SCAN) != modes.end()) {
        aggressiveness = static_cast<Aggressiveness>(modes.at(BluespawnMode::SCAN));
    } else {
        aggressiveness = Aggressiveness::Normal;
    }
    if(modes.find(BluespawnMode::MITIGATE) != modes.end()) {
        RunMitigations(modes[BluespawnMode::MITIGATE] & 0x01, modes[BluespawnMode::MITIGATE] & 0x02);
    }
    if(modes.find(BluespawnMode::HUNT) != modes.end()) {
        RunHunts();
    }
    if(modes.find(BluespawnMode::MONITOR) != modes.end()) {
        RunMonitor();
    }

    ThreadPool::GetInstance().Wait();
    Bluespawn::detections.Wait();
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
    std::string help_category = result["help"].as<std::string>();

    if(CompareIgnoreCase(help_category, std::string{ "hunt" })) {
        Bluespawn::io.InformUser(StringToWidestring(options.help({ "hunt" })));
    } else if(CompareIgnoreCase(help_category, std::string{ "monitor" })) {
        Bluespawn::io.InformUser(StringToWidestring(options.help({ "monitor" })));
    } else if(CompareIgnoreCase(help_category, std::string{ "mitigate" })) {
        Bluespawn::io.InformUser(StringToWidestring(options.help({ "mitigate" })));
    } else {
        Bluespawn::io.InformUser(StringToWidestring(options.help()));
    }
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

void ParseLogSinks(const std::string& sinks) {
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
            auto XML = std::make_shared<Log::XMLSink>();
            Log::AddSink(XML, levels);
            Bluespawn::detectionSinks.emplace_back(XML);
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
    Bluespawn bluespawn{};

    print_banner();

    bluespawn.check_correct_arch();

    cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

    // clang-format off
    options.add_options()
        ("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
        ("n,monitor", "Monitor the System for malicious activity, dispatching hunts as changes are detected.",
            cxxopts::value<std::string>()->implicit_value("Normal"))
        ("m,mitigate", "Mitigates vulnerabilities by applying security settings. Available options: audit, enforce", 
             cxxopts::value<std::string>()->implicit_value("audit"))
        ("a,aggressiveness", "Sets the aggressiveness of BLUESPAWN. Options are intensive, normal, and cursory.",
            cxxopts::value<std::string>()->default_value("Normal"))
        ("help", "Help Information. You can also specify a category for help on a specific module such as hunt.",
            cxxopts::value<std::string>()->implicit_value("general"))
        ("log", "Specify how Bluespawn should log events. Options are console (default), xml, and debug.",
            cxxopts::value<std::string>()->default_value("console"))
        ("r,react", "Specifies how bluespawn should react to potential threats dicovered during hunts.",
             cxxopts::value<std::string>()->default_value(""))
        ("v,verbose", "Verbosity", cxxopts::value<int>()->default_value("1"))
        ("debug", "Enable Debug Output", cxxopts::value<int>()->default_value("0"));
    
    options.add_options("mitigate")(
        "force", "Use this option to forcibly apply mitigations with no prompt", cxxopts::value<bool>());
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

        ParseLogSinks(result["log"].as<std::string>());

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

        if(result.count("aggressiveness")) {
            bluespawn.EnableMode(BluespawnMode::SCAN, static_cast<DWORD>(GetAggressiveness(result["aggressiveness"])));
        }
        if(result.count("mitigate")) {
            bool bForceEnforce = false;
            if(result.count("force"))
                bForceEnforce = true;

            MitigationMode mode = MitigationMode::Audit;
            if(result["mitigate"].as<std::string>() == "e" || result["mitigate"].as<std::string>() == "enforce")
                mode = MitigationMode::Enforce;

            bluespawn.EnableMode(BluespawnMode::MITIGATE,
                                 (static_cast<DWORD>(bForceEnforce) << 1) | (static_cast<DWORD>(mode) << 0));
        }
        if(result.count("hunt")) {
            bluespawn.EnableMode(BluespawnMode::HUNT);
        }
        if(result.count("monitor")) {
            bluespawn.EnableMode(BluespawnMode::MONITOR);
        }

        bluespawn.Run();
    } catch(cxxopts::OptionParseException e1) {
        Bluespawn::io.InformUser(StringToWidestring(options.help()));
        LOG_ERROR(e1.what());
    }
    return 0;
}
