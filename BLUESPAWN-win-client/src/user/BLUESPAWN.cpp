#include "user/bluespawn.h"

#include <map>
#include <memory>
#include <thread>

#include <VersionHelpers.h>

#include "util/DynamicLinker.h"
#include "util/StringUtils.h"
#include "util/log/CLISink.h"
#include "util/log/DebugSink.h"
#include "util/log/JSONSink.h"
#include "util/log/XMLSink.h"
#include "util/ThreadPool.h"

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

DEFINE_FUNCTION(BOOL, IsWow64Process2, NTAPI, HANDLE hProcess, USHORT* pProcessMachine, USHORT* pNativeMachine);
LINK_FUNCTION(IsWow64Process2, KERNEL32.DLL);

HuntRegister Bluespawn::huntRecord{};
MitigationRegister Bluespawn::mitigationRecord{};
Aggressiveness Bluespawn::aggressiveness{ Aggressiveness::Normal };
DetectionRegister Bluespawn::detections{ Certainty::Moderate };
ReactionManager Bluespawn::reaction{};
std::vector<DetectionSink*> Bluespawn::detectionSinks{};
bool Bluespawn::EnablePreScanDetections{ false };
bool loadedMitigations{ false };

std::map<std::wstring, std::unique_ptr<Log::LogSink>> sinkMap{};
std::map<std::wstring, std::unique_ptr<Reaction>> availableReactions{};

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

    CheckArch();

    availableReactions.emplace(L"carve-memory", std::make_unique<Reactions::CarveMemoryReaction>());
    availableReactions.emplace(L"delete-file", std::make_unique<Reactions::DeleteFileReaction>());
    availableReactions.emplace(L"quarantine-file", std::make_unique<Reactions::QuarantineFileReaction>());
    availableReactions.emplace(L"remove-value", std::make_unique<Reactions::RemoveValueReaction>());
    availableReactions.emplace(L"suspend", std::make_unique<Reactions::SuspendProcessReaction>());
}

void Bluespawn::CheckArch(){
    BOOL bIsWow64 = FALSE;
    if(IsWindows10OrGreater() && Linker::IsWow64Process2){
        USHORT ProcessMachine;
        USHORT NativeMachine;
        Linker::IsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine);
        if(ProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN){
            bIsWow64 = TRUE;
        }
    } else{
        IsWow64Process(GetCurrentProcess(), &bIsWow64);
    }
    if(bIsWow64){
        Bluespawn::io.AlertUser(L"Running the x86 version of BLUESPAWN on an x64 system! This configuration is not "
                                L"fully supported, so we recommend downloading the x64 version.",
                                5000, ImportanceLevel::MEDIUM);
        LOG_WARNING("Running the x86 version of BLUESPAWN on an x64 system! This configuration is not fully supported, "
                    "so we recommend downloading the x64 version.");
    }
}

void Bluespawn::SetLogSinks(const std::vector<std::wstring>& sinks, const std::wstring& logdir) {
    std::wstring outputFolderPath = L".";

    auto outputDir = FileSystem::Folder(logdir);
    if(outputDir.GetFolderExists() && !outputDir.GetCurIsFile() && outputDir.GetFolderWrite()) {
        outputFolderPath = outputDir.GetFolderPath();
    } else {
        LOG_ERROR(L"Unable to access " << logdir << L" to write logs. Defaulting to current directory.");
        Bluespawn::io.AlertUser(L"Unable to access " + logdir + L" to write logs. Defaulting to current directory.",
                                5000, ImportanceLevel::MEDIUM);
    }

    std::vector<Log::LogLevel*> levels{
        Log::LogLevel::LogError.get(),    Log::LogLevel::LogWarn.get(),     Log::LogLevel::LogInfo1.get(),
        Log::LogLevel::LogInfo2.get(),    Log::LogLevel::LogInfo3.get(),    Log::LogLevel::LogVerbose1.get(),
        Log::LogLevel::LogVerbose2.get(), Log::LogLevel::LogVerbose3.get(),
    };

    for(auto& sinkName : sinks) {
        Log::LogSink* sink{ nullptr };
        if(sinkMap.find(sinkName) != sinkMap.end()){
            sink = sinkMap.at(sinkName).get();
        } else if(sinkName == L"console"){
            sinkMap.emplace(L"console", std::make_unique<Log::CLISink>());
            sink = sinkMap.at(sinkName).get();
        } else if(sinkName == L"xml"){
            sinkMap.emplace(L"xml", std::make_unique<Log::XMLSink>(outputFolderPath));
            sink = sinkMap.at(sinkName).get();
        } else if(sinkName == L"json"){
            sinkMap.emplace(L"json", std::make_unique<Log::JSONSink>(outputFolderPath));
            sink = sinkMap.at(sinkName).get();
        } else if(sinkName == L"debug"){
            sinkMap.emplace(L"debug", std::make_unique<Log::DebugSink>());
            sink = sinkMap.at(sinkName).get();
        }
        if(sink){
            Log::AddSink(sink, levels);
            if(auto detectionSink = dynamic_cast<DetectionSink*>(sink)){
                Bluespawn::detectionSinks.emplace_back(detectionSink);
            }
        } else {
            Bluespawn::io.AlertUser(L"Unknown log sink \"" + sinkName + L"\"", INFINITY, ImportanceLevel::MEDIUM);
        }
    }
}

void Bluespawn::AddDetectionSink(DetectionSink* sink) {
    Bluespawn::detectionSinks.emplace_back(sink);
}

void Bluespawn::SetAggressiveness(Aggressiveness level) {
    Bluespawn::aggressiveness = level;
}

void Bluespawn::RunHunts(const std::vector<std::wstring>& included, const std::vector<std::wstring>& excluded) {
    Bluespawn::io.InformUser(L"Running Hunts");
    DWORD tactics = UINT_MAX;
    DWORD dataSources = UINT_MAX;
    DWORD affectedThings = UINT_MAX;
    Scope scope{};

    huntRecord.RunHunts(included, excluded, scope);
}

void Bluespawn::Monitor(const std::vector<std::wstring>& included, const std::vector<std::wstring>& excluded) {
    Bluespawn::io.InformUser(L"Beginning Monitor");
    DWORD tactics = UINT_MAX;
    DWORD dataSources = UINT_MAX;
    DWORD affectedThings = UINT_MAX;
    Scope scope{};

    huntRecord.SetupMonitoring(included, excluded);

    std::thread logFlusher{ []() {
        HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
        while(true) {
            SetEvent(hRecordEvent);
            Sleep(5000);
        }
    } };
    logFlusher.detach();
}

void Bluespawn::SetReactions(const std::vector<std::wstring>& reactions) {
    for(auto& reaction : reactions){
        if(availableReactions.find(reaction) != availableReactions.end()){
            Bluespawn::reaction.AddHandler(std::move(availableReactions[reaction]));
        } else{
            Bluespawn::io.AlertUser(L"Unknown reaction \"" + reaction + L"\"", INFINITY,
                                    ImportanceLevel::MEDIUM);
        }
    }
}

void Bluespawn::AddMitigations(std::string mitigationJson){
    Bluespawn::mitigationRecord.ParseMitigationsJSON(
        AllocationWrapper{ const_cast<char*>(mitigationJson.c_str()), mitigationJson.size() });
}

std::map<Mitigation*, MitigationReport> Bluespawn::RunMitigations(const MitigationsConfiguration& config, 
                                                                  bool enforce){
    if(enforce){
        return Bluespawn::mitigationRecord.EnforceMitigations(config);
    } else{
        return Bluespawn::mitigationRecord.AuditMitigations(config);
    }
}

std::shared_ptr<Detection> Bluespawn::ScanProcess(DWORD pid){
    std::vector<std::shared_ptr<Detection>> detections{};
    Hunts::HuntT1055::HandleReport(detections, Hunts::HuntT1055::QueueProcessScan(pid));
    if(detections.size()){
        return detections[0];
    } else{
        return nullptr;
    }
}
std::shared_ptr<Detection> Bluespawn::ScanFile(const std::wstring& filePath){
    if(FileScanner::PerformQuickScan(filePath)){
        return Bluespawn::detections.AddDetection(Detection(FileDetectionData{ filePath }));
    }
    return nullptr;
}
std::vector<std::shared_ptr<Detection>> Bluespawn::ScanFolder(const std::wstring& folderPath){
    FileSystem::Folder folder{ folderPath };
    if(!folder.GetFolderExists()){
        Bluespawn::io.AlertUser(L"Folder " + folder.GetFolderPath() + L" not found");
        return {};
    }
    std::vector<std::shared_ptr<Detection>> detections{};
    auto folderContents{ folder.GetFiles() };
    for(auto& file : folderContents){
        if(FileScanner::PerformQuickScan(file.GetFilePath())){
            detections.emplace_back(Bluespawn::detections.AddDetection(Detection(FileDetectionData{ file })));
        }
    }
    return detections;
}

void Bluespawn::WaitForTasks(){
    ThreadPool::GetInstance().Wait();
}