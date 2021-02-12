#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <map>

#include "util/configurations/Registry.h"
#include "util/log/DetectionSink.h"
#include "util/log/Log.h"

#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "reaction/ReactionManager.h"
#include "scan/DetectionRegister.h"
#include "user/banners.h"
#include "user/CLI.h"

enum class BluespawnMode { HUNT, SCAN, MONITOR, MITIGATE };

class Bluespawn {
    std::map<BluespawnMode, int> modes;
    std::vector<std::wstring> vIncludedHunts;
    std::vector<std::wstring> vExcludedHunts; 

    std::optional<MitigationsConfiguration> mitigationConfig;

    void RunMitigations(bool enforce);
    void RunHunts();
    void RunMonitor();
    void RunScan();

    public:
    std::vector<FileSystem::File> scanFiles;
    std::vector<int> scanProcesses;

    Bluespawn();

    void AddReaction(std::unique_ptr<Reaction>&& reaction);
    void EnableMode(BluespawnMode mode, int argument = 0);
    void SetIncludedHunts(std::vector<std::string> includedHunts);
    void SetExcludedHunts(std::vector<std::string> excludedHunts);
    void SetMitigationConfig(const MitigationsConfiguration& config);
    void Run();

    void check_correct_arch();

    static const IOBase& io;
    static HuntRegister huntRecord;
    static MitigationRegister mitigationRecord;
    static Aggressiveness aggressiveness;
    static DetectionRegister detections;
    static std::vector<std::shared_ptr<DetectionSink>> detectionSinks;
    static bool EnablePreScanDetections;

    static ReactionManager reaction;
};
