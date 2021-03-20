#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>


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

class Bluespawn {

public:
    static const IOBase& io;
    static HuntRegister huntRecord;
    static MitigationRegister mitigationRecord;
    static Aggressiveness aggressiveness;
    static DetectionRegister detections;
    static std::vector<DetectionSink*> detectionSinks;
    static ReactionManager reaction;
    static bool EnablePreScanDetections;

    Bluespawn();
    void CheckArch();
    void SetLogSinks(const std::vector<std::wstring>& sinks, const std::wstring& logdir);
    void AddDetectionSink(DetectionSink* sink);
    void SetAggressiveness(Aggressiveness level);
    void RunHunts(const std::vector<std::wstring>& included, const std::vector<std::wstring>& excluded);
    void Monitor(const std::vector<std::wstring>& included, const std::vector<std::wstring>& excluded);
    void SetReactions(const std::vector<std::wstring>& reactions);
    void AddMitigations(std::string mitigationJson);
    std::map<Mitigation*, MitigationReport> RunMitigations(const MitigationsConfiguration& config, bool enforce);
    void WaitForTasks();
    std::shared_ptr<Detection> ScanProcess(DWORD pid);
    std::shared_ptr<Detection> ScanFile(const std::wstring& filePath);
    std::vector<std::shared_ptr<Detection>> ScanFolder(const std::wstring& folderPath);
};