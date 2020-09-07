#include "util/log/ServerSink.h"

#include <cpr/cpr.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>

#include "util/StringUtils.h"
#include "util/Utils.h"
#include "util/configurations/CollectInfo.h"

#include "user/bluespawn.h"

namespace Log {

    void UpdateLog(ServerSink* sink) {
        HandleWrapper hRecordEvent{ CreateEventW(nullptr, false, false, L"Local\\FlushLogs") };
        while(true) {
            WaitForSingleObject(hRecordEvent, INFINITE);
            sink->Flush();
        }
    }

    ServerSink::ServerSink(const std::wstring ServerAddress) :
        wServerAddress{ ServerAddress }, thread{
            CreateThread(nullptr, 0, PTHREAD_START_ROUTINE(UpdateLog), this, CREATE_SUSPENDED, nullptr)
        } {
        ResumeThread(thread);
    }

    ServerSink::~ServerSink() { TerminateThread(thread, 0); }

    void ServerSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {}

    void ServerSink::AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength) {}

    void ServerSink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && !Bluespawn::EnablePreScanDetections) {
            return;
        }

        BeginCriticalSection __{ *detection };
        BeginCriticalSection _{ hGuard };
    }

    void ServerSink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                       IN CONST std::shared_ptr<Detection>& second,
                                       IN CONST Association& strength) {}

    void ServerSink::LogMessage(const LogLevel& level, const std::wstring& message) {
        BeginCriticalSection _{ hGuard };

        if(level.Enabled()) {
            json payload = json::object();
            payload["version"] = "1.1";
            payload["host"] = "WIN-2389DM8W";
            payload["short_message"] = WidestringToString(message);
            payload["timestamp"] = std::time(0);
            payload["level"] = 6;

            cpr::Response r = cpr::Post(cpr::Url{ WidestringToString(wServerAddress) },
                                        cpr::Header{ { "Content-Type", "application/json" } },
                                        cpr::Body{ payload.dump(-1) });
        }
    }

    bool ServerSink::operator==(const LogSink& sink) const {
        return (bool) dynamic_cast<const ServerSink*>(&sink) &&
               dynamic_cast<const ServerSink*>(&sink)->wServerAddress == wServerAddress;
    }

    void ServerSink::Flush() {}
};   // namespace Log
