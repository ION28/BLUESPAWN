#include "util/log/ServerSink.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>

#include "util/StringUtils.h"
#include "util/Utils.h"
#include "util/rpc/RpcClient.h"

#include "user/bluespawn.h"

namespace Log {

    ServerSink::ServerSink(const std::wstring ServerAddress) :
        wServerAddress{ ServerAddress },
        client(grpc::CreateChannel(WidestringToString(wServerAddress), grpc::InsecureChannelCredentials())) {}

    void ServerSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {}

    void ServerSink::AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength) {}

    void ServerSink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && !Bluespawn::EnablePreScanDetections) {
            return;
        }

        BeginCriticalSection __{ *detection };
    }

    void ServerSink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                       IN CONST std::shared_ptr<Detection>& second,
                                       IN CONST Association& strength) {}

    void ServerSink::LogMessage(const LogLevel& level, const std::wstring& message) {
        if(level.Enabled()) {
            auto severity = static_cast<bluespawn::LogMessageRequest_Severity>(level.severity);
            auto detail = static_cast<bluespawn::LogMessageRequest_Detail>(*level.detail);
            bool response = client.SendLogMessage(message, severity, detail);
        }
    }

    bool ServerSink::operator==(const LogSink& sink) const {
        return (bool) dynamic_cast<const ServerSink*>(&sink) &&
               dynamic_cast<const ServerSink*>(&sink)->wServerAddress == wServerAddress;
    }
};   // namespace Log
