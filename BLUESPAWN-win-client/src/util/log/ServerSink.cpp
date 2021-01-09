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

    ServerSink::ServerSink(const std::string address) :
        ServerAddress{ address }, client{ grpc::CreateChannel(address, grpc::InsecureChannelCredentials()) } {}

    void ServerSink::UpdateCertainty(IN CONST std::shared_ptr<Detection>& detection) {
        BeginCriticalSection __{ *detection };

        if(detections.find(detection->dwID) != detections.end()) {
            bool response = client.UpdateCertainty(detection);
        }
    }

    void ServerSink::AddAssociation(IN DWORD detection_id, IN DWORD associated, IN double strength) {
        if(detections.find(detection_id) != detections.end()) {
            bool response = client.AddAssociation(detection_id, associated, strength);
        }
    }

    void ServerSink::RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN RecordType type) {
        if(type == RecordType::PreScan && !Bluespawn::EnablePreScanDetections) {
            return;
        }

        BeginCriticalSection __{ *detection };

        bool response = client.RecordDetection(detection, type);
    }

    void ServerSink::RecordAssociation(IN CONST std::shared_ptr<Detection>& first,
                                       IN CONST std::shared_ptr<Detection>& second,
                                       IN CONST Association& strength) {
        UpdateCertainty(first);
        UpdateCertainty(second);

        if(detections.find(first->dwID) != detections.end()) {
            AddAssociation(first->dwID, second->dwID, strength);
        }

        if(detections.find(second->dwID) != detections.end()) {
            AddAssociation(second->dwID, first->dwID, strength);
        }
    }

    void ServerSink::LogMessage(const LogLevel& level, const std::wstring& message) {
        if(level.Enabled()) {
            bool response = client.SendLogMessage(message, level.severity, *level.detail);
        }
    }

    bool ServerSink::operator==(const LogSink& sink) const {
        return (bool) dynamic_cast<const ServerSink*>(&sink) &&
               dynamic_cast<const ServerSink*>(&sink)->ServerAddress == ServerAddress;
    }
};   // namespace Log
