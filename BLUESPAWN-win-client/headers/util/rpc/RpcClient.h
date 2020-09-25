#pragma once

#include <grpcpp/grpcpp.h>

#include <memory>

#include "util/log/DetectionSink.h"
#include "util/log/LogLevel.h"
#include "util/log/Loggable.h"
#include "util/wrappers.hpp"

#include "BLUESPAWN-common/bluespawnpb/bluespawn.grpc.pb.h"

using namespace bluespawn;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

namespace RpcClient {
    class RpcClient {
        private:
        std::unique_ptr<protobuffer::BluespawnRPC::Stub> stub_;

        protobuffer::Detection SerializeDetectionObject(IN CONST std::shared_ptr<Detection>& detection,
                                                        IN CONST RecordType type = RecordType::PostScan);

        public:
        RpcClient(std::shared_ptr<Channel> channel) : stub_(protobuffer::BluespawnRPC::NewStub(channel)){};

        bool RecordDetection(IN CONST std::shared_ptr<Detection>& detection, IN CONST RecordType type);

        bool SendLogMessage(const std::wstring& msg, Log::Severity severity, Log::Detail detail);
    };

};   // namespace RpcClient
