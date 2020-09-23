#pragma once

#include <grpcpp/grpcpp.h>

#include <memory>

#include "util/log/Loggable.h"
#include "util/wrappers.hpp"

#include "BLUESPAWN-common/bluespawnpb/bluespawn.grpc.pb.h"

using bluespawn::BluespawnRPC;
using bluespawn::LogMessage;
using bluespawn::ResponseMessage;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

namespace RpcClient {
    class RpcClient {
        private:
        std::unique_ptr<BluespawnRPC::Stub> stub_;

        public:
        RpcClient(std::shared_ptr<Channel> channel) : stub_(BluespawnRPC::NewStub(channel)){};

        bool SendLogMessage(const std::wstring& msg, bluespawn::LogSeverity severity, bluespawn::LogDetail detail);
    };

};   // namespace RpcClient
