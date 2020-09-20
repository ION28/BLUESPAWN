#pragma once

#include <grpcpp/grpcpp.h>

#include <memory>

#include "util/log/Loggable.h"
#include "util/wrappers.hpp"

#include "BLUESPAWN-common/bluespawnpb/bluespawn.grpc.pb.h"

using bluespawn::LogMessageRequest;
using bluespawn::LogMessageResponse;
using bluespawn::LogReceiver;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

namespace RpcClient {
    class RpcClient {
        private:
        std::unique_ptr<LogReceiver::Stub> stub_;

        public:
        RpcClient(std::shared_ptr<Channel> channel) : stub_(LogReceiver::NewStub(channel)){};

        bool SendLogMessage(const std::wstring& msg,
                            bluespawn::LogMessageRequest_Severity severity,
                            bluespawn::LogMessageRequest_Detail);
    };

};   // namespace RpcClient
